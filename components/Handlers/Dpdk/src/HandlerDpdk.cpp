#include "Handlers/Dpdk/HandlerDpdk.h"

#include "Handlers/Dpdk/Acl/Classification/Rules.h"
#include "Handlers/Dpdk/Acl/WorkerAcl.h"
#include "Handlers/Dpdk/DpdkDevice.h"
#include "Handlers/Dpdk/DpdkDeviceFactory.h"
#include "Handlers/Dpdk/DpdkEal.h"
#include "Handlers/Dpdk/DummyWorker.h"
#include "Handlers/Dpdk/JsonObjectDpdk.h"
#include "Handlers/Dpdk/RteMemPool.h"
#include "Handlers/Dpdk/RteSocket.h"
#include "Handlers/Dpdk/RuleMaker.h"
#include "NetDecoder/EtherType.h"

// dpdk
#include <iostream>
#include <rte_ethdev.h>
#include <rte_metrics.h>

// std
#include <atomic>
#include <list>
#include <memory>
#include <print>

namespace Nta::Network {

using DpdkDeviceList = std::list<std::shared_ptr<DpdkDevice>>;

static const std::unordered_map<std::string_view, uint16_t> EthertypePairs{
    {"eth", ETHER_HDR},
    {"vlan", ETHERTYPE_VLAN_SWP},
    {"ip", ETHERTYPE_IP_SWP},
    {"ipv6", ETHERTYPE_IPV6_SWP},
    {"mpls", ETHERTYPE_MPLS_SWP},
    {"ppoed", ETHERTYPE_PPPOED_SWP},
    {"ppoes", ETHERTYPE_PPPOES_SWP}};

auto RegexWordSearch = [](const std::string &regex, const std::string &line) {
    return std::regex_search(line, std::regex(regex));
};

auto IsValidLinkLayer = [](const std::string &linkLayer) -> std::pair<std::string_view, bool> {
    for (const auto &elem : EthertypePairs) {
        auto regex = std::string{"^"}.append(elem.first);
        if (RegexWordSearch(regex, linkLayer))
            return {elem.first, true};
    }
    return {{}, false};
};

auto GetLinkLayer = [](const Json::Objects::Worker &cfg) {
    // Create worker
    if (auto [name, valid] = IsValidLinkLayer(cfg.linkLayer); !valid) {
        std::println(std::cerr, "{}: link layer: \"{}\" invalid!", "APP", cfg.linkLayer);
    } else {
        return EthertypePairs.at(name);
    }
    return ETHER_HDR;
};

auto printSockWarn = [](auto dev, auto id) {
    std::println(
        "{}: device {} has {} socket!",
        "APP",
        dev->GetDeviceName(),
        id == SOCKET_ID_ANY ? "SOCKET_ID_ANY" : std::to_string(id));
    std::fflush(stdout);
};

auto printMemPoolWarn = []<typename... S>(auto mp, S... s) {
    if (mp == nullptr) {
        std::println("{}: set {} instead of {}", "APP", s...);
        std::fflush(stdout);
    }
};

// Function does the search for a DPDK device
auto findDpdkDev = [](const DpdkDeviceList &devices, const std::string &pci) {
    auto it = std::find_if(std::begin(devices), std::end(devices), [&pci](auto &&dev) {
        if (!dev)
            return false;
        return std::strcmp(pci.c_str(), dev->GetDeviceName().data()) == 0;
    });

    return *it;
};

template <typename Tuple, size_t N>
auto CreateRteRules(const std::vector<std::string> &rules, const std::array<rte_acl_field_def, N> &) {
    RteRuleMaker<Tuple, N> maker;

    std::vector<RteAclLookupRule<N>> rteRules{};
    rteRules.reserve(rules.size());

    std::for_each(std::begin(rules), std::end(rules), [&](const auto &rule) { rteRules.push_back(maker.Make(rule)); });

    return rteRules;
}

template <typename T> auto CreateRteRule(const std::string &rule) {
    return RteRuleMaker<typename T::tuple_type, T::tuple_defs_size>{}.Make(rule);
}

struct HandlerDpdk::Impl {
    ~Impl() = default;
    std::atomic_bool isInited{false};
    Json::Objects::DpdkObject config;
    std::vector<DpdkWorkerPtr> workers;
    std::map<int, RteCpuSocket> cpuSockets;
    std::map<int, RteMemPool> memPools;
    DpdkDeviceList devices;
};

HandlerDpdk::HandlerDpdk(const Json::Objects::DpdkObject &config)
    : m_Impl{new HandlerDpdk::Impl(), [](auto p) { delete p; }} {
    m_Impl->config = config;
}

HandlerDpdk::~HandlerDpdk() noexcept {
    Close();
}

void HandlerDpdk::Open() {
    if (m_Impl->isInited)
        throw std::runtime_error("Handler already opened!");

    // Args for the DPDK EAL
    std::vector<const char *> argPtrs{};
    argPtrs.reserve(std::numeric_limits<char>::max());

    // Opened devices
    std::map<std::string, std::shared_ptr<Network::DpdkDevice>> openedDevices;

    // Add proramm gname (necessary condition for the DPDK's ubutualization)
    argPtrs.push_back(m_Impl->config.m_Type.c_str());

    for (auto p : m_Impl->config.GetEalAdditionalOptions())
        argPtrs.push_back(p.data());

    // Process additional EAL args
    for (auto &[k, v] : m_Impl->config.m_EalCmdLine.args) {
        argPtrs.push_back(k.c_str());
        if (!v.empty())
            argPtrs.push_back(v.c_str());
    }

    // Init DPDK
    auto ealPointer = Device::DpdkEal::GetInstance(argPtrs);

    // Create cpu sockets
    for (auto numaId = 0; numaId < rte_socket_count(); numaId++) {
        // Common vars
        auto socketId = rte_socket_id_by_idx(numaId);

        // Create mempools
        auto name = "mempool_" + std::to_string(numaId);
        auto opt = m_Impl->config.m_MemPoolsOpts.Get(socketId);
        m_Impl->memPools.emplace(
            socketId,
            RteMemPool{
                name.c_str(), //
                opt.m_TotalMbufNum,
                opt.m_MbufCacheSize,
                opt.m_PrivSize,
                opt.m_MbufSize,
                numaId} //
        );

        // Create cpu sockets
        m_Impl->cpuSockets.emplace(socketId, RteCpuSocket{});
        // #ifdef RTE_LIB_METRICS
        //         /* Init metrics library */
        //         rte_metrics_init(idx);
        // #endif
    }

    if (m_Impl->cpuSockets.empty()) {
        throw std::runtime_error("DPDK has no available sockets!");
    }

    // Get DPDK device count
    auto devCount = rte_eth_dev_count_avail();
    if (devCount == 0) {
        throw std::runtime_error("DPDK device list is empty!");
    }

    Device::DpdkDeviceFactory factory;
    for (uint16_t port = 0; port < devCount; port++) {
        m_Impl->devices.emplace_back(factory.CreateEthDevDpdk(port, m_Impl->config.m_PromiscuousMode));
    }

    // Setup the workers
    for (const auto &workerCfg : m_Impl->config.m_Workers) {

        // Get workers core id
        auto coreId = workerCfg.ealCore;

        if (!rte_lcore_is_enabled(coreId)) {
            throw std::runtime_error(
                "Trying to use core #" + std::to_string(coreId) + " which isn't initialized by DPDK!");
        }

        // Create temporary rules vector
        std::vector<RteAclLookupRule<FiveTupleIp4Defs.size()>> tupleFiveRteRulesIp4{};

        if (workerCfg.type == "acl") {
            tupleFiveRteRulesIp4.clear();

            // Process input_packet_classification array
            for (const auto &cx : workerCfg.packetCx) {
                if (cx.type == "route") {
                    auto routeRules = CreateRteRules<FiveTupleIp4>(cx.tupleFiveIp4Rules, FiveTupleIp4Defs);
                    tupleFiveRteRulesIp4.insert(
                        tupleFiveRteRulesIp4.end(), std::begin(routeRules), std::end(routeRules));
                } else if (cx.type == "drop") {
                    auto dropRules = CreateRteRules<FiveTupleIp4>(cx.tupleFiveIp4Rules, FiveTupleIp4Defs);
                    tupleFiveRteRulesIp4.insert(tupleFiveRteRulesIp4.end(), std::begin(dropRules), std::end(dropRules));
                } else {
                    throw std::runtime_error("At least one rule should be present in the classification array!");
                    return;
                }
            }

            std::for_each(
                std::begin(workerCfg.packetRules), std::end(workerCfg.packetRules), [&tupleFiveRteRulesIp4](auto &obj) {
                    if (obj.type == "tuple5") {
                        tupleFiveRteRulesIp4.push_back(CreateRteRule<Rules::Tuple5>(obj.rule));
                    } else {
                        throw std::runtime_error(std::format("Unsupported rule type: {}!", obj.type));
                    }
                });

            // Try to find lcore's socket id
            auto wCoreSockId = rte_lcore_to_socket_id(coreId);
            if (auto socketIt = m_Impl->cpuSockets.find(wCoreSockId); socketIt != std::end(m_Impl->cpuSockets)) {

                // Try to find 5t context for socket
                auto tupleFiveIp4Context = socketIt->second.GetTupleFiveIp4Context(coreId);

                // If it doesn't exist
                if (!tupleFiveIp4Context) {
                    // Create ACL context
                    tupleFiveIp4Context = std::make_shared<RteAclContext>(
                        FiveTupleIp4Defs.size(),
                        8,
                        wCoreSockId,
                        workerCfg.type + "_tuple_five_ip4_worker_" + std::to_string(coreId));
                    tupleFiveIp4Context->SetCfgDefs(FiveTupleIp4Defs);
                    tupleFiveIp4Context->SetNumCategories(1);                     ///\todo move in config
                    if (!tupleFiveIp4Context->SetClassify(RTE_ACL_CLASSIFY_AVX2)) ///\todo add in config
                    {
                        if (!tupleFiveIp4Context->SetClassify(RTE_ACL_CLASSIFY_SCALAR)) {
                            throw std::runtime_error("Failed to setup classify method for ACL context\n");
                            return;
                        }
                    }
                    socketIt->second.AddTupleFiveIp4Context(coreId, tupleFiveIp4Context);
                }

                // Add rules in context
                tupleFiveIp4Context->AddRules(tupleFiveRteRulesIp4);

                auto rxDevPtr = findDpdkDev(m_Impl->devices, workerCfg.rxDevicePciAddr);
                if (!rxDevPtr)
                    throw std::runtime_error("Device " + workerCfg.rxDevicePciAddr + " doesn't exist!");

                auto txDevPtr = findDpdkDev(m_Impl->devices, workerCfg.txDevicePciAddr);
                if (!txDevPtr)
                    throw std::runtime_error("Device " + workerCfg.txDevicePciAddr + " doesn't exist!");

                // Try to find device's socket id
                auto mpRxSockId = rxDevPtr->GetSocketId();
                auto mpTxSockId = txDevPtr->GetSocketId();

                printSockWarn(rxDevPtr, mpRxSockId);
                printSockWarn(txDevPtr, mpTxSockId);

                // Create mempool pointers
                rte_mempool *mpRx{nullptr};
                rte_mempool *mpTx{nullptr};
                {
                    // Try to find device's memory pool
                    auto mpRxIt = m_Impl->memPools.find(mpRxSockId);
                    auto mpTxIt = m_Impl->memPools.find(mpTxSockId);

                    // If the devices don't belong to any core and therefore do not belong to any mempool
                    if (auto end = std::end(m_Impl->memPools); mpRxIt == end && mpTxIt == end) {

                        // Try to find mempool by the worker core ID
                        auto mpCommon = m_Impl->memPools.find(wCoreSockId);

                        if (mpCommon == end)
                            throw std::runtime_error(
                                "APP: There is no available memory pool for socket: " + std::to_string(wCoreSockId) +
                                "!");

                        mpRx = mpCommon->second.GetRteMemPoolPtr();
                        mpTx = mpCommon->second.GetRteMemPoolPtr();

                        ///\todo LOG
                    } else {
                        mpRx = mpRxIt->second.GetRteMemPoolPtr();
                        mpTx = mpTxIt->second.GetRteMemPoolPtr();

                        ///\todo LOG
                    }
                }

                if (!mpRx && !mpTx)
                    throw std::runtime_error("APP: There are no available memory pools!");

                // Setup device queues
                printMemPoolWarn(mpRx, "mpRx", "mpTx");
                rxDevPtr->SetRteMemPool(mpRx != nullptr ? mpRx : mpTx);

                printMemPoolWarn(mpTx, "mpTx", "mpRx");
                txDevPtr->SetRteMemPool(mpTx != nullptr ? mpTx : mpRx);

                rxDevPtr->SetRteMemPool(mpRx);
                rxDevPtr->Configure();

                txDevPtr->SetRteMemPool(mpTx);
                txDevPtr->Configure();

                // Create worker
                auto linkLayer = GetLinkLayer(workerCfg);

                auto workerAcl =
                    std::make_unique<WorkerAcl>(rxDevPtr, txDevPtr, tupleFiveIp4Context, linkLayer, coreId);
                workerAcl->StopAtEmptyRxEnable(workerCfg.stopAtEmptyRx);

                std::println(
                    "{}: link layer: {} is set for worker at core: {}.", "APP", linkLayer, workerAcl->GetCoreId());

                for (auto q : workerCfg.rxQueuesIdxs) {
                    rxDevPtr->SetupRxQueue(q);
                    workerAcl->SetQueueIdxRx(q);
                }

                for (auto q : workerCfg.txQueuesIdxs) {
                    txDevPtr->SetupTxQueue(q);
                    workerAcl->SetQueueIdxTx(q);
                }

                m_Impl->workers.push_back(std::move(workerAcl));
                ///\todo LOG CFG_OK
            } else {
                // Never throw
                throw std::runtime_error("Unknown socket id: " + std::to_string(rte_lcore_to_socket_id(coreId)) + "!");
            }
        } else if (workerCfg.type == "dummy") {
            m_Impl->workers.push_back(std::make_unique<Dummy>(coreId));
        } else {
            throw std::runtime_error("Unsupported worker type: " + workerCfg.type + "!");
        }
    }

    // Build all ACL contexts
    for (auto &[core, socket] : m_Impl->cpuSockets) {
        (void)core;
        std::for_each(
            std::begin(socket.GetTupleFiveIp4Contexts()),
            std::end(socket.GetTupleFiveIp4Contexts()),
            [&](const auto &ctx) {
                if (auto ctxIp4 = ctx.second; ctxIp4 != nullptr) {
                    ctxIp4->Build();
                }
            });
        std::for_each(
            std::begin(socket.GetTupleFiveIp6Contexts()),
            std::end(socket.GetTupleFiveIp6Contexts()),
            [&](const auto &ctx) {
                if (auto ctxIp6 = ctx.second; ctxIp6 != nullptr) {
                    ctxIp6->Build();
                }
            });
    }
}

void HandlerDpdk::Close() {
    StopDpdkWorkerThreads();
    // #ifdef RTE_LIB_METRICS
    //     rte_metrics_deinit();
    // #endif
}

void HandlerDpdk::SetCallback(std::function<CallBackFunctionType> &&f) {
    ///\todo
}

auto HandlerDpdk::GetCallback() -> std::function<CallBackFunctionType> {
    return {};
}
bool HandlerDpdk::StartDpdkWorkerThreads(std::vector<DpdkWorkerPtr> &workerThreadsVec) {
    constexpr auto trampoline = [](void *arg) {
        if (arg == nullptr)
            return -1;
        auto self = reinterpret_cast<AbstractWorker *>(arg);
        return self->Run(nullptr);
    };

    bool isOk{false};

    for (auto &worker : workerThreadsVec) {
        auto ret = rte_eal_remote_launch(trampoline, worker.get(), worker->GetCoreId());
        isOk = (ret == 0);
    }
    return isOk;
}

void HandlerDpdk::StopDpdkWorkerThreads() {
    if (m_Impl->workers.empty()) {
        return;
    }

    // Stop workers
    for (const auto &worker : m_Impl->workers) {
        worker->Stop();
        rte_eal_wait_lcore(worker->GetCoreId());
        // PCPP_LOG_DEBUG("Thread on core [" << worker->getCoreId() << "] stopped");
    }
    m_Impl->workers.clear();
    // PCPP_LOG_DEBUG("All worker threads stopped");*/

    // Close devices
    for (auto &dev : m_Impl->devices) {
        dev->Close();
    }
    m_Impl->devices.clear();

    // Free buffers
    for (auto &mp : m_Impl->memPools) {
        mp.second.Free();
    }
    m_Impl->memPools.clear();
}

void HandlerDpdk::Loop() {
    // Start capture in async mode
    if (!StartDpdkWorkerThreads(m_Impl->workers)) {
        throw std::runtime_error("Couldn't start worker threads!");
    }

    // Wait for threads
    auto lcoreId{RTE_MAX_LCORE};
    RTE_LCORE_FOREACH_WORKER(lcoreId) {
        if (rte_eal_wait_lcore(lcoreId) < 0)
            return;
    }
}

bool HandlerDpdk::SingleShot() {
    return false;
}
} // namespace Nta::Network
