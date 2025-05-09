#include "Handlers/Dpdk/HandlerDpdk.h"

#include "Handlers/Dpdk/Acl/LookupAcl.h"
#include "Handlers/Dpdk/Acl/WorkerAcl.h"
#include "Handlers/Dpdk/DummyWorker.h"
#include "Handlers/Dpdk/Errno.h"
#include "Handlers/Dpdk/JsonObjectDpdk.h"
#include "Handlers/Dpdk/RteSocket.h"
#include "Handlers/Dpdk/RuleMaker.h"

#include <DpdkDevice.h>
#include <DpdkDeviceList.h>
#include <atomic>
#include <memory>

namespace Nta::Network {

template <typename Tuple, size_t N>
auto CreateRteRules(const std::vector<std::string> &rules, const std::array<rte_acl_field_def, N> &) {
    RteRuleMaker<Tuple> maker;

    std::vector<RteAclLookupRule<N>> rteRules{};
    rteRules.reserve(rules.size());

    std::for_each(std::begin(rules), std::end(rules), [&](const auto &rule) { rteRules.push_back(maker.Make(rule)); });

    return rteRules;
}

struct HandlerDpdk::Impl {
    ~Impl() {
        for (const auto *w : workers) {
            delete w;
        }
    }

    std::atomic_bool isInited{false};
    Json::Objects::DpdkObject config;
    std::vector<pcpp::DpdkWorkerThread *> workers;
    std::map<int, RteCpuSocket> cpuSockets;
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

    // Process additional EAL args
    for (auto &[k, v] : m_Impl->config.m_EalCmdLine.args) {
        argPtrs.push_back(k.c_str());
        if (!v.empty())
            argPtrs.push_back(v.c_str());
    }

    // Init DPDK
    auto tempArgv = const_cast<char **>(argPtrs.data());
    m_Impl->isInited.store(pcpp::DpdkDeviceList::initDpdk(
        m_Impl->config.m_CoreMask,
        m_Impl->config.m_BufPoolSizePerDevice,
        m_Impl->config.m_HeadRoomSize,
        m_Impl->config.m_MainLcore,
        argPtrs.size(),
        tempArgv));

    if (!m_Impl->isInited.load())
        throw std::runtime_error("DPDK initialization failed!");

    // Create cpu sockets
    for (auto idx = 0; idx < rte_socket_count(); idx++) {
        m_Impl->cpuSockets.emplace(rte_socket_id_by_idx(idx), RteCpuSocket{});
    }

    if (m_Impl->cpuSockets.empty()) {
        throw std::runtime_error("DPDK has no available sockets!");
        // return;
    }

    // Removing DPDK master core from core mask because DPDK worker threads cannot run on master core
    const auto coreMaskToUse =
        m_Impl->config.m_CoreMask & ~(pcpp::DpdkDeviceList::getInstance().getDpdkMasterCore().Mask);

    // Converting masked cores bits to the cores numbers
    std::vector<int> maskedCoreNumbers{};
    maskedCoreNumbers.reserve(RTE_MAX_LCORE);

    auto tempCoreMask = coreMaskToUse;
    for (auto coreNum = 0; tempCoreMask > 0; coreNum++) {
        if (tempCoreMask & 1) {
            maskedCoreNumbers.push_back(coreNum);
        }
        tempCoreMask = tempCoreMask >> 1;
    }

    // Find DPDK devices
    auto &deviceList = pcpp::DpdkDeviceList::getInstance().getDpdkDeviceList();
    if (deviceList.empty()) {
        throw std::runtime_error("DPDK device list is empty!");
    }

    // Dev search function
    auto devSearch = [&](const std::string_view &pciAddress) {
        auto it = std::find_if(
            std::begin(deviceList), std::end(deviceList), [addr = pciAddress](pcpp::DpdkDevice *const dev) {
                if (!dev)
                    return false;
                return addr == dev->getPciAddress();
            });
        return it == std::end(deviceList) ? nullptr : *it;
    };

    // Creates and open Nta::Network::DpdkDevice
    auto openDpdkDev = [&devSearch, &openedDevices](
                           const std::string &pci,
                           const Json::Objects::WorkerQueueRange &numOfRxQueues,
                           const Json::Objects::WorkerQueueRange &numOfTxQueues) {
        if (auto opnDevIt = openedDevices.find(pci); opnDevIt != std::end(openedDevices))
            return opnDevIt->second;

        auto dev = devSearch(pci);

        if (!dev)
            throw std::runtime_error("Device #" + pci + "\"" + " not found!");

        if (!dev->openMultiQueues(numOfRxQueues.queueIdxs.size()/*back()*/, numOfTxQueues.queueIdxs.size()/*back()*/)) {
            throw std::runtime_error(
                "Couldn't open device #" + std::to_string(dev->getDeviceId()) + ", PMD '" + dev->getPMDName() + "'");
        }

        auto opnDevPtr = std::make_shared<Network::DpdkDevice>(dev);

        auto [it, ok] = openedDevices.try_emplace(pci, opnDevPtr);
        (void)it;

        if(!ok)
            throw std::runtime_error("Error while insertin opened device #" + pci + "\"" + "!");

        return opnDevPtr;
    };

    // Process config of the workers
    for (auto n = 0; const auto &worker : m_Impl->config.workers) {

        // Get workers core id
        auto coreId = worker.ealCore;

        // Create temporary rules vector
        std::vector<RteAclLookupRule<FiveTupleIp4Defs.size()>> tupleFiveRteRulesIp4{};

        // If worker hasn't specified core number
        if (coreId < 0) {
            if (!(n < maskedCoreNumbers.size())) {
                throw std::runtime_error("Supposed core id #" + std::to_string(n) + " isn't initialized by DPDK!");
            }

            // Get first core number from the list of masked cores
            coreId = maskedCoreNumbers[n++];
        }

        if (!rte_lcore_is_enabled(coreId)) {
            throw std::runtime_error(
                "Trying to use core #" + std::to_string(coreId) + " which isn't initialized by DPDK!");
        }

        if (worker.type == "acl") {
            tupleFiveRteRulesIp4.clear();

            // Process input_packet_classification array
            for (const auto &cx : worker.packetCx) {
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

            if (auto socketIt = m_Impl->cpuSockets.find(rte_lcore_to_socket_id(coreId));
                socketIt != std::end(m_Impl->cpuSockets)) {

                auto tupleFiveIp4Context = socketIt->second.GetTupleFiveIp4Context(coreId);

                if (!tupleFiveIp4Context) {
                    // Create ACL context
                    tupleFiveIp4Context = std::make_shared<RteAclContext>(
                        FiveTupleIp4Defs.size(),
                        8,
                        rte_lcore_to_socket_id(coreId),
                        worker.type + "_tuple_five_ip4_worker_" + std::to_string(coreId));
                    tupleFiveIp4Context->SetCfgDefs(FiveTupleIp4Defs);
                    tupleFiveIp4Context->SetNumCategories(1);                     ///\todo move in config
                    if (!tupleFiveIp4Context->SetClassify(RTE_ACL_CLASSIFY_AVX2)) ///\todo add in config
                    {
                        if (!tupleFiveIp4Context->SetClassify(RTE_ACL_CLASSIFY_SCALAR)) {
                            throw std::runtime_error("Failed to setup classify method for  ACL context\n");
                            return;
                        }
                    }
                    socketIt->second.AddTupleFiveIp4Context(coreId, tupleFiveIp4Context);
                }

                // Add rules in context
                tupleFiveIp4Context->AddRules(tupleFiveRteRulesIp4);

                // Create worker
                auto rxDevPtr = openDpdkDev(worker.rxDevicePciAddr, worker.rxQueuesIdxs, worker.txQueuesIdxs);
                auto txDevPtr = openDpdkDev(worker.txDevicePciAddr, worker.rxQueuesIdxs, worker.txQueuesIdxs);

                auto workerAcl = new WorkerAcl(rxDevPtr, txDevPtr, tupleFiveIp4Context, coreId);
                workerAcl->SetQueueIdxsRx(worker.rxQueuesIdxs.queueIdxs);
                workerAcl->SetQueueIdxsTx(worker.txQueuesIdxs.queueIdxs);
                m_Impl->workers.push_back(std::move(workerAcl));
            } else {
                // Never throw
                throw std::runtime_error("Unknown socket id: " + std::to_string(rte_lcore_to_socket_id(coreId)) + "!");
            }

        } else if (worker.type == "dummy") {
            m_Impl->workers.push_back(new Dummy());
        } else {
            throw std::runtime_error("Unsupported worker type: " + worker.type + "!");
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

    // Start capture in async mode
    if (!StartDpdkWorkerThreads(coreMaskToUse, m_Impl->workers)) {
        throw std::runtime_error("Couldn't start worker threads!");
    }
}

void HandlerDpdk::Close() {
    StopDpdkWorkerThreads();
}

void HandlerDpdk::SetCallback(std::function<CallBackFunctionType> &&f) {}

auto HandlerDpdk::GetCallback() -> std::function<CallBackFunctionType> {
    return {};
}

bool HandlerDpdk::StartDpdkWorkerThreads(
    const uint32_t coreMask,
    std::vector<pcpp::DpdkWorkerThread *> &workerThreadsVec) {
    if (coreMask & pcpp::DpdkDeviceList::getInstance().getDpdkMasterCore().Mask) {
        throw std::runtime_error("Cannot run worker thread on DPDK master core");
    }

    auto dpdkThreadStarter = [](void *p) {
        auto thread = reinterpret_cast<pcpp::DpdkWorkerThread *>(p);
        return static_cast<int>(thread->run(rte_lcore_id()));
    };

    for (auto workerIt = workerThreadsVec.begin(); workerIt != workerThreadsVec.end(); workerIt++) {
        int err = rte_eal_remote_launch(
            static_cast<lcore_function_t *>(dpdkThreadStarter), *workerIt, (*workerIt)->getCoreId());
        if (auto message = GetDpdkErrorMessage(err); err != 0) {
            for (const auto &thread : workerThreadsVec) {
                thread->stop();
                rte_eal_wait_lcore(thread->getCoreId());
                ///\todo Log LOG_DEBUG("Thread on core [" << thread->getCoreId() << "] stopped");
            }
            ///\todo Log LOG_ERROR("Cannot create worker thread #" << getCoreId << ". Error was: [" << strerror(err) << "]");
            return false;
        }
    }
    return true;
}

void HandlerDpdk::StopDpdkWorkerThreads() {
    if (m_Impl->workers.empty()) {
        return;
        // throw std::runtime_error("No worker threads were set");
    }

    for (const auto &worker : m_Impl->workers) {
        worker->stop();
        rte_eal_wait_lcore(worker->getCoreId());
        // PCPP_LOG_DEBUG("Thread on core [" << worker->getCoreId() << "] stopped");
    }

    m_Impl->workers.clear();
    // PCPP_LOG_DEBUG("All worker threads stopped");
}

void HandlerDpdk::Loop() {
    auto lcoreId = RTE_MAX_LCORE;
    RTE_LCORE_FOREACH_WORKER(lcoreId) {
        if (rte_eal_wait_lcore(lcoreId) < 0)
            return;
    }
}

bool HandlerDpdk::SingleShot() {
    return false;
}
} // namespace Nta::Network
