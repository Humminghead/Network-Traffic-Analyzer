#include "Handlers/Dpdk/HandlerDpdk.h"

#include "Handlers/Dpdk/Acl/LookupAcl.h"
#include "Handlers/Dpdk/Acl/WorkerAcl.h"
#include "Handlers/Dpdk/DummyWorker.h"
#include "Handlers/Dpdk/JsonObjectDpdk.h"
#include "Handlers/Dpdk/RuleMaker.h"

#include <DpdkDevice.h>
#include <DpdkDeviceList.h>
#include <atomic>
#include <memory>

namespace Nta::Network {

struct HandlerDpdk::Impl {
    std::atomic_bool inited{false};
    Json::Objects::DpdkObject m_Config;
    RteLookupAcl m_Acl;
    std::vector<RteAclLookupRule<FiveTupleIp4Defs.size()>> tupleFiveIp4RteRules{};
    RteRuleMaker<FiveTupleIp4> tupleFiveRuleMakerIp4{};
    // std::vector<std::unique_ptr<pcpp::DpdkWorkerThread>> workers;
    std::vector<pcpp::DpdkWorkerThread *> workers;
};

HandlerDpdk::HandlerDpdk(const Json::Objects::DpdkObject &config)
    : m_Impl{new HandlerDpdk::Impl(), [](auto p) { delete p; }} {
    m_Impl->m_Config = config;
}

HandlerDpdk::~HandlerDpdk() noexcept {
    Close();
}

void HandlerDpdk::Open() {
    if (m_Impl->inited)
        throw std::runtime_error("Handler already opned!");

    std::vector<const char *> argPtrs{};
    argPtrs.reserve(std::numeric_limits<char>::max());

    // Process additional EAL args
    for (auto &[k, v] : m_Impl->m_Config.m_EalCmdLine.args) {
        argPtrs.push_back(k.c_str());
        argPtrs.push_back(v.c_str());
    }

    // Init DPDK
    auto tempArgv = const_cast<char **>(argPtrs.data());
    m_Impl->inited.store(pcpp::DpdkDeviceList::initDpdk(
        m_Impl->m_Config.m_CoreMask,
        m_Impl->m_Config.m_BufPoolSizePerDevice,
        m_Impl->m_Config.m_HeadRoomSize,
        m_Impl->m_Config.m_MainLcore,
        argPtrs.size(),
        tempArgv));

    if (!m_Impl->inited.load())
        throw std::runtime_error("DPDK initialization failed!");

    // Removing DPDK master core from core mask because DPDK worker threads cannot run on master core
    const auto coreMaskToUse =
        m_Impl->m_Config.m_CoreMask & ~(pcpp::DpdkDeviceList::getInstance().getDpdkMasterCore().Mask);

    // Converting masked cores bits to the cores numbers
    std::vector<int> maskedCoreNumbers;
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

    // Create ACL context for each socket
    std::vector<std::shared_ptr<RteAclContext>> contexts;
    std::vector<std::string> ctxNames;
    auto socketCount = rte_socket_count();
    ctxNames.reserve(socketCount);

    for (auto n = 0; n < socketCount; n++) {
        auto ctx = std::make_shared<RteAclContext>();
        ctxNames.push_back("handler-dpdk-context_" + std::to_string(n));
        ctx->SetName(ctxNames.back());
        ctx->SetNumFieldsAndRuleSize(FiveTupleIp4Defs.size());
        ctx->SetMaxRuleCount(8); ///\todo
        ctx->SetSocketId(rte_socket_id_by_idx(n));
        ctx->Create();

        if (!ctx->SetClassify(RTE_ACL_CLASSIFY_AVX2)) ///\todo add in config
        {
            if (!ctx->SetClassify(RTE_ACL_CLASSIFY_SCALAR))
                throw std::runtime_error("Failed to setup classify method for  ACL context\n");
        }

        // ctx->AddRules(m_Impl->tupleFiveIp4RteRules);
        // ctx->SetNumCategories(1); ///\todo move in config
        // ctx->SetCfgDefs(FiveTupleIp4Defs);
        // ctx->Build();

        contexts.push_back(std::move(ctx));
    }

    // Open all DPDK devices
    std::vector<std::shared_ptr<DpdkDevice>> openedDevices;
    for (auto &device : deviceList) {
        auto devicePtr = std::make_shared<DpdkDevice>(device);
        auto totalNumOfRxQueues = devicePtr->GetTotalNumOfRxQueues();
        auto totalNumOfTxQueues = devicePtr->GetTotalNumOfTxQueues();

        if (!devicePtr->OpenMultiQueues(totalNumOfRxQueues, totalNumOfTxQueues)) {
            throw std::runtime_error(
                "Couldn't open device #" + std::to_string(devicePtr->GetDeviceId()) + ", PMD '" +
                devicePtr->GetPMDName() + "'");
        }

        openedDevices.push_back(devicePtr);
    }

    // Process config of the workers
    for (auto n = 0; const auto &worker : m_Impl->m_Config.workers) {

        // Create worker
        auto coreId = worker.ealCore;

        // If worker hasn't specified core number
        if (coreId < 0)
        {
            if (!(n < maskedCoreNumbers.size())) {
                throw std::runtime_error(
                    "Supposed core id #" + std::to_string(n) + " isn't initialized by DPDK!");
            }

            // Get first core number from the list of masked cores
            coreId = maskedCoreNumbers[n++];
        }

        if (!rte_lcore_is_enabled(coreId)) {
            throw std::runtime_error(
                "Trying to use core #" + std::to_string(coreId) + " which isn't initialized by DPDK!");
        }

        if (worker.type == "acl") {
            // Process input_packet_classification array
            for (const auto &cx : worker.packetCx) {
                if (cx.type == "route") {
                    m_Impl->tupleFiveIp4RteRules.reserve(cx.tupleFiveIp4Rules.size());
                    std::for_each(
                        std::begin(cx.tupleFiveIp4Rules), std::end(cx.tupleFiveIp4Rules), [&](const auto &rule) {
                            m_Impl->tupleFiveIp4RteRules.push_back(m_Impl->tupleFiveRuleMakerIp4.Make(rule));
                        });
                } else if (cx.type == "drop") {
                    ///\todo
                } else {
                    throw std::runtime_error("At least one rule should be present in the classification array!");
                }
            }

            auto context = std::find_if(
                std::begin(contexts),
                std::end(contexts),
                [coreSocket = rte_lcore_to_socket_id(coreId)](const auto &ctx) {
                    return coreSocket == ctx->GetSocketId();
                });

            if(context == std::end(contexts)){
                throw std::runtime_error("Unable to find context for core: " + std::to_string(coreId) + "!");
            }

            m_Impl->workers.push_back(new WorkerAcl(openedDevices[0], openedDevices[0], *context));

        }else if(worker.type == "dummy"){
            m_Impl->workers.push_back(new Dummy());
        }
        else {
            throw std::runtime_error("Unsupported worker type: " + worker.type + "!");
        }
    }

    ///\todo
    ///

    // ctx->AddRules(m_Impl->tupleFiveIp4RteRules);
    // ctx->SetNumCategories(1); ///\todo move in config
    // ctx->SetCfgDefs(FiveTupleIp4Defs);
    // ctx->Build();

    // m_Impl->workers.push_back(new WorkerAcl(openedDevices[0], openedDevices[0], contexts[0]));
    // m_Impl->workers.push_back(new Dummy());
    // m_Impl->workers.push_back(new Dummy());

    // Start capture in async mode
    if (!pcpp::DpdkDeviceList::getInstance().startDpdkWorkerThreads(coreMaskToUse, m_Impl->workers)) {
        throw std::runtime_error("Couldn't start worker threads!");
    }
}

void HandlerDpdk::Close() {}

void HandlerDpdk::SetCallback(std::function<CallBackFunctionType> &&f) {}

auto HandlerDpdk::GetCallback() -> std::function<CallBackFunctionType> {
    return {};
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
