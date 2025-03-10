#include "Handlers/Dpdk/HandlerDpdk.h"

#include "Handlers/Dpdk/Acl/LookupAcl.h"
#include "Handlers/Dpdk/Acl/Worker.h"
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
    std::vector<RteAclLookupRule<FiveTupleIp4Defs.size()>> fiveTupleIp4Rules{};
    RteRuleMaker<FiveTupleIp4> fiveTupleMaker{};
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

    for (auto &[k, v] : m_Impl->m_Config.m_EalCmdLine.args) {
        argPtrs.push_back(k.c_str());
        argPtrs.push_back(v.c_str());
    }

    m_Impl->fiveTupleIp4Rules.reserve(m_Impl->m_Config.m_PacketCx.size());

    for (const auto &cx : m_Impl->m_Config.m_PacketCx) {
        if (cx.type == "route") {
            std::for_each(std::begin(cx.rules), std::end(cx.rules), [&](auto &rule) {
                m_Impl->fiveTupleIp4Rules.push_back(m_Impl->fiveTupleMaker.Make(rule));
            });
        } else if (cx.type == "drop") {
            ///\todo
        } else {
            throw std::runtime_error("At least one rule should be present in the classification array!");
        }
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
        ctx->SetSocketId(n);
        ctx->Create();

        if (!ctx->SetClassify(RTE_ACL_CLASSIFY_AVX2)) ///\todo add in config
        {
            if (!ctx->SetClassify(RTE_ACL_CLASSIFY_SCALAR))
                throw std::runtime_error("Failed to setup classify method for  ACL context\n");
        }

        ctx->AddRules(m_Impl->fiveTupleIp4Rules);
        ctx->SetNumCategories(1); ///\todo move in config
        ctx->SetCfgDefs(FiveTupleIp4Defs);
        ctx->Build();

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

    ///\todo
    m_Impl->workers.push_back(new Worker(openedDevices[0], openedDevices[0], contexts[0]));
    m_Impl->workers.push_back(new Dummy());
    m_Impl->workers.push_back(new Dummy());

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
