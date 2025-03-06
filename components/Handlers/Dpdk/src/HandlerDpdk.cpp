#include "Handlers/Dpdk/HandlerDpdk.h"

#include "Handlers/Dpdk/JsonObjectDpdk.h"
#include "Handlers/Dpdk/Acl/LookupAcl.h"
#include "Handlers/Dpdk/RuleMaker.h"
#include "Handlers/Dpdk/DummyWorker.h"
#include "Handlers/Dpdk/Acl/Worker.h"

#include <DpdkDeviceList.h>
#include <DpdkDevice.h>
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
    std::vector<pcpp::DpdkWorkerThread*> workers;
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

    char **tempArgv{nullptr};
    size_t i=0,beg = 0, end = 0;

    std::vector<const char *> argPtrs{};
    argPtrs.reserve(std::numeric_limits<char>::max());

    for (auto &[k,v] : m_Impl->m_Config.m_EalCmdLine.args) {
        argPtrs.push_back(k.c_str());
        argPtrs.push_back(v.c_str());
    }

    m_Impl->fiveTupleIp4Rules.reserve(m_Impl->m_Config.m_PacketCx.size());

    for(const auto& cx: m_Impl->m_Config.m_PacketCx){
        if (cx.type == "acl") {
            std::for_each(std::begin(cx.rules),std::end(cx.rules),[&](auto &rule){
               m_Impl->fiveTupleIp4Rules.push_back(m_Impl->fiveTupleMaker.Make(rule));
            });
        } else {
            ///\todo log or throw
        }
    }    

    tempArgv = const_cast<char **>(argPtrs.data());
    m_Impl->inited.store(pcpp::DpdkDeviceList::initDpdk(
        m_Impl->m_Config.m_CoreMask,
        m_Impl->m_Config.m_BufPoolSizePerDevice,
        0,///\todo
        m_Impl->m_Config.m_MainLcore,
        argPtrs.size(),
        tempArgv));

    if (!m_Impl->inited.load())
        throw std::runtime_error("DPDK initialization failed!");

    RteAclContext ctx{};
    ctx.SetName("handler-dpdk-context");
    ctx.SetNumFieldsAndRuleSize(FiveTupleIp4Defs.size());
    ctx.SetMaxRuleCount(8);
    ctx.Create();

    if (!ctx.SetClassify(RTE_ACL_CLASSIFY_AVX2)) ///\todo add in config
    {
        if (!ctx.SetClassify(RTE_ACL_CLASSIFY_SCALAR))
            throw std::runtime_error("Failed to setup classify method for  ACL context\n");
    }

    ctx.AddRules(m_Impl->fiveTupleIp4Rules);
    ctx.SetNumCategories(1);///\todo move in config
    ctx.SetCfgDefs(FiveTupleIp4Defs);
    ctx.Build();

    // Find DPDK devices
    auto &deviceList = pcpp::DpdkDeviceList::getInstance().getDpdkDeviceList();
    if (deviceList.empty()) {
        throw std::runtime_error("DPDK device list is empty!");
    }

        // Open DPDK devices
        auto device = std::make_shared<DpdkDevice>(deviceList.at(0));
        auto totalNumOfRxQueues = device->GetTotalNumOfRxQueues();
        auto totalNumOfTxQueues = device->GetTotalNumOfTxQueues();

    if (!device->OpenMultiQueues(totalNumOfRxQueues, totalNumOfTxQueues))
    {
        throw std::runtime_error(
            "Couldn't open device1 #" + std::to_string(device->GetDeviceId()) + ", PMD '" + device->GetPMDName() + "'");
    }

    m_Impl->workers.push_back(new Worker(device, device, std::move(ctx)));
    m_Impl->workers.push_back(new Dummy());

    // Start capture in async mode
    if (!pcpp::DpdkDeviceList::getInstance().startDpdkWorkerThreads(m_Impl->m_Config.m_CoreMask, m_Impl->workers))
    {
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
