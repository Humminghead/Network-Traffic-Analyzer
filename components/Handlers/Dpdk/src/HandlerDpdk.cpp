#include "Handlers/Dpdk/HandlerDpdk.h"

#include "Handlers/Dpdk/JsonObjectDpdk.h"
#include "Handlers/Dpdk/Acl/LookupAcl.h"
#include "Handlers/Dpdk/RuleMaker.h"

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
        0,
        m_Impl->m_Config.m_MainLcore,
        argPtrs.size(),
        tempArgv));

    if (!m_Impl->inited.load())
        throw std::runtime_error("DPDK initialization failed!");

    RteAclContext ctx{"Handler DPDK context", FiveTupleIp4Defs.size(), 8};
    ctx.AddRules(m_Impl->fiveTupleIp4Rules);
    ctx.SetNumFields(FiveTupleIp4Defs.size());
    ctx.SetNumCategories(2);
    ctx.SetCfgDefs(FiveTupleIp4Defs);

    ctx.Build();
}

void HandlerDpdk::Close() {}

void HandlerDpdk::SetCallback(std::function<CallBackFunctionType> &&f) {}

auto HandlerDpdk::GetCallback() -> std::function<CallBackFunctionType> {
    return {};
}

void HandlerDpdk::Loop() {}

bool HandlerDpdk::SingleShot() {
    return false;
}
} // namespace Nta::Network
