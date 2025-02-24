#include "Handlers/Dpdk/HandlerDpdk.h"

#include "Handlers/Dpdk/JsonObjectDpdk.h"
#include "Handlers/Dpdk/Acl/LookupAcl.h"

#include <DpdkDeviceList.h>
#include <memory>

namespace Nta::Network {

struct HandlerDpdk::Impl {
    Json::Objects::DpdkObject m_Config;
};

HandlerDpdk::HandlerDpdk(const Json::Objects::DpdkObject &config)
    : m_Impl{new HandlerDpdk::Impl(), [](auto p) { delete p; }} {
    m_Impl->m_Config = config;
}

HandlerDpdk::~HandlerDpdk() noexcept {
    Close();
}

void HandlerDpdk::Open() {
    char **tempArgv{nullptr};
    size_t i=0,beg = 0, end = 0;

    std::vector<const char *> argPtrs{};
    argPtrs.reserve(std::numeric_limits<char>::max());

    for (auto &[k,v] : m_Impl->m_Config.m_EalCmdLine.args) {
        argPtrs.push_back(k.c_str());
        argPtrs.push_back(v.c_str());
    }

    tempArgv = const_cast<char **>(argPtrs.data());
    bool ok = pcpp::DpdkDeviceList::initDpdk(
        m_Impl->m_Config.m_CoreMask,
        m_Impl->m_Config.m_BufPoolSizePerDevice,
        0,
        m_Impl->m_Config.m_MainLcore,
        argPtrs.size(),
        tempArgv);

    if (!ok)
        throw std::runtime_error("DPDK initialization failed!");
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
