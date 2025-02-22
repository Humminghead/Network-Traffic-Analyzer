#include "Handlers/Dpdk/HandlerDpdk.h"

#include "Handlers/Dpdk/JsonObjectDpdk.h"

#include <memory>

namespace Nta::Network {

struct HandlerDpdk::Impl {
    Json::Objects::JsonObjectDpdk mConfig;
};

HandlerDpdk::HandlerDpdk(const Json::Objects::JsonObjectDpdk &config)
    : m_Impl{new HandlerDpdk::Impl(), [](auto p) { delete p; }} {
    m_Impl->mConfig = config;
}

HandlerDpdk::~HandlerDpdk() noexcept {
    Close();
}

void HandlerDpdk::Open() {
}

void HandlerDpdk::Close() {
}

void HandlerDpdk::SetCallback(std::function<CallBackFunctionType> &&f) {
}

auto HandlerDpdk::GetCallback() -> std::function<CallBackFunctionType> {
    return {};
}

void HandlerDpdk::Loop() {
}

bool HandlerDpdk::SingleShot() {
    return false;
}
} // namespace Nta::Network
