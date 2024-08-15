#pragma once

#include <functional>
#include <stdint.h>

namespace Nta::Network {

enum class HandlerIfaces { Pcap, Unknown };

struct HandlerAbstract {
    using CallBackFunctionType = bool(const struct timeval, const uint8_t *, const size_t);

    virtual void Open() = 0;
    virtual void Close() = 0;
    virtual void Loop() = 0;
    virtual auto SingleShot() -> bool = 0;
    virtual auto SetCallback(std::function<CallBackFunctionType> &&f) -> void = 0;
    virtual auto GetCallback() -> std::function<CallBackFunctionType> = 0;
    virtual auto GetIfaceType() const -> const HandlerIfaces = 0;
};

} // namespace Nta::Network
