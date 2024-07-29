#pragma once

#include <ip/NwaIpVersion.h>
#include <ip/NwaIpHandlerResult.h>
#include <memory>
#include <utility>

namespace Nwa::Network {

struct Ip4 {};
struct Ip6 {};

template<class HandlerResult>
class HandlerBase {
  public:
    virtual ~HandlerBase() = default;

    virtual std::pair<bool, std::unique_ptr<HandlerResult>> Handle(const uint8_t *, size_t) const = 0;
    // virtual const IpVersion GetHandlerType() const = 0;
};

template <typename Ip> class IpHandler;
} // namespace Nwa::Network

#include <ip/NwaIp4Handler.h>
#include <ip/NwaIp6Handler.h>
