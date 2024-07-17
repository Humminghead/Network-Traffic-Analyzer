#pragma once

#include <netinet/ip.h>

namespace Nwa::Network {
template <> class IpHandler<Ip4> : public IpHandlerBase {
  public:
    std::pair<bool, std::unique_ptr<IpHandlerResult>> Handle(const uint8_t *d, size_t sz) const override {
        return HandlePrivate(d, sz);
    }

    const IpVersion GetHandlerType() const override { return IpVersion::Ip4; }

  private:
    auto HandlePrivate(const uint8_t *d, size_t sz) const -> std::pair<bool, std::unique_ptr<IpHandlerResult>>;
};
} // namespace Nwa::Network

#include <ip/NwaIp4Handler.tcc>
