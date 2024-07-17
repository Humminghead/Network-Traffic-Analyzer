#pragma once

#include <memory>

namespace Nwa::Network {
template <> class IpHandler<Ip6> : public IpHandlerBase {
  public:
    std::pair<bool, std::unique_ptr<IpHandlerResult>> Handle(const uint8_t *d, size_t sz) const override { return {}; }

    const IpVersion GetHandlerType() const override { return IpVersion::Ip6; }
};
} // namespace Nwa::Network
