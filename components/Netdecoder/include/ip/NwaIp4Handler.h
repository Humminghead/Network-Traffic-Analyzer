#pragma once

#include "ip/NwaIpHandler.h"
#include <netinet/ip.h>

namespace Nta::Network {

template <> class IpHandler<Ip4> : public HandlerBase<HandlerResult> {
  public:
    Result<HandlerResult> Handle(const uint8_t *d, size_t sz) const override { return HandlePrivate(d, sz); }

    // const IpVersion GetHandlerType() const override { return IpVersion::Ip4; }

  private:
    auto HandlePrivate(const uint8_t *d, size_t sz) const -> Result<HandlerResult>;
};
} // namespace Nta::Network


