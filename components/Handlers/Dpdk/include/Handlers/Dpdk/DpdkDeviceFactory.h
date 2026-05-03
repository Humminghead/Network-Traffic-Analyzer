#pragma once

#include "Handlers/Dpdk/DpdkDevice.h"
#include <Device.h>
#include <memory>

namespace Nta::Network::Device {
class DpdkDevPrivate {
  protected:
    DpdkDevPrivate() = default;

  public:
    virtual auto CreateEthDevDpdk(const uint16_t port, const bool promisc) const -> std::shared_ptr<DpdkDevice> = 0;
};

class DpdkDeviceFactory : AbstractDeviceFactory<DpdkDevPrivate> {
  public:
    virtual auto CreateEthDevDpdk(const uint16_t port, const bool promisc) const
        -> std::shared_ptr<DpdkDevice> override;
};
} // namespace Nta::Network::Device
