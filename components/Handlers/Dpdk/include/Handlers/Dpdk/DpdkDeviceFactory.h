#pragma once

#include "Handlers/Dpdk/DpdkDevice.h"
#include <Device.h>
#include <memory>

namespace Nta::Network {

namespace Device {

class DpdkDevPrivate {
  protected:
    DpdkDevPrivate() = default;

  public:
    virtual auto CreateEthDevDpdk() const -> std::unique_ptr<DpdkDevice> = 0;
};

class DpdkDeviceFactory : AbstractDeviceFactory<DpdkDevPrivate> {
  public:
    virtual auto CreateEthDevDpdk() const -> std::unique_ptr<DpdkDevice> override;
};
} // namespace Device
} // namespace Nta::Network
