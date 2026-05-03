#include "Handlers/Dpdk/DpdkDeviceFactory.h"
#include "Handlers/Dpdk/DpdkDevice.h"
#include <memory>

auto Nta::Network::Device::DpdkDeviceFactory::CreateEthDevDpdk(const uint16_t port, const bool promisc) const
    -> std::shared_ptr<DpdkDevice> {
    return std::make_shared<DpdkDevice>(port, promisc);
}
