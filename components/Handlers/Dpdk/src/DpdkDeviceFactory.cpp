#include "Handlers/Dpdk/DpdkDeviceFactory.h"
#include "Handlers/Dpdk/DpdkDevice.h"
#include <rte_ethdev.h>
#include <list>
#include <print>

auto Nta::Network::Device::DpdkDeviceFactory::CreateEthDevDpdk() const -> std::unique_ptr<Nta::Network::DpdkDevice> {

    std::list<DpdkDevice> devices;


    for (uint16_t n = 0, devCount = rte_eth_dev_count_avail(); n < devCount; n++) {
        std::println("{}",n);
    }

    return nullptr;
}
