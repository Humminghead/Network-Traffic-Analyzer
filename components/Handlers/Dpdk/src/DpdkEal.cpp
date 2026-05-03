#include "Handlers/Dpdk/DpdkEal.h"
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_version.h>
#include <print>

namespace Nta::Network::Device{
std::shared_ptr<DpdkEal> DpdkEal::m_instance{nullptr};

auto DpdkEal::EalInit(const std::vector<const char *> &params) -> bool {
    auto argv = const_cast<char**>(params.data());
    std::println("DPDK version: {}", rte_version());
    if (rte_eal_init(params.size(), argv) >= 0) {
        return true;
    } else {
        throw std::runtime_error("EAL error: " + std::string{rte_strerror(rte_errno)});
    }
}

} // namespace Nta::Network
