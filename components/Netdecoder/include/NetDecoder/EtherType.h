#pragma once

#include <bit>
#include <cstdint>
#include <linux/mpls.h>
#include <netinet/ether.h>

namespace Nta::Network {

constexpr auto ETHERTYPE_VLAN_SWP = std::byteswap(static_cast<uint16_t>(ETHERTYPE_VLAN));
constexpr auto ETHERTYPE_IP_SWP = std::byteswap(static_cast<uint16_t>(ETHERTYPE_IP));
constexpr auto ETHERTYPE_IPV6_SWP = std::byteswap(static_cast<uint16_t>(ETHERTYPE_IPV6));
constexpr auto ETHERTYPE_MPLS_SWP = std::byteswap(static_cast<uint16_t>(0x8847));
constexpr auto ETHERTYPE_PPPOED_SWP = std::byteswap(static_cast<uint16_t>(0x8864));
constexpr auto ETHERTYPE_PPPOES_SWP = std::byteswap(static_cast<uint16_t>(0x8863));
constexpr auto ETHER_HDR = static_cast<uint16_t>(0x0000);

} // namespace Nta::Network
