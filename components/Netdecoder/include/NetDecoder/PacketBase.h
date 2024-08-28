#pragma once

#include <array>
#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/vlan.h>

/*RFC8200 4.1.  Extension Header Order
  IPv6 header                           |
  Hop-by-Hop Options header             |_Per-Fragment Headers
  Destination Options header (note 1)   |
  Routing header                        |
  Fragment header
  Authentication header (note 2)                    |
  Encapsulating Security Payload header (note 2)    |_Extension (ESP is not considered
  Destination Options header (note 3)               |           an extension header)
  Upper-Layer header                                |-Upper-Layer Headers and ESP
  --------------------------------------------------------------------------
  Original:
  +-----------------+-----------------+--------+--------+-//-+--------+
  |  Per-Fragment   |Ext & Upper-Layer|  first | second |    |  last  |
  |    Headers      |    Headers      |fragment|fragment|....|fragment|
  +-----------------+-----------------+--------+--------+-//-+--------+
  Fragmented:
   +------------------+---------+-------------------+----------+
   |  Per-Fragment    |Fragment | Ext & Upper-Layer |  first   |
   |    Headers       | Header  |   Headers         | fragment |
   +------------------+---------+-------------------+----------+
   ....
   +------------------+--------+----------+
   |  Per-Fragment    |Fragment|   last   |
   |    Headers       | Header | fragment |
   +------------------+--------+----------+
  */

// Linux
struct mpls_label;

static constexpr const size_t MAX_MPLS_CNT = 4; //!< Максимальное количество mpls меток в пакете.
static constexpr const size_t MAX_VLAN_CNT = 8; //!< Максимальное количество vlan меток в пакете.

namespace Nta::Network {
// struct GtpHeader;
struct PppoeHeader;
struct SctpHdr;

struct Packet {
    using MplsArray = std::array<const mpls_label *, MAX_MPLS_CNT>;
    using VlansArray = std::array<const vlan_tag *, MAX_VLAN_CNT>;

    const struct ether_header *ethHeader{nullptr};
    const struct PppoeHeader *pppoeHeader{nullptr};

    VlansArray vlansTags{};
    MplsArray mplsLabels{};

    const struct iphdr *ip4Header{nullptr};
    const struct ip6_hdr *ip6Header{nullptr};
    const struct ip6_frag *ip6Fragment{nullptr};

    const struct udphdr *udpHeader{nullptr};
    const struct tcphdr *tcpHeader{nullptr};

    const struct SctpHdr *sctpHeader{nullptr};

    const struct icmphdr *icmpHeader{nullptr};
    const struct icmp6_hdr *icmp6Header{nullptr};

    // const uint8_t* payload{nullptr};

    void Reset();
    void ResetLowerLevels();
};
} // namespace Nta::Network
