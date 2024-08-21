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
struct GtpHeader;
struct PppoeHeader;
struct SctpHdr;

struct BytesCount{
    // Bytes count in packet by OSI layers
    size_t L2{0}; // Data link layer(Eth,802.11q...)
    size_t L3{0}; // Network layer(Ipv4,Ipv6...)
    size_t L4{0}; // Transport layer(TCP,UDP)
    size_t L5{0}; // Session layer(ADSP,ASP,SCP,SOCKS5...)
    size_t L6{0}; // Presentation layer(VT,RDA,FTAM...)
    size_t L7{0}; // Application layer(BitTorent,NFS,RTP,SMTP...)
};

struct PacketBase {
    using MplsArray = std::array<const struct mpls_label *, MAX_MPLS_CNT>;
    using VlansArray = std::array<const vlan_tag *, MAX_VLAN_CNT>;

    const struct ether_header *ethHeader{nullptr};
    const struct PppoeHeader *pppoeHeader{nullptr};

    size_t vlanCounter{0};         //!< Количество vlan меток.
    VlansArray vlansTags{nullptr}; //!< Vlan метки. Количество указанов в Packet::vlan_cnt.

    size_t mplsCounter{0}; //!< Количество mplsLabels headers
    MplsArray mplsLabels{};

    const struct iphdr *ip4Header{nullptr};
    const struct ip6_hdr *ip6Header{nullptr};
    const struct ip6_frag *ip6Fragment{nullptr};

    union {
        const struct udphdr *udpHeader{nullptr};
        const struct tcphdr *tcpHeader;
    };

    const struct SctpHdr *sctpHeader{nullptr};

    union {
        const struct icmphdr *icmpHeader{nullptr};
        const struct icmp6_hdr *icmp6Header;
    };

    const struct GtpHeader *gtpHeader{nullptr};

    BytesCount bytes{};

    explicit PacketBase() = default;
    virtual ~PacketBase() = default;

    void Reset();
    uint16_t GetIpProtocol() const;
    int8_t GetIpVersion() const;
    int8_t GetGtpVersion() const;
    static int8_t GetGtpVersion(const struct GtpHeader &gtph);
    size_t GetTotalSize() const;
    bool IsGtpv1HdrExt() const;
    bool IsIpFragment() const;
    bool IsIp4Fragment() const;
    bool IsIp6Fragment() const;

    void ResetLowerLevels();
};
} // namespace Nta::Network
