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

// Linux
struct mpls_label;

static constexpr const size_t MAX_ETH_CNT = 2; //!< Максимальное количество vlan меток в пакете.
static constexpr const size_t MAX_MPLS_CNT = 4; //!< Максимальное количество vlan меток в пакете.
static constexpr const size_t MAX_VLAN_CNT = 8; //!< Максимальное количество vlan меток в пакете.

namespace Nta::Network {
struct GtpHeader;
struct PppoeHeader;
struct SctpHdr;

struct PacketBase {
    using MplsArray = std::array<const struct mpls_label *, 4>;
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

    // Bytes count in packet by OSI layers
    size_t l2_size{0}; // Data link layer(Eth,802.11q...)
    size_t l3_size{0}; // Network layer(Ipv4,Ipv6...)
    size_t l4_size{0}; // Transport layer(TCP,UDP)
    size_t l5_size{0}; // Session layer(ADSP,ASP,SCP,SOCKS5...)
    size_t l6_size{0}; // Presentation layer(VT,RDA,FTAM...)
    size_t l7_size{0}; // Application layer(BitTorent,NFS,RTP,SMTP...)

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
