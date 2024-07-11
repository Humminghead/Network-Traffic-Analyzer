#pragma once

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <pcap/vlan.h>
#include <array>

static constexpr const size_t MAX_ETH_CNT = 2;  //!< Максимальное количество vlan меток в пакете.
static constexpr const size_t MAX_MPLS_CNT = 4;  //!< Максимальное количество vlan меток в пакете.
static constexpr const size_t MAX_VLAN_CNT = 8;  //!< Максимальное количество vlan меток в пакете.

struct GtpHeader;
struct pppoe_header;
struct sctphdr;
struct mpls_label;

namespace protocols
{
// clang-format off
struct PacketBase {

    using MplsArray = std::array<const struct mpls_label*,4>;
    using VlansArray = std::array<const vlan_tag*,MAX_VLAN_CNT>;

    uint32_t                    tm            {0};
    uint32_t                    tm_ns         {0};

    const struct ether_header*  eth           {nullptr};

    const struct pppoe_header*  pppoe         {nullptr};

    size_t                      vlan_cnt      {0};       //!< Количество vlan меток.
    VlansArray                  vlans         {nullptr}; //!< Vlan метки. Количество указанов в Packet::vlan_cnt.

    size_t                      mpls_cnt      {0};       //!< Количество mpls headers
    MplsArray                   mpls          {};


    const struct iphdr*         iph           {nullptr};
    const struct ip6_hdr*       ip6h          {nullptr};
    const struct ip6_frag*      ip6frag       {nullptr};

    union {
        const struct udphdr*        udph      {nullptr};
        const struct tcphdr*        tcph;
    };

    const struct sctphdr*       sctph         {nullptr};    

    union {
        const struct icmphdr*       icmp_hdr  {nullptr};
        const struct icmp6_hdr*     icmp6_hdr;
    };

    const struct GtpHeader*     gtph          {nullptr};

    // Bytes count in packet by OSI layers
    size_t                      l2_size     {0}; //Data link layer(Eth,802.11q...)
    size_t                      l3_size     {0}; //Network layer(Ipv4,Ipv6...)
    size_t                      l4_size     {0}; //Transport layer(TCP,UDP)
    size_t                      l5_size     {0}; //Session layer(ADSP,ASP,SCP,SOCKS5...)
    size_t                      l6_size     {0}; //Presentation layer(VT,RDA,FTAM...)
    size_t                      l7_size     {0}; //Application layer(BitTorent,NFS,RTP,SMTP...)

    PacketBase()                =   default;
    PacketBase(const uint32_t& tm_, const uint32_t& tm_ns_) : tm(tm_), tm_ns(tm_ns_) {}
    virtual ~PacketBase()       =   default;

    void                        reset();
    uint16_t                    get_ip_protocol() const;
    int8_t                      get_ip_version() const;
    int8_t                      get_gtp_version() const;
    static int8_t               get_gtp_version(const struct GtpHeader& gtph);
    size_t                      get_total_size() const;
    bool                        is_gtpv1_hdr_ext() const;
    bool                        is_ip_fragment() const;
    bool                        is_ip4_fragment() const;
    bool                        is_ip6_fragment() const;

    void                        reset_lower_levels();
};
}
