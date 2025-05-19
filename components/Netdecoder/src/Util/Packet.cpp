#include "NetDecoder/Util/Packet.h"
#include "NetDecoder/Gtp/Gtp1Defs.h"
#include "NetDecoder/Gtp/GtpHeader.h"
#include "NetDecoder/LinkLayer.h"
#include "NetDecoder/PacketBase.h"
#include <netinet/ip6.h>
#include <bit>

namespace Nta::Network::Util {

constexpr auto typeVlanSwd = std::byteswap(static_cast<uint16_t>(ETHERTYPE_VLAN));
constexpr auto typeIpSwapped = std::byteswap(static_cast<uint16_t>(ETHERTYPE_IP));
constexpr auto typeIp6Swapped = std::byteswap(static_cast<uint16_t>(ETHERTYPE_IPV6));
constexpr auto typeMplsSwapped = std::byteswap(static_cast<uint16_t>(0x8847));
constexpr auto typePppoeDiscoverySwapped = std::byteswap(static_cast<uint16_t>(0x8864));
constexpr auto typePppoeSessionSwapped = std::byteswap(static_cast<uint16_t>(0x8863));

uint16_t GetIpProtocol(const Packet &p) {
    return p.ip4Header != nullptr ? p.ip4Header->protocol : p.ip6Header != nullptr ? p.ip6Header->ip6_nxt : IPPROTO_MAX;
}

int8_t GetIpVersion(const Packet &p) {
    return p.ip4Header != nullptr ? 4 : p.ip6Header != nullptr ? 6 : -1;
}

int8_t GetGtpVersion(const GtpHeader *gtph) {
    return (gtph->common.flags & 0b11100000) >> 5;
}

bool IsGtpv1HdrExt(const GtpHeader *p) {
    return p == nullptr ? false : (p->common.flags & GTPV1_HDR_EXT) == GTPV1_HDR_EXT;
}

bool IsIp4FragmentFlagSet(const iphdr *ip4Header) {
    if (ip4Header == nullptr)
        return false;
    const uint16_t iph_flags = htons(ip4Header->frag_off) & (IP_DF | IP_MF | IP_RF);
    const uint16_t iph_frag_off = htons(ip4Header->frag_off) & IP_OFFMASK;
    if ((iph_flags & IP_DF) == IP_DF)
        return false;
    return (((iph_flags & IP_MF) == IP_MF) || (iph_frag_off != 0));
}

bool IsIp4Fragment(const Packet &p) {    
    return IsIp4FragmentFlagSet(p.ip4Header);
}

bool IsIp6Fragment(const ip6_frag *p) {
    return p ? (htons(p->ip6f_offlg) & (IP_MF | IP_OFFMASK)) : false;
}

bool IsIp6Icmp(const Packet &p) {
    return p.ip6Header ? p.ip6Header->ip6_nxt == IPPROTO_ICMPV6 : false;
}

LinkLayer GetL2Type(const Packet &p) {
    return p.protoList?p.protoList->at(0):LinkLayer::Unknown;
}

uint16_t GetL3Type(const Packet &p){
    if (p.ethHeader && p.ethHeader->ether_type == typeVlanSwd) {
        for(auto tag : p.vlansTags){
            if(!tag){
                // return --tag->vlan_tci
            }
        }
    }else  {

    }
}

uint16_t GetL4Type(const Packet &p){}

LinkLayer GetLinkLayerFromNetProtoType(const uint16_t linkLayer) {
    switch (static_cast<uint16_t>(linkLayer)) {
    case 0x4788: // MPLS
        return LinkLayer::Mpls;
    case 0x0081: // VLAN
        return LinkLayer::Vlan;
    case 0x6488: // PPPoE PPP Session Stage
        return LinkLayer::PPPoEs;
    case 0x6388: // PPPoE Discovery Stage
        return LinkLayer::PPpoEd;
        break;
    // https://techhub.hpe.com/eginfolib/networking/docs/switches/5120si/cg/5998-8489_l2-lan_cg/content/436042676.htm
    case 0x0008: // IpV4
        return LinkLayer::Ip4;
    case 0xDD86: // Ipv6
        return LinkLayer::Ip6;
    case 0x0000:
        return LinkLayer::Eth;
    default:
        return LinkLayer::Unknown;
    }
}

} // namespace Nta::Network::Util
