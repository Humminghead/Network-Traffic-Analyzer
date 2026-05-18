#include "NetDecoder/Util/Packet.h"
#include "NetDecoder/Gtp/Gtp1Defs.h"
#include "NetDecoder/Gtp/GtpHeader.h"
#include "NetDecoder/PacketBase.h"
#include <netinet/ip6.h>

namespace Nta::Network::Util {

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

uint32_t GetPacketType(const Packet &p){
    return (static_cast<uint32_t>(GetL2Type(p)) | static_cast<uint32_t>(GetL3Type(p)) | static_cast<uint32_t>(GetL4Type(p)));
}

LinkLayerProto GetL2Type(const Packet &p) {
    return GetOsiLayer<OsiLevel::Data>(*p.protoList).Get();
}

LinkLayerProto GetL3Type(const Packet &p){
    return GetOsiLayer<OsiLevel::Network>(*p.protoList).Get();
}

LinkLayerProto GetL4Type(const Packet &p){
    return GetOsiLayer<OsiLevel::Transport>(*p.protoList).Get();
}

} // namespace Nta::Network::Util
