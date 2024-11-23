#include "NetDecoder/Util/Packet.h"
#include "NetDecoder/Gtp/Gtp1Defs.h"
#include "NetDecoder/Gtp/GtpHeader.h"
#include "NetDecoder/PacketBase.h"

namespace Nta::Network::Util {

///\todo: check it ???
uint16_t GetIpProtocol(const Packet &p) {
    return p.ip4Header != nullptr   ? p.ip4Header->protocol
           : p.ip6Header != nullptr ? p.ip6Fragment != nullptr ? p.ip6Fragment->ip6f_nxt : p.ip6Header->ip6_nxt
                                     : IPPROTO_MAX;
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

bool IsIp4Fragment(const Packet &p) {
    if (p.ip4Header == nullptr)
        return false;
    const uint16_t iph_flags = htons(p.ip4Header->frag_off) & (IP_DF | IP_MF | IP_RF);
    const uint16_t iph_frag_off = htons(p.ip4Header->frag_off) & IP_OFFMASK;
    if ((iph_flags & IP_DF) == IP_DF)
        return false;
    return (((iph_flags & IP_MF) == IP_MF) || (iph_frag_off != 0));
}

bool IsIp6Fragment(const Packet &p) {
    return p.ip6Fragment ? (htons(p.ip6Fragment->ip6f_offlg) & (IP_MF | IP_OFFMASK)) : false;
}

bool IsIpFragment(const Packet &p) {
    return p.ip4Header != nullptr ? IsIp4Fragment(p) : p.ip6Header != nullptr ? IsIp6Fragment(p) : false;
}

} // namespace Nta::Network::Util
