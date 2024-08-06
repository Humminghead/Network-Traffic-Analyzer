#include "packetbase.h"

#include <algorithm>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>

#include "gtp/Gtp1Defs.h"
#include "gtp/GtpHeader.h"

namespace Nwa::Network {

void PacketBase::Reset() {
    vlanCounter = 0;
    mplsCounter = 0;

    ethHeader = nullptr;
    pppoeHeader = nullptr;
    std::for_each(std::begin(vlansTags), std::end(vlansTags), [](auto *&p) { p = nullptr; });
    std::for_each(std::begin(mplsLabels), std::end(mplsLabels), [](auto *&p) { p = nullptr; });
    ip4Header = nullptr;
    ip6Header = nullptr;
    ip6Fragment = nullptr;
    udpHeader = nullptr;
    icmpHeader = nullptr;
    gtpHeader = nullptr;
    sctpHeader = nullptr;

    l2_size = 0;
    l3_size = 0;
    l4_size = 0;
    l5_size = 0;
    l6_size = 0;
    l7_size = 0;
}

// TODO: проверить ???
uint16_t PacketBase::GetIpProtocol() const {
    return ip4Header != nullptr   ? ip4Header->protocol
           : ip6Header != nullptr ? ip6Fragment != nullptr ? ip6Fragment->ip6f_nxt : ip6Header->ip6_nxt
                                  : IPPROTO_MAX;
}

int8_t PacketBase::GetIpVersion() const {
    return ip4Header != nullptr ? 4 : ip6Header != nullptr ? 6 : -1;
}

int8_t PacketBase::GetGtpVersion() const {
    return gtpHeader ? GetGtpVersion(*gtpHeader) : 0;
}

int8_t PacketBase::GetGtpVersion(const GtpHeader &gtph) {
    return (gtph.common.flags & 0b11100000) >> 5;
}

size_t PacketBase::GetTotalSize() const {
    return l2_size + l3_size + l4_size + l5_size + l6_size + l7_size;
}

bool PacketBase::IsGtpv1HdrExt() const {
    return gtpHeader == nullptr ? false : (gtpHeader->common.flags & GTPV1_HDR_EXT) == GTPV1_HDR_EXT;
}

bool PacketBase::IsIpFragment() const {
    return ip4Header != nullptr ? IsIp4Fragment() : ip6Header != nullptr ? IsIp6Fragment() : false;
}

bool PacketBase::IsIp4Fragment() const {
    if (ip4Header == nullptr)
        return false;
    const uint16_t iph_flags = htons(ip4Header->frag_off) & (IP_DF | IP_MF | IP_RF);
    const uint16_t iph_frag_off = htons(ip4Header->frag_off) & IP_OFFMASK;
    if ((iph_flags & IP_DF) == IP_DF)
        return false;
    return (((iph_flags & IP_MF) == IP_MF) || (iph_frag_off != 0));
}

bool PacketBase::IsIp6Fragment() const {
    return ip6Fragment ? (htons(ip6Fragment->ip6f_offlg) & (IP_MF | IP_OFFMASK)) : false;
}

void PacketBase::ResetLowerLevels() {
    tcpHeader = nullptr;
    sctpHeader = nullptr;
    gtpHeader = nullptr;
    l4_size = {0};
    l5_size = {0};
    l6_size = {0};
    l7_size = {0};
}

} // namespace Nwa::Network
