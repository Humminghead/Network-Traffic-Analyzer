#include "packetbase.h"

#include <string.h>
#include <algorithm>
#include "gtp/GtpHeader.h"
#include "gtp/Gtp1Defs.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>

namespace protocols 
{

void PacketBase::reset()
{
    vlan_cnt = 0;
    mpls_cnt = 0;

    eth = nullptr;
    std::for_each(std::begin(vlans), std::end(vlans), [](auto*& p) { p = nullptr; });
    pppoe = nullptr;
    std::for_each(std::begin(mpls), std::end(mpls), [](auto*& p) { p = nullptr; });

    iph = nullptr;
    ip6h = nullptr;
    ip6frag = nullptr;
    udph = nullptr;
    icmp_hdr = nullptr;
    gtph = nullptr;
    sctph = nullptr;

    l2_size = 0;
    l3_size = 0;
    l4_size = 0;
    l5_size = 0;
    l6_size = 0;
    l7_size = 0;
}

// TODO: проверить ???
uint16_t PacketBase::get_ip_protocol() const
{
    return iph != nullptr ? iph->protocol : ip6h != nullptr ? ip6frag != nullptr ? ip6frag->ip6f_nxt : ip6h->ip6_nxt : IPPROTO_MAX;
}

int8_t PacketBase::get_ip_version() const{
    return iph != nullptr ? 4 : ip6h != nullptr ? 6 : -1;
}

int8_t PacketBase::get_gtp_version() const{
    return gtph ? get_gtp_version(*gtph) : 0;
}

int8_t PacketBase::get_gtp_version(const GtpHeader &gtph) {
    return (gtph.common.flags & 0b11100000) >> 5;
}

size_t PacketBase::get_total_size() const
{
    return l2_size + l3_size + l4_size + l5_size + l6_size + l7_size;
}

bool PacketBase::is_gtpv1_hdr_ext() const
{
    return gtph == nullptr ? false : (gtph->common.flags & GTPV1_HDR_EXT) == GTPV1_HDR_EXT;
}

bool PacketBase::is_ip_fragment() const
{
    return
        iph != nullptr  ? is_ip4_fragment():
        ip6h != nullptr ? is_ip6_fragment():
        false;
}

bool PacketBase::is_ip4_fragment() const{
    if(iph == nullptr) return false;
    const uint16_t iph_flags = htons(iph->frag_off) & (IP_DF|IP_MF|IP_RF);
    const uint16_t iph_frag_off = htons(iph->frag_off) & IP_OFFMASK;
    if((iph_flags & IP_DF) == IP_DF) return false;
    return (((iph_flags & IP_MF) == IP_MF) || (iph_frag_off != 0));
}

bool PacketBase::is_ip6_fragment() const{
    return ip6frag ? (htons(ip6frag->ip6f_offlg) & (IP_MF|IP_OFFMASK)) : false;
}

void PacketBase::reset_lower_levels(){
    tcph = nullptr;
    sctph = nullptr;
    gtph = nullptr;
    l4_size = {0};
    l5_size = {0};
    l6_size = {0};
    l7_size = {0};
}

}  // namespace protocols
