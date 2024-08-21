#include "NetDecoder/DecoderBase.h"

#include "NetDecoder/DecodeStat.h"
#include "NetDecoder/Ip/NwaIp6Handler.h"
#include "NetDecoder/PacketBase.h"
#include "NetDecoder/PppOe/PPPoELayer.h"
#include "NetDecoder/PppOe/PppTypes.h"
#include "NetDecoder/Sctp/Sctp.h"
#include "NetDecoder/Shift.h"
#include <linux/mpls.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/vlan.h>

namespace Nta::Network {

struct NetDecoderBase::Impl {
    EthStat ethstat;
    VlanStat vlanstat;
    IpStat ipstat;
    UdpStat udpstat;
    TcpStat tcpstat;
    SctpStat sctpstat;
    GtpStat gtpstat;
    GtpStat gtp2stat;
};

NetDecoderBase::ptr_impl::~ptr_impl() {}

NetDecoderBase::NetDecoderBase() : d{std::make_unique<Impl>()} {}

bool NetDecoderBase::DecodeEth(const uint8_t *&data, size_t &size, const ether_header *&eth) {
    d->ethstat.pkt_count++;

    if (size < sizeof(struct ether_header)) {
        d->ethstat.no_space++;
        return false;
    }

    eth = reinterpret_cast<const struct ether_header *>(data);
    shift_left(size, sizeof(struct ether_header));

    return true;
}

bool NetDecoderBase::DecodeVlan(const uint8_t *&data, size_t &size, const vlan_tag *&vlan) {
    d->vlanstat.pkt_count++;

    if (size < sizeof(struct vlan_tag)) {
        d->vlanstat.no_space++;
        return false;
    }
    vlan = reinterpret_cast<const struct vlan_tag *>(data);
    shift_left(size, sizeof(struct vlan_tag));
    return true;
}

bool NetDecoderBase::DecodeIpv4(const uint8_t *&data, size_t &size, const iphdr *&iph) {
    d->ipstat.pkt_count++;

    iph = reinterpret_cast<const iphdr *>(data);

    if (size == sizeof(struct iphdr)) {
        d->ipstat.no_space++;
        return true;
    }

    if (uint16_t tot_len = ntohs(iph->tot_len); size < tot_len) {
        d->ipstat.invalid_tot_len++;
        return false;
    }

    d->ipstat.ipv4++;

    if (const auto proto = iph->protocol; proto == IPPROTO_TCP)
        d->ipstat.ipv4_tcp++;
    else if (proto == IPPROTO_UDP)
        d->ipstat.ipv4_udp++;
    else if (proto == IPPROTO_ICMP)
        d->ipstat.ipv4_icmp++;
    else
        d->ipstat.invalid_protocol++;

    data = data + sizeof(struct iphdr);
    size = size - sizeof(struct iphdr);

    return true;
}

bool NetDecoderBase::DecodeIpv6(const uint8_t *&data, size_t &size, const ip6_hdr *&ip6h, const ip6_frag *&ip6frag) {
    d->ipstat.pkt_count++;

    ///\todo
    auto [ok, res] = IpHandler<Ip6>{}.Handle(data,size);

    if(!ok) return false;

    ip6h = reinterpret_cast<const struct ip6_hdr *>(data);

    data = res->GetPayloadDataVirt();
    size = res->GetPayloadLenghtVirt();
    return true;
}

bool NetDecoderBase::DecodeUdp(const uint8_t *&data, size_t &size, const udphdr *&udph) {
    d->udpstat.pkt_count++;

    if (size < sizeof(struct udphdr)) {
        d->udpstat.no_space++;
        return false;
    }

    udph = reinterpret_cast<const struct udphdr *>(data);
    shift_left(size, sizeof(struct udphdr));

    return true;
}

bool NetDecoderBase::DecodeTcp(const uint8_t *&data, size_t &size, const tcphdr *&tcph) {
    d->tcpstat.pkt_count++;

    if (size < sizeof(struct tcphdr)) {
        d->tcpstat.no_space++;
        return false;
    }

    tcph = reinterpret_cast<const struct tcphdr *>(data);
    size_t tcph_size = tcph->doff << 2;

    if (size < tcph_size) {
        d->tcpstat.no_space++;
        return false;
    }

    shift_left(size, tcph_size);

    return true;
}

bool NetDecoderBase::DecodeSctp(const uint8_t *&data, size_t &size, const SctpHdr *&sctph) {

    d->sctpstat.pkt_count++;

    if (size < sizeof(struct SctpHdr)) {
        d->sctpstat.no_space++;
        return false;
    }

    sctph = reinterpret_cast<const struct SctpHdr *>(data);
    shift_left(size, sizeof(struct SctpHdr));

    return true;
}

EthStat &NetDecoderBase::GetEthStat() const {
    return d->ethstat;
}

VlanStat &NetDecoderBase::GetVlanStat() const {
    return d->vlanstat;
}

IpStat &NetDecoderBase::GetIpStat() const {
    return d->ipstat;
}

UdpStat &NetDecoderBase::GetUdpStat() const {
    return d->udpstat;
}

TcpStat &NetDecoderBase::GetTcpStat() const {
    return d->tcpstat;
}

void NetDecoderBase::ResetStat() {
    d->ethstat.reset();
    d->vlanstat.reset();
    d->ipstat.reset();
    d->udpstat.reset();
    d->tcpstat.reset();
}
} // namespace Nta::Network
