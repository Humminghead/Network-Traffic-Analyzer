#include "decoderbase.h"

#include <PPPoELayer.h>
#include <PppTypes.h>
#include <ip4parser.h>
#include <ip6parser.h>
#include <ipparseresult.h>
#include <linux/mpls.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/vlan.h>

#include "packetbase.h"
#include "sctp/sctp.h"
#include "shift.h"
#include "decodestat.h"

namespace  protocols {

struct DecoderBase::Impl {
    EthStat ethstat;
    VlanStat vlanstat;
    IpStat ipstat;
    UdpStat udpstat;
    TcpStat tcpstat;
    SctpStat sctpstat;
    GtpStat gtpstat;
    GtpStat gtp2stat;    
};

DecoderBase::ptr_impl::~ptr_impl()
{
}

DecoderBase::DecoderBase() : d{std::make_unique<Impl>()}
{
}

bool DecoderBase::decodeEth(const uint8_t*& data, size_t& size, const ether_header*& eth)
{
    d->ethstat.pkt_count++;

    if (size < sizeof(struct ether_header)) {
        d->ethstat.no_space++;
        return false;
    }

    eth = reinterpret_cast<const struct ether_header*>(data);
    shift_left(size, sizeof(struct ether_header));

    return true;
}

bool DecoderBase::decodeVlan(const uint8_t*& data, size_t& size, const vlan_tag*& vlan)
{
    d->vlanstat.pkt_count++;

    if (size < sizeof(struct vlan_tag)) {
        d->vlanstat.no_space++;
        return false;
    }
    vlan = reinterpret_cast<const struct vlan_tag*>(data);
    shift_left(size, sizeof(struct vlan_tag));
    return true;
}

bool DecoderBase::decodeIpv4(uint32_t tm_sec, const uint8_t*& data, size_t& size, const iphdr*& iph)
{
    d->ipstat.pkt_count++;

    protocols::IpParseResult res;
    if (!protocols::parseIp4(data, size, res)) {
        ///\todo Добавить признак отличия no_space от invalid_version
        d->ipstat.no_space++;
        d->ipstat.invalid_version++;
        return false;
    }
    d->ipstat.ipv4++;

    if (!res.good()) return false;

    if (res.payload_proto == IPPROTO_TCP)
        d->ipstat.ipv4_tcp++;
    else if (res.payload_proto == IPPROTO_UDP)
        d->ipstat.ipv4_udp++;
    else if (res.payload_proto == IPPROTO_ICMP)
        d->ipstat.ipv4_icmp++;
    else
        d->ipstat.invalid_protocol++;

    iph = reinterpret_cast<const iphdr*>(res.hdr);
    data = res.payload;
    size = res.payload_len;

    return true;
}

bool DecoderBase::decodeIpv6(uint32_t tm_sec, const uint8_t*& data, size_t& size, const ip6_hdr *&ip6h, const ip6_frag *&ip6frag)
{
    d->ipstat.pkt_count++;

    protocols::IpParseResult res;
    if (!protocols::parseIp6(data, size, res)) {
        d->ipstat.no_space++;
        return false;
    }
    d->ipstat.ipv6++;    
    if (res.payload_proto == IPPROTO_TCP)
        d->ipstat.ipv6_tcp++;
    else if (res.payload_proto == IPPROTO_UDP)
        d->ipstat.ipv6_udp++;
    else if (res.payload_proto == IPPROTO_ICMPV6)
        d->ipstat.ipv6_icmpv6++;
    else
        d->ipstat.invalid_protocol++;
    ip6h = reinterpret_cast<const ip6_hdr*>(res.hdr);
    ip6frag = reinterpret_cast<const ip6_frag*>(res.frag_hdr);
    data = res.payload;
    size = res.payload_len;
    return true;
}

bool DecoderBase::decodeUdp(const uint8_t *&data, size_t& size, const udphdr*& udph)
{
    d->udpstat.pkt_count++;

    if (size < sizeof(struct udphdr)) {
        d->udpstat.no_space++;
        return false;
    }

    udph = reinterpret_cast<const struct udphdr*>(data);
    shift_left(size, sizeof(struct udphdr));

    return true;
}

bool DecoderBase::decodeTcp(const uint8_t*& data, size_t& size, const tcphdr *&tcph)
{
    d->tcpstat.pkt_count++;

    if (size < sizeof(struct tcphdr)) {
        d->tcpstat.no_space++;
        return false;
    }

    tcph = reinterpret_cast<const struct tcphdr*>(data);
    size_t tcph_size = tcph->doff << 2;

    if (size < tcph_size) {
        d->tcpstat.no_space++;
        return false;
    }

    shift_left(size, tcph_size);

    return true;
}

bool DecoderBase::decodeSctp(const uint8_t *&data, size_t &size, const sctphdr *&sctph){

    d->sctpstat.pkt_count++;

    if (size < sizeof(struct sctphdr)) {
        d->sctpstat.no_space++;
        return false;
    }

    sctph = reinterpret_cast<const struct sctphdr*>(data);
    shift_left(size, sizeof(struct sctphdr));

    return true;
}

EthStat& DecoderBase::getEthStat() const
{
    return d->ethstat;
}

VlanStat& DecoderBase::getVlanStat() const
{
    return d->vlanstat;
}

IpStat& DecoderBase::getIpStat() const
{
    return d->ipstat;
}

UdpStat& DecoderBase::getUdpStat() const
{
    return d->udpstat;
}

TcpStat& DecoderBase::getTcpStat() const
{
    return d->tcpstat;
}

void DecoderBase::resetStat()
{
    d->ethstat.reset();
    d->vlanstat.reset();
    d->ipstat.reset();
    d->udpstat.reset();
    d->tcpstat.reset();
}
}
