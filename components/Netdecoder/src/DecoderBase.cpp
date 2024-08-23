#include "NetDecoder/DecoderBase.h"

#include "NetDecoder/Ip/NwaIp6Handler.h"
#include "NetDecoder/PacketBase.h"
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
    IpHandler<Ip4> m_Ip4h;///\todo
    IpHandler<Ip6> m_Ip6h;
};

NetDecoderBase::ptr_impl::~ptr_impl() {}

NetDecoderBase::NetDecoderBase() : d{std::make_unique<Impl>()} {}

bool NetDecoderBase::DecodeEth(const uint8_t *&data, size_t &size, const ether_header *&eth) {
    if (size < sizeof(struct ether_header)) {
        return false;
    }

    eth = reinterpret_cast<const struct ether_header *>(data);
    shift_left(size, sizeof(struct ether_header));

    return true;
}

bool NetDecoderBase::DecodeVlan(const uint8_t *&data, size_t &size, const vlan_tag *&vlan) {
    if (size < sizeof(struct vlan_tag)) {
        return false;
    }
    vlan = reinterpret_cast<const struct vlan_tag *>(data);
    shift_left(size, sizeof(struct vlan_tag));
    return true;
}

bool NetDecoderBase::DecodeIpv4(const uint8_t *&data, size_t &size, const iphdr *&iph) {
    iph = reinterpret_cast<const iphdr *>(data);

    if (size == sizeof(struct iphdr)) {
        return true;
    }

    if (uint16_t tot_len = ntohs(iph->tot_len); size < tot_len) {
        return false;
    }

    data = data + sizeof(struct iphdr);
    size = size - sizeof(struct iphdr);

    return true;
}

bool NetDecoderBase::DecodeIpv6(const uint8_t *&data, size_t &size, const ip6_hdr *&ip6h, const ip6_frag *&ip6frag) {

    auto [ok, res] = d->m_Ip6h.Handle(data, size);

    if (!ok)
        return false;

    ip6h = reinterpret_cast<const struct ip6_hdr *>(data);

    data = res->GetPayloadDataVirt();
    size = res->GetPayloadLenghtVirt();
    return true;
}

bool NetDecoderBase::DecodeUdp(const uint8_t *&data, size_t &size, const udphdr *&udph) {

    if (size < sizeof(struct udphdr)) {
        return false;
    }

    udph = reinterpret_cast<const struct udphdr *>(data);
    shift_left(size, sizeof(struct udphdr));

    return true;
}

bool NetDecoderBase::DecodeTcp(const uint8_t *&data, size_t &size, const tcphdr *&tcph) {

    if (size < sizeof(struct tcphdr)) {
        return false;
    }

    tcph = reinterpret_cast<const struct tcphdr *>(data);
    size_t tcph_size = tcph->doff << 2;

    if (size < tcph_size) {
        return false;
    }

    shift_left(size, tcph_size);

    return true;
}

bool NetDecoderBase::DecodeSctp(const uint8_t *&data, size_t &size, const SctpHdr *&sctph) {

    if (size < sizeof(struct SctpHdr)) {
        return false;
    }

    sctph = reinterpret_cast<const struct SctpHdr *>(data);
    shift_left(size, sizeof(struct SctpHdr));

    return true;
}
} // namespace Nta::Network
