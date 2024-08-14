#include "decoder.h"

#include <PPPoELayer.h>
#include <PppTypes.h>
#include <PppoeHeader.h>
#include <linux/mpls.h>

#include "decodestat.h"
#include "gtp/GtpHeader.h"
#include "packetbase.h"
#include "sctp/sctp.h"
#include "shift.h"

#include "ip/NwaIpHandler.h"

/*type + code + checksum + id + seq + timestamp*/
constexpr size_t IcmpShift = sizeof(struct icmphdr) + sizeof(uint64_t);

namespace Nta::Network {

struct NetDecoder::Impl {
    IpHandler<Ip4> m_Ip4h;
    IpHandler<Ip6> m_Ip6h;
};

NetDecoder::NetDecoder() : NetDecoderBase(), m_Impl{std::make_unique<Impl>()} {}

bool NetDecoder::HandleEth(const uint8_t *&d, size_t &sz, PacketBase &packet) noexcept {
    if (!DecodeEth(d, sz, packet.ethHeader))
        return false;

    packet.l2_size += sizeof(ether_header);
    return true;
}

bool NetDecoder::HandleVlan(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept {
    if (!d)
        return false;
    if (pkt.vlanCounter > (pkt.vlansTags.size() > 0 ? pkt.vlansTags.size() - 1 : 0))
        return false;

    uint16_t nextProto{0}, tNextProto{0}; // ex. ipType

    // Обработка vlan меток.
    auto &VlanConterLnk = pkt.vlanCounter;
    const uint8_t *tData = d;
    while (nextProto == 0) {
        if (VlanConterLnk >= MAX_VLAN_CNT) {
            GetVlanStat().invalid_ethertype++;
            return false;
        }
        if (auto *vlan = pkt.vlansTags[VlanConterLnk]; !DecodeVlan(tData, sz, vlan)) {
            GetVlanStat().invalid_ethertype++;
            return false;
        } else {
            if (pkt.vlansTags[VlanConterLnk] == nullptr)
                pkt.vlansTags[VlanConterLnk] = vlan;
        }
        tNextProto = ntohs((pkt.vlansTags[VlanConterLnk])->vlan_tci);
        if (tNextProto != ETHERTYPE_VLAN)
            nextProto = tNextProto;
        pkt.l2_size += sizeof(vlan_tag);
        VlanConterLnk++;
        tData = d + (VlanConterLnk * sizeof(vlan_tag));
    }

    return true;
}

bool NetDecoder::HandlePPPoE(const uint8_t *&d, size_t &sz, PacketBase &packet) noexcept {
    if (!d)
        return false;

    PPPoELayer layer(d, sz);

    if (PPPoECode::PPPOE_CODE_SESSION != layer.getHeaderCode()) {
        shift_left(sz, layer.getLayerPayloadSize());
        return false;
    }

    if (uint16_t ppp_proto = htobe16(*(uint16_t *)layer.getLayerPayload());
        ppp_proto == PCPP_PPP_IP || ppp_proto == PCPP_PPP_IPV6) {
        packet.pppoeHeader = layer.getPPPoEHeader();
    } else {
        shift_left(sz, layer.getLayerPayloadSize());
        return false;
    }

    shift_left(sz, layer.getHeaderLen());
    packet.l2_size += layer.getHeaderLen();

    return true;
}

bool NetDecoder::HandleMpls(const uint8_t *&d, size_t &sz, PacketBase &packet) noexcept {
    if (!d)
        return false;
    if (packet.mplsCounter > (packet.mplsLabels.size() > 0 ? packet.mplsLabels.size() - 1 : 0))
        return false;

    for (size_t dShift = 0;; dShift += sizeof(mpls_label), packet.mplsCounter++) {
        if (sz < sizeof(mpls_label) || packet.mplsCounter == packet.mplsLabels.size()) {
            return false;
        }
        packet.mplsLabels[packet.mplsCounter] = reinterpret_cast<const struct mpls_label *>(d + dShift);

        if (mpls_label *lbl = (mpls_label *)(d + dShift);
            ((lbl->entry >> MPLS_LS_S_SHIFT) & MPLS_LS_S_MASK) == MPLS_LS_S_MASK) {
            dShift += sizeof(mpls_label);
            dShift += 4; // PW Ethernet Control Word
            packet.l2_size += dShift;
            packet.mplsCounter++;
            shift_left(sz, dShift);
            break;
        }
    }

    return true;
}

bool NetDecoder::HandleIp(const uint8_t *&d, size_t &sz, PacketBase &packet) noexcept {
    if (!d)
        return false;

    switch (const uint8_t ipVersion = d[0] >> 4; ipVersion) {
        case 4:
            if (!DecodeIpv4(d, sz, packet.ip4Header)) {
                return false;
            } else {
                packet.l3_size += sizeof(iphdr);
            }

            break;
        case 6:
            if (!DecodeIpv6(d, sz, packet.ip6Header, packet.ip6Fragment)) {
                return false;
            }

            break;
        default:
            GetIpStat().invalid_version++;
            return false;
    }

    return true;
}

bool NetDecoder::HandleTcp(const uint8_t *&d, size_t &sz, PacketBase &packet) noexcept {
    if (!d)
        return false;
    if (!DecodeTcp(d, sz, packet.tcpHeader))
        return false;
    packet.l4_size += packet.tcpHeader->doff * 4; // doff:4 i.e. count_doff's * 4;

    return true;
}

bool NetDecoder::HandleUdp(const uint8_t *&d, size_t &sz, PacketBase &packet) noexcept {
    if (!d)
        return false;

    if (!DecodeUdp(d, sz, packet.udpHeader))
        return false;
    packet.l4_size += sizeof(udphdr);

    if (const auto dLen = htobe16(packet.udpHeader->len); dLen >= sizeof(udphdr)) {
        packet.l7_size = dLen - sizeof(udphdr);
    } else {
        return false;
    }

    return true;
}

bool NetDecoder::HandleSctp(const uint8_t *&d, size_t &sz, PacketBase &packet) noexcept {
    if (!d)
        return false;

    if (!DecodeSctp(d, sz, packet.sctpHeader))
        return false;
    packet.l4_size += sizeof(SctpHdr);
    packet.l7_size += sz;

    return true;
}

bool NetDecoder::HandleGtp(const uint8_t *&d, size_t &sz, PacketBase &packet) noexcept {
    packet.l7_size = sz;

    if (!d)
        return false;
    if (!sz)
        return false;

    if (sz < sizeof(GtpHeader))
        return false;

    const GtpHeader *gtph = reinterpret_cast<const struct GtpHeader *>(d);

    if (sz < htons(gtph->common.length))
        return false;

    packet.gtpHeader = gtph;
    sz -= sizeof(GtpCommon);

    return true;
}

bool NetDecoder::FullProcessing(const uint16_t linkLayer, const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept {
    if (!d)
        return false;

    const uint8_t *tData = d + pkt.l2_size;

    switch (linkLayer) {
        case 0x4788: // MPLS
            if (!HandleMpls(tData, sz, pkt))
                return false;
            if (!FullProcessing(0, d, sz, pkt))
                return false;
            break;
        case 0x0081: // VLAN
            if (!HandleVlan(tData, sz, pkt))
                return false;
            if (!FullProcessing(
                    pkt.vlansTags[pkt.vlanCounter > 0 ? pkt.vlanCounter - 1 : pkt.vlanCounter]->vlan_tci, d, sz, pkt))
                return false;
            break;
        case 0x6488: // PPPoE
        case 0x6388: {
            if (!HandlePPPoE(tData, sz, pkt))
                return false;
            tData += sizeof(struct PppoeHeader);
            // Detect PPP PROTOCOL id
            // https://docs.oracle.com/cd/E19096-01/sol.ppp301/805-4018/6j3qil164/index.html
            if (auto idSize = sizeof(uint16_t); sz < idSize)
                return false;
            else {
                pkt.l2_size += idSize;
                sz -= idSize;
            }
            if (const auto *id = (const uint16_t *)tData; *id != 0x2100)
                return false;
            if (!FullProcessing(0x0008, d, sz, pkt))
                return false;
        } break;
        case 0x0008: // IpV4
                     // https://techhub.hpe.com/eginfolib/networking/docs/switches/5120si/cg/5998-8489_l2-lan_cg/content/436042676.htm
        case 0xDD86: // Ipv6
            if (!HandleIp(tData, sz, pkt))
                return false;
            if (pkt.IsIpFragment()) {
                pkt.l7_size = sz;
                return true;
            }
            if (!ProcessTransportLayers(tData, sz, pkt))
                return false;
            break;
        case 0x0000:
            if (!HandleEth(tData, sz, pkt))
                return false;
            if (!FullProcessing(pkt.ethHeader->ether_type, d, sz, pkt))
                return false;
            break;
        default:
            return false;
    }
    return true;
}

bool NetDecoder::ProcessTransportLayers(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept {
    const uint16_t proto = pkt.GetIpProtocol();

    ///\todo Пересмотреть обработку заголовкой IPv6. В данной точке указатель d
    ///указывает на payload после заговка ipV6
    if (auto version = pkt.GetIpVersion(); version != 4 && version != 6)
        return false;

    if (proto == IPPROTO_TCP) {
        if (!HandleTcp(d, sz, pkt))
            return false;
        pkt.l7_size = sz;
        return true;
    } else if (proto == IPPROTO_UDP) {
        if (!HandleUdp(d, sz, pkt))
            return false;
        pkt.l7_size = sz;
        return true;
    } else if (proto == IPPROTO_ICMP) {
        pkt.icmpHeader = reinterpret_cast<const struct icmphdr *>(d);
        if (pkt.icmpHeader->type != ICMP_ECHOREPLY && pkt.icmpHeader->type != ICMP_ECHO)
            return false;
        sz -= IcmpShift;
        if (IcmpShift > sz) { // Mailformed
            return false;
        }
        pkt.l4_size = IcmpShift;
        pkt.l7_size = sz;
        return true;
    } else if (proto == IPPROTO_ICMPV6) {
        ///\todo проверить правильность определения размера данных ICMPv6
        /// packet.l7_d = d + sizeof(icmp6_hdr);
        pkt.icmp6Header = reinterpret_cast<const struct icmp6_hdr *>(d);
        sz -= sizeof(icmp6_hdr);
        pkt.l4_size = sizeof(icmp6_hdr);
        pkt.l7_size = sz;
        return true;
    } else if (proto == IPPROTO_SCTP) {
        return HandleSctp(d, sz, pkt);
    }
    return false;
}

NetDecoder::Result NetDecoder::HandleEth(const uint8_t *&d, size_t &sz) noexcept {
    PacketBase packet{};
    bool ok = HandleEth(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandleVlan(const uint8_t *&d, size_t &sz) noexcept {
    PacketBase packet{};
    bool ok = HandleVlan(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandlePPPoE(const uint8_t *&d, size_t &sz) noexcept {
    PacketBase packet{};
    bool ok = HandlePPPoE(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandleMpls(const uint8_t *&d, size_t &sz) noexcept {
    PacketBase packet{};
    bool ok = HandleMpls(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandleIp(const uint8_t *&d, size_t &sz) noexcept {
    PacketBase packet{};
    bool ok = HandleIp(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandleTcp(const uint8_t *&d, size_t &sz) noexcept {
    PacketBase packet{};
    bool ok = HandleTcp(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandleUdp(const uint8_t *&d, size_t &sz) noexcept {
    PacketBase packet{};
    bool ok = HandleUdp(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandleSctp(const uint8_t *&d, size_t &sz) noexcept {
    PacketBase packet{};
    bool ok = HandleSctp(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandleGtp(const uint8_t *&d, size_t &sz) noexcept {
    PacketBase packet{};
    bool ok = HandleGtp(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::FullProcessing(const uint16_t linkLayer, const uint8_t *&d, size_t &sz) noexcept {
    PacketBase packet{};
    bool ok = FullProcessing(linkLayer, d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::ProcessTransportLayers(const uint8_t *&d, size_t &sz) noexcept {
    PacketBase packet{};
    bool ok = ProcessTransportLayers(d, sz, packet);
    return std::make_tuple(ok, packet);
}

} // namespace Nta::Network
