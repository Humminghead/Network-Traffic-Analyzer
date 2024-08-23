#include "NetDecoder/Decoder.h"

#include <NetDecoder/PppOe/PPPoELayer.h>
#include <NetDecoder/PppOe/PppTypes.h>
#include <NetDecoder/PppOe/PppoeHeader.h>
#include <linux/mpls.h>

#include "NetDecoder/DecodeStat.h"
#include "NetDecoder/Gtp/GtpHeader.h"
#include "NetDecoder/PacketBase.h"
#include "NetDecoder/Sctp/Sctp.h"
#include "NetDecoder/Shift.h"
#include "NetDecoder/Util/Packet.h"

/*type + code + checksum + id + seq + timestamp*/
constexpr size_t IcmpShift = sizeof(struct icmphdr) + sizeof(uint64_t);

namespace Nta::Network {

struct BytesCount {
    // Bytes count in packet by OSI layers
    size_t m_CounterL2{0}; // Data link layer(Eth,802.11q...)
    size_t m_CounterL3{0}; // Network layer(Ipv4,Ipv6...)
    size_t m_CounterL4{0}; // Transport layer(TCP,UDP)
    size_t m_CounterL5{0}; // Session layer(ADSP,ASP,SCP,SOCKS5...)
    size_t m_CounterL6{0}; // Presentation layer(VT,RDA,FTAM...)
    size_t m_CounterL7{0}; // Application layer(BitTorent,NFS,RTP,SMTP...)
};

struct NetDecoder::Impl {
    BytesCount m_Bytes{};
};

NetDecoder::ImplPointer::~ImplPointer() {}

NetDecoder::NetDecoder() : NetDecoderBase(), m_Impl{std::make_unique<Impl>()} {}

bool NetDecoder::HandleEth(const uint8_t *&d, size_t &sz, Packet &packet) noexcept {
    if (!DecodeEth(d, sz, packet.ethHeader))
        return false;

    m_Impl->m_Bytes.m_CounterL2 += sizeof(ether_header);
    return true;
}

bool NetDecoder::HandleVlan(const uint8_t *&d, size_t &sz, Packet &pkt, size_t &idx) noexcept {
    if (!d)
        return false;

    if (pkt.vlansTags.size() == 0)
        return false;

    const uint8_t *tData = d;

    for (auto &tag : pkt.vlansTags) {
        if (!DecodeVlan(tData, sz, tag))
            break;

        m_Impl->m_Bytes.m_CounterL2 += sizeof(vlan_tag);
        tData += m_Impl->m_Bytes.m_CounterL2;

        if (auto next = ntohs(tag->vlan_tci); next != ETHERTYPE_VLAN)
            return true;

        idx++;
    }

    return false;
}

bool NetDecoder::HandlePPPoE(const uint8_t *&d, size_t &sz, Packet &packet) noexcept {
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
    m_Impl->m_Bytes.m_CounterL2 += layer.getHeaderLen();

    return true;
}

bool NetDecoder::HandleMpls(const uint8_t *&d, size_t &sz, Packet &packet, size_t &idx) noexcept {
    if (!d)
        return false;

    if (idx > (packet.mplsLabels.size() > 0 ? packet.mplsLabels.size() - 1 : 0))
        return false;

    for (size_t dShift = 0;; dShift += sizeof(mpls_label), idx++) {
        if (sz < sizeof(mpls_label) || idx == packet.mplsLabels.size()) {
            return false;
        }
        packet.mplsLabels[idx] = reinterpret_cast<const struct mpls_label *>(d + dShift);

        if (mpls_label *lbl = (mpls_label *)(d + dShift);
            ((lbl->entry >> MPLS_LS_S_SHIFT) & MPLS_LS_S_MASK) == MPLS_LS_S_MASK) {
            dShift += sizeof(mpls_label);
            dShift += 4; // PW Ethernet Control Word
            m_Impl->m_Bytes.m_CounterL2 += dShift;
            idx++;
            shift_left(sz, dShift);
            break;
        }
    }

    return true;
}

bool NetDecoder::HandleIp4(const uint8_t *&d, size_t &sz, Packet &packet) noexcept {
    if (!d)
        return false;

    if (const uint8_t ipVersion = d[0] >> 4; ipVersion != 4) {
        GetIpStat().invalid_version++;
        return false;
    }

    if (!DecodeIpv4(d, sz, packet.ip4Header))
        return false;

    m_Impl->m_Bytes.m_CounterL3 += sizeof(iphdr);

    return true;
}

bool NetDecoder::HandleIp6(const uint8_t *&d, size_t &sz, Packet &pkt) noexcept {
    if (!d)
        return false;

    if (const uint8_t ipVersion = d[0] >> 4; ipVersion != 6) {
        GetIpStat().invalid_version++;
        return false;
    }

    const auto sTmp = sz;
    if (!DecodeIpv6(d, sz, pkt.ip6Header, pkt.ip6Fragment))
        return false;

    m_Impl->m_Bytes.m_CounterL3 += sTmp - sz;

    return true;
}

bool NetDecoder::HandleTcp(const uint8_t *&d, size_t &sz, Packet &packet) noexcept {
    if (!d)
        return false;
    if (!DecodeTcp(d, sz, packet.tcpHeader))
        return false;
    m_Impl->m_Bytes.m_CounterL4 += packet.tcpHeader->doff * 4; // doff:4 i.e. count_doff's * 4;

    return true;
}

bool NetDecoder::HandleUdp(const uint8_t *&d, size_t &sz, Packet &packet) noexcept {
    if (!d)
        return false;

    if (!DecodeUdp(d, sz, packet.udpHeader))
        return false;
    m_Impl->m_Bytes.m_CounterL4 += sizeof(udphdr);

    if (const auto dLen = htobe16(packet.udpHeader->len); dLen >= sizeof(udphdr)) {
        m_Impl->m_Bytes.m_CounterL7 = dLen - sizeof(udphdr);
    } else {
        return false;
    }

    return true;
}

bool NetDecoder::HandleSctp(const uint8_t *&d, size_t &sz, Packet &packet) noexcept {
    if (!d)
        return false;

    if (!DecodeSctp(d, sz, packet.sctpHeader))
        return false;
    m_Impl->m_Bytes.m_CounterL4 += sizeof(SctpHdr);
    m_Impl->m_Bytes.m_CounterL7 += sz;

    return true;
}

bool NetDecoder::HandleGtp(const uint8_t *&d, size_t &sz, Packet &packet) noexcept {
    m_Impl->m_Bytes.m_CounterL7 = sz;

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

bool NetDecoder::FullProcessing(const LinkLayer linkLayer, const uint8_t *&d, size_t &sz, Packet &packet) noexcept {
    if (!d)
        return false;

    const uint8_t *tData = d + m_Impl->m_Bytes.m_CounterL2;

    switch (static_cast<uint16_t>(linkLayer)) {
        case 0x4788: // MPLS
            if (size_t idx = 0; !HandleMpls(tData, sz, packet, idx))
                return false;
            if (!FullProcessing(LinkLayer::Eth, d, sz, packet))
                return false;
            break;
        case 0x0081: // VLAN
            if (size_t pos = 0; HandleVlan(tData, sz, packet, pos) &&
                                FullProcessing(static_cast<LinkLayer>(packet.vlansTags[pos]->vlan_tci), d, sz, packet))
                return true;
            else
                return false;
            break;
        case 0x6488:   // PPPoE PPP Session Stage
        case 0x6388: { // PPPoE Discovery Stage
            if (!HandlePPPoE(tData, sz, packet))
                return false;
            tData += sizeof(struct PppoeHeader);
            // Detect PPP PROTOCOL id
            // https://docs.oracle.com/cd/E19096-01/sol.ppp301/805-4018/6j3qil164/index.html
            if (auto idSize = sizeof(uint16_t); sz < idSize)
                return false;
            else {
                m_Impl->m_Bytes.m_CounterL2 += idSize;
                sz -= idSize;
            }
            if (const auto *id = (const uint16_t *)tData; *id != 0x2100)
                return false;
            if (!FullProcessing(LinkLayer::Ip4, d, sz, packet))
                return false;
        } break;
        // https://techhub.hpe.com/eginfolib/networking/docs/switches/5120si/cg/5998-8489_l2-lan_cg/content/436042676.htm
        case 0x0008: // IpV4
            if (!HandleIp4(tData, sz, packet))
                return false;
            if (Util::IsIpFragment(packet)) {
                m_Impl->m_Bytes.m_CounterL7 = sz;
                return true;
            }
            if (!ProcessTransportLayers(tData, sz, packet))
                return false;
            break;
        case 0xDD86: // Ipv6
            if (!HandleIp6(tData, sz, packet))
                return false;
            if (Util::IsIpFragment(packet)) {
                m_Impl->m_Bytes.m_CounterL7 = sz;
                return true;
            }
            if (!ProcessTransportLayers(tData, sz, packet))
                return false;
            break;
        case 0x0000:
            if (!HandleEth(tData, sz, packet))
                return false;
            if (!FullProcessing(static_cast<LinkLayer>(packet.ethHeader->ether_type), d, sz, packet))
                return false;
            break;
        default:
            return false;
    }
    return true;
}

bool NetDecoder::ProcessTransportLayers(const uint8_t *&d, size_t &sz, Packet &pkt) noexcept {
    const uint16_t proto = Util::GetIpProtocol(pkt);

    ///\todo Пересмотреть обработку заголовкой IPv6. В данной точке указатель d
    /// указывает на payload после заговка ipV6
    if (auto version = Util::GetIpVersion(pkt); version != 4 && version != 6)
        return false;

    if (proto == IPPROTO_TCP) {
        if (!HandleTcp(d, sz, pkt))
            return false;
        m_Impl->m_Bytes.m_CounterL7 = sz;
        return true;
    } else if (proto == IPPROTO_UDP) {
        if (!HandleUdp(d, sz, pkt))
            return false;
        m_Impl->m_Bytes.m_CounterL7 = sz;
        return true;
    } else if (proto == IPPROTO_ICMP) {
        pkt.icmpHeader = reinterpret_cast<const struct icmphdr *>(d);
        if (pkt.icmpHeader->type != ICMP_ECHOREPLY && pkt.icmpHeader->type != ICMP_ECHO)
            return false;
        sz -= IcmpShift;
        if (IcmpShift > sz) { // Mailformed
            return false;
        }
        m_Impl->m_Bytes.m_CounterL4 = IcmpShift;
        m_Impl->m_Bytes.m_CounterL7 = sz;
        return true;
    } else if (proto == IPPROTO_ICMPV6) {
        ///\todo проверить правильность определения размера данных ICMPv6
        /// packet.l7_d = d + sizeof(icmp6_hdr);
        pkt.icmp6Header = reinterpret_cast<const struct icmp6_hdr *>(d);
        sz -= sizeof(icmp6_hdr);
        m_Impl->m_Bytes.m_CounterL4 = sizeof(icmp6_hdr);
        m_Impl->m_Bytes.m_CounterL7 = sz;
        return true;
    } else if (proto == IPPROTO_SCTP) {
        return HandleSctp(d, sz, pkt);
    }
    return false;
}

NetDecoder::Result NetDecoder::HandleEth(const uint8_t *&d, size_t &sz) noexcept {
    Packet packet{};
    bool ok = HandleEth(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandleVlan(const uint8_t *&d, size_t &sz) noexcept {
    Packet packet{};
    size_t idx{0};
    bool ok = HandleVlan(d, sz, packet, idx);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandlePPPoE(const uint8_t *&d, size_t &sz) noexcept {
    Packet packet{};
    bool ok = HandlePPPoE(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandleMpls(const uint8_t *&d, size_t &sz) noexcept {
    Packet packet{};
    size_t idx{0};
    bool ok = HandleMpls(d, sz, packet, idx);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandleIp4(const uint8_t *&d, size_t &sz) noexcept {
    Packet packet{};
    bool ok = HandleIp4(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandleIp6(const uint8_t *&d, size_t &sz) noexcept {
    Packet packet{};
    bool ok = HandleIp6(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandleTcp(const uint8_t *&d, size_t &sz) noexcept {
    Packet packet{};
    bool ok = HandleTcp(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandleUdp(const uint8_t *&d, size_t &sz) noexcept {
    Packet packet{};
    bool ok = HandleUdp(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandleSctp(const uint8_t *&d, size_t &sz) noexcept {
    Packet packet{};
    bool ok = HandleSctp(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::HandleGtp(const uint8_t *&d, size_t &sz) noexcept {
    Packet packet{};
    bool ok = HandleGtp(d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::FullProcessing(const LinkLayer linkLayer, const uint8_t *&d, size_t &sz) noexcept {
    Packet packet{};
    bool ok = FullProcessing(linkLayer, d, sz, packet);
    return std::make_tuple(ok, packet);
}

NetDecoder::Result NetDecoder::ProcessTransportLayers(const uint8_t *&d, size_t &sz) noexcept {
    Packet packet{};
    bool ok = ProcessTransportLayers(d, sz, packet);
    return std::make_tuple(ok, packet);
}

size_t NetDecoder::GetHandledBytesTotal() const noexcept {
    return m_Impl->m_Bytes.m_CounterL2 + m_Impl->m_Bytes.m_CounterL3 + m_Impl->m_Bytes.m_CounterL4 + m_Impl->m_Bytes.m_CounterL5 + m_Impl->m_Bytes.m_CounterL6 +
           m_Impl->m_Bytes.m_CounterL7;
}

size_t NetDecoder::GetHandledBytesL7() const noexcept {
    return m_Impl->m_Bytes.m_CounterL7;
}

void NetDecoder::ResetHandledBytes() const noexcept {
    m_Impl->m_Bytes.m_CounterL2 = 0;
    m_Impl->m_Bytes.m_CounterL3 = 0;
    m_Impl->m_Bytes.m_CounterL4 = 0;
    m_Impl->m_Bytes.m_CounterL5 = 0;
    m_Impl->m_Bytes.m_CounterL6 = 0;
    m_Impl->m_Bytes.m_CounterL7 = 0;
}

size_t NetDecoder::GetHandledBytesL6() const noexcept {
    return m_Impl->m_Bytes.m_CounterL6;
}

size_t NetDecoder::GetHandledBytesL5() const noexcept {
    return m_Impl->m_Bytes.m_CounterL5;
}

size_t NetDecoder::GetHandledBytesL4() const noexcept {
    return m_Impl->m_Bytes.m_CounterL4;
}

size_t NetDecoder::GetHandledBytesL3() const noexcept {
    return m_Impl->m_Bytes.m_CounterL3;
}

size_t NetDecoder::GetHandledBytesL2() const noexcept {
    return m_Impl->m_Bytes.m_CounterL2;
}

} // namespace Nta::Network
