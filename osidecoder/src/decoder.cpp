#include "decoder.h"

#include <PPPoELayer.h>
#include <PppTypes.h>
#include <PppoeHeader.h>
#include <linux/mpls.h>

#include "decodestat.h"
#include "gtp/GtpHeader.h"
#include "sctp/sctp.h"
#include "packetbase.h"
#include "shift.h"

/*type + code + checksum + id + seq + timestamp*/
constexpr size_t IcmpShift = sizeof(struct icmphdr) +  sizeof(uint64_t);

namespace protocols
{
bool Decoder::treatEth(const uint8_t *&data, size_t& size, PacketBase& packet) noexcept
{
    if (!decodeEth(data, size, packet.eth)) return false;

    packet.l2_size += sizeof(ether_header);
    return true;
}

bool Decoder::treatVlan(const uint8_t*& data, size_t& size, PacketBase& packet) noexcept
{
    if(!data) return false;
    if (packet.vlan_cnt > (packet.vlans.size() > 0 ? packet.vlans.size() - 1 : 0)) return false;

    uint16_t nextProto{0},tNextProto{0};  // ex. ipType

    // Обработка vlan меток.
    auto& vlan_cnt = packet.vlan_cnt;
    const uint8_t* tData = data;
    while (nextProto == 0) {
        if (vlan_cnt >= MAX_VLAN_CNT) {
            getVlanStat().invalid_ethertype++;
            return false;
        }
        if (auto* vlan = packet.vlans[vlan_cnt]; !decodeVlan(tData, size, vlan)) {
            getVlanStat().invalid_ethertype++;
            return false;
        } else {
            if(packet.vlans[vlan_cnt] == nullptr) packet.vlans[vlan_cnt] = vlan;
        }
        tNextProto = ntohs((packet.vlans[vlan_cnt])->vlan_tci);
        if (tNextProto != ETHERTYPE_VLAN) nextProto = tNextProto;
        packet.l2_size += sizeof(vlan_tag);
        vlan_cnt++;
        tData = data+(vlan_cnt*sizeof(vlan_tag));
    }    

    return true;
}

bool Decoder::treatPPPoE(const uint8_t*& data, size_t& size, PacketBase& packet) noexcept
{
    if(!data) return false;

    PPPoELayer layer(data, size);

    if (PPPoECode::PPPOE_CODE_SESSION != layer.getHeaderCode()) {
        shift_left(size, layer.getLayerPayloadSize());
        return false;
    }

    if (uint16_t ppp_proto = htobe16(*(uint16_t*)layer.getLayerPayload()); ppp_proto == PCPP_PPP_IP || ppp_proto == PCPP_PPP_IPV6) {
        packet.pppoe = layer.getPPPoEHeader();
    } else {
        shift_left(size, layer.getLayerPayloadSize());
        return false;
    }

    shift_left(size, layer.getHeaderLen());
    packet.l2_size += layer.getHeaderLen();

    return true;
}


bool Decoder::treatMpls(const uint8_t*& data, size_t& size, PacketBase& packet) noexcept
{
    if(!data) return false;
    if (packet.mpls_cnt > (packet.mpls.size() > 0 ? packet.mpls.size() - 1 : 0)) return false;

    for (size_t dShift = 0;; dShift += sizeof(mpls_label), packet.mpls_cnt++) {
        if (size < sizeof(mpls_label) || packet.mpls_cnt == packet.mpls.size()) {
            return false;
        }
        packet.mpls[packet.mpls_cnt] = reinterpret_cast<const struct mpls_label*>(data + dShift);

        if (mpls_label* lbl = (mpls_label*)(data + dShift); ((lbl->entry >> MPLS_LS_S_SHIFT) & MPLS_LS_S_MASK) == MPLS_LS_S_MASK) {
            dShift += sizeof(mpls_label);
            dShift += 4; //PW Ethernet Control Word
            packet.l2_size+=dShift;
            packet.mpls_cnt++;
            shift_left(size, dShift);
            break;
        }
    }

    return true;
}

bool Decoder::treatIp(const uint8_t*& data, size_t& size, PacketBase& packet) noexcept
{
    if(!data) return false;

    // Size of GTP-header excluded from flow_*_size
    switch (const uint8_t ip_version = data[0] >> 4; ip_version) {  // ip version
        case 4:
            if (!decodeIpv4(packet.tm, data, size, packet.iph)) {
                return false;
            } else {
                packet.l3_size += sizeof(iphdr);
            }

            break;
        case 6:
            if (!decodeIpv6(packet.tm, data, size, packet.ip6h, packet.ip6frag)) {
                return false;
            }

            break;
        default:
            getIpStat().invalid_version++;
            return false;
    }
    
    return true;
}

bool Decoder::treatTcp(const uint8_t*& data, size_t& size, PacketBase& packet) noexcept
{
    if(!data) return false;
    if (!decodeTcp(data, size, packet.tcph)) return false;
    packet.l4_size += packet.tcph->doff * 4;  // doff:4 i.e. count_doff's * 4;

    return true;
}

bool Decoder::treatUdp(const uint8_t*& data, size_t& size, PacketBase& packet) noexcept
{
    if(!data) return false;

    if (!decodeUdp(data, size, packet.udph)) return false;
    packet.l4_size += sizeof(udphdr);

    if (const auto dLen = htobe16(packet.udph->len); dLen >= sizeof(udphdr)) {
        packet.l7_size = dLen - sizeof(udphdr);
    } else {
        return false;
    }

    return true;
}

bool Decoder::treatSctp(const uint8_t *&data, size_t &size, PacketBase &packet) noexcept
{
    if(!data) return false;

    if (!decodeSctp(data, size, packet.sctph)) return false;
    packet.l4_size += sizeof(sctphdr);
    packet.l7_size += size;

    return true;
}

bool Decoder::treatGtp(const uint8_t*& data, size_t& size, PacketBase& packet) noexcept
{
    packet.l7_size = size;

   if(!data) return false;
   if(!size) return false;

   if (size < sizeof(GtpHeader)) return false;

   const GtpHeader *gtph = reinterpret_cast<const struct GtpHeader*>(data);

   if (size < htons(gtph->common.length)) return false;

   packet.gtph = gtph;
   size -= sizeof(GtpCommon);

   return true;
}

bool Decoder::treatHeaders(const uint16_t linkLayer, const uint8_t *&data, size_t &size, PacketBase& packet) noexcept{

    if(!data) return false;

    const uint8_t* tData = data + packet.l2_size;

    switch (linkLayer) {
        case 0x4788: //MPLS
            if (!treatMpls(tData, size, packet)) return false;
            if (!treatHeaders(0, data, size, packet)) return false;
            break;
        case 0x0081: //VLAN
            if (!treatVlan(tData, size, packet)) return false;
            if (!treatHeaders(packet.vlans[packet.vlan_cnt > 0 ? packet.vlan_cnt - 1 : packet.vlan_cnt]->vlan_tci, data, size, packet))
                return false;
            break;
        case 0x6488: //PPPoE
        case 0x6388: {
            if (!treatPPPoE(tData, size, packet)) return false;
            tData += sizeof(struct pppoe_header);
            // Detect PPP PROTOCOL id https://docs.oracle.com/cd/E19096-01/sol.ppp301/805-4018/6j3qil164/index.html
            if (auto idSize = sizeof(uint16_t); size < idSize) return false;
            else {
                packet.l2_size += idSize;
                size -= idSize;
            }
            if (const auto* id = (const uint16_t*)tData; *id != 0x2100) return false;
            if (!treatHeaders(0x0008, data, size, packet)) return false;
        } break;
        case 0x0008: //IpV4 https://techhub.hpe.com/eginfolib/networking/docs/switches/5120si/cg/5998-8489_l2-lan_cg/content/436042676.htm
        case 0xDD86: //Ipv6
            if (!treatIp(tData, size, packet)) return false;
            if (packet.is_ip_fragment()) {
                packet.l7_size = size;
                return true;
            }
            if (!treatTransportLayers(tData, size, packet)) return false;
            break;
        case 0x0000:
            if (!treatEth(tData, size, packet)) return false;
            if (!treatHeaders(packet.eth->ether_type, data, size, packet))
                return false;
            break;
        default:
            return false;
    }
    return true;
}

bool Decoder::treatTransportLayers(const uint8_t*& data, size_t& size, PacketBase& packet) noexcept
{
    const uint16_t proto = packet.get_ip_protocol();

    ///\todo Пересмотреть обработку заголовкой IPv6. В данной точке указатель data указывает на payload после заговка ipV6
    if (auto ver = packet.get_ip_version(); ver != 4 && ver != 6) return false;

    if (proto == IPPROTO_TCP) {
        if (!treatTcp(data, size, packet)) return false;
        packet.l7_size = size;
        return true;
    } else if (proto == IPPROTO_UDP) {
        if (!treatUdp(data, size, packet)) return false;
        packet.l7_size = size;
        return true;
    } else if (proto == IPPROTO_ICMP) {
        packet.icmp_hdr = reinterpret_cast<const struct icmphdr*>(data);
        if (packet.icmp_hdr->type != ICMP_ECHOREPLY && packet.icmp_hdr->type != ICMP_ECHO)
            return false;
        size -= IcmpShift;
        if (IcmpShift > size) {  // Mailformed
            return false;
        }
        packet.l4_size = IcmpShift;
        packet.l7_size = size;
        return true;
    } else if (proto == IPPROTO_ICMPV6) {
        ///\todo проверить правильность определения размера данных ICMPv6
        /// packet.l7_data = data + sizeof(icmp6_hdr);
        packet.icmp6_hdr = reinterpret_cast<const struct icmp6_hdr*>(data);
        size -= sizeof(icmp6_hdr);
        packet.l4_size = sizeof(icmp6_hdr);
        packet.l7_size = size;
        return true;
    } else if (proto == IPPROTO_SCTP) {
        return treatSctp(data, size, packet);
    }
    return false;
}

Decoder::Result Decoder::treatEth(const uint32_t& tm, const uint32_t& tm_ns, const uint8_t*& data, size_t& size) noexcept
{
    PacketBase packet(tm, tm_ns);
    bool ok = treatEth(data, size, packet);
    return std::make_tuple(ok, packet);
}

Decoder::Result Decoder::treatVlan(const uint32_t& tm, const uint32_t& tm_ns, const uint8_t*& data, size_t& size) noexcept
{
    PacketBase packet(tm, tm_ns);
    bool ok = treatVlan(data, size, packet);
    return std::make_tuple(ok, packet);
}

Decoder::Result Decoder::treatPPPoE(const uint32_t& tm, const uint32_t& tm_ns, const uint8_t*& data, size_t& size) noexcept
{
    PacketBase packet(tm, tm_ns);
    bool ok = treatPPPoE(data, size, packet);
    return std::make_tuple(ok, packet);
}

Decoder::Result Decoder::treatMpls(const uint32_t& tm, const uint32_t& tm_ns, const uint8_t*& data, size_t& size) noexcept
{
    PacketBase packet(tm, tm_ns);
    bool ok = treatMpls(data, size, packet);
    return std::make_tuple(ok, packet);
}

Decoder::Result Decoder::treatIp(const uint32_t& tm, const uint32_t& tm_ns, const uint8_t*& data, size_t& size) noexcept
{
    PacketBase packet(tm, tm_ns);
    bool ok = treatIp(data, size, packet);
    return std::make_tuple(ok, packet);
}

Decoder::Result Decoder::treatTcp(const uint32_t &tm, const uint32_t &tm_ns, const uint8_t *&data, size_t &size) noexcept
{
    PacketBase packet(tm, tm_ns);
    bool ok = treatTcp(data, size, packet);
    return std::make_tuple(ok, packet);
}

Decoder::Result Decoder::treatUdp(const uint32_t &tm, const uint32_t &tm_ns, const uint8_t *&data, size_t &size) noexcept
{
    PacketBase packet(tm, tm_ns);
    bool ok = treatUdp(data, size, packet);
    return std::make_tuple(ok, packet);
}

Decoder::Result Decoder::treatSctp(const uint32_t &tm, const uint32_t &tm_ns, const uint8_t *&data, size_t &size) noexcept
{
    PacketBase packet(tm, tm_ns);
    bool ok = treatSctp(data, size, packet);
    return std::make_tuple(ok, packet);
}

Decoder::Result Decoder::treatGtp(const uint32_t& tm, const uint32_t& tm_ns, const uint8_t*& data, size_t& size) noexcept
{
    PacketBase packet(tm, tm_ns);
    bool ok = treatGtp(data, size, packet);
    return std::make_tuple(ok, packet);
}

Decoder::Result Decoder::treatHeaders(const uint32_t& tm, const uint32_t& tm_ns, const uint16_t linkLayer, const uint8_t *&data, size_t &size) noexcept
{
    PacketBase packet(tm, tm_ns);
    bool ok = treatHeaders(linkLayer, data, size, packet);
    return std::make_tuple(ok, packet);
}

Decoder::Result Decoder::treatTransportLayers(const uint32_t& tm, const uint32_t& tm_ns, const uint8_t *&data, size_t &size) noexcept
{
    PacketBase packet(tm, tm_ns);
    bool ok = treatTransportLayers(data, size, packet);
    return std::make_tuple(ok, packet);
}


}  // namespace protocols
