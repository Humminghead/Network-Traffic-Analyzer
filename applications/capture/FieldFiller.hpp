#pragma once

#include "NetDecoder/PacketBase.h"
#include "NetDecoder/PppOe/PppoeHeader.h"
#include "NetDecoder/Sctp/Sctp.h"

#include <ThriftModels/FlowModel.h>

#include <algorithm>
#include <linux/mpls.h>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

namespace Nta::Network {

template <class Field, class Model> struct FieldFiller;

template <> struct FieldFiller<ether_header, FlowModel> {
    static void Fill(const ether_header *eth, FlowModel &m) {
        if(!eth)
        {
            m.m_EthDstMac.SetEmpty(true);
            m.m_EthSrcMac.SetEmpty(true);
            m.m_Ethtype.SetEmpty(true);
            return;
        }
        std::copy_n(eth->ether_shost, ETH_ALEN, m.m_EthSrcMac.Value().begin());
        std::copy_n(eth->ether_dhost, ETH_ALEN, m.m_EthDstMac.Value().begin());
        m.m_Ethtype.SetValue(eth->ether_type);
        m.m_EthSrcMac.SetEmpty(false);
        m.m_EthDstMac.SetEmpty(false);
    }
};

template <> struct FieldFiller<Nta::Network::PppoeHeader, FlowModel> {
    static void Fill(const Nta::Network::PppoeHeader *pppoe, FlowModel &m) {
        if(!pppoe){
            m.m_PPPoEVersion.SetEmpty(true);
            m.m_PPPoEType.SetEmpty(true);
            m.m_PPPoECode.SetEmpty(true);
            m.m_PPPoESessionId.SetEmpty(true);
            m.m_PPPoEPayloadLen.SetEmpty(true);
            return;
        }
        m.m_PPPoEVersion.SetValue(pppoe->version);
        m.m_PPPoEType.SetValue(pppoe->type);
        m.m_PPPoECode.SetValue(pppoe->code);
        m.m_PPPoESessionId.SetValue(htons(pppoe->sessionId));
        m.m_PPPoEPayloadLen.SetValue(htons(pppoe->payloadLength));
    }
};

template <> struct FieldFiller<Nta::Network::Packet::VlansArray, FlowModel> {
    static void Fill(const Nta::Network::Packet::VlansArray & vlan, FlowModel & m) {
        if(!vlan.front()){
            m.m_VlanTpid.SetEmpty(true);
            m.m_VlanDepth.SetEmpty(true);
            m.m_VlanTci.SetEmpty(true);
            return;
        }

        auto _unused = std::ranges::find_if(
            vlan, [&depth = m.m_VlanDepth.Value()](auto *vl) { return nullptr == vl ? true : ++depth, false; });
        (void)_unused;
        m.m_VlanDepth.SetEmpty(false);
        m.m_VlanTci.SetValue(vlan[m.m_VlanDepth.Value() - 1]->vlan_tci);
        m.m_VlanTpid.SetValue(vlan[m.m_VlanDepth.Value() - 1]->vlan_tpid);
    }
};

template <> struct FieldFiller<Nta::Network::Packet::MplsArray, FlowModel> {
    using MplsHeader = std::remove_cv_t<std::remove_pointer_t<Nta::Network::Packet::MplsArray::value_type>>;

    static void Fill(const Nta::Network::Packet::MplsArray &mpls, FlowModel &m) {
        if (!mpls.front()) {
            m.m_MplsHeader.SetEmpty(true);
            return;
        }

        auto _unused = std::ranges::find_if(mpls, [&](const MplsHeader *header) {
            if (nullptr == header)
                return true;
            else {
                m.m_MplsHeader.SetValue(htonl(header->entry));
                return false;
            }
        });
    }
};

template <> struct FieldFiller<iphdr, FlowModel> {
    static void Fill(const iphdr *iph, FlowModel &m) {
        if (!iph) {
            m.m_SourceAddrIp4.SetEmpty(true);
            m.m_DesinationAddrIp4.SetEmpty(true);
            m.m_IpProtocol.SetEmpty(true);
            return;
        }

        m.m_SourceAddrIp4.SetValue(iph->saddr);
        m.m_DesinationAddrIp4.SetValue(iph->daddr);
        m.m_IpProtocol.SetValue(iph->protocol);
    }
};

template <> struct FieldFiller<ip6_hdr, FlowModel> {
    static void Fill(const ip6_hdr *ip6h, FlowModel &m) {
        if (!ip6h) {
            m.m_SourceAddrIp6.SetEmpty(true);
            m.m_DesinationAddrIp6.SetEmpty(true);
            m.m_IpProtocol.SetEmpty(true);
            return;
        }

        m.m_SourceAddrIp6.Value().clear();
        m.m_DesinationAddrIp6.Value().clear();

        std::copy(
            &(ip6h->ip6_src.s6_addr[0]),
            &(ip6h->ip6_src.s6_addr[0]) + sizeof(in6_addr::s6_addr),
            std::back_inserter(m.m_SourceAddrIp6.Value()));

        std::copy(
            &(ip6h->ip6_dst.s6_addr[0]),
            &(ip6h->ip6_dst.s6_addr[0]) + sizeof(in6_addr::s6_addr),
            std::back_inserter(m.m_DesinationAddrIp6.Value()));

        m.m_IpProtocol.SetValue(ip6h->ip6_nxt);
    }
};

template <> struct FieldFiller<ip6_frag, FlowModel> {
    static void Fill(const ip6_frag *, FlowModel &) {}
};

template <> struct FieldFiller<udphdr, FlowModel> {
    static void Fill(const udphdr *udp, FlowModel &m) {
        if (!udp) {
            m.m_SrcPort.SetEmpty(true);
            m.m_DstPort.SetEmpty(true);
            return;
        }
        m.m_SrcPort.SetValue(udp->source);
        m.m_DstPort.SetValue(udp->dest);
    }
};

template <> struct FieldFiller<tcphdr, FlowModel> {
    static void Fill(const tcphdr *tcp, FlowModel &m) {
        if (!tcp) {
            m.m_SrcPort.SetEmpty(true);
            m.m_DstPort.SetEmpty(true);
            return;
        }
        m.m_SrcPort.SetValue(tcp->source);
        m.m_DstPort.SetValue(tcp->dest);
    }
};

template <> struct FieldFiller<Nta::Network::SctpHdr, FlowModel> {
    static void Fill(const Nta::Network::SctpHdr *sctp, FlowModel &m) {
        if (!sctp) {
            m.m_SrcPort.SetEmpty(true);
            m.m_DstPort.SetEmpty(true);
            return;
        }
        m.m_SrcPort.SetValue(sctp->source);
        m.m_DstPort.SetValue(sctp->dest);
    }
};

template <> struct FieldFiller<icmphdr, FlowModel> {
    static void Fill(const icmphdr *icmp, FlowModel &m) {
        if(!icmp){

        }
    }
};

template <> struct FieldFiller<icmp6_hdr, FlowModel> {
    static void Fill(const icmp6_hdr *icmpv6, FlowModel &m) {}
};
} // namespace Nta::Network
