#pragma once

#include <packetbase.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>
#include <pcap/sll.h>
#include <hex_dump.h>
#include <gtp/GtpHeader.h>
#include <gtp/Gtp1Defs.h>
#include <gtp/Gtp2Defs.h>
#include <pppoe/PppoeHeader.h>
#include <linux/mpls.h>
#include <iostream>

#define HEXNUM_FMT(x) std::hex << std::setw(x) << std::right << std::setfill('0')
#define HEXDUMP_FMT HEXNUM_FMT(2)
#define DECNUM_FMT(x) std::dec << std::setw(x) << std::right << std::setfill(' ')
#define DECIMAL_FMT DECNUM_FMT(5)
#define MILLISEC_FMT '.' << std::dec << std::setw(6) << std::right << std::setfill('0')
#define NANOSEC_FMT '.' << std::dec << std::setw(9) << std::right << std::setfill('0')
#define GTPV2_T_FLAG 0b00001000

struct payloadLocator {
    uint8_t* data {nullptr};
    size_t size {0};
    uint8_t* getPayload() { return data + size; } 
    void addHeader(const void* hdr, size_t hdrSize) {
        if ( hdr > data) {
            data = (uint8_t*)hdr;
            size = hdrSize;
        }
    }
    void clear() { data = nullptr; size = 0; }
    bool packetParse(const protocols::PacketBase& pkt) {
        clear();
        addHeader((const void*)pkt.eth, sizeof(ether_header)); 
        addHeader((const void*)pkt.pppoe, sizeof(pppoe_header));
        for (auto hdr : pkt.vlans) { addHeader((const void*)hdr, sizeof(vlan_tag)); }
        addHeader((const void*)pkt.iph, sizeof(iphdr));
        addHeader((const void*)pkt.ip6h, sizeof(ip6_hdr));
        switch (pkt.get_ip_protocol()) {
            case IPPROTO_UDP: addHeader((const void*)pkt.udph, sizeof(udphdr)); break;
            case IPPROTO_TCP: addHeader((const void*)pkt.tcph, pkt.tcph->doff << 2); break;
            case IPPROTO_ICMP: addHeader((const void*)pkt.icmp_hdr, sizeof(icmphdr)); break;
            case IPPROTO_ICMPV6: addHeader((const void*)pkt.icmp6_hdr, sizeof(icmp6_hdr)); break;
            default: break;
        }
        if (pkt.gtph) {
            size_t toL7 = pkt.gtph->common.length - pkt.l7_size + sizeof(GtpHeader);
            addHeader((const void*)pkt.gtph, toL7); //, "\ngtp -"); 
        }
        return data != nullptr;   
    }
};

class PacketDumper {
private:
    static const char* errMark;
    static std::ostream& bufferDump(std::ostream& dumpStream, const uint8_t* buf, size_t size, char divider = ' ') {
        if (buf && size) {
            dumpStream << HEXDUMP_FMT << (unsigned)buf[0];
            for (size_t i = 1; i < size; ++i) {
                dumpStream << divider << HEXDUMP_FMT << (unsigned)buf[i];
            }
        }
        return dumpStream;
    }

public:
    static void dump(const protocols::PacketBase& pkt, std::string& result) {
        const char* errMark { "Err" };
        std::stringstream dumpStream;
        dumpStream << "\nPacket dump: ";
        std::time_t pkt_time = static_cast<std::time_t>(pkt.tm);
        std::tm tm = *std::localtime(&pkt_time);
        dumpStream << std::put_time( &tm, "Time: %Y-%m-%d %H:%M:%S") << NANOSEC_FMT << pkt.tm_ns
            << "\n hdr | size | details";
        size_t sz {0};
        size_t total {0}; //calculated total packet size
        uint16_t ether_type {0};
        size_t i = 0;
    //eth:
        sz = sizeof(struct ether_header);
        total += sz;
        if (pkt.eth) {
            dumpStream << "\nETH" << i << " |" << DECIMAL_FMT << sz << " | src: ";
            bufferDump(dumpStream, pkt.eth->ether_shost, ETH_ALEN, ':');
            dumpStream << "; dst: ";
            bufferDump(dumpStream, pkt.eth->ether_dhost, ETH_ALEN, ':');
            ether_type = pkt.eth->ether_type;
            dumpStream << "; etherType: 0x" << HEXNUM_FMT(4) << pkt.eth->ether_type;
            ++i;
        }

    //pppoe:
        if (pkt.pppoe) {
            sz = sizeof(struct pppoe_header);
            total += sz;
            dumpStream << "\nPPPOE|" << DECIMAL_FMT << sz << " | ";
            bufferDump(dumpStream, reinterpret_cast<const uint8_t*>(pkt.pppoe), sz);
            dumpStream 
                << "; version: " << (unsigned)pkt.pppoe->version 
                << ", type: " << (unsigned)pkt.pppoe->type 
                << ", code: " << (unsigned)pkt.pppoe->code;
        }

    //vlan:
        sz = sizeof(struct vlan_tag);
        total += sz * pkt.vlan_cnt;;
        i = 0;
        for (auto vl : pkt.vlans) {
            if (!vl) break;
            dumpStream << "\nVLAN" << i << "|" << DECIMAL_FMT << sz << " | ";
            bufferDump(dumpStream, reinterpret_cast<const uint8_t*>(vl), sizeof(struct vlan_tag));
            ether_type = ntohs(vl->vlan_tci);
            dumpStream 
                << "; vlan_tpid: " << vl->vlan_tpid 
                << "; vlan_tci: " << vl->vlan_tci 
                << "; etherType: 0x" << HEXNUM_FMT(4) << ether_type;
            ++i;
        }

    //mpls
        if (pkt.mpls_cnt) {
            sz = sizeof(struct mpls_label);
            for (size_t i = 0; ((i < pkt.mpls_cnt) && pkt.mpls[i]); ++i) {
                total += sz;
                auto mp = pkt.mpls[i];
                dumpStream << "\nMPLS" << i << "|" << DECIMAL_FMT << sz << " | entry: 0x" << HEXNUM_FMT(2) << mp->entry;
            }
        }

    //gtp:
        if (pkt.gtph) {
            unsigned version = protocols::PacketBase::get_gtp_version(*pkt.gtph);
            sz = sizeof(struct GtpCommon);
            if (version == GTP_VERSION_1)
                sz += sizeof(struct Gtp1Hdr);
            else if (version == GTP_VERSION_2)
                sz += sizeof(struct Gtp2Hdr);
            else
                version = 0;    

            //gtpCommon
            total += sz;
            dumpStream << "\nGTPv" << version << "|" << DECIMAL_FMT << sz << " | ";
            bufferDump(dumpStream, reinterpret_cast<const uint8_t*>(pkt.gtph), sz);
            dumpStream << "\n     |      | flags: " << HEXNUM_FMT(2) << (unsigned)pkt.gtph->common.flags
                << "; msgtype: 0x" << HEXNUM_FMT(2) << (unsigned)pkt.gtph->common.msgtype
                << "; length: " << std::dec << (unsigned)pkt.gtph->common.length;

            switch (version) {
            case GTP_VERSION_1:
                dumpStream << "; teid: 0x" << HEXNUM_FMT(8) << pkt.gtph->in.gtpv1_hdr.teid;
                if (pkt.gtph->common.flags & GTPV1_HDR_SN_FLAG)
                    dumpStream << "; seqno: 0x" << HEXNUM_FMT(4) << pkt.gtph->in.gtpv1_hdr.seqno;
                if (pkt.gtph->common.flags & GTPV1_HDR_EH_FLAG)
                    dumpStream << "; nexthdr: 0x" << HEXNUM_FMT(2) << pkt.gtph->in.gtpv1_hdr.nexthdr;
                if (pkt.gtph->common.flags & GTPV1_HDR_NPDU_FLAG)
                    dumpStream << "; nextpdu: 0x" << HEXNUM_FMT(2) << pkt.gtph->in.gtpv1_hdr.npduno;
                break;
            case GTP_VERSION_2:
                if (pkt.gtph->common.flags & GTPV2_T_FLAG)
                    dumpStream << "; teid: 0x" << HEXNUM_FMT(8) << pkt.gtph->in.gtpv2_hdr.teid(pkt.gtph->common.flags)
                        << "; seq: 0x" << HEXNUM_FMT(6) << pkt.gtph->in.gtpv2_hdr.seq(pkt.gtph->common.flags);
                else
                    dumpStream << "; teid: No TEID; seq: 0x" << HEXNUM_FMT(6) << pkt.gtph->in.gtpv2_hdr.seq(pkt.gtph->common.flags);
            default:
                break;
            }
        }

    //ipv4:
        if (pkt.iph) {
            sz = sizeof(struct iphdr);
            total += sz;
            dumpStream << "\nIPV4 |" << DECIMAL_FMT << sz;
            char ipstr[INET_ADDRSTRLEN];
            memset(ipstr, 0, INET_ADDRSTRLEN);
            strcpy(ipstr, errMark);
            inet_ntop(AF_INET, &pkt.iph->saddr, ipstr, INET_ADDRSTRLEN);
            dumpStream << " | src: " << ipstr;              /* source address */
            memset(ipstr, 0, INET_ADDRSTRLEN);
            strcpy(ipstr, errMark);
            inet_ntop(AF_INET, &pkt.iph->daddr, ipstr, INET_ADDRSTRLEN);
            dumpStream << "; dst: " << ipstr;              /* destination address */
            dumpStream << "; protocol: " << pkt.get_ip_protocol();
        }

    //ipv6:
        if (pkt.ip6h) {
            sz = sizeof(struct ip6_hdr);
            total += sz;
            dumpStream << "\nIPV6 |" << DECIMAL_FMT << sz;
            char ipstr[INET6_ADDRSTRLEN];
            memset(ipstr, 0, INET6_ADDRSTRLEN);
            strcpy(ipstr, errMark);
            inet_ntop(AF_INET6, &pkt.ip6h->ip6_src, ipstr, INET6_ADDRSTRLEN);
            dumpStream << " | src: " << ipstr;           //struct in6_addr ip6_src;  /* source address */
            memset(ipstr, 0, INET6_ADDRSTRLEN);
            strcpy(ipstr, errMark);
            inet_ntop(AF_INET6, &pkt.ip6h->ip6_dst, ipstr, INET6_ADDRSTRLEN);
            dumpStream << "; dst: " << ipstr;           //struct in6_addr ip6_dst;  /* destination address */
            dumpStream << "; protocol: " << pkt.get_ip_protocol();
        }

    //tcp-udp-icmp:
        unsigned proto = pkt.get_ip_protocol();
        if (IPPROTO_UDP == proto) {
            if (pkt.udph) {
                sz = sizeof(struct udphdr);
                total += sz;
                dumpStream << "\nUDP  |" << DECIMAL_FMT << sz 
                    << " | srcPort: " << std::dec << ntohs(pkt.udph->source)
                    << "; dstPort: " << std::dec << ntohs(pkt.udph->dest)
                    << "; len: " << std::dec << ntohs(pkt.udph->len)
                    << "; check: 0x" << HEXNUM_FMT(4) << pkt.udph->check;
            }
        } else if (IPPROTO_TCP == proto) {
            if (pkt.tcph) {
                sz = pkt.tcph->doff << 2;
                if (sz) {
                    total += sz;
                    dumpStream << "\nTCP  |" << DECIMAL_FMT << sz
                        << " | srcPort: " << std::dec << ntohs(pkt.tcph->source)
                        << "; dstPort: " << std::dec << ntohs(pkt.tcph->dest);
                }
            }
        } else if (IPPROTO_ICMP == proto) {
            if (pkt.icmp_hdr) {
                sz = sizeof(struct icmphdr);
                total += sz;
                dumpStream << "\nICMP |" << DECIMAL_FMT << sz;
                dumpStream 
                    << "; type: " << (unsigned)pkt.icmp_hdr->type 
                    << "; code: " << (unsigned)pkt.icmp_hdr->code
                    << "; checksum: 0x" << HEXNUM_FMT(4) << pkt.icmp_hdr->checksum
                    << "; id: 0x" << HEXNUM_FMT(4) << pkt.icmp_hdr->un.echo.id
                    << "; sequence/mtu: 0x" << HEXNUM_FMT(4) << pkt.icmp_hdr->un.echo.sequence;
            }
        } else if (IPPROTO_ICMPV6 == proto) {
            if (pkt.icmp6_hdr) {
                sz = sizeof(struct icmp6_hdr);
                total += sz;
                dumpStream << "\nICMP6|" << DECIMAL_FMT << sz;
                dumpStream 
                    << "; type: " << (unsigned)pkt.icmp6_hdr->icmp6_type 
                    << "; code: " << (unsigned)pkt.icmp6_hdr->icmp6_code
                    << "; checksum: 0x" << HEXNUM_FMT(4) << pkt.icmp6_hdr->icmp6_cksum
                    << "; dataun: 0x"; 
                    bufferDump(dumpStream, reinterpret_cast<const uint8_t*>(&pkt.icmp6_hdr->icmp6_dataun), sizeof(pkt.icmp6_hdr->icmp6_dataun));
            }
        }

    //app:
        if (pkt.l7_size) {
            dumpStream << "\nAPP  |" << DECIMAL_FMT << pkt.l7_size << " |";
            payloadLocator p;
            if (p.packetParse(pkt)) {
                uint8_t* pl = p.getPayload();
                if (pl) {
                    dumpStream  << "\n";
                    common::utils::hexDumper::dump(dumpStream, pl, pkt.l7_size);
                }
            }
        }

    //summary:
        total += pkt.l7_size;
        dumpStream << "\nTotal|" << DECIMAL_FMT << total 
            << " | l2_size: " << pkt.l2_size << "; l3_size: " << pkt.l3_size
            << "; l4_size: " << pkt.l4_size << "; l5_size: " << pkt.l5_size
            << "; l6_size: " << pkt.l6_size << "; l7_size: " << pkt.l7_size;

        dumpStream << '\n';
        result.append(dumpStream.str());
    }
};

#undef MILLISEC_FMT
#undef DECIMAL_FMT
#undef HEXDUMP_FMT

