#include "NetDecoder/Util/Packet.h"
#include <NetDecoder/Decoder.h>
#include <NetDecoder/Gtp/GtpHeader.h>
#include <NetDecoder/PacketBase.h>
#include <NetDecoder/PppOe/PppoeHeader.h>
#include <NetDecoder/Sctp/Sctp.h>
#include <gtest/gtest.h>
#include <gtest/internal/gtest-internal.h>

using namespace Nta::Network;

NetDecoder decoder;

class NetDecoderCompleteTest : public ::testing::Test {
  public:
    NetDecoderCompleteTest() {}

    auto &getDecoder() { return decoder; }

  protected:
    virtual void SetUp() {}
    virtual void TearDown() {}
    static void SetUpTestSuite() {}
    static void TearDownTestSuite() {}
};

constexpr std::array<uint8_t, 14>
    ethHdr{0xcc, 0x03, 0x04, 0xdc, 0x00, 0x10, 0xcc, 0x04, 0x04, 0xdc, 0x00, 0x10, 0x88, 0x47};

TEST_F(NetDecoderCompleteTest, handle_eth_nullptr_test) {
    auto &decoder = this->getDecoder();

    const uint8_t *data = nullptr;
    size_t size = 0;

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandleEth(data, size);

    ASSERT_FALSE(status);
    ASSERT_EQ(packet.ethHeader, nullptr);
    ASSERT_EQ(size, 0);
}

TEST_F(NetDecoderCompleteTest, handle_vlan_nullptr_test) {
    auto &decoder = this->getDecoder();

    const uint8_t *data = nullptr;
    size_t size = 0;

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandleVlan(data, size);

    ASSERT_FALSE(status);    
    std::for_each(std::begin(packet.vlansTags), std::end(packet.vlansTags), [](auto p) { ASSERT_EQ(p, nullptr); });    
    ASSERT_EQ(size, 0);
}

TEST_F(NetDecoderCompleteTest, handle_pppoe_nullptr_test) {
    auto &decoder = this->getDecoder();

    const uint8_t *data = nullptr;
    size_t size = 0;

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandlePPPoE(data, size);

    ASSERT_FALSE(status);
    ASSERT_EQ(packet.pppoeHeader, nullptr);
    ASSERT_EQ(size, 0);
}

TEST_F(NetDecoderCompleteTest, handle_mpls_nullptr_test) {
    auto &decoder = this->getDecoder();

    const uint8_t *data = nullptr;
    size_t size = 0;

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandleMpls(data, size);

    ASSERT_FALSE(status);
    std::for_each(std::begin(packet.mplsLabels), std::end(packet.mplsLabels), [](auto p) { ASSERT_EQ(p, nullptr); });    
    ASSERT_EQ(size, 0);
}

TEST_F(NetDecoderCompleteTest, handle_ip_nullptr_test) {
    auto &decoder = this->getDecoder();

    const uint8_t *data = nullptr;
    size_t size = 0;

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandleIp4(data, size);

    ASSERT_FALSE(status);
    ASSERT_EQ(packet.ip4Header, nullptr);
    ASSERT_EQ(packet.ip6Header, nullptr);
    ASSERT_EQ(size, 0);
}

TEST_F(NetDecoderCompleteTest, handle_udp_nullptr_test) {
    auto &decoder = this->getDecoder();

    const uint8_t *data = nullptr;
    size_t size = 0;

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandleUdp(data, size);

    ASSERT_FALSE(status);
    ASSERT_EQ(packet.udpHeader, nullptr);
    ASSERT_EQ(size, 0);
}

TEST_F(NetDecoderCompleteTest, handle_tcp_nullptr_test) {
    auto &decoder = this->getDecoder();

    const uint8_t *data = nullptr;
    size_t size = 0;

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandleTcp(data, size);

    ASSERT_FALSE(status);
    ASSERT_EQ(packet.tcpHeader, nullptr);
    ASSERT_EQ(size, 0);
}

TEST_F(NetDecoderCompleteTest, handle_gtp_nullptr_test) {
    auto &decoder = this->getDecoder();

    const uint8_t *data = nullptr;
    size_t size = 0;

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandleGtp(data, size);

    ASSERT_FALSE(status);
    ASSERT_EQ(packet.gtpHeader, nullptr);
    ASSERT_EQ(size, 0);
}

/*
    Ethernet II
    Destination: cc:03:04:dc:00:10 (cc:03:04:dc:00:10)
    Source: cc:04:04:dc:00:10 (cc:04:04:dc:00:10)
    Type: MPLS label switched packet (0x8847)
*/

TEST_F(NetDecoderCompleteTest, handle_eth_test) {
    auto &decoder = this->getDecoder();

    const uint8_t *data = ethHdr.data();
    size_t size = ethHdr.size();

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandleEth(data, size);

    ASSERT_TRUE(status);

    struct ether_header *tEth{(struct ether_header *)ethHdr.data()};

    ASSERT_EQ(packet.ethHeader->ether_dhost, tEth->ether_dhost);
    ASSERT_EQ(packet.ethHeader->ether_shost, tEth->ether_shost);
    ASSERT_EQ(htobe16(packet.ethHeader->ether_type), 0x8847);
    ASSERT_EQ(decoder.GetHandledBytesL2(), 14);
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 14);
    ASSERT_EQ(size, 0);
}

/*
    802.1Q Virtual LAN, PRI: 0, DEI: 0, ID: 1
       000. .... .... .... = Priority: Best Effort (default) (0)
       ...0 .... .... .... = DEI: Ineligible
       .... 0000 0000 0001 = ID: 1
       Type: VLAN (0x8100)


    802.1Q Virtual LAN, PRI: 0, DEI: 0, ID: 20
      000. .... .... .... = Priority: Best Effort (default) (0)
      ...0 .... .... .... = DEI: Ineligible
      .... 0000 0001 0100 = ID: 20
      Type: IPv4 (0x0800)

 */
constexpr std::array<uint8_t, 8> vlanHdr{0x00, 0x01, 0x81, 0x00, 0x00, 0x14, 0x08, 0x00};

TEST_F(NetDecoderCompleteTest, handle_vlan_test) {
    auto &decoder = this->getDecoder();

    const uint8_t *data = vlanHdr.data();
    size_t size = vlanHdr.size();
    size_t vlansCntr = 0;

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandleVlan(data, size);

    ASSERT_TRUE(status);

    // ASSERT_EQ(packet.vlanCounter, 2);
    std::for_each(std::begin(packet.vlansTags), std::end(packet.vlansTags), [&](auto p) {
        if (p)
            vlansCntr++;
    });
    ASSERT_EQ(vlansCntr, 2);
    ASSERT_EQ(decoder.GetHandledBytesL2(), 8);
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 8);
    ASSERT_EQ(size, 0);
}

/*
    PPP-over-Ethernet Session
        0001 .... = Version: 1
        .... 0001 = Type: 1
        Code: Session Data (0x00)
        Session ID: 0x1b26
        Payload Length: 1402
    Point-to-Point Protocol
        Protocol: Internet Protocol version 4 (0x0021)
 */
constexpr std::array<uint8_t, 8> pppoeHdr{0x11, 0x00, 0x1b, 0x26, 0x05, 0x7a, 0x00, 0x21};

TEST_F(NetDecoderCompleteTest, handle_pppoe_test) {
    auto &decoder = this->getDecoder();

    const uint8_t *data = pppoeHdr.data();
    size_t size = pppoeHdr.size();

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandlePPPoE(data, size);

    ASSERT_TRUE(status);

    ASSERT_FALSE(packet.pppoeHeader == nullptr);
    ASSERT_EQ(packet.pppoeHeader->code, 0);
    ASSERT_EQ(htobe16(packet.pppoeHeader->payloadLength), 1402);
    ASSERT_EQ(htobe16(packet.pppoeHeader->sessionId), 0x1b26);
    ASSERT_EQ(packet.pppoeHeader->type, 1);
    ASSERT_EQ(packet.pppoeHeader->version, 1);
}

/*
    MultiProtocol Label Switching Header, Label: 16, Exp: 0, S: 1, TTL: 255
        0000 0000 0000 0001 0000 .... .... .... = MPLS Label: 16
        .... .... .... .... .... 000. .... .... = MPLS Experimental Bits: 0
        .... .... .... .... .... ...1 .... .... = MPLS Bottom Of Label Stack: 1
        .... .... .... .... .... .... 1111 1111 = MPLS TTL: 255
*/
constexpr std::array<uint8_t, 8> mplsHdr{0x00, 0x01, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00};

TEST_F(NetDecoderCompleteTest, handle_mpls_test) {
    auto &decoder = this->getDecoder();

    const uint8_t *data = mplsHdr.data();
    size_t size = mplsHdr.size();

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandleMpls(data, size);

    ASSERT_TRUE(status);
    ASSERT_EQ(decoder.GetHandledBytesL2(), 8);
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 8);
    ASSERT_EQ(size, 0);
}

/*
    Internet Protocol Version 4, Src: 45.136.22.26, Dst: 100.74.58.223
        0100 .... = Version: 4
        .... 0101 = Header Length: 20 bytes (5)
        Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
        Total Length: 52
        Identification: 0xb117 (45335)
        Flags: 0x4000, Don't fragment
        Fragment offset: 0
        Time to live: 55
        Protocol: TCP (6)
        Header checksum: 0xaa9d [validation disabled]
        [Header checksum status: Unverified]
        Source: 45.136.22.26
        Destination: 100.74.58.223

    Transmission Control Protocol, Src Port: 443, Dst Port: 47130, Seq: 1, Ack: 1, Len: 1348
        Source Port: 443
        Destination Port: 47130
        [Stream index: 0]
        [TCP Segment Len: 1348]
        Sequence number: 1    (relative sequence number)
        Sequence number (raw): 437730824
        [Next sequence number: 1349    (relative sequence number)]
        Acknowledgment number: 1    (relative ack number)
        Acknowledgment number (raw): 2754057268
        1000 .... = Header Length: 32 bytes (8)
        Flags: 0x010 (ACK)
        Window size value: 14850
        [Calculated window size: 14850]
        [Window size scaling factor: -1 (unknown)]
        Checksum: 0x05fe [unverified]
        [Checksum Status: Unverified]
        Urgent pointer: 0
        Options: (12 bytes), No-Operation (NOP), No-Operation (NOP), Timestamps
        [SEQ/ACK analysis]
        [Timestamps]
        TCP payload (1348 bytes)
 */
constexpr std::array<uint8_t, 52> ip4Hdr{0x45, 0x00, 0x00, 0x34, 0xb1, 0x17, 0x40, 0x00, 0x37, 0x06, 0xaa, 0x9d, 0x2d,
                                         0x88, 0x16, 0x1a, 0x64, 0x4a, 0x3a, 0xdf, 0x01, 0xbb, 0xb8, 0x1a, 0x1a, 0x17,
                                         0x3e, 0x08, 0xa4, 0x27, 0x94, 0x34, 0x80, 0x10, 0x3a, 0x02, 0x05, 0xfe, 0x00,
                                         0x00, 0x01, 0x01, 0x08, 0x0a, 0xa7, 0x05, 0x2c, 0xc1, 0xe1, 0x6d, 0xf0, 0x0f};

TEST_F(NetDecoderCompleteTest, handle_ip4_test) {
    auto &decoder = this->getDecoder();

    const uint8_t *data = ip4Hdr.data();
    size_t size = ip4Hdr.size();

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandleIp4(data, size);

    const struct iphdr *tIpH{(const struct iphdr *)ip4Hdr.data()};

    ASSERT_TRUE(status);
    ASSERT_FALSE(packet.ip4Header == nullptr);
    ASSERT_EQ(packet.ip4Header->daddr, tIpH->daddr);
    ASSERT_EQ(packet.ip4Header->saddr, tIpH->saddr);
    ASSERT_EQ(packet.ip4Header->check, tIpH->check);
    ASSERT_EQ(packet.ip4Header->frag_off, tIpH->frag_off);
    ASSERT_EQ(packet.ip4Header->id, tIpH->id);
    ASSERT_EQ(packet.ip4Header->ihl, tIpH->ihl);
    ASSERT_EQ(packet.ip4Header->protocol, tIpH->protocol);
    ASSERT_EQ(packet.ip4Header->tos, tIpH->tos);
    ASSERT_EQ(packet.ip4Header->tot_len, tIpH->tot_len);
    ASSERT_EQ(packet.ip4Header->ttl, tIpH->ttl);
    ASSERT_EQ(decoder.GetHandledBytesL3(), 20);
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 20);
    ASSERT_EQ(size, 32);
}

/*
    Internet Protocol Version 6, Src: 2607:f2c0:f00f:b001::face:b00c, Dst: 2001:4f8:3:d::61
        0110 .... = Version: 6
        .... 0000 0000 .... .... .... .... .... = Traffic Class: 0x00 (DSCP: CS0, ECN: Not-ECT)
        .... .... .... 0000 0000 0000 0000 0000 = Flow Label: 0x00000
        Payload Length: 84
        Next Header: UDP (17)
        Hop Limit: 255
        Source: 2607:f2c0:f00f:b001::face:b00c
        Destination: 2001:4f8:3:d::61
    User Datagram Protocol, Src Port: 4342, Dst Port: 4342
        Source Port: 4342
        Destination Port: 4342
        Length: 84
        Checksum: 0x8f5f [unverified]
        [Checksum Status: Unverified]
        [Stream index: 0]
        [Timestamps]
    Locator/ID Separation Protocol
        0011 .... .... .... .... .... = Type: Map-Register (3)
        .... 1... .... .... .... .... = P bit (Proxy-Map-Reply): Set
        .... .0.. .... .... .... .... = S bit (LISP-SEC capable): Not set
        .... ..0. .... .... .... .... = I bit (xTR-ID present): Not set
        .... ...0 .... .... .... .... = R bit (Built for an RTR): Not set
        .... .... 0000 0000 0000 000. = Reserved bits: 0x0000
        .... .... .... .... .... ...1 = M bit (Want-Map-Notify): Set
        Record Count: 1
        Nonce: 0x0000000000000000
        Key ID: 0x0001
        Authentication Data Length: 20
        Authentication Data: c43f24c6e706f9a5bcd09287f416b53e430d58b3
        Mapping Record 1, EID Prefix: 153.16.31.80/28, TTL: 5, Action: No-Action, Authoritative
            Record TTL: 5
            Locator Count: 1
            EID Mask Length: 28
            000. .... .... .... = Action: No-Action (0)
            ...1 .... .... .... = Authoritative bit: Set
            .... .000 0000 0000 = Reserved: 0x000
            0000 .... .... .... = Reserved: 0x0
            .... 0000 0000 0000 = Mapping Version: 0
            EID Prefix AFI: IPv4 (1)
            EID Prefix: 153.16.31.80
            Locator Record 1, Local RLOC: 2607:f2c0:f00f:b001::face:b00c, Reachable, Priority/Weight: 1/100, Multicast
   Priority/Weight: 255/0 Priority: 1 Weight: 100 Multicast Priority: 255 Multicast Weight: 0 Flags: 0x0005 AFI: IPv6
   (2) Locator: 2607:f2c0:f00f:b001::face:b00c
 */
// clang-format off
constexpr std::array<uint8_t, 124> ip6Hdr{
    0x60, 0x00, 0x00, 0x00, 0x00, 0x54, 0x11, 0xff, 0x26, 0x07, 0xf2, 0xc0, 0xf0, 0x0f, 0xb0, 0x01, 0x00, 0x00,
    0x00, 0x00, 0xfa, 0xce, 0xb0, 0x0c, 0x20, 0x01, 0x04, 0xf8, 0x00, 0x03, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x61, 0x10, 0xf6, 0x10, 0xf6, 0x00, 0x54,
    // Locator/ID Separation Protocol
    0x8f, 0x5f, 0x38, 0x00, 0x01, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x14, 0xc4, 0x3f, 0x24, 0xc6, 0xe7, 0x06, 0xf9, 0xa5,
    0xbc, 0xd0, 0x92, 0x87, 0xf4, 0x16, 0xb5, 0x3e, 0x43, 0x0d, 0x58, 0xb3, 0x00, 0x00, 0x00, 0x05, 0x01, 0x1c,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x99, 0x10, 0x1f, 0x50, 0x01, 0x64, 0xff, 0x00, 0x00, 0x05, 0x00, 0x02,
    0x26, 0x07, 0xf2, 0xc0, 0xf0, 0x0f, 0xb0, 0x01, 0x00, 0x00, 0x00, 0x00, 0xfa, 0xce, 0xb0, 0x0c};
// clang-format on

TEST_F(NetDecoderCompleteTest, handle_ip6_test) {
    using Ip6AddrP = std::array<uint8_t, 16> *;
    auto &decoder = this->getDecoder();

    const uint8_t *data = ip6Hdr.data();
    size_t size = ip6Hdr.size();

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandleIp6(data, size);

    const struct ip6_hdr *tIp6H{(const struct ip6_hdr *)ip6Hdr.data()};

    ASSERT_TRUE(status);
    ASSERT_FALSE(packet.ip6Header == nullptr);
    ASSERT_TRUE(std::equal(
        std::begin(*(Ip6AddrP)&packet.ip6Header->ip6_src),
        std::end(*(Ip6AddrP)&packet.ip6Header->ip6_src),
        std::begin(*(Ip6AddrP)&tIp6H->ip6_src)));
    ASSERT_TRUE(std::equal(
        std::begin(*(Ip6AddrP)&packet.ip6Header->ip6_dst),
        std::end(*(Ip6AddrP)&packet.ip6Header->ip6_dst),
        std::begin(*(Ip6AddrP)&tIp6H->ip6_dst)));
    ASSERT_EQ(packet.ip6Header->ip6_ctlun.ip6_un2_vfc, tIp6H->ip6_ctlun.ip6_un2_vfc);
    ASSERT_EQ(packet.ip6Header->ip6_ctlun.ip6_un1.ip6_un1_flow, tIp6H->ip6_ctlun.ip6_un1.ip6_un1_flow);
    ASSERT_EQ(packet.ip6Header->ip6_ctlun.ip6_un1.ip6_un1_hlim, tIp6H->ip6_ctlun.ip6_un1.ip6_un1_hlim);
    ASSERT_EQ(packet.ip6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt, tIp6H->ip6_ctlun.ip6_un1.ip6_un1_nxt);
    ASSERT_EQ(packet.ip6Header->ip6_ctlun.ip6_un1.ip6_un1_plen, tIp6H->ip6_ctlun.ip6_un1.ip6_un1_plen);
    ASSERT_EQ(size, 84);
    ASSERT_EQ(decoder.GetHandledBytesL3(), 40);
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 40);
}

/*
    User Datagram Protocol, Src Port: 35024, Dst Port: 18569
        Source Port: 35024
        Destination Port: 18569
        Length: 28
        Checksum: 0xc643 [unverified]
        [Checksum Status: Unverified]
        [Stream index: 0]
            [Timestamps]
*/
constexpr std::array<uint8_t, 8> udpHdr{0x88, 0xd0, 0x48, 0x89, 0x00, 0x1c, 0xc6, 0x43};

TEST_F(NetDecoderCompleteTest, handle_udp_test) {
    auto &decoder = this->getDecoder();

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    const uint8_t *data = udpHdr.data();
    size_t size = udpHdr.size();

    auto [status, packet] = decoder.HandleUdp(data, size);

    ASSERT_TRUE(status);
    ASSERT_FALSE(packet.udpHeader == nullptr);
    ASSERT_EQ(htobe16(packet.udpHeader->check), 0xc643);
    ASSERT_EQ(htobe16(packet.udpHeader->dest), 18569);
    ASSERT_EQ(htobe16(packet.udpHeader->source), 35024);
    ASSERT_EQ(htobe16(packet.udpHeader->len), 28);
    ASSERT_EQ(decoder.GetHandledBytesL4(), 8);
    ASSERT_EQ(decoder.GetHandledBytesL7(), 20);
    ASSERT_EQ(decoder.GetHandledBytesTotal(),28);
    ASSERT_EQ(size, 0);
}

/*
    Transmission Control Protocol, Src Port: 443, Dst Port: 51250, Seq: 4189, Ack: 1, Len: 1396
        Source Port: 443
        Destination Port: 51250
        [Stream index: 1]
        [TCP Segment Len: 1396]
        Sequence number: 4189    (relative sequence number)
        Sequence number (raw): 3473894090
        [Next sequence number: 5585    (relative sequence number)]
        Acknowledgment number: 1    (relative ack number)
        Acknowledgment number (raw): 648736462
        1000 .... = Header Length: 32 bytes (8)
        Flags: 0x010 (ACK)
        Window size value: 2773
        [Calculated window size: 2773]
        [Window size scaling factor: -1 (unknown)]
        Checksum: 0x400b [unverified]
        [Checksum Status: Unverified]
        Urgent pointer: 0
        Options: (12 bytes), No-Operation (NOP), No-Operation (NOP), Timestamps
        [SEQ/ACK analysis]
        [Timestamps]
        TCP payload (1396 bytes)
 */
constexpr std::array<uint8_t, 32> tcpHdr{0x01, 0xbb, 0xc8, 0x32, 0xcf, 0x0f, 0x6a, 0xca, 0x26, 0xaa, 0xee,
                                         0xce, 0x80, 0x10, 0x0a, 0xd5, 0x40, 0x0b, 0x00, 0x00, 0x01, 0x01,
                                         0x08, 0x0a, 0xc8, 0xb7, 0xbd, 0x88, 0x03, 0x59, 0xed, 0xa8};
TEST_F(NetDecoderCompleteTest, handle_tcp_test) {
    auto &decoder = this->getDecoder();

    const uint8_t *data = tcpHdr.data();
    size_t size = tcpHdr.size();

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandleTcp(data, size);

    auto *tcp = packet.tcpHeader;

    ASSERT_TRUE(status);
    ASSERT_FALSE(tcp == nullptr);
    ASSERT_EQ(htobe16(tcp->source), 443);
    ASSERT_EQ(htobe16(tcp->dest), 51250);
    ASSERT_EQ(htonl(tcp->seq), 3473894090);
    ASSERT_EQ(htonl(tcp->ack_seq), 648736462);
    ASSERT_EQ(tcp->res1, 0);
    ASSERT_EQ(tcp->res2, 0);
    ASSERT_EQ(tcp->doff, 8);
    ASSERT_EQ(tcp->fin, 0);
    ASSERT_EQ(tcp->psh, 0);
    ASSERT_EQ(tcp->syn, 0);
    ASSERT_EQ(tcp->rst, 0);
    ASSERT_EQ(tcp->ack, 1);
    ASSERT_EQ(tcp->urg, 0);
    ASSERT_EQ(htobe16(tcp->window), 2773);
    ASSERT_EQ(htobe16(tcp->check), 0x400b);
    ASSERT_EQ(tcp->urg_ptr, 0);
    ASSERT_EQ(decoder.GetHandledBytesL4(), 32);
    ASSERT_EQ(decoder.GetHandledBytesTotal(),32);
    ASSERT_EQ(size, 0);
}

/*
    GPRS Tunneling Protocol
        Flags: 0x30
            001. .... = Version: GTP release 99 version (1)
            ...1 .... = Protocol type: GTP (1)
            .... 0... = Reserved: 0
            .... .0.. = Is Next Extension Header present?: No
            .... ..0. = Is Sequence Number present?: No
            .... ...0 = Is N-PDU number present?: No
        Message Type: T-PDU (0xff)
        Length: 81
        TEID: 0x80fce135 (2164056373)
 */
constexpr std::array<uint8_t, 98> gtpHdr{0x30, 0xff, 0x00, 0x51, 0x80, 0xfc, 0xe1, 0x35};

TEST_F(NetDecoderCompleteTest, handle_gtp_test) {
    auto &decoder = this->getDecoder();

    const uint8_t *data = gtpHdr.data();
    size_t size = gtpHdr.size();

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandleGtp(data, size);

    const GtpHeader *gtp = packet.gtpHeader;

    ASSERT_TRUE(status);
    ASSERT_FALSE(gtp == nullptr);
    ASSERT_EQ(gtp->common.flags, 0x30);
    ASSERT_EQ(htobe16(gtp->common.length), 81);
    ASSERT_EQ(gtp->common.msgtype, 0xff);
    ASSERT_EQ(htonl(gtp->in.gtpv1_hdr.teid), 2164056373);
    ASSERT_EQ(decoder.GetHandledBytesL7(), 98);
    ASSERT_EQ(decoder.GetHandledBytesTotal(),98);
    ASSERT_FALSE(Util::IsGtpv1HdrExt(packet));
    ASSERT_EQ(size, 94);
}

/*
    Stream Control Transmission Protocol, Src Port: 16384 (16384), Dst Port: 2944 (2944)
        Source port: 16384
        Destination port: 2944
        Verification tag: 0x00016f0a
        [Association index: 65535]
        Checksum: 0x6db01882 [unverified]
        [Checksum Status: Unverified]
        DATA chunk(ordered, complete segment, TSN: 671236933, SID: 0, SSN: 41149, PPID: 7, payload length: 75 bytes)
 */
constexpr std::array<uint8_t, 28> sctpHdr{0x40, 0x00, 0x0b, 0x80, 0x00, 0x01, 0x6f, 0x0a, 0x6d, 0xb0,
                                          0x18, 0x82, 0x00, 0x03, 0x00, 0x5b, 0x28, 0x02, 0x43, 0x45,
                                          0x00, 0x00, 0xa0, 0xbd, 0x00, 0x00, 0x00, 0x07};

TEST_F(NetDecoderCompleteTest, handle_sctp_test) {
    auto &decoder = this->getDecoder();

    const uint8_t *data = sctpHdr.data();
    size_t size = sctpHdr.size();

    decoder.ResetHandledBytes();
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 0);

    auto [status, packet] = decoder.HandleSctp(data, size);

    const SctpHdr *sctp = packet.sctpHeader;

    ASSERT_TRUE(status);
    ASSERT_FALSE(sctp == nullptr);
    ASSERT_EQ(htobe16(sctp->source), 16384);
    ASSERT_EQ(htobe16(sctp->dest), 2944);
    ASSERT_EQ(htonl(sctp->vtag), 0x00016f0a);
    ASSERT_EQ(htonl(sctp->checksum), 0x6db01882);
    ASSERT_EQ(size, 16);
    ASSERT_EQ(decoder.GetHandledBytesL4(), 12);
    ASSERT_EQ(decoder.GetHandledBytesL7(), 16);
    ASSERT_EQ(decoder.GetHandledBytesTotal(), 28);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
