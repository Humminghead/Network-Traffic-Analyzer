#include <netinet/in.h>
#include <gtest/gtest.h>
#include <gtest/internal/gtest-internal.h>
#include <ip/ip6parser.h>
#include <ip/ipparseresult.h>

#include "samples_ip6_packets.h"

#include "ip/NwaIpHandler.h"

class Ip6ParserTest : public ::testing::Test
{
public:
    Ip6ParserTest() {}

protected:
    virtual void SetUp() {}
    virtual void TearDown() {}
    static void SetUpTestSuite() {}
    static void TearDownTestSuite() {}
};

TEST_F(Ip6ParserTest, parseIp6IcmpPacket0)
{
    using namespace Nwa::Network;
    IpHandler<Ip6> handler;

    // handler.SetNextHandler(std::make_unique<Ip6PayloadHandler>());
    // handler.GetNextHandler()->get()->Handle(nullptr,0);

    uint8_t* data = (uint8_t*)ip6_icmp_pkt.data();
    size_t len = ip6_icmp_pkt.size();

    auto [ok,res] = handler.Handle(data,len);



    ASSERT_TRUE(ok);

    ASSERT_NE(nullptr, res->GetPayloadDataVirt());
    ASSERT_EQ(68, res->GetPayloadLenghtVirt());
    ASSERT_FALSE(res->GetIsFragmentedFlagVirt());
    ASSERT_EQ(0, res->GetFragmentIdVirt());
    ASSERT_EQ(0, res->GetFragmentMoreFlagVirt());
    ASSERT_EQ(0, res->GetFragmentOffsetVirt());
    ASSERT_EQ(58 /*esp*/, res->GetPayloadProtocolVirt());
}

// TEST_F(Ip6ParserTest, parseIp6IcmpPacket)
// {
//     Nwa::Network::IpParseResult res;
//     uint8_t* data = (uint8_t*)ip6_icmp_pkt.data();
//     size_t len = ip6_icmp_pkt.size();
//     ASSERT_TRUE(parseIp6(data, len, res));
//     ASSERT_EQ(data, res.hdr);
//     ASSERT_EQ(48, res.hdr_len);
//     ASSERT_NE(nullptr, res.payload);
//     ASSERT_EQ(68, res.payload_len);
//     ASSERT_FALSE(res.fragmented());
//     ASSERT_EQ(0, res.fragment.id);
//     ASSERT_EQ(0, res.fragment.more);
//     ASSERT_EQ(0, res.fragment.offset);
//     ASSERT_EQ(0, res.fragment.reserved);
//     ASSERT_EQ(58 /*esp*/, res.payload_proto);
//     ASSERT_EQ(48, res.payload - data);
// }

// TEST_F(Ip6ParserTest, parseIp6FirstFrPacket)
// {
//     Nwa::Network::IpParseResult res;
//     uint8_t* data = (uint8_t*)ip6_frag1_esp_pkt.data();
//     size_t len = ip6_frag1_esp_pkt.size();
//     ASSERT_TRUE(parseIp6(data, len, res));
//     ASSERT_EQ(data, res.hdr);
//     ASSERT_EQ(48, res.hdr_len);
//     ASSERT_NE(nullptr, res.payload);
//     ASSERT_EQ(1400, res.payload_len);
//     ASSERT_TRUE(res.fragmented());
//     ASSERT_EQ(0xc23fa0d8, res.fragment.id);
//     ASSERT_EQ(1, res.fragment.more);
//     ASSERT_EQ(0, res.fragment.offset);
//     ASSERT_EQ(0, res.fragment.reserved);
//     ASSERT_EQ(50 /*esp*/, res.payload_proto);
//     ASSERT_EQ(48, res.payload - data);
// }

// TEST_F(Ip6ParserTest, parseIp6LastFrPacket)
// {
//     Nwa::Network::IpParseResult res;
//     uint8_t* data = (uint8_t*)ip6_frag2_esp_pkt.data();
//     size_t len = ip6_frag2_esp_pkt.size();
//     ASSERT_TRUE(parseIp6(data, len, res));
//     ASSERT_EQ(data, res.hdr);
//     ASSERT_EQ(48, res.hdr_len);
//     ASSERT_NE(nullptr, res.payload);
//     ASSERT_EQ(116, res.payload_len);
//     ASSERT_TRUE(res.fragmented());
//     ASSERT_EQ(0xc23fa0d8, res.fragment.id);
//     ASSERT_EQ(0, res.fragment.more);
//     ASSERT_EQ(1400, res.fragment.offset);
//     ASSERT_EQ(0, res.fragment.reserved);
//     ASSERT_EQ(50 /*esp*/, res.payload_proto);
//     ASSERT_EQ(48, res.payload - data);
// }
// TEST_F(Ip6ParserTest, parseIp6NoExtHdrToredoPacket)
// {
//     Nwa::Network::IpParseResult res;
//     uint8_t* data = (uint8_t*)ip6_no_next_hdr_pkt.data();
//     size_t len = ip6_no_next_hdr_pkt.size();
//     ASSERT_TRUE(parseIp6(data, len, res));
//     ASSERT_EQ(data, res.hdr);
//     ASSERT_EQ(40, res.hdr_len);
//     ASSERT_EQ(nullptr, res.payload);
//     ASSERT_EQ(0, res.payload_len);
//     ASSERT_FALSE(res.fragmented());
//     ASSERT_EQ(0, res.fragment.id);
//     ASSERT_EQ(0, res.fragment.more);
//     ASSERT_EQ(0, res.fragment.offset);
//     ASSERT_EQ(0, res.fragment.reserved);
//     ASSERT_EQ(IPPROTO_NONE, res.payload_proto);
// }

// TEST_F(Ip6ParserTest, parseIp6HopAndNoExtHdrPacket)
// {
//     Nwa::Network::IpParseResult res;
//     uint8_t* data = (uint8_t*)ip6_hop_none_pkt.data();
//     size_t len = ip6_hop_none_pkt.size();
//     ASSERT_TRUE(parseIp6(data, len, res));
//     ASSERT_EQ(data, res.hdr);
//     ASSERT_EQ(48, res.hdr_len);
//     ASSERT_EQ(nullptr, res.payload);
//     ASSERT_EQ(0, res.payload_len);
//     ASSERT_FALSE(res.fragmented());
//     ASSERT_EQ(0, res.fragment.id);
//     ASSERT_EQ(0, res.fragment.more);
//     ASSERT_EQ(0, res.fragment.offset);
//     ASSERT_EQ(0, res.fragment.reserved);
//     ASSERT_EQ(IPPROTO_NONE, res.payload_proto);
// }

// TEST_F(Ip6ParserTest, parseIp6NullData)
// {
//     Nwa::Network::IpParseResult res;
//     uint8_t* data = nullptr;
//     size_t len = std::numeric_limits<size_t>::max();
//     ASSERT_FALSE(parseIp6(data, len, res));
//     ASSERT_FALSE(res.good());
// }

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
