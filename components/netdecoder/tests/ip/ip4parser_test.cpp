#include <gtest/gtest.h>
#include <gtest/internal/gtest-internal.h>
#include <ip/ip4parser.h>
#include <ip/ipparseresult.h>

#include "samples_ip4_packets.h"
using namespace protocols;

class Ip4ParserTest : public ::testing::Test
{
public:
    Ip4ParserTest() {}

protected:
    virtual void SetUp() {}
    virtual void TearDown() {}
    static void SetUpTestSuite() {}
    static void TearDownTestSuite() {}
};

TEST_F(Ip4ParserTest, parseIp4UdpFrame1Packet)
{
    IpParseResult res;
    uint8_t* data = (uint8_t*)ip4_udp_fr1.data();
    size_t len = ip4_udp_fr1.size();
    ASSERT_TRUE(parseIp4(data, len, res));
    ASSERT_EQ(data, res.hdr);
    ASSERT_EQ(20, res.hdr_len);
    ASSERT_EQ(1444, res.total_len);
    ASSERT_NE(nullptr, res.payload);
    ASSERT_EQ(1424, res.payload_len);
    ASSERT_TRUE(res.fragmented());
    ASSERT_EQ(0x00005103, res.fragment.id);
    ASSERT_EQ(1, res.fragment.more);
    ASSERT_EQ(0, res.fragment.offset);
    ASSERT_EQ(0, res.fragment.reserved);
    ASSERT_EQ(17 /*udp*/, res.payload_proto);
    ASSERT_EQ(20, res.payload - data);
}

TEST_F(Ip4ParserTest, parseIp4UdpFrame2Packet)
{
    IpParseResult res;
    uint8_t* data = (uint8_t*)ip4_udp_fr2.data();
    size_t len = ip4_udp_fr2.size();
    ASSERT_TRUE(parseIp4(data, len, res));
    ASSERT_EQ(data, res.hdr);
    ASSERT_EQ(52, res.total_len);
    ASSERT_EQ(20, res.hdr_len);
    ASSERT_NE(nullptr, res.payload);
    ASSERT_EQ(32, res.payload_len);
    ASSERT_TRUE(res.fragmented());
    ASSERT_EQ(0x00005103, res.fragment.id);
    ASSERT_EQ(0, res.fragment.more);
    ASSERT_EQ(1424, res.fragment.offset);
    ASSERT_EQ(0, res.fragment.reserved);
    ASSERT_EQ(17 /*udp*/, res.payload_proto);
    ASSERT_EQ(20, res.payload - data);
}

TEST_F(Ip4ParserTest, parseIp4UdpAssembledPacket)
{
    IpParseResult res;
    uint8_t* data = (uint8_t*)ip4_udp_assembled.data();
    size_t len = ip4_udp_assembled.size();
    ASSERT_TRUE(parseIp4(data, len, res));
    ASSERT_EQ(data, res.hdr);
    ASSERT_EQ(1476, res.total_len);
    ASSERT_EQ(20, res.hdr_len);
    ASSERT_NE(nullptr, res.payload);
    ASSERT_EQ(1456, res.payload_len);
    ASSERT_FALSE(res.fragmented());
    ASSERT_EQ(0x00005103, res.fragment.id);
    ASSERT_EQ(0, res.fragment.more);
    ASSERT_EQ(0, res.fragment.offset);
    ASSERT_EQ(0, res.fragment.reserved);
    ASSERT_EQ(17 /*udp*/, res.payload_proto);
    ASSERT_EQ(20, res.payload - data);
}

TEST_F(Ip4ParserTest, parseIp4NullData)
{
    IpParseResult res;
    uint8_t* data = nullptr;
    size_t len = std::numeric_limits<size_t>::max();
    ASSERT_FALSE(parseIp4(data, len, res));
    ASSERT_FALSE(res.good());
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
