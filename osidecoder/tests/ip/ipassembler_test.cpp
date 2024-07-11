#include <gtest/gtest.h>
#include <gtest/internal/gtest-internal.h>

#include <ip/ipparseresult.h>
#include <ip/asm_ip/assembler_ip.h>
#include <ip/asm_ip/assembler_ip_config.h>
#include <ip/ip4parser.h>
#include <packetbase.h>

#include "samples_ip4_packets.h"

class IpAssemblerTest : public ::testing::Test
{
public:
    IpAssemblerTest() {}

protected:
    virtual void SetUp() {}
    virtual void TearDown() {}
    static void SetUpTestSuite() {}
    static void TearDownTestSuite() {}
};

TEST_F(IpAssemblerTest, test)
{
    protocols::IpParseResult res;
    preprocessing::ip::AsmIpConfiguration conf;
    conf.enabled = true;
    protocols::IpAssemblerStat stat;
    preprocessing::ip::assembler asm_ip(conf, stat);
    protocols::PacketBase packet;
    packet.tm = 0;
    packet.tm_ns = 1;
    packet.iph = (iphdr*)(ip4_udp_fr2.data());
    packet.l3_size = ip4_udp_fr2.length();

    ASSERT_TRUE(protocols::parseIp4((uint8_t*)(packet.iph), packet.l3_size, res));
    ASSERT_TRUE(res.good());
    ASSERT_TRUE(res.fragmented());
    ASSERT_EQ(res.hdr_len, 20);
    ASSERT_EQ(res.payload_len, 32);
    ASSERT_EQ(res.total_len, 52);
    ASSERT_EQ(res.fragment.id, 20739);
    ASSERT_EQ(res.fragment.offset, 1424);
    ASSERT_EQ(res.fragment.more, 0);
    size_t sz = res.payload_len;
    ASSERT_FALSE(asm_ip.addFragment(packet, res.payload, sz));

    packet.reset();
    packet.tm = 0;
    packet.tm_ns = 2;
    packet.iph = (iphdr*)(ip4_udp_fr1.data());
    packet.l3_size = ip4_udp_fr1.length();
    ASSERT_TRUE(protocols::parseIp4((uint8_t*)(packet.iph), packet.l3_size, res));
    ASSERT_TRUE(res.good());
    ASSERT_TRUE(res.fragmented());
    ASSERT_EQ(res.hdr_len, 20);
    ASSERT_EQ(res.payload_len, 1424);
    ASSERT_EQ(res.total_len, 1444);
    ASSERT_EQ(res.fragment.id, 20739);
    ASSERT_EQ(res.fragment.offset, 0);
    ASSERT_EQ(res.fragment.more, 1);
    sz = res.payload_len;
    ASSERT_TRUE(asm_ip.addFragment(packet, res.payload, sz));
    ASSERT_TRUE(res.fragmented());
    ASSERT_EQ(sz, 1456);
    ASSERT_EQ(res.fragment.more, 1);
    ASSERT_EQ(res.fragment.offset, 0);

    std::string apkt((char*)res.payload, sz);
    std::string upkt(ip4_udp_assembled.data() + sizeof(iphdr), ip4_udp_assembled.length() - sizeof(iphdr));
    ASSERT_EQ(apkt, upkt);
}

TEST_F(IpAssemblerTest, test_disabled)
{
    protocols::IpParseResult res;
    preprocessing::ip::AsmIpConfiguration conf;
//    conf.enabled = false; //(default)
    protocols::IpAssemblerStat stat;
    preprocessing::ip::assembler asm_ip(conf, stat);
    protocols::PacketBase packet;
    packet.tm = 0;
    packet.tm_ns = 1;
    packet.iph = (iphdr*)(ip4_udp_fr2.data());
    packet.l3_size = ip4_udp_fr2.length();

    ASSERT_TRUE(protocols::parseIp4((uint8_t*)(packet.iph), packet.l3_size, res));
    ASSERT_TRUE(res.good());
    ASSERT_TRUE(res.fragmented());
    size_t sz = res.payload_len;

    ASSERT_FALSE(asm_ip.addFragment(packet, res.payload, sz));

    packet.reset();
    packet.tm = 0;
    packet.tm_ns = 2;
    packet.iph = (iphdr*)(ip4_udp_fr1.data());
    packet.l3_size = ip4_udp_fr1.length();
    ASSERT_TRUE(protocols::parseIp4((uint8_t*)ip4_udp_fr1.data(), packet.l3_size, res));
    ASSERT_TRUE(res.good());
    ASSERT_TRUE(res.fragmented());
    sz = res.payload_len;
    ASSERT_FALSE(asm_ip.addFragment(packet, res.payload, sz));
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
