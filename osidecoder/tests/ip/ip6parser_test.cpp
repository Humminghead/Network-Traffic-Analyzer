#include <netinet/in.h>
#include <gtest/gtest.h>
#include <gtest/internal/gtest-internal.h>
#include <ip/ip6parser.h>
#include <ip/ipparseresult.h>

#include "samples_ip6_packets.h"

// #ifdef DEBUG_SIGNAL
// #include "SegfaultDumper.h"
// #endif

/**
 * @brief Сохранение тестовых данных в PCAP
 * Нужно для анализа, когда неизвестно происхождение данных
 * 
 *   Примеры использования:
 *   writeDataToPcap(0, 1, "test_icmp6_", (uint8_t*)ip6_icmp_pkt.data(), ip6_icmp_pkt.size());
 *   writeDataToPcap(0, 1, "test_fr1_", (uint8_t*)ip6_frag1_esp_pkt.data(), ip6_frag1_esp_pkt.size());
 *   writeDataToPcap(0, 2, "test_fr2_", (uint8_t*)ip6_frag2_esp_pkt.data(), ip6_frag2_esp_pkt.size());
 *   writeDataToPcap(0, 2, "test_tor_", (uint8_t*)ip6_no_next_hdr_pkt.data(), ip6_no_next_hdr_pkt.size());
 *   writeDataToPcap(0, 2, "test_hop_", (uint8_t*)ip6_hop_none_pkt.data(), ip6_hop_none_pkt.size());
 *
 */
// void writeDataToPcap(uint32_t tm, uint32_t tm_ns, const std::string& name, uint8_t* data, size_t len) {
//     segfault_dumping::context_t ctx(static_cast<uint32_t>(0x00000065));
//     ctx.sniffer_id = 11;
//     ctx.thread_id = 22;
//     ctx.packet.tm_sec = tm;
//     ctx.packet.tm_nsec = tm_ns;
//     ctx.packet.data = data;
//     ctx.packet.size = len;
//     ctx.init("/tmp/", name);
//     ctx.dump(11);
// }

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

TEST_F(Ip6ParserTest, parseIp6IcmpPacket)
{
    protocols::IpParseResult res;
    uint8_t* data = (uint8_t*)ip6_icmp_pkt.data();
    size_t len = ip6_icmp_pkt.size();
    ASSERT_TRUE(parseIp6(data, len, res));
    ASSERT_EQ(data, res.hdr);
    ASSERT_EQ(48, res.hdr_len);
    ASSERT_NE(nullptr, res.payload);
    ASSERT_EQ(68, res.payload_len);
    ASSERT_FALSE(res.fragmented());
    ASSERT_EQ(0, res.fragment.id);
    ASSERT_EQ(0, res.fragment.more);
    ASSERT_EQ(0, res.fragment.offset);
    ASSERT_EQ(0, res.fragment.reserved);
    ASSERT_EQ(58 /*esp*/, res.payload_proto);
    ASSERT_EQ(48, res.payload - data);
}

TEST_F(Ip6ParserTest, parseIp6FirstFrPacket)
{
    protocols::IpParseResult res;
    uint8_t* data = (uint8_t*)ip6_frag1_esp_pkt.data();
    size_t len = ip6_frag1_esp_pkt.size();
    ASSERT_TRUE(parseIp6(data, len, res));
    ASSERT_EQ(data, res.hdr);
    ASSERT_EQ(48, res.hdr_len);
    ASSERT_NE(nullptr, res.payload);
    ASSERT_EQ(1400, res.payload_len);
    ASSERT_TRUE(res.fragmented());
    ASSERT_EQ(0xc23fa0d8, res.fragment.id);
    ASSERT_EQ(1, res.fragment.more);
    ASSERT_EQ(0, res.fragment.offset);
    ASSERT_EQ(0, res.fragment.reserved);
    ASSERT_EQ(50 /*esp*/, res.payload_proto);
    ASSERT_EQ(48, res.payload - data);
}

TEST_F(Ip6ParserTest, parseIp6LastFrPacket)
{
    protocols::IpParseResult res;
    uint8_t* data = (uint8_t*)ip6_frag2_esp_pkt.data();
    size_t len = ip6_frag2_esp_pkt.size();
    ASSERT_TRUE(parseIp6(data, len, res));
    ASSERT_EQ(data, res.hdr);
    ASSERT_EQ(48, res.hdr_len);
    ASSERT_NE(nullptr, res.payload);
    ASSERT_EQ(116, res.payload_len);
    ASSERT_TRUE(res.fragmented());
    ASSERT_EQ(0xc23fa0d8, res.fragment.id);
    ASSERT_EQ(0, res.fragment.more);
    ASSERT_EQ(1400, res.fragment.offset);
    ASSERT_EQ(0, res.fragment.reserved);
    ASSERT_EQ(50 /*esp*/, res.payload_proto);
    ASSERT_EQ(48, res.payload - data);
}
TEST_F(Ip6ParserTest, parseIp6NoExtHdrToredoPacket)
{
    protocols::IpParseResult res;
    uint8_t* data = (uint8_t*)ip6_no_next_hdr_pkt.data();
    size_t len = ip6_no_next_hdr_pkt.size();
    ASSERT_TRUE(parseIp6(data, len, res));
    ASSERT_EQ(data, res.hdr);
    ASSERT_EQ(40, res.hdr_len);
    ASSERT_EQ(nullptr, res.payload);
    ASSERT_EQ(0, res.payload_len);
    ASSERT_FALSE(res.fragmented());
    ASSERT_EQ(0, res.fragment.id);
    ASSERT_EQ(0, res.fragment.more);
    ASSERT_EQ(0, res.fragment.offset);
    ASSERT_EQ(0, res.fragment.reserved);
    ASSERT_EQ(IPPROTO_NONE, res.payload_proto);
}

TEST_F(Ip6ParserTest, parseIp6HopAndNoExtHdrPacket)
{
    protocols::IpParseResult res;
    uint8_t* data = (uint8_t*)ip6_hop_none_pkt.data();
    size_t len = ip6_hop_none_pkt.size();
    ASSERT_TRUE(parseIp6(data, len, res));
    ASSERT_EQ(data, res.hdr);
    ASSERT_EQ(48, res.hdr_len);
    ASSERT_EQ(nullptr, res.payload);
    ASSERT_EQ(0, res.payload_len);
    ASSERT_FALSE(res.fragmented());
    ASSERT_EQ(0, res.fragment.id);
    ASSERT_EQ(0, res.fragment.more);
    ASSERT_EQ(0, res.fragment.offset);
    ASSERT_EQ(0, res.fragment.reserved);
    ASSERT_EQ(IPPROTO_NONE, res.payload_proto);
}

TEST_F(Ip6ParserTest, parseIp6NullData)
{
    protocols::IpParseResult res;
    uint8_t* data = nullptr;
    size_t len = std::numeric_limits<size_t>::max();
    ASSERT_FALSE(parseIp6(data, len, res));
    ASSERT_FALSE(res.good());
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
