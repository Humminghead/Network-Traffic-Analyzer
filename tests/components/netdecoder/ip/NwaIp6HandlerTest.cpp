#include <gtest/gtest.h>
#include <gtest/internal/gtest-internal.h>
#include <NetDecoder/ip/ip6parser.h>
#include <netinet/in.h>

#include "NwaIp6HandlerTestHeadersData.h"

#include "NetDecoder/ip/NwaIpHandler.h"

class Ip6ParserTest : public ::testing::Test {
  public:
    Ip6ParserTest() {}

  protected:
    virtual void SetUp() {}
    virtual void TearDown() {}
    static void SetUpTestSuite() {}
    static void TearDownTestSuite() {}
};

TEST_F(Ip6ParserTest, parseIp6IcmpPacket0) {
    using namespace Nta::Network;
    IpHandler<Ip6> handler;

    uint8_t *data = (uint8_t *)ip6_icmp_pkt.data();
    size_t len = ip6_icmp_pkt.size();

    auto [ok, res] = handler.Handle(data, len);

    ASSERT_TRUE(ok);
    ASSERT_EQ(40, res->GetHeaderLenVirt());
    ASSERT_NE(nullptr, res->GetPayloadDataVirt());
    ASSERT_EQ(68, res->GetPayloadLenghtVirt());
    ASSERT_FALSE(res->GetIsFragmentedFlagVirt());
    ASSERT_EQ(0, res->GetFragmentIdVirt());
    ASSERT_EQ(0, res->GetFragmentMoreFlagVirt());
    ASSERT_EQ(0, res->GetFragmentOffsetVirt());
    ASSERT_EQ(58 /*esp*/, res->GetPayloadProtocolVirt());
    ASSERT_EQ(48, res->GetPayloadDataVirt() - data);
}

TEST_F(Ip6ParserTest, parseIp6FirstFrPacket) {
    uint8_t *data = (uint8_t *)ip6_frag1_esp_pkt.data();
    size_t len = ip6_frag1_esp_pkt.size();

    using namespace Nta::Network;
    IpHandler<Ip6> handler;
    auto [ok, res] = handler.Handle(data, len);

    ASSERT_TRUE(ok);
    ASSERT_EQ(40, res->GetHeaderLenVirt());
    ASSERT_NE(nullptr, res->GetPayloadDataVirt());
    ASSERT_EQ(1400, res->GetPayloadLenghtVirt());
    ASSERT_TRUE(res->GetIsFragmentedFlagVirt());
    ASSERT_EQ(0xc23fa0d8, res->GetFragmentIdVirt());
    ASSERT_EQ(1, res->GetFragmentMoreFlagVirt());
    ASSERT_EQ(0, res->GetFragmentOffsetVirt());
    ASSERT_EQ(50, res->GetPayloadProtocolVirt());
    ASSERT_EQ(48, res->GetPayloadDataVirt() - data);
}

TEST_F(Ip6ParserTest, parseIp6LastFrPacket) {
    uint8_t *data = (uint8_t *)ip6_frag2_esp_pkt.data();
    size_t len = ip6_frag2_esp_pkt.size();

    using namespace Nta::Network;
    IpHandler<Ip6> handler;
    auto [ok, res] = handler.Handle(data, len);

    ASSERT_TRUE(ok);
    ASSERT_EQ(40, res->GetHeaderLenVirt());
    ASSERT_NE(nullptr, res->GetPayloadDataVirt());
    ASSERT_EQ(116, res->GetPayloadLenghtVirt());
    ASSERT_TRUE(res->GetIsFragmentedFlagVirt());
    ASSERT_EQ(0xc23fa0d8, res->GetFragmentIdVirt());
    ASSERT_EQ(0, res->GetFragmentMoreFlagVirt());
    ASSERT_EQ(1400, res->GetFragmentOffsetVirt());
    ASSERT_EQ(50, res->GetPayloadProtocolVirt());
    ASSERT_EQ(48, res->GetPayloadDataVirt() - data);
}

TEST_F(Ip6ParserTest, parseIp6NoExtHdrToredoPacket) {
    uint8_t *data = (uint8_t *)ip6_no_next_hdr_pkt.data();
    size_t len = ip6_no_next_hdr_pkt.size();

    using namespace Nta::Network;
    IpHandler<Ip6> handler;
    auto [ok, res] = handler.Handle(data, len);

    ASSERT_TRUE(ok);
    ASSERT_EQ(40, res->GetHeaderLenVirt());
    ASSERT_EQ(nullptr, res->GetPayloadDataVirt());
    ASSERT_EQ(0, res->GetPayloadLenghtVirt());
    ASSERT_FALSE(res->GetIsFragmentedFlagVirt());
    ASSERT_EQ(0, res->GetFragmentIdVirt());
    ASSERT_EQ(0, res->GetFragmentMoreFlagVirt());
    ASSERT_EQ(0, res->GetFragmentOffsetVirt());
    ASSERT_EQ(IPPROTO_NONE, res->GetPayloadProtocolVirt());
}

TEST_F(Ip6ParserTest, parseIp6HopAndNoExtHdrPacket) {
    uint8_t *data = (uint8_t *)ip6_hop_none_pkt.data();
    size_t len = ip6_hop_none_pkt.size();

    using namespace Nta::Network;
    IpHandler<Ip6> handler;
    auto [ok, res] = handler.Handle(data, len);

    ASSERT_TRUE(ok);
    ASSERT_EQ(40, res->GetHeaderLenVirt());
    ASSERT_EQ(nullptr, res->GetPayloadDataVirt());
    ASSERT_EQ(0, res->GetPayloadLenghtVirt());
    ASSERT_FALSE(res->GetIsFragmentedFlagVirt());
    ASSERT_EQ(0, res->GetFragmentIdVirt());
    ASSERT_EQ(0, res->GetFragmentMoreFlagVirt());
    ASSERT_EQ(0, res->GetFragmentOffsetVirt());
    ASSERT_EQ(IPPROTO_NONE, res->GetPayloadProtocolVirt());
}

TEST_F(Ip6ParserTest, parseIp6NullData) {
    uint8_t *data = nullptr;
    size_t len = std::numeric_limits<size_t>::max();

    using namespace Nta::Network;
    IpHandler<Ip6> handler;
    auto [ok, res] = handler.Handle(data, len);

    ASSERT_FALSE(ok);
    (void)res;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
