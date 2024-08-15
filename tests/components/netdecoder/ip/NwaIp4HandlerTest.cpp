#include "NwaIp4HandlerTestHeadersData.h"
#include <gtest/gtest.h>
#include <gtest/internal/gtest-internal.h>
#include <NetDecoder/ip/NwaIpHandler.h>

using namespace Nta::Network;

class NetDecoderIp4HandlerTest : public ::testing::Test {
  public:
    NetDecoderIp4HandlerTest() {}

  protected:
    virtual void SetUp() {}
    virtual void TearDown() {}
    static void SetUpTestSuite() {}
    static void TearDownTestSuite() {}
};

TEST_F(NetDecoderIp4HandlerTest, Ip4UdpFrame1Packet) {
    using namespace Nta::Network;
    IpHandler<Ip4> ip4h;

    uint8_t *data = (uint8_t *)Ip4UdpFragment0.data();
    size_t len = Ip4UdpFragment0.size();

    auto [ok, result] = ip4h.Handle(data, len);

    ASSERT_TRUE(ok);

    ASSERT_EQ(Nta::Network::IpVersion::Ip4, result->GetIpProtocolVersionVirt());
    ASSERT_EQ(20, result->GetHeaderLenVirt());
    ASSERT_EQ(1444, result->GetHeaderTotalLenVirt());
    ASSERT_NE(nullptr, result->GetPayloadDataVirt());
    ASSERT_EQ(1424, result->GetPayloadLenghtVirt());
    ASSERT_TRUE(result->GetIsFragmentedFlagVirt());
    ASSERT_EQ(0x00005103, result->GetFragmentIdVirt());
    ASSERT_TRUE(result->GetFragmentMoreFlagVirt());
    ASSERT_EQ(0, result->GetFragmentOffsetVirt());
    ASSERT_EQ(17, result->GetPayloadProtocolVirt());
    ASSERT_EQ(20, result->GetPayloadDataVirt() - data);
}

TEST_F(NetDecoderIp4HandlerTest, Ip4UdpFrame2Packet) {
    using namespace Nta::Network;
    IpHandler<Ip4> ip4h;

    uint8_t *data = (uint8_t *)Ip4UdpFragment1.data();
    size_t len = Ip4UdpFragment1.size();

    auto [ok, res] = ip4h.Handle(data, len);

    ASSERT_TRUE(ok);
    ASSERT_EQ(52, res->GetHeaderTotalLenVirt());
    ASSERT_EQ(20, res->GetHeaderLenVirt());
    ASSERT_NE(nullptr, res->GetPayloadDataVirt());
    ASSERT_EQ(32, res->GetPayloadLenghtVirt());
    ASSERT_TRUE(res->GetIsFragmentedFlagVirt());
    ASSERT_EQ(0x00005103, res->GetFragmentIdVirt());
    ASSERT_EQ(0, res->GetFragmentMoreFlagVirt());
    ASSERT_EQ(1424, res->GetFragmentOffsetVirt());
    ASSERT_EQ(17, res->GetPayloadProtocolVirt());
    ASSERT_EQ(20, res->GetPayloadDataVirt() - data);
}

TEST_F(NetDecoderIp4HandlerTest, Ip4UdpAssembledPacket)
{
    using namespace Nta::Network;
    IpHandler<Ip4> ip4h;

    uint8_t* data = (uint8_t*)Ip4UdpAssembledIpHdr.data();
    size_t len = Ip4UdpAssembledIpHdr.size();

    auto [ok, res] = ip4h.Handle(data, len);

    ASSERT_TRUE(ok);
    ASSERT_EQ(1476, res->GetHeaderTotalLenVirt());
    ASSERT_EQ(20, res->GetHeaderLenVirt());
    ASSERT_NE(nullptr, res->GetPayloadDataVirt());
    ASSERT_EQ(1456, res->GetPayloadLenghtVirt());
    ASSERT_FALSE(res->GetIsFragmentedFlagVirt());
    ASSERT_EQ(0x00005103, res->GetFragmentIdVirt());
    ASSERT_EQ(0, res->GetFragmentMoreFlagVirt());
    ASSERT_EQ(0, res->GetFragmentOffsetVirt());
    ASSERT_EQ(17, res->GetPayloadProtocolVirt());
    ASSERT_EQ(20, res->GetPayloadDataVirt() - data);
}

TEST_F(NetDecoderIp4HandlerTest, Ip4NullData)
{
    using namespace Nta::Network;
    IpHandler<Ip4> ip4h;

    uint8_t* data = nullptr;
    size_t len = std::numeric_limits<size_t>::max();

    auto [ok, res] = ip4h.Handle(data, len);

    ASSERT_FALSE(ok);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
