#pragma once

#include <ip/NwaIpVersion.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <string.h>
#include <utility>

namespace Nta::Network {

struct IpFragment {
    virtual ~IpFragment() = default;

    virtual const uint32_t GetFragmentIdVirt() const = 0;
    virtual const uint16_t GetFragmentOffsetVirt() const = 0;
    virtual const bool GetFragmentMoreFlagVirt() const = 0;
    virtual const bool GetIsFragmentedFlagVirt() const = 0;
};

struct HandlerResultIp4 {
    virtual ~HandlerResultIp4() = default;

    virtual const uint32_t GetSrcAddressIp4Virt() const = 0;
    virtual const uint32_t GetDstAddressIp4Virt() const = 0;
};

struct HandlerResultIp6 {
    virtual ~HandlerResultIp6() = default;

    virtual const in6_addr GetSrcAddressIp6Virt() const = 0;
    virtual const in6_addr GetDstAddressIp6Virt() const = 0;
};

struct HandlerResult : HandlerResultIp4, HandlerResultIp6, IpFragment {
    virtual ~HandlerResult() = default;

    virtual const size_t GetPayloadLenghtVirt() const = 0;
    virtual const uint8_t *GetPayloadDataVirt() const = 0;
    virtual const uint8_t GetPayloadProtocolVirt() const = 0;
    virtual const size_t GetHeaderLenVirt() const = 0;
    virtual const size_t GetHeaderTotalLenVirt() const = 0;
    virtual const IpVersion GetIpProtocolVersionVirt() const = 0;
};

struct IpHandlerResultDefaults : public HandlerResult {
    const uint8_t *GetPayloadData(const uint8_t *) const { return nullptr; }
    const size_t GetPayloadLenght(const uint8_t *) const { return 0; }
    const uint8_t GetPayloadProtocol() const { return 0; };
    const uint32_t GetFragmentId() const { return 0; }
    const uint16_t GetFragmentOffset() const { return 0; }
    const size_t GetHeaderLen() const { return 0; };
    const size_t GetHeaderTotalLen() const { return 0; };
    const bool GetFragmentMoreFlag() const { return false; }
    const bool GetIsFragmentedFlag() const { return false; }
    const IpVersion GetIpProtocolVersion() const { return IpVersion::Unknown; }
    const uint32_t GetSrcAddressIp4() const { return 0; }
    const uint32_t GetDstAddressIp4() const { return 0; }
    const in6_addr GetSrcAddressIp6() const { return {}; }
    const in6_addr GetDstAddressIp6() const { return {}; }
};

template <class Res, class Super = IpHandlerResultDefaults> struct IpVirtualResult : public Super {
    const uint8_t *GetPayloadDataVirt() const override { return static_cast<const Res *>(this)->GetPayloadData(); };
    const size_t GetPayloadLenghtVirt() const override { return static_cast<const Res *>(this)->GetPayloadLenght(); }
    const uint8_t GetPayloadProtocolVirt() const override {
        return static_cast<const Res *>(this)->GetPayloadProtocol();
    }
    const size_t GetHeaderLenVirt() const override { return static_cast<const Res *>(this)->GetHeaderLen(); };
    const size_t GetHeaderTotalLenVirt() const override { return static_cast<const Res *>(this)->GetHeaderTotalLen(); };
    const uint32_t GetFragmentIdVirt() const override { return static_cast<const Res *>(this)->GetFragmentId(); }
    const uint16_t GetFragmentOffsetVirt() const override {
        return static_cast<const Res *>(this)->GetFragmentOffset();
    };
    const bool GetFragmentMoreFlagVirt() const override {
        return static_cast<const Res *>(this)->GetFragmentMoreFlag();
    }

    const bool GetIsFragmentedFlagVirt() const override {
        return static_cast<const Res *>(this)->GetIsFragmentedFlag();
    }

    const IpVersion GetIpProtocolVersionVirt() const override {
        return static_cast<const Res *>(this)->GetIpProtocolVersion();
    }
    const uint32_t GetSrcAddressIp4Virt() const override { return static_cast<const Res *>(this)->GetSrcAddressIp4(); };
    const uint32_t GetDstAddressIp4Virt() const override { return static_cast<const Res *>(this)->GetDstAddressIp4(); };
    const in6_addr GetSrcAddressIp6Virt() const override { return static_cast<const Res *>(this)->GetSrcAddressIp6(); };
    const in6_addr GetDstAddressIp6Virt() const override { return static_cast<const Res *>(this)->GetDstAddressIp6(); };
};

struct Ip4PrivateFields {
    bool m_fragmentMoreFlag{false};
    IpVersion m_ipProtoVersion{IpVersion::Ip4};
    uint8_t m_payloadProtocol{0};
    uint16_t m_fragmentId{0};
    uint16_t m_fragmentOffset{0};
    uint32_t m_SourceAddr{0};
    uint32_t m_DestAddr{0};
    size_t m_totalLen{0};
    const uint8_t *m_payloadDataPtr{nullptr};
};

struct Ip4HandlerResult : public IpVirtualResult<Ip4HandlerResult>, private Ip4PrivateFields {
    Ip4HandlerResult(Ip4PrivateFields &&fields) : Ip4PrivateFields{std::move(fields)} {}

    const uint8_t *GetPayloadData() const { return m_payloadDataPtr; }
    const size_t GetPayloadLenght() const { return m_totalLen < GetHeaderLen() ? 0 : m_totalLen - GetHeaderLen(); }
    const uint8_t GetPayloadProtocol() const { return m_payloadProtocol; }
    const uint32_t GetFragmentId() const { return ntohs(m_fragmentId); }
    const bool GetFragmentMoreFlag() const { return m_fragmentMoreFlag; }
    const bool GetIsFragmentedFlag() const { return (m_fragmentMoreFlag == true) || m_fragmentOffset > 0; }
    const uint16_t GetFragmentOffset() const { return m_fragmentOffset; }
    const uint8_t GetHeaderLen() const { return sizeof(struct iphdr); };
    const IpVersion GetIpProtocolVersion() const { return m_ipProtoVersion; }
    const size_t GetHeaderTotalLen() const { return m_totalLen; };
    const uint32_t GetSrcAddressIp4() const { return m_SourceAddr; }
    const uint32_t GetDstAddressIp4() const { return m_DestAddr; }
};

struct Ip6PrivateFields {
    size_t m_totalLen{0};
    size_t m_NextDataSize{0};
    uint32_t m_fragmentId{0};
    uint16_t m_fragmentOffset{0};
    uint8_t m_NextProtocol{0};
    IpVersion m_ipProtoVersion{IpVersion::Ip6};
    bool m_fragmentMoreFlag{false};
    const uint8_t *m_NextData{nullptr};
    in6_addr m_SourceAddr{};
    in6_addr m_DestAddr{};
};

struct Ip6HandlerResult : public IpVirtualResult<Ip6HandlerResult>, private Ip6PrivateFields {
    Ip6HandlerResult(Ip6PrivateFields &&fields) : Ip6PrivateFields{std::move(fields)} {}

    const uint8_t *GetPayloadData() const { return m_NextData; }
    const size_t GetPayloadLenght() const { return m_NextDataSize; }
    const uint8_t GetPayloadProtocol() const { return m_NextProtocol; }
    const uint8_t GetHeaderLen() const { return sizeof(struct ip6_hdr); };
    const IpVersion GetIpProtocolVersion() const { return m_ipProtoVersion; }
    const size_t GetHeaderTotalLen() const { return m_totalLen; };
    const in6_addr GetSrcAddressIp6() const { return m_SourceAddr; }
    const in6_addr GetDstAddressIp6() const { return m_DestAddr; }
    const bool GetIsFragmentedFlag() const { return m_fragmentMoreFlag == true || m_fragmentId != 0; }
    virtual const uint32_t GetFragmentId() const { return m_fragmentId; }
    virtual const uint16_t GetFragmentOffset() const { return m_fragmentOffset; }
    virtual const bool GetFragmentMoreFlag() const { return m_fragmentMoreFlag; }
};
} // namespace Nta::Network

// const uint32_t GetFragmentId() const { return ntohs(m_fragmentId); }
// const bool GetFragmentMoreFlag() const { return m_fragmentMoreFlag; }
// const bool GetIsFragmentedFlag() const { return (m_fragmentMoreFlag == true) || m_fragmentOffset > 0; }
// const uint16_t GetFragmentOffset() const { return m_fragmentOffset; }
// bool m_fragmentMoreFlag{false};
// uint16_t m_fragmentId{0};
// uint16_t m_fragmentOffset{0};
