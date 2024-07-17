#pragma once

#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

namespace Nwa::Network {

struct IpHandlerResult {
    virtual ~IpHandlerResult() = default;

    virtual const size_t GetPayloadLenghtVirt() const = 0;
    virtual const uint8_t *GetPayloadDataVirt() const = 0;
    virtual const uint8_t GetPayloadProtocolVirt() const = 0;
    virtual const uint32_t GetFragmentIdVirt() const = 0;
    virtual const uint16_t GetFragmentOffsetVirt() const = 0;
    virtual const bool GetFragmentMoreFlagVirt() const = 0;
    virtual const size_t GetHeaderLenVirt() const = 0;
    virtual const size_t GetHeaderTotalLenVirt() const = 0;
    virtual const IpVersion GetIpProtocolVersionVirt() const = 0;
    virtual const bool GetIsFragmentedFlagVirt() const = 0;
};

struct IpHandlerResultDefaults : public IpHandlerResult {
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
};

struct Ip4HandlerResult : public IpVirtualResult<Ip4HandlerResult> {
    const uint8_t *GetPayloadData() const { return m_payloadDataPtr; }
    const size_t GetPayloadLenght() const { return m_totalLen < m_Ip4HeaderLen ? 0 : m_totalLen - m_Ip4HeaderLen; }
    const uint8_t GetPayloadProtocol() const { return m_payloadProtocol; }

    const uint32_t GetFragmentId() const { return ntohs(m_fragmentId); }
    const bool GetFragmentMoreFlag() const { return m_fragmentMoreFlag; }
    const bool GetIsFragmentedFlag() const { return (m_fragmentMoreFlag == true) || m_fragmentOffset > 0; }
    const uint16_t GetFragmentOffset() const { return m_fragmentOffset; }
    const uint8_t GetHeaderLen() const { return m_Ip4HeaderLen; };
    const IpVersion GetIpProtocolVersion() const { return m_ipProtoVersion; }

    const size_t GetHeaderTotalLen() const { return m_totalLen; };

    constexpr static uint16_t m_Ip4HeaderLen{20}; // 20 bytes ((header->ihl << 2))
    bool m_fragmentMoreFlag{false};
    uint8_t m_payloadProtocol{0};
    uint16_t m_fragmentId{0};
    uint16_t m_fragmentOffset{0};
    const uint8_t *m_payloadDataPtr{nullptr};
    size_t m_totalLen{0};
    IpVersion m_ipProtoVersion{IpVersion::Unknown};
};
} // namespace Nwa::Network
