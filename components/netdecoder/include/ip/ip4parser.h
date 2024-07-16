#pragma once

#include <memory>
#include <stdint.h>
#include <string.h>

// to cpp
#include <netinet/ip.h>
#include <utility>

namespace Nwa::Network {

enum class IpVersion : uint8_t { Ip4 = 4, Ip6 = 6, Unknown };

struct IpHandlerResult {
    ~IpHandlerResult() = default;

  // protected:
    virtual const size_t GetPayloadLenghtVirt() const = 0;
    virtual const uint8_t *GetPayloadDataVirt() const = 0;
    virtual const uint8_t GetPayloadProtocolVirt() const = 0;
    virtual const uint32_t GetFragmentIdVirt() const = 0;
    virtual const uint16_t GetFragmentOffsetVirt() const = 0;
    virtual const bool GetFragmentMoreFlagVirt() const = 0;
    virtual const size_t GetHeaderLenVirt() const = 0;
    virtual const size_t GetHeaderTotalLenVirt() const = 0;
    // virtual void SetPayloadDataVirt(const uint8_t*) = 0;
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

    // void SetPayloadData(const uint8_t*) {}
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
    // void SetPayloadDataVirt(const uint8_t *d) override { static_cast<Res *>(this)->SetPayloadData(d); };
};

struct Ip4HandlerResult : public IpVirtualResult<Ip4HandlerResult> {
    const uint8_t *GetPayloadData() const { return m_payloadDataPtr; }
    const size_t GetPayloadLenght() const { return m_totalLen < m_Ip4HeaderLen ? 0 : m_totalLen - m_Ip4HeaderLen; }
    const uint8_t GetPayloadProtocol() const  { return m_payloadProtocol; }

    const uint32_t GetFragmentId() const { return ntohs(m_fragmentId); }
    const bool GetFragmentMoreFlag() const { return m_fragmentMoreFlag; }
    const uint16_t GetFragmentOffset() const { return m_fragmentOffset; }
    const uint8_t GetHeaderLen() const { return m_Ip4HeaderLen; };
    // const IpVersion GetIpProtocolVersion() const /*override*/ { return m_ipProtoVersion; }

    const size_t GetHeaderTotalLen() const { return m_totalLen; };

    // protected:
    constexpr static uint16_t m_Ip4HeaderLen{20}; // 20 bytes ((header->ihl << 2))
    bool m_fragmentMoreFlag{false};
    uint8_t m_payloadProtocol{0};
    uint16_t m_fragmentId{0};
    uint16_t m_fragmentOffset{0};
    const uint8_t *m_payloadDataPtr{nullptr};
    size_t m_totalLen{0};
    IpVersion m_ipProtoVersion{IpVersion::Unknown};
};

class IpHandlerBase {
  public:
    virtual ~IpHandlerBase() = default;

    virtual std::pair<bool, std::unique_ptr<IpHandlerResult>> Handle(const uint8_t *, size_t) const = 0;
};

class Ip4Handler : public IpHandlerBase {
  public:
    std::pair<bool, std::unique_ptr<IpHandlerResult>> Handle(const uint8_t *d, size_t sz) const override {

        if (!d || sz < sizeof(struct iphdr))
            return {false, nullptr};

        if (const uint8_t version = d[0] >> 4; version != 4)
            return {false, nullptr};

        const iphdr *header = reinterpret_cast<const struct iphdr *>(d);

        const auto totalLen = ntohs(header->tot_len);

        if (sz < totalLen)
            return {false, nullptr};

        auto r = std::make_unique<Ip4HandlerResult>();

        r->m_ipProtoVersion = IpVersion::Ip4;

        r->m_totalLen = totalLen;

        if (Ip4HandlerResult::m_Ip4HeaderLen == sz)
            return {true, nullptr};

        r->m_payloadProtocol = header->protocol;

        r->m_payloadDataPtr = d + Ip4HandlerResult::m_Ip4HeaderLen;

        r->m_fragmentId = header->id; // ntohs in Ip4HandlerResult::GetFragmentId

        uint16_t tOffset = ntohs(header->frag_off);

        r->m_fragmentOffset = (tOffset & IP_OFFMASK) << 3;

        r->m_fragmentMoreFlag = (tOffset & IP_MF) ? true : false;

        return {true, std::move(r)};
    }
};

struct IpParseResult;
bool HandleIp4(const uint8_t *data, size_t len, IpParseResult &res);
} // namespace Nwa::Network
