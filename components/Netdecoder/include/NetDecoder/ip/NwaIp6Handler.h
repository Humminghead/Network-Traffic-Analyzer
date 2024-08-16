#pragma once

#include "NetDecoder/ip/NwaIpHandler.h"
#include <memory>
#include <netinet/ip6.h>

namespace Nta::Network {
static bool CheckData(const Ip6PrivateFields &f) noexcept {
    if (!f.m_NextData)
        return false;

    if (f.m_NextDataSize < sizeof(ip6_ext))
        return false;

    return true;
}

static void ShiftPayloadIpv6(Ip6PrivateFields &f, const size_t shift) noexcept {
    f.m_NextDataSize -= shift;
    f.m_NextDataSize == 0 ? f.m_NextData = nullptr : f.m_NextData += shift;
}

static Result<HandlerResult> HandleExtensionsIp6(Ip6PrivateFields &&f) {
    if (IPPROTO_NONE == f.m_NextProtocol)
        return {true, std::make_unique<Ip6HandlerResult>(std::move(f))};

    if (bool isValid = CheckData(f); !isValid)
        return {false, std::make_unique<Ip6HandlerResult>(std::move(f))};

    // https://datatracker.ietf.org/doc/html/rfc2460#page-7
    if (const auto &next = f.m_NextProtocol; IPPROTO_HOPOPTS == next) {
        const auto *ext = reinterpret_cast<const ip6_ext *>(f.m_NextData);
        const auto tLen = ext->ip6e_len == 0 ? 8 : (ext->ip6e_len * 8) + 8;
        f.m_NextProtocol = ext->ip6e_nxt;
        ShiftPayloadIpv6(f, tLen);
        return HandleExtensionsIp6(std::move(f));
    } else if (IPPROTO_ROUTING == next) {
        const auto *ext = reinterpret_cast<const ip6_rthdr *>(f.m_NextData);

        f.m_NextProtocol = ext->ip6r_nxt;
        auto tLen = (ext->ip6r_len * 8) // length in units of 8 octets
                    + sizeof(ip6_rthdr) // first 4 fields
                    + 4;                // first segment, flags, reserved
        ShiftPayloadIpv6(f, tLen);

        return HandleExtensionsIp6(std::move(f));
    } else if (IPPROTO_FRAGMENT == next) {
        if (f.m_NextDataSize < sizeof(ip6_frag))
            return {false, std::make_unique<Ip6HandlerResult>(std::move(f))};

        const auto *header = reinterpret_cast<const ip6_frag *>(f.m_NextData);

        f.m_NextProtocol = header->ip6f_nxt;

        ShiftPayloadIpv6(f, sizeof(ip6_frag));

        f.m_fragmentId = ntohl(header->ip6f_ident);
        f.m_fragmentOffset = ntohs(header->ip6f_offlg & IP6F_OFF_MASK);
        f.m_fragmentMoreFlag = (header->ip6f_offlg & IP6F_MORE_FRAG) ? true : false;

        return HandleExtensionsIp6(std::move(f));
    } else if (IPPROTO_DSTOPTS == next) {
        const auto *ext = reinterpret_cast<const ip6_dest *>(f.m_NextData);

        const auto tLen = ext->ip6d_len == 0 ? 8 : (ext->ip6d_len * 8) + 8;
        f.m_NextProtocol = ext->ip6d_nxt;
        ShiftPayloadIpv6(f, tLen);

        return HandleExtensionsIp6(std::move(f));
    }
    ///\todo Maybe it doesnt necessary to do
    /// Authentication
    /// Encapsulating Security Payload

    return {true, std::make_unique<Ip6HandlerResult>(std::move(f))};
}

template <> class IpHandler<Ip6> : public HandlerBase<HandlerResult> {
  public:
    Result<HandlerResult> Handle(const uint8_t *d, const size_t& sz) const override {
        if (d == nullptr)
            return {false, nullptr};

        if (sz < sizeof(ip6_hdr))
            return {false, nullptr};

        if (const auto version = d[0] >> 4; version != static_cast<decltype(version)>(IpVersion::Ip6))
            return {false, nullptr};

        const ip6_hdr *header = reinterpret_cast<const struct ip6_hdr *>(d);

        auto f = Ip6PrivateFields{};

        f.m_SourceAddr = header->ip6_src;

        f.m_DestAddr = header->ip6_dst;

        f.m_totalLen = sz;

        f.m_NextProtocol = header->ip6_nxt;

        f.m_NextDataSize = ntohs(header->ip6_plen);

        if (f.m_NextDataSize > f.m_totalLen)
            return {false, std::make_unique<Ip6HandlerResult>(std::move(f))};

        f.m_NextData = f.m_NextDataSize > 0 ? d + sizeof(struct ip6_hdr) : nullptr;

        return HandleExtensionsIp6(std::move(f));
    }
};

} // namespace Nta::Network

// const IpVersion GetHandlerType() const override { return IpVersion::Ip6; }
