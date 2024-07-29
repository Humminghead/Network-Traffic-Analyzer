#pragma once

#include "ip/NwaIpHandler.h"
#include <netinet/ip6.h>
#include <memory>

namespace Nwa::Network {
class Ip6PayloadHandler : public HandlerBase<IpHandlerResult> {
  public:
    std::pair<bool, std::unique_ptr<IpHandlerResult>> Handle(const uint8_t *data, size_t len) const override {
        size_t parsed_bytes = 0;
        uint8_t next_hdr = 0;

        // Hop-by-Hop is restricted to appear immediately after an IPv6 header only
        // https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
        // IPv6 Extension Header Types
        for (uint32_t hl = 0; len >= sizeof(ip6_ext); parsed_bytes += hl, len -= hl) {
            const ip6_ext *ex_hdr = reinterpret_cast<const ip6_ext *>(data + parsed_bytes);

            hl = (ex_hdr->ip6e_len + 1) * 8;
            switch (next_hdr) {
                case IPPROTO_HOPOPTS:
                case IPPROTO_DSTOPTS:
                case IPPROTO_ROUTING:
                case IPPROTO_MH:
                case 139 /*Host Identity Protocol*/:
                    if (len < hl)
                        return {false, nullptr};
                    break;
                case IPPROTO_FRAGMENT: {                    
                    auto frag_hdr = data + parsed_bytes;
                    hl = sizeof(ip6_frag);
                    if (len < hl)
                        return {false, nullptr};
                    const ip6_frag *fr_hdr =
                        reinterpret_cast<const ip6_frag *>(data + parsed_bytes); //Указатель на заголовок фрагмента
                    auto fragment_id = ntohl(fr_hdr->ip6f_ident);
                    auto fragment_offset = ntohs(fr_hdr->ip6f_offlg & IP6F_OFF_MASK);
                    auto fragment_more = (fr_hdr->ip6f_offlg & IP6F_MORE_FRAG) ? 1 : 0;
                } break;
                case IPPROTO_AH: { /*51 Authentication Header*/
                    hl = (ex_hdr->ip6e_len + 2) * 4;
                    if (len < hl)
                        return {false, nullptr};
                    auto hdr_len = parsed_bytes + hl;
                    if (len == hl || next_hdr == IPPROTO_NONE) { /*AH may be applied alone*/
                        auto payload = data + hdr_len;
                        auto payload_len = hl;
                        return {true, nullptr};
                    }
                } break;
                    // RFC 8200 #4.5: Encapsulating Security Payload не относится к заголовкам расширения
                    // (ipv6-ext-headers) и должен обрабатываться как Upper-Layer header (payload); Здесь его место в
                    // default.
                    //            case IPPROTO_ESP: /*50 Encapsulating Security Payload*/
                    //                //Пока оставлю так, но надо esp разбирать. теоретически за ним еще могут быть
                    //                //заголовки. Размер esp зависит от метода шифрования
                    // case 140:  // Shim6 Protocol - неизвестно что это ???
                case IPPROTO_NONE: {
                    auto payload_proto = next_hdr;
                    auto hdr_len = parsed_bytes + hl;
                    auto payload = nullptr;
                    auto payload_len = 0;
                    return {true, nullptr};
                }
                default: // Upper-Layer protocol
                    return {true, nullptr};
            }
            next_hdr = ex_hdr->ip6e_nxt;
            auto payload_proto = next_hdr;
            auto hdr_len = parsed_bytes + hl;
            auto payload_len = len - hl;
            auto payload = payload_len ? data + hdr_len : nullptr;
        }
        return {true, nullptr};
    }
};

template <>
class IpHandler<Ip6> : public HandlerBase<IpHandlerResult> /*, public ChainHandlerBase<Ip6PayloadHandler>*/ {
  public:
    std::pair<bool, std::unique_ptr<IpHandlerResult>> Handle(const uint8_t *d, size_t sz) const override {
        if (!d || sz < sizeof(ip6_hdr))
            return {false, nullptr};

        if (const auto version = d[0] >> 4; version != static_cast<decltype(version)>(IpVersion::Ip6))
            return {false, nullptr};

        const ip6_hdr *header = reinterpret_cast<const struct ip6_hdr *>(d);

        auto f = Ip6PrivateFields{};

        f.m_SourceAddr = header->ip6_src;

        f.m_DestAddr = header->ip6_dst;

        f.m_totalLen = sz;

        f.m_payloadProtocol = header->ip6_nxt;

        if (f.m_payloadLen = ntohs(header->ip6_plen); f.m_payloadLen == 0)
            return {false, std::make_unique<Ip6HandlerResult>(std::move(f))};

        if (f.m_payloadLen > f.m_totalLen)
            return {false, nullptr};

        f.m_payloadDataPtr = f.m_payloadLen > 0 ? d + sizeof(struct ip6_hdr) : nullptr;

        return {true, std::make_unique<Ip6HandlerResult>(std::move(f))};
    }
};

} // namespace Nwa::Network

// const IpVersion GetHandlerType() const override { return IpVersion::Ip6; }
