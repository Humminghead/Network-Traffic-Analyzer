#pragma once

namespace Nwa::Network {

auto IpHandler<Ip4>::HandlePrivate(const uint8_t *d, size_t sz) const
    -> std::pair<bool, std::unique_ptr<IpHandlerResult>> {
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

} // namespace Nwa::Network
