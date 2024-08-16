#include "NetDecoder/ip/NwaIp4Handler.h"

namespace Nta::Network {

auto IpHandler<Ip4>::HandlePrivate(const uint8_t *d, const size_t& sz) const -> Result<HandlerResult>{
    if (!d || sz < sizeof(struct iphdr))
        return {false, nullptr};

    if (const uint8_t version = d[0] >> 4; version != 4)
        return {false, nullptr};

    const iphdr *header = reinterpret_cast<const struct iphdr *>(d);

    const auto totalLen = ntohs(header->tot_len);

    if (sz < totalLen)
        return {false, nullptr};

    auto r = Ip4PrivateFields();

    r.m_ipProtoVersion = IpVersion::Ip4;

    r.m_totalLen = totalLen;

    if (sizeof(struct iphdr) == sz)
        return {true, nullptr};

    r.m_payloadProtocol = header->protocol;

    r.m_payloadDataPtr = d + sizeof(struct iphdr);

    r.m_fragmentId = header->id; // ntohs in Ip4HandlerResult::GetFragmentId

    uint16_t tOffset = ntohs(header->frag_off);

    r.m_fragmentOffset = (tOffset & IP_OFFMASK) << 3;

    r.m_fragmentMoreFlag = (tOffset & IP_MF) ? true : false;

    return {true, std::make_unique<Ip4HandlerResult>(std::move(r))};
}


} // namespace Nta::Network
