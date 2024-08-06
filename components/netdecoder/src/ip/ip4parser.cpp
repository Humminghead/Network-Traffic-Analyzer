#include <netinet/ip.h>

#include "ip/ip4parser.h"
#include "ip/ipparseresult.h"

namespace Nwa::Network
{
bool HandleIp4(const uint8_t* data, size_t len, IpParseResult& res)
{
    res.reset();
    if (!data || len < sizeof(iphdr) || ((data[0] >> 4) != 4)) return false;
    res.version = 4;
    const iphdr* hdr = reinterpret_cast<const iphdr*>(data);
    uint16_t tot_len = ntohs(hdr->tot_len);
    if (len < tot_len) return false;
    res.hdr = data;
    res.hdr_len = hdr->ihl << 2;
    res.total_len = tot_len;
    if (len == res.hdr_len) return true;
    res.payload = data + res.hdr_len;
    res.payload_proto = hdr->protocol;
    res.payload_len = tot_len - res.hdr_len;
    res.fragment.id = ntohs(hdr->id);
    uint16_t offset = ntohs(hdr->frag_off);
    res.fragment.offset = (offset & IP_OFFMASK) << 3;
    res.fragment.more = (offset & IP_MF) ? 1 : 0;
    return true;
}
}  // namespace protocols
