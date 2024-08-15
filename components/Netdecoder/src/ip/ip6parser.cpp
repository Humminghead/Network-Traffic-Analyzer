#include "NetDecoder/ip/ip6parser.h"

#include "NetDecoder/ip/ipparseresult.h"
#include "NetDecoder/packetbase.h"
#include <netinet/ip6.h>

namespace Nta::Network {
/*RFC8200 4.1.  Extension Header Order
  IPv6 header                           |
  Hop-by-Hop Options header             |_Per-Fragment Headers
  Destination Options header (note 1)   |
  Routing header                        |
  Fragment header
  Authentication header (note 2)                    |
  Encapsulating Security Payload header (note 2)    |_Extension (ESP is not considered
  Destination Options header (note 3)               |           an extension header)
  Upper-Layer header                                |-Upper-Layer Headers and ESP
  --------------------------------------------------------------------------
  Original:
  +-----------------+-----------------+--------+--------+-//-+--------+
  |  Per-Fragment   |Ext & Upper-Layer|  first | second |    |  last  |
  |    Headers      |    Headers      |fragment|fragment|....|fragment|
  +-----------------+-----------------+--------+--------+-//-+--------+
  Fragmented:
   +------------------+---------+-------------------+----------+
   |  Per-Fragment    |Fragment | Ext & Upper-Layer |  first   |
   |    Headers       | Header  |   Headers         | fragment |
   +------------------+---------+-------------------+----------+
   ....
   +------------------+--------+----------+
   |  Per-Fragment    |Fragment|   last   |
   |    Headers       | Header | fragment |
   +------------------+--------+----------+
  */
#define SHIFT_DATA(n)                                                                                                  \
    parsed_bytes += n;                                                                                                 \
    len -= n;
#define SHIFT_DATA_COM(n) parsed_bytes += n, len -= n

bool parseIp6(const uint8_t *data, size_t len, IpParseResult &res) {
    res.reset();

    if (!data || len < sizeof(ip6_hdr) || ((data[0] >> 4) != 6))
        return false;
    res.version = 6;

    const ip6_hdr *per_fr_hdrs = reinterpret_cast<const ip6_hdr *>(data);
    size_t payload_len = ntohs(per_fr_hdrs->ip6_ctlun.ip6_un1.ip6_un1_plen);
    size_t parsed_bytes = 0;
    SHIFT_DATA(sizeof(ip6_hdr));
    res.hdr_len = parsed_bytes;
    res.payload_len = len;
    res.payload = res.payload_len ? data + res.hdr_len : nullptr;

    if (len < payload_len)
        return false;
    if (len > payload_len)
        len = payload_len;
    res.hdr = data;
    res.total_len = payload_len + sizeof(ip6_hdr);
    uint8_t next_hdr = per_fr_hdrs->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    res.payload_proto = next_hdr;
    if (len < sizeof(ip6_ext)) {
        res.hdr_len = sizeof(ip6_hdr);
        res.payload_len = 0;
        res.payload = nullptr;
        return next_hdr == IPPROTO_NONE;
    }

    // Hop-by-Hop is restricted to appear immediately after an IPv6 header only
    // https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
    // IPv6 Extension Header Types
    for (uint32_t hl = 0; len >= sizeof(ip6_ext); SHIFT_DATA_COM(hl)) {
        const ip6_ext *ex_hdr = reinterpret_cast<const ip6_ext *>(data + parsed_bytes);

        hl = (ex_hdr->ip6e_len + 1) * 8;
        switch (next_hdr) {
            case IPPROTO_HOPOPTS:
            case IPPROTO_DSTOPTS:
            case IPPROTO_ROUTING:
            case IPPROTO_MH:
            case 139 /*Host Identity Protocol*/:
                if (len < hl)
                    return false;
                break;
            case IPPROTO_FRAGMENT: {
                res.frag_hdr = data + parsed_bytes;
                hl = sizeof(ip6_frag);
                if (len < hl)
                    return false;
                const ip6_frag *fr_hdr =
                    reinterpret_cast<const ip6_frag *>(data + parsed_bytes); // Указатель на заголовок фрагмента
                res.fragment.id = ntohl(fr_hdr->ip6f_ident);
                res.fragment.offset = ntohs(fr_hdr->ip6f_offlg & IP6F_OFF_MASK);
                res.fragment.more = (fr_hdr->ip6f_offlg & IP6F_MORE_FRAG) ? 1 : 0;
            } break;
            case IPPROTO_AH: { /*51 Authentication Header*/
                hl = (ex_hdr->ip6e_len + 2) * 4;
                if (len < hl)
                    return false;
                res.hdr_len = parsed_bytes + hl;
                if (len == hl || next_hdr == IPPROTO_NONE) { /*AH may be applied alone*/
                    res.payload = data + res.hdr_len;
                    res.payload_len = hl;
                    return true;
                }
            } break;
                // RFC 8200 #4.5: Encapsulating Security Payload не относится к заголовкам расширения (ipv6-ext-headers)
                // и должен обрабатываться как Upper-Layer header (payload); Здесь его место в default.
                //            case IPPROTO_ESP: /*50 Encapsulating Security Payload*/
                //                //Пока оставлю так, но надо esp разбирать. теоретически за ним еще могут быть
                //                //заголовки. Размер esp зависит от метода шифрования
                // case 140:  // Shim6 Protocol - неизвестно что это ???
            case IPPROTO_NONE:
                res.payload_proto = next_hdr;
                res.hdr_len = parsed_bytes + hl;
                res.payload = nullptr;
                res.payload_len = 0;
                return true;
            default: // Upper-Layer protocol
                return true;
        }
        next_hdr = ex_hdr->ip6e_nxt;
        res.payload_proto = next_hdr;
        res.hdr_len = parsed_bytes + hl;
        res.payload_len = len - hl;
        res.payload = res.payload_len ? data + res.hdr_len : nullptr;
    }

    return len == 0;
}

} // namespace Nta::Network
