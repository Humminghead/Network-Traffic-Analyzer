#pragma once

#include <cstdint>

namespace Nta::Network {
/*
 * The 32 bits are divided into several fields to mark packet types. Note that
 * each field is indexical.
 * - Bit 3:0 is for L2 types.
 * - Bit 7:4 is for L3 or outer L3 (for tunneling case) types.
 * - Bit 11:8 is for L4 or outer L4 (for tunneling case) types.
 * - Bit 15:12 is for tunnel types.
 * - Bit 19:16 is for inner L2 types.
 * - Bit 23:20 is for inner L3 types.
 * - Bit 27:24 is for inner L4 types.
 * - Bit 31:28 is reserved.
 */
enum class LinkLayerProto : uint32_t {
    Eth = 0x00000001,
    Vlan = 0x00000006,
    Mpls = 0x0000000a,
    PPpoEd = 0x00000008, // https://datatracker.ietf.org/doc/html/rfc2516
    PPPoEs = 0x00000008,
    Ip4 = 0x00000010,
    Ip6 = 0x00000040,
    Tcp = 0x00000100,
    Udp = 0x00000200,
    Icmp = 0x00000500,
    Sctp = 0x00000400,
    Gtp = 0x00007000, // gtpc
    // Gtpu = 0x00008000
    Unknown = 0xFFFF // Reserved (https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml)
};
} // namespace Nta::Network
