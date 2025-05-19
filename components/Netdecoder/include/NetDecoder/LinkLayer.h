#pragma once

namespace Nta::Network {
enum class LinkLayer : unsigned short {
    Eth = 0x0,
    Vlan = 0x0081,
    Mpls = 0x4788,
    PPpoEd = 0x6488, // https://datatracker.ietf.org/doc/html/rfc2516
    PPPoEs = 0x6388,
    Ip4 = 0x0008,
    Ip6 = 0xDD86,
    Tcp = 0x06,
    Udp = 0x11,
    Sctp = 0x32,
    Gtp,
    PwEthCw,
    Unknown = 0xFFFF //Reserved (https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml)
};
}
