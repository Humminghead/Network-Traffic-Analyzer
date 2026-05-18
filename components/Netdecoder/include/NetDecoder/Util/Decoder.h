#pragma once

// #include "Decoder.h"

// LinkLayer GetLinkLayerFromNetProtoType(const uint16_t linkLayer);
// LinkLayer GetLinkLayerFromNetProtoType(const uint16_t linkLayer) {
//     switch (static_cast<uint16_t>(linkLayer)) {
//     case 0x4788: // MPLS
//         return LinkLayer::Mpls;
//     case 0x0081: // VLAN
//         return LinkLayer::Vlan;
//     case 0x6488: // PPPoE PPP Session Stage
//         return LinkLayer::PPPoEs;
//     case 0x6388: // PPPoE Discovery Stage
//         return LinkLayer::PPpoEd;
//         break;
//     // https://techhub.hpe.com/eginfolib/networking/docs/switches/5120si/cg/5998-8489_l2-lan_cg/content/436042676.htm
//     case 0x0008: // IpV4
//         return LinkLayer::Ip4;
//     case 0xDD86: // Ipv6
//         return LinkLayer::Ip6;
//     case 0x0000:
//         return LinkLayer::Eth;
//     default:
//         return LinkLayer::Unknown;
//     }
// }


// template <OsiLevel L, class OsiArray> auto &GetLayerProtoStore(OsiArray &levels) {
//     return std::get<static_cast<int>(L)>(levels);
// }

