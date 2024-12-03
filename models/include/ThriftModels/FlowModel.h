#pragma once

#include <TModelField.h>
#include <cstdint>
#include <vector>

namespace Nta::Network {

struct FlowModel {
    static constexpr apache::thrift::serialize::TModelName name = "\nNetwork Decoder Result";
    apache::thrift::serialize::TModelField<bool> m_Success{"Success", {}};

    apache::thrift::serialize::TModelField<std::array<uint8_t,6>> m_EthSrcMac{"ETH src mac", {}};
    apache::thrift::serialize::TModelField<std::array<uint8_t,6>> m_EthDstMac{"ETH dst mac", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_Ethtype{"ETH type", {}};

    apache::thrift::serialize::TModelField<uint16_t> m_VlanTpid{"ETH 8021Q", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_VlanTci{"VLAN TCI", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_VlanDepth{"VLAN depth", {}};

    apache::thrift::serialize::TModelField<uint8_t> m_PPPoEVersion{"PPPoE version", {}};
    apache::thrift::serialize::TModelField<uint8_t> m_PPPoEType{"PPPoE type", {}};
    apache::thrift::serialize::TModelField<uint8_t> m_PPPoECode{"PPPoE code", {}};

    apache::thrift::serialize::TModelField<uint32_t> m_MplsHeader{"MPLS header", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_PPPoESessionId{"PPPoE session ID", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_PPPoEPayloadLen{"PPPoE payload length", {}};

    apache::thrift::serialize::TModelField<uint8_t> m_Icmp4Type{"ICMP type", {}};
    apache::thrift::serialize::TModelField<uint8_t> m_Icmp4Code{"ICMP code", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_Icmp4Crc{"ICMP checksum", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_Icmp4IdLe{"ICMP identifier (LE)", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_Icmp4SeqLe{"ICMP sequence number (LE)", {}};
    apache::thrift::serialize::TModelField<uint32_t> m_Icmp4Gateway{"ICMP gateway", {}};

    apache::thrift::serialize::TModelField<uint8_t> m_Icmp6Type{"ICMPv6 type", {}};
    apache::thrift::serialize::TModelField<uint8_t> m_Icmp6Code{"ICMPv6 code", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_Icmp6Crc{"ICMPv6 checksum", {}};

    apache::thrift::serialize::TModelField<uint32_t> m_SourceAddrIp4{"IP4 src addr", {}};
    apache::thrift::serialize::TModelField<uint32_t> m_DesinationAddrIp4{"IP4 dst addr", {}};
    apache::thrift::serialize::TModelField<uint8_t> m_Ip4NextProtocol{"IP4 next protocol", {}};
    apache::thrift::serialize::TModelField<bool> m_Ip4IsFragment{"IP4 fragment flag", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_Ip4FragmentId{"IP4 fragment identification", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_Ip4FragmentOffset{"IP4 fragment offset", {}};

    apache::thrift::serialize::TModelField<std::vector<char>> m_SourceAddrIp6{"IP6 src addr", {}};
    apache::thrift::serialize::TModelField<std::vector<char>> m_DesinationAddrIp6{"IP6 dst addr", {}};
    apache::thrift::serialize::TModelField<uint8_t> m_Ip6NextProtocol{"IP6 next protocol", {}};
    apache::thrift::serialize::TModelField<bool> m_Ip6IsFragment{"IP6 fragment flag", {}};

    apache::thrift::serialize::TModelField<uint16_t> m_TcpSrcPort{"TCP src port", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_TcpDstPort{"TCP dst port", {}};

    apache::thrift::serialize::TModelField<uint16_t> m_UdpSrcPort{"UDP src port", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_UdpDstPort{"UDP dst port", {}};

    apache::thrift::serialize::TModelField<uint16_t> m_SctpSrcPort{"SCTP src port", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_SctDstPort{"SCTP dst port", {}};

    apache::thrift::serialize::TModelField<std::vector<char>> m_Payload{"Payload", {}};
};

} // namespace Nta::Network
