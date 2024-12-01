#pragma once

#include <TModelField.h>
#include <cstdint>
#include <vector>

namespace Nta::Network {

struct FlowModel {    
    static constexpr apache::thrift::serialize::TModelName name = "FlowModel";    
    apache::thrift::serialize::TModelField<bool> m_Success{"Success", {}};
    apache::thrift::serialize::TModelField<std::array<uint8_t,6>> m_EthSrcMac{"Eth source mac", {}};
    apache::thrift::serialize::TModelField<std::array<uint8_t,6>> m_EthDstMac{"Eth dest mac", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_Ethtype{"Eth type", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_VlanTpid{"Eth 8021Q", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_VlanTci{"Vlan TCI", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_VlanDepth{"Vlan depth", {}};
    apache::thrift::serialize::TModelField<uint8_t> m_PPPoEVersion{"PPPoE version", {}};
    apache::thrift::serialize::TModelField<uint8_t> m_PPPoEType{"PPPoE type", {}};
    apache::thrift::serialize::TModelField<uint8_t> m_PPPoECode{"PPPoE code", {}};
    apache::thrift::serialize::TModelField<uint32_t> m_MplsHeader{"Mpls header", {}};
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
    apache::thrift::serialize::TModelField<uint8_t> m_IpProtocol{"IP protocol", {}};
    apache::thrift::serialize::TModelField<uint32_t> m_SourceAddrIp4{"IP4 source addr", {}};
    apache::thrift::serialize::TModelField<uint32_t> m_DesinationAddrIp4{"IP4 destination addr", {}};
    apache::thrift::serialize::TModelField<std::vector<char>> m_SourceAddrIp6{"IP6 source addr", {}};
    apache::thrift::serialize::TModelField<std::vector<char>> m_DesinationAddrIp6{"IP6 destination addr", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_TcpSrcPort{"TCP source port", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_TcpDstPort{"TCP destination port", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_UdpSrcPort{"UDP Source port", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_UdpDstPort{"UDP destination port", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_SctpSrcPort{"SCTP Source port", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_SctDstPort{"SCTP destination port", {}};
    apache::thrift::serialize::TModelField<std::vector<char>> m_Payload{"Payload", {}};
};

} // namespace Nta::Network
