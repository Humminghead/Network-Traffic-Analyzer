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
    apache::thrift::serialize::TModelField<uint8_t> m_IpProtocol{"Protocol", {}};
    apache::thrift::serialize::TModelField<uint32_t> m_SourceAddrIp4{"Source ip4-addr", {}};
    apache::thrift::serialize::TModelField<uint32_t> m_DesinationAddrIp4{"Destination ip4-addr", {}};
    apache::thrift::serialize::TModelField<std::vector<char>> m_SourceAddrIp6{"Source ip6-addr", {}};
    apache::thrift::serialize::TModelField<std::vector<char>> m_DesinationAddrIp6{"Destination ip6-addr", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_SrcPort{"Source port", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_DstPort{"Destination port", {}};
    apache::thrift::serialize::TModelField<std::vector<char>> m_Payload{"Payload", {}};
};

} // namespace Nta::Network
