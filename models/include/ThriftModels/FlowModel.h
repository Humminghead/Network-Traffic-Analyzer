#pragma one

#include <TModelField.h>
#include <cstdint>
#include <vector>

namespace Nta::Network {

struct FlowModel {
    static constexpr apache::thrift::serialize::TModelName name = "FlowModel";
    apache::thrift::serialize::TModelField<uint8_t> m_Protocol{"Protocol", {}};
    apache::thrift::serialize::TModelField<uint32_t> m_SourceAddrIp4{"Source ip4-addr", {}};
    apache::thrift::serialize::TModelField<uint32_t> m_DesinationAddrIp4{"Destination ip4-addr", {}};
    apache::thrift::serialize::TModelField<std::vector<char>> m_SourceAddrIp6{"Source ip6-addr", {}};
    apache::thrift::serialize::TModelField<std::vector<char>> m_DesinationAddrIp6{"Destination ip6-addr", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_SrcPort{"Source port", {}};
    apache::thrift::serialize::TModelField<uint16_t> m_DstPort{"Destination port", {}};
    apache::thrift::serialize::TModelField<std::vector<char>> m_Payload{"Payload", {}};
};

} // namespace Nta::Network
