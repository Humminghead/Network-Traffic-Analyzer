#pragma once

// 7.1.1. Rule definition
// https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html#overview

#include "Handlers/Dpdk/Acl/Classification/Rules.h"
#include <array>
#include <cstdint>

namespace Nta::Network::Acl::Rules {

/*!
 * \brief defines order of IPV4VLAN classifications
 * \details
 *  That effectively defines order of IPV4VLAN classifications:
 *  - Proto
 *  - Vlan (TAG and DOMAIN)
 *  - IpSrc SRC IP ADDRESS
 *  - IpDst DST IP ADDRESS
 *  - Ports (SRC and DST)
 */
enum class FiveTupleIp4InputIndex : uint8_t { Proto = 0, Vlan, IpSrc, IpDst, Ports, Num };

// Component positions in the rule text string
using Proto = Acl::Rules::Detail::RteAclField<Acl::Rules::Detail::IpProto, uint32_t, std::index_sequence<14>, 15>;
using IpSrc =
    Acl::Rules::Detail::RteAclField<Acl::Rules::Detail::RteIpV4, uint32_t, std::index_sequence<0, 1, 2, 3>, 4>;
using IpDst =
    Acl::Rules::Detail::RteAclField<Acl::Rules::Detail::RteIpV4, uint32_t, std::index_sequence<5, 6, 7, 8>, 9>;
using SrcPort = Acl::Rules::Detail::RteAclField<Acl::Rules::Detail::Port, uint16_t, std::index_sequence<10>, 11>;
using DstPort = Acl::Rules::Detail::RteAclField<Acl::Rules::Detail::Port, uint16_t, std::index_sequence<12>, 13>;

// Tuple-5
using Tuple5 = Acl::Rules::RteAclFieldArray<Proto, IpSrc, IpDst, SrcPort, DstPort>;

constexpr static std::array<rte_acl_field_def, 5> FiveTupleIp4Defs = {
    {/* first input field - always one byte long. */
     {
         .type = RTE_ACL_FIELD_TYPE_BITMASK,
         .size = sizeof(uint8_t),
         .field_index = 0,
         .input_index = static_cast<decltype(rte_acl_field_def::input_index)>(FiveTupleIp4InputIndex::Proto),
         .offset = 0 /*offsetof(struct FiveTupleIp4, proto)*/,
     },

     /* next input field (IPv4 source address) - 4 consecutive bytes. */
     {
         .type = RTE_ACL_FIELD_TYPE_MASK,
         .size = sizeof(uint32_t),
         .field_index = 1,
         .input_index = static_cast<decltype(rte_acl_field_def::input_index)>(FiveTupleIp4InputIndex::IpSrc),
         .offset = offsetof(struct rte_ipv4_hdr, src_addr) - offsetof(struct rte_ipv4_hdr, next_proto_id),
     },

     /* next input field (IPv4 destination address) - 4 consecutive bytes. */
     {
         .type = RTE_ACL_FIELD_TYPE_MASK,
         .size = sizeof(uint32_t),
         .field_index = 2,
         .input_index = static_cast<decltype(rte_acl_field_def::input_index)>(FiveTupleIp4InputIndex::IpDst),
         .offset = offsetof(struct rte_ipv4_hdr, dst_addr) - offsetof(struct rte_ipv4_hdr, next_proto_id),
     },

     /*
      * Next 2 fields (src & dst ports) form 4 consecutive bytes.
      * They share the same input index.
      */
     {
         .type = RTE_ACL_FIELD_TYPE_RANGE,
         .size = sizeof(uint16_t),
         .field_index = 3,
         .input_index = static_cast<decltype(rte_acl_field_def::input_index)>(FiveTupleIp4InputIndex::Ports),
         .offset = sizeof(struct rte_ipv4_hdr) - offsetof(struct rte_ipv4_hdr, next_proto_id),
     },

     {
         .type = RTE_ACL_FIELD_TYPE_RANGE,
         .size = sizeof(uint16_t),
         .field_index = 4,
         .input_index = static_cast<decltype(rte_acl_field_def::input_index)>(FiveTupleIp4InputIndex::Ports),
         .offset = sizeof(struct rte_ipv4_hdr) - offsetof(struct rte_ipv4_hdr, next_proto_id) + sizeof(uint16_t),
     }}};
} // namespace Nta::Network::Acl::Rules
