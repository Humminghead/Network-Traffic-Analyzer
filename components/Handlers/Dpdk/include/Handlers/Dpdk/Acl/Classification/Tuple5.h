#pragma once

// 7.1.1. Rule definition
// https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html#overview

#include <array>
#include <cstdint>
#include <rte_acl.h>
namespace Nta::Network {

struct FiveTupleIp4 {
    uint8_t proto;
    uint32_t ipSrc;
    uint32_t ipDst;
    uint16_t portSrc;
    uint16_t portDst;
};

constexpr static std::array<rte_acl_field_def, 5> FiveTupleIp4Defs = {
    {/* first input field - always one byte long. */
     {
         .type = RTE_ACL_FIELD_TYPE_BITMASK,
         .size = sizeof(uint8_t),
         .field_index = 0,
         .input_index = 0,
         .offset = offsetof(struct FiveTupleIp4, proto),
     },

     /* next input field (IPv4 source address) - 4 consecutive bytes. */
     {
         .type = RTE_ACL_FIELD_TYPE_MASK,
         .size = sizeof(uint32_t),
         .field_index = 1,
         .input_index = 1,
         .offset = offsetof(struct FiveTupleIp4, ipSrc),
     },

     /* next input field (IPv4 destination address) - 4 consecutive bytes. */
     {
         .type = RTE_ACL_FIELD_TYPE_MASK,
         .size = sizeof(uint32_t),
         .field_index = 2,
         .input_index = 2,
         .offset = offsetof(struct FiveTupleIp4, ipDst),
     },

     /*
      * Next 2 fields (src & dst ports) form 4 consecutive bytes.
      * They share the same input index.
      */
     {
         .type = RTE_ACL_FIELD_TYPE_RANGE,
         .size = sizeof(uint16_t),
         .field_index = 3,
         .input_index = 3,
         .offset = offsetof(struct FiveTupleIp4, portSrc),
     },

     {
         .type = RTE_ACL_FIELD_TYPE_RANGE,
         .size = sizeof(uint16_t),
         .field_index = 4,
         .input_index = 3,
         .offset = offsetof(struct FiveTupleIp4, portDst),
     }}};
} // namespace Nta::Network
