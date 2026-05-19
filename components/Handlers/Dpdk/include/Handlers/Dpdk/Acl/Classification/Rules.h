#pragma once

#include "Handlers/Dpdk/Acl/Classification/Tuple5.h"

#include <array>

struct rte_acl_field_def;

namespace Nta::Network::Rules {

template <typename T>
concept IsRteAclFieldDef = std::is_same_v<rte_acl_field_def,T>;

// Helper type trait to inspect the array
template <typename T> struct ArrayTraits : std::false_type {
    static constexpr size_t size = 0;
};

template <typename D, size_t N>
struct ArrayTraits<std::array<D, N>> : std::true_type {
    using element_type = D;
    static constexpr size_t size = N;
};

template <typename T>
concept IsRteAclFieldDefArray = ArrayTraits<std::remove_cvref_t<T>>::value && IsRteAclFieldDef<typename ArrayTraits<std::remove_cvref_t<T>>::element_type>;

template <typename Tuple, IsRteAclFieldDefArray Defs> struct UnifiedTuple {
    using tuple_type = Tuple;
    using tuple_defs_type = Defs;
    constexpr inline static size_t tuple_defs_size = ArrayTraits<std::remove_cvref_t<Defs>>::size;
};

using Tuple5 = UnifiedTuple<FiveTupleIp4, decltype(FiveTupleIp4Defs)>;
} // namespace Nta::Network::Rules