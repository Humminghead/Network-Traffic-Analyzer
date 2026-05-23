#pragma once

#include <array>
#include <rte_acl.h>
#include <rte_ip.h>
#include <stdint.h>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace Nta::Network::Acl::Rules {

namespace Detail {
template <typename T>
concept U8Type = std::is_same_v<uint8_t, T>;

template <typename T>
concept U16Type = std::is_same_v<uint16_t, T>;

template <typename T>
concept U32Type = std::is_same_v<uint32_t, T>;

template <typename T>
concept U64Type = std::is_same_v<uint64_t, T>;

template <typename Tag, typename MaskType, typename ValPos, size_t MaskPos> struct RteAclField {
    using value_tag = Tag;
    using mask_type = MaskType;
    using value_pos = ValPos;

    static constexpr auto mask_pos = MaskPos;
};

struct RteIpV4 {
    constexpr static size_t field_count = 4;
    using value_type = uint32_t;
};

struct IpProto {
    constexpr static size_t field_count = 1;
    using value_type = uint8_t;
};

struct Port {
    constexpr static size_t field_count = 1;
    using value_type = uint16_t;
};

template <typename T>
concept IsRteIpV4 = std::is_same_v<RteIpV4, T>;

template <typename T>
concept IsIpProto = std::is_same_v<IpProto, T>;

template <typename T>
concept IsPort = std::is_same_v<Port, T>;

template <typename Tag> struct RteField;

template <IsRteIpV4 Tag> struct RteField<Tag> {
    template <typename Tuple, size_t... Ints> static auto Make(Tuple &&values, std::integer_sequence<size_t, Ints...>) {
        static_assert(
            sizeof...(Ints) == std::tuple_size_v<Tuple> && std::tuple_size_v<Tuple> == Tag::field_count &&
                sizeof...(Ints) == Tag::field_count,
            "Wrong IPv4 argument format!");

        constexpr auto makeIpv4 = [](uint16_t a, uint16_t b, uint16_t c, uint16_t d) { return RTE_IPV4(a, b, c, d); };

        return rte_acl_field_types{
            .u32{static_cast<Tag::value_type>(makeIpv4(std::get<Ints>(std::forward<Tuple>(values))...))}};
    }
};

template <IsIpProto Tag> struct RteField<Tag> {
    template <typename Tuple, size_t... Ints> static auto Make(Tuple &&values, std::integer_sequence<size_t, Ints...>) {
        static_assert(
            std::tuple_size_v<Tuple> == Tag::field_count && sizeof...(Ints) == Tag::field_count,
            "Wrong proto argument format!");
        return rte_acl_field_types{.u32{static_cast<Tag::value_type>(std::get<0>(std::forward<Tuple>(values)))}};
    }
};

template <IsPort Tag> struct RteField<Tag> {
    template <typename Tuple, size_t... Ints> static auto Make(Tuple &&values, std::integer_sequence<size_t, Ints...>) {
        static_assert(
            std::tuple_size_v<Tuple> == Tag::field_count && sizeof...(Ints) == Tag::field_count,
            "Wrong port proto argument format!");
        return rte_acl_field_types{.u16{static_cast<Tag::value_type>(std::get<0>(std::forward<Tuple>(values)))}};
    }
};

template <typename Tag> struct RteMask;

template <U8Type Tag> struct RteMask<Tag> {
    template <typename T> static auto Make(T &&tuple) {
        static_assert(std::tuple_size_v<T> == 1, "Wrong rte U8 mask argument format!");
        return rte_acl_field_types{.u8{static_cast<Tag>(std::get<0>(std::forward<T>(tuple)))}};
    }
};

template <U16Type Tag> struct RteMask<Tag> {
    template <typename T> static auto Make(T &&tuple) {
        static_assert(std::tuple_size_v<T> == 1, "Wrong rte U16 mask argument format!");
        return rte_acl_field_types{.u16{static_cast<Tag>(std::get<0>(std::forward<T>(tuple)))}};
    }
};

template <U32Type Tag> struct RteMask<Tag> {
    template <typename T> static auto Make(T &&tuple) {
        static_assert(std::tuple_size_v<T> == 1, "Wrong rte U32 mask argument format!");
        return rte_acl_field_types{.u32{static_cast<Tag>(std::get<0>(std::forward<T>(tuple)))}};
    }
};

template <U64Type Tag> struct RteMask<Tag> {
    template <typename T> static auto Make(T &&tuple) {
        static_assert(std::tuple_size_v<T> == 1, "Wrong rte U64 mask argument format!");
        return rte_acl_field_types{.u64{static_cast<Tag>(std::get<0>(std::forward<T>(tuple)))}};
    }
};

constexpr static auto vec_to_tuple = []<typename Array, size_t... Idx>(const Array &a, std::index_sequence<Idx...>) {
    return std::make_tuple(a.at(Idx)...);
};

template <typename... Field> constexpr static auto RteAclFieldArrayMake(const std::vector<uint16_t> &values) {

    //clang-format off
    return std::array<rte_acl_field, sizeof...(Field)>{rte_acl_field{
        .value = RteField<typename Field::value_tag>::Make(
            vec_to_tuple(values, typename Field::value_pos{}),
            std::make_index_sequence<Field::value_tag::field_count>()),
        .mask_range =
            RteMask<typename Field::mask_type>::Make(vec_to_tuple(values, std::index_sequence<Field::mask_pos>{}))}...};
    //clang-format on
}
} // namespace Detail

template <typename... Field> struct RteAclFieldArray {
    constexpr static size_t field_count = sizeof...(Field);

    constexpr static auto GetFields = [](const std::vector<uint16_t> &values) {
        return Detail::RteAclFieldArrayMake<Field...>(values);
    };
};
} // namespace Nta::Network::Acl::Rules