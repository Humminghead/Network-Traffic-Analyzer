#pragma once

#include <Handlers/Common/JsonObjectHandler.h>
#include <Util/Json.h>
#include <Util/String.h>
#include <nlohmann/json.hpp>

namespace Nta::Json::Objects {

struct DpdkEalCmdLineArg{
    std::string key;
    std::string value;
};

[[maybe_unused]] static void to_json(nlohmann::json &j, const DpdkEalCmdLineArg &p) {
    j={{p.key, p.value}};
}

[[maybe_unused]] static void from_json(const nlohmann::json &j, DpdkEalCmdLineArg &p) {
    p.key = j.items().begin().key();
    p.value = Util::String::RemoveSpaces(j.items().begin().value());
}

struct DpdkEalCmdLine{
    std::vector<DpdkEalCmdLineArg> args;
};

[[maybe_unused]] static void to_json(nlohmann::json &j, const DpdkEalCmdLine &p) {
}

[[maybe_unused]] static void from_json(const nlohmann::json &j, DpdkEalCmdLine &p) {
    j.get_to(p.args);
}

struct DpdkObject : HandlerObject {
    uint32_t m_CoreMask{0};
    uint32_t m_BufPoolSizePerDevice{0};
    uint32_t m_MainLcore{0};
    uint32_t m_NumOfMemoryChannels{0};
    DpdkEalCmdLine m_EalCmdLine{};
    bool m_PromiscuousMode{false};

    [[maybe_unused]] static auto ToJson(const DpdkObject &p) -> nlohmann::json {
        // clang-format off
        return {
             {"eal_core_mask", p.m_CoreMask},
             {"eal_mbuf_size", p.m_BufPoolSizePerDevice},
             {"eal_main_lcore", p.m_MainLcore},
             {"eal_memory_channels", p.m_NumOfMemoryChannels},
             {"eal_cmd_line_arguments", p.m_EalCmdLine},
             {"promiscuous", p.m_PromiscuousMode}
        };
        // clang-format on
    }

    [[maybe_unused]] static void FromJson(const nlohmann::json &j, DpdkObject &p) {
        ///\warning execeptions if field name is mising
        j.at("eal_core_mask").get_to(p.m_CoreMask);
        j.at("eal_mbuf_size").get_to(p.m_BufPoolSizePerDevice);
        j.at("eal_memory_channels").get_to(p.m_NumOfMemoryChannels);
        Util::Json::GetTo(j, "eal_cmd_line_arguments", p.m_EalCmdLine);
        Util::Json::GetTo(j, "eal_main_lcore", p.m_MainLcore);
        Util::Json::GetTo(j, "promiscuous", p.m_PromiscuousMode);
    }
};

[[maybe_unused]] static void to_json(nlohmann::json &j, const DpdkObject &p) {
    ///\warning may corrupt app memory (uncheked)
    // clang-format off
    std::apply(
        [&j](auto&&... jIn) {
            (j.merge_patch(jIn), ...);
        },
        std::make_tuple(HandlerObject::ToJson(p), DpdkObject::ToJson(p)));
    // clang-format on
}

[[maybe_unused]] static void from_json(const nlohmann::json &j, DpdkObject &p) {
    HandlerObject::FromJson(j, p);
    DpdkObject::FromJson(j, p);
}

} // namespace Nta::Json::Objects
