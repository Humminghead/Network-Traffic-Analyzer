#pragma once

#include "Util/Json.h"
#include <cstring>
#include <nlohmann/json.hpp>
#include <string>

namespace Nta::Json::Objects {
struct JsonObjectTransport {
    JsonObjectTransport();
    ~JsonObjectTransport() = default;

    bool m_UseZlib{false};
    bool m_UseMultiplexed{false};
    std::string m_Type{};
    std::string m_WorkDir{};
    std::string m_Host{};
    std::size_t m_Port{};
    std::string m_BufferType{"none"};
    std::string m_Protocol{};
    std::size_t m_MaxMessageSize{0};
    std::size_t m_MaxFrameSize{0};
    std::size_t m_RecursionLimit{0};
};

[[maybe_unused]] static void to_json(nlohmann::json &j, const JsonObjectTransport &t) {
    j = nlohmann::json{
        {"use_zlib", t.m_UseZlib},
        {"multiplexed", t.m_UseMultiplexed},
        {"type", t.m_Type},
        {"workdir", t.m_WorkDir},
        {"host", t.m_Host},
        {"port", t.m_Port},
        {"protocol", t.m_Protocol},
        {"buffer_type",t.m_BufferType},
        {"max_message_size", t.m_MaxMessageSize},
        {"max_frame_size", t.m_MaxFrameSize},
        {"recursion_limit", t.m_RecursionLimit},
    };
}
[[maybe_unused]] static void from_json(const nlohmann::json &j, JsonObjectTransport &t) {
    Util::Json::GetTo(j, "use_zlib", t.m_UseZlib);
    Util::Json::GetTo(j, "multiplexed", t.m_UseMultiplexed);
    Util::Json::GetTo(j, "type", t.m_Type);
    Util::Json::GetTo(j, "workdir", t.m_WorkDir);
    Util::Json::GetTo(j, "host", t.m_Host);
    Util::Json::GetTo(j, "port", t.m_Port);
    Util::Json::GetTo(j, "buffer_type", t.m_BufferType);
    Util::Json::GetTo(j, "protocol", t.m_Protocol);
    Util::Json::GetTo(j, "max_message_size", t.m_MaxMessageSize);
    Util::Json::GetTo(j, "max_frame_size", t.m_MaxFrameSize);
    Util::Json::GetTo(j, "recursion_limit", t.m_RecursionLimit);
}
} // namespace Nta::Json::Objects

