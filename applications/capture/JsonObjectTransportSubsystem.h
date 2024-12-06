#pragma once

#include "Util/Json.h"
#include <cstring>
#include <nlohmann/json.hpp>
#include <string>
#include <filesystem>

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
    std::size_t m_MsgQueueSize{};
    std::string m_BufferType{"none"};
    std::string m_Protocol{};
    std::size_t m_MaxMessageSize{0};
    std::size_t m_MaxFrameSize{0};
    std::size_t m_RecursionLimit{0};
    std::size_t m_FramesCount{0};
    std::string m_Ciphers{};
    std::filesystem::path m_CaCertFilePath{};
    std::filesystem::path m_ServerCertPath{};
    std::filesystem::path m_PrivateKeyPath{};
    bool m_Authentication{true};
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
        {"message_queue_size", t.m_MsgQueueSize},
        {"frames_count", t.m_FramesCount},        
        {"ciphers",t.m_Ciphers},
        {"ca_file_path",t.m_CaCertFilePath},
        {"server_cert_path",t.m_ServerCertPath},
        {"private_key_path",t.m_PrivateKeyPath},
        {"authentication",t.m_Authentication}
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
    Util::Json::GetTo(j, "message_queue_size", t.m_MsgQueueSize);
    Util::Json::GetTo(j, "frames_count", t.m_FramesCount);
    Util::Json::GetTo(j, "ciphers", t.m_Ciphers);
    Util::Json::GetTo(j, "ca_file_path", t.m_CaCertFilePath);
    Util::Json::GetTo(j, "server_cert_path", t.m_ServerCertPath);
    Util::Json::GetTo(j, "private_key_path", t.m_PrivateKeyPath);
    Util::Json::GetTo(j, "authentication", t.m_Authentication);
}
} // namespace Nta::Json::Objects

