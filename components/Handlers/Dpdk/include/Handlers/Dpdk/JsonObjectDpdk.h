#pragma once

#include <Handlers/Common/JsonObjectHandler.h>
#include <Util/Json.h>
#include <Util/String.h>
#include <nlohmann/json.hpp>

namespace Nta::Json::Objects {

//-----------------------------------------------------------------------------------
struct MemPoolOpt
{
    uint16_t m_Socket{0};
    uint16_t m_MbufSize{2048};
    uint16_t m_PrivSize{0};
    uint32_t m_MbufCacheSize{512};
    uint32_t m_TotalMbufNum{32000};
};
[[maybe_unused]] static void to_json(nlohmann::json &j, const MemPoolOpt &p) {
    ///\todo
    (void)p;
}

[[maybe_unused]] static void from_json(const nlohmann::json &j, MemPoolOpt &p) {
    Util::Json::GetTo(j,"socket", p.m_Socket);
    Util::Json::GetTo(j,"priv_size", p.m_Socket);
    Util::Json::GetTo(j,"mbuf_size", p.m_MbufSize);
    Util::Json::GetTo(j,"mbuf_cache_size", p.m_MbufCacheSize);
    Util::Json::GetTo(j,"total_mbuf_num", p.m_TotalMbufNum);
}

//-----------------------------------------------------------------------------------
struct MemPoolOptions
{
    std::vector<MemPoolOpt> parameters;

    auto Get(const uint16_t socket) const {
        auto it = std::ranges::find_if(parameters, [&socket](const auto& p){
            return p.m_Socket == socket;
        });

        if(it != parameters.end())
            return *it;

        // If mempool parameters not found return defaul values
        return MemPoolOpt{};
    }
};

[[maybe_unused]] static void to_json(nlohmann::json &j, const MemPoolOptions &p) {
    ///\todo
    (void)p;
}

[[maybe_unused]] static void from_json(const nlohmann::json &j, MemPoolOptions &p) {
    j.get_to(p.parameters);
}

//-----------------------------------------------------------------------------------
struct DpdkEalCmdLineArg {
    std::string key;
    std::string value;
};

[[maybe_unused]] static void to_json(nlohmann::json &j, const DpdkEalCmdLineArg &p) {
    j = {{p.key, p.value}};
}

[[maybe_unused]] static void from_json(const nlohmann::json &j, DpdkEalCmdLineArg &p) {
    p.key = j.items().begin().key();
    p.value = Util::String::RemoveSpaces(j.items().begin().value());
}

//-----------------------------------------------------------------------------------
struct DpdkEalCmdLine {
    std::vector<DpdkEalCmdLineArg> args;
};

[[maybe_unused]] static void to_json(nlohmann::json &j, const DpdkEalCmdLine &p) {
    ///\todo
}

[[maybe_unused]] static void from_json(const nlohmann::json &j, DpdkEalCmdLine &p) {
    j.get_to(p.args);
}

//-----------------------------------------------------------------------------------
struct InputPacketClassification {
    std::string type{};
    std::vector<std::string> tupleFiveIp4Rules{};
};

[[maybe_unused]] static void to_json(nlohmann::json &j, const InputPacketClassification &p) {
    ///\todo
}

[[maybe_unused]] static void from_json(const nlohmann::json &j, InputPacketClassification &p) {
    j.at("type").get_to(p.type);
    std::transform(
        std::begin(p.type), std::end(p.type), std::begin(p.type), [](const char c) { return std::tolower(c); });
    j.at("tuple-five-rules").get_to(p.tupleFiveIp4Rules);
}

//-----------------------------------------------------------------------------------
struct WorkerQueueRange {
    std::vector<int> queueIdxs;

    // Iterartor support
    constexpr auto begin() const noexcept { return std::begin(queueIdxs); }
    constexpr auto end() const noexcept { return std::end(queueIdxs); }
};

[[maybe_unused]] static void to_json(nlohmann::json &j, const WorkerQueueRange &p) {
    ///\todo
}

[[maybe_unused]] static void from_json(const nlohmann::json &j, WorkerQueueRange &p) {
    if (std::string type = j.at("type"); type == "range") {
        int min = 0, max = 0;
        Util::Json::GetTo(j, "min", min);
        Util::Json::GetTo(j, "max", max);

        min = std::min(min, max);
        max = std::max(min, max);

        while(min <= max){
            p.queueIdxs.push_back(min++);
        }
    } else if (type == "id") {
        for (auto& id : j.at("indices")) {
            p.queueIdxs.push_back(id);
        }
        std::sort(std::begin(p.queueIdxs), std::end(p.queueIdxs));
    } else {
        throw std::runtime_error("Unsupported type: " + type);
    }
}

//-----------------------------------------------------------------------------------
struct Worker {
    std::string type{};
    std::string linkLayer{"eth"};
    int ealCore{-1};
    bool stopAtEmptyRx{false};
    std::string rxDevicePciAddr{};
    std::string txDevicePciAddr{};
    WorkerQueueRange rxQueuesIdxs{};
    WorkerQueueRange txQueuesIdxs{};
    std::vector<InputPacketClassification> packetCx{};
};
[[maybe_unused]] static void to_json(nlohmann::json &j, const Worker &p) {
    j =  {
         {"input_packet_classification", p.packetCx}
    };
}

[[maybe_unused]] static void from_json(const nlohmann::json &j, Worker &p) {
    j.at("type").get_to(p.type);
    std::transform(std::begin(p.type), std::end(p.type), std::begin(p.type), [](const char c) { return std::tolower(c); });
    Util::Json::GetTo(j, "eal_core", p.ealCore);
    Util::Json::GetTo(j, "rx_device", p.rxDevicePciAddr);
    Util::Json::GetTo(j, "tx_device", p.txDevicePciAddr);
    Util::Json::GetTo(j, "rx_queues_idxs", p.rxQueuesIdxs);
    Util::Json::GetTo(j, "tx_queues_idxs", p.txQueuesIdxs);
    Util::Json::GetTo(j, "link_layer", p.linkLayer);
    std::transform( // to lower conversion
        std::begin(p.linkLayer),
        std::end(p.linkLayer),
        std::begin(p.linkLayer),
        [](auto c) { return std::tolower(c); });
    Util::Json::GetTo(j, "input_packet_classification", p.packetCx);
    Util::Json::GetTo(j, "stop_at_empty_rx", p.stopAtEmptyRx);
}
//-----------------------------------------------------------------------------------
struct DpdkObject : HandlerObject {
    uint32_t m_BufPoolSizePerDevice{0};
    uint32_t m_HeadRoomSize{0};
    DpdkEalCmdLine m_EalCmdLine{};
    MemPoolOptions m_MemPoolsOpts{};
    bool m_PromiscuousMode{false};
    bool m_NoPci{false};
    bool m_InMemory{false};
    bool m_NoShconf{false};
    bool m_NoHuge{false};
    bool m_NoTelemetry{false};
    bool m_CreateUioDev{false};
    bool m_VmwareTscMap{false};
    bool m_NoHpet{false};
    bool m_LegacyMem{false};
    bool m_MatchAllocations{false};
    std::vector<Worker> m_Workers{};

    [[maybe_unused]] static auto ToJson(const DpdkObject &p) -> nlohmann::json {
        // clang-format off
        return {
             {"no-pci", p.m_NoPci},
             {"in-memory", p.m_InMemory},
             {"no-shconf", p.m_NoShconf},
             {"no-huge", p.m_NoHuge},
             {"no-telemetry", p.m_NoTelemetry},
             {"create-uio-dev", p.m_CreateUioDev},
             {"vmware-tsc-map", p.m_VmwareTscMap},
             {"no-hpet", p.m_NoHpet},
             {"legacy-mem", p.m_LegacyMem},
             {"match-allocations", p.m_MatchAllocations},
             {"eal_mbuf_size", p.m_BufPoolSizePerDevice},             
             {"eal_mbuf_headroom_size",p.m_HeadRoomSize},
             {"eal_cmd_line_arguments", p.m_EalCmdLine},
             {"mempools", p.m_MemPoolsOpts},
             {"promiscuous", p.m_PromiscuousMode},
             {"workers", p.m_Workers}
        };
        // clang-format on
    }    

    [[maybe_unused]] static void FromJson(const nlohmann::json &j, DpdkObject &p) {

        // Converts all integers values in the JSON string to std::string
        auto convertNumbers = [](const nlohmann::json &j, const std::string &name, DpdkEalCmdLine &value) {
            if (j.contains(name)) {
                for (auto item : j.at(name)) {
                    using ValueType = nlohmann::detail::value_t;
                    for (auto obj : item.items()) {
                        auto k = obj.key();
                        if (auto type = obj.value().type();
                            type == ValueType::number_integer || type == ValueType::number_unsigned) {
                            value.args.push_back(DpdkEalCmdLineArg{k, std::to_string(obj.value().get<size_t>())});
                        } else if (type == ValueType::string) {
                            value.args.push_back(DpdkEalCmdLineArg{k, obj.value().get<std::string>()});
                        } else {
                            throw std::runtime_error("Unsupported conversion!");
                        }
                    }
                }
            }
            return value;
        };

        Util::Json::GetTo(j,"no-pci", p.m_NoPci);
        Util::Json::GetTo(j,"in-memory", p.m_InMemory);
        Util::Json::GetTo(j,"no-shconf", p.m_NoShconf);
        Util::Json::GetTo(j,"no-huge", p.m_NoHuge);
        Util::Json::GetTo(j,"no-telemetry", p.m_NoTelemetry);
        Util::Json::GetTo(j,"create-uio-dev", p.m_CreateUioDev);
        Util::Json::GetTo(j,"vmware-tsc-map", p.m_VmwareTscMap);
        Util::Json::GetTo(j,"no-hpet", p.m_NoHpet);
        Util::Json::GetTo(j,"legacy-mem", p.m_LegacyMem);
        Util::Json::GetTo(j,"match-allocations", p.m_MatchAllocations);
        Util::Json::GetTo(j, "eal_cmd_line_arguments", p.m_EalCmdLine, convertNumbers);
        Util::Json::GetTo(j, "promiscuous", p.m_PromiscuousMode);
        j.at("eal_mbuf_size").get_to(p.m_BufPoolSizePerDevice);
        Util::Json::GetTo(j, "eal_mbuf_headroom_size", p.m_HeadRoomSize);
        Util::Json::GetTo(j, "mempools", p.m_MemPoolsOpts);
        j.at("workers").get_to(p.m_Workers);
    }

    constexpr auto GetEalAdditionalOptions() const -> std::vector<std::string_view> {
        std::vector<std::string_view> args{};
        if (m_NoPci)
            args.push_back(R"(--no-pci)");
        if (m_InMemory)
            args.push_back(R"(--in-memory)");
        if (m_NoShconf)
            args.push_back(R"(-no-shconf)");
        if (m_NoHuge)
            args.push_back(R"(--no-huge)");
        if (m_NoTelemetry)
            args.push_back(R"(--no-telemetry)");
        if (m_CreateUioDev)
            args.push_back(R"(--create-uio-dev)");
        if (m_VmwareTscMap)
            args.push_back(R"(--vmware-tsc-map)");
        if (m_NoHpet)
            args.push_back(R"(--no-hpet)");
        if (m_LegacyMem)
            args.push_back(R"(--legacy-mem)");
        if (m_MatchAllocations)
            args.push_back(R"(--match-allocations)");

        return args;
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
