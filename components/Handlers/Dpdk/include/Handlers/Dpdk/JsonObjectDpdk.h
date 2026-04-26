#pragma once

#include <Handlers/Common/JsonObjectHandler.h>
#include <Util/Json.h>
#include <Util/String.h>
#include <nlohmann/json.hpp>

namespace Nta::Json::Objects {

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

[[maybe_unused]] static void to_json(nlohmann::json &j, const DpdkEalCmdLine &p) {}

[[maybe_unused]] static void from_json(const nlohmann::json &j, DpdkEalCmdLine &p) {
    j.get_to(p.args);
}

//-----------------------------------------------------------------------------------
struct InputPacketClassification {
    std::string type{};
    std::vector<std::string> tupleFiveIp4Rules{};
};

[[maybe_unused]] static void to_json(nlohmann::json &j, const InputPacketClassification &p) {}

[[maybe_unused]] static void from_json(const nlohmann::json &j, InputPacketClassification &p) {
    j.at("type").get_to(p.type);
    std::transform(
        std::begin(p.type), std::end(p.type), std::begin(p.type), [](const char c) { return std::tolower(c); });
    j.at("tuple-five-rules").get_to(p.tupleFiveIp4Rules);
}

//-----------------------------------------------------------------------------------
struct WorkerQueueRange {
    std::vector<int> queueIdxs;
};

[[maybe_unused]] static void to_json(nlohmann::json &j, const WorkerQueueRange &p) {

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
    int ealCore{-1};
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
    Util::Json::GetTo(j, "input_packet_classification", p.packetCx);
}
//-----------------------------------------------------------------------------------
struct DpdkObject : HandlerObject {
    uint32_t m_BufPoolSizePerDevice{0};
    uint32_t m_HeadRoomSize{0};
    DpdkEalCmdLine m_EalCmdLine{};    
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
    std::vector<Worker> workers{};

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
             {"promiscuous", p.m_PromiscuousMode},
             {"workers", p.workers}
        };
        // clang-format on
    }

    [[maybe_unused]] static void FromJson(const nlohmann::json &j, DpdkObject &p) {
        j.at("no-pci").get_to(p.m_NoPci);
        j.at("in-memory").get_to(p.m_InMemory);
        j.at("no-shconf").get_to(p.m_NoShconf);
        j.at("no-huge").get_to(p.m_NoHuge);
        j.at("no-telemetry").get_to(p.m_NoTelemetry);
        j.at("create-uio-dev").get_to(p.m_CreateUioDev);
        j.at("vmware-tsc-map").get_to(p.m_VmwareTscMap);
        j.at("no-hpet").get_to(p.m_NoHpet);
        j.at("legacy-mem").get_to(p.m_LegacyMem);
        j.at("match-allocations").get_to(p.m_MatchAllocations);
        j.at("eal_mbuf_size").get_to(p.m_BufPoolSizePerDevice);        
        Util::Json::GetTo(j, "eal_cmd_line_arguments", p.m_EalCmdLine);        
        Util::Json::GetTo(j, "promiscuous", p.m_PromiscuousMode);
        Util::Json::GetTo(j, "eal_mbuf_headroom_size", p.m_HeadRoomSize);
        j.at("workers").get_to(p.workers);
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
