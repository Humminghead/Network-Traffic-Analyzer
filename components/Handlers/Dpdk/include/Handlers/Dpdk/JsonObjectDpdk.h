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
    uint32_t m_CoreMask{0};
    uint32_t m_BufPoolSizePerDevice{0};
    uint32_t m_MainLcore{0};
    uint32_t m_NumOfMemoryChannels{0};
    uint32_t m_HeadRoomSize{0};
    DpdkEalCmdLine m_EalCmdLine{};    
    bool m_PromiscuousMode{false};
    std::vector<Worker> workers{};

    [[maybe_unused]] static auto ToJson(const DpdkObject &p) -> nlohmann::json {
        // clang-format off
        return {
             {"eal_core_mask", p.m_CoreMask},
             {"eal_mbuf_size", p.m_BufPoolSizePerDevice},
             {"eal_main_lcore", p.m_MainLcore},
             {"eal_memory_channels", p.m_NumOfMemoryChannels},
             {"eal_mbuf_headroom_size",p.m_HeadRoomSize},
             {"eal_cmd_line_arguments", p.m_EalCmdLine},             
             {"promiscuous", p.m_PromiscuousMode},
             {"workers", p.workers}
        };
        // clang-format on
    }

    [[maybe_unused]] static void FromJson(const nlohmann::json &j, DpdkObject &p) {
        ///\warning execeptions if field name is mising

        if (auto coreMask = j.at("eal_core_mask"); coreMask.is_string()) {
            constexpr static std::string spacers{"xb"};

            auto coreMaskStr = std::string{};
            coreMaskStr.reserve(sizeof(uint64_t) * 8);
            coreMask.get_to(coreMaskStr);

            if (coreMaskStr.size() < 3)
                throw std::runtime_error("Wrong format of eal_core_mask. Supported values are: 0x.., 0b... or dec!");

            if (auto it = std::find_first_of(
                    std::begin(coreMaskStr), std::end(coreMaskStr), std::begin(spacers), std::end(spacers));
                it != std::end(coreMaskStr)) {

                const auto lit = *it;
                coreMaskStr.erase(0, std::distance(coreMaskStr.begin(), std::next(it)));

                try {
                    if (lit == 'x') {
                        p.m_CoreMask = static_cast<decltype(p.m_CoreMask)>(std::stol(coreMaskStr, nullptr, 16));
                    } else if (lit == 'b') {
                        p.m_CoreMask = static_cast<decltype(p.m_CoreMask)>(std::stol(coreMaskStr, nullptr, 2));
                    } else {
                        throw std::runtime_error("Unsupported litteral in eal_core_mask: " + std::string{lit});
                    }
                } catch (const std::exception &e) {
                    throw std::runtime_error(e.what());
                }
            }
        } else {
            j.at("eal_core_mask").get_to(p.m_CoreMask);
        }

        j.at("eal_mbuf_size").get_to(p.m_BufPoolSizePerDevice);
        j.at("eal_memory_channels").get_to(p.m_NumOfMemoryChannels);
        Util::Json::GetTo(j, "eal_cmd_line_arguments", p.m_EalCmdLine);
        Util::Json::GetTo(j, "eal_main_lcore", p.m_MainLcore);        
        Util::Json::GetTo(j, "promiscuous", p.m_PromiscuousMode);
        Util::Json::GetTo(j, "eal_mbuf_headroom_size", p.m_HeadRoomSize);
        j.at("workers").get_to(p.workers);
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
