#include <GetOptPP/ConsoleKeyOption.h>
#include <GetOptPP/ConsoleOptionsHandler.h>
#include <HandlerPcap.h>
#include <JsonObjectPcap.h>
#include <filesystem>
#include <fstream>
#include <ip/NwaIp6Handler.h>
#include <pcap/pcap.h>
#include <string.h> //strlen
#include <thread>
#include <decoder.h>

using namespace std;

namespace utils {
namespace filesystem {

/* Reads file in vector*/
[[maybe_unused]] auto ReadBinaryFile(const std::filesystem::path &path) noexcept {
    std::ifstream stream(path.c_str(), std::ios::binary);

    std::vector<char> vec;

    if (stream.is_open()) {
        stream.seekg(0, std::ios::end);
        auto size = stream.tellg();
        stream.seekg(0, std::ios::beg);

        vec.resize(size);
        stream.read((char *)vec.data(), size);

        return vec;
    }

    return vec;
}
} // namespace filesystem
namespace ip {
/*
 * Converts a string containing an (IPv4) Internet Protocol
 * dotted address into a proper address
 */
static uint32_t ip2long(const char *ip) {
    struct in_addr s;

    if (!strlen(ip) || // pcap
        !inet_aton(ip, &s))
        return 0;

    return ntohl(s.s_addr);
}
} // namespace ip
} // namespace utils

using namespace Nwa;

int main(int argc, char **argv) {
    bool helpInvoked{false};

    GetOptPlusPlus::ConsoleOptionsHandler cmdHandler(argc, argv);
    Json::Objects::JsonObjectPcap pcapCfg;

    std::string bpfFilterString{
        "ip and src <IP_SRC> and dst <IP_DST> and tcp and src port <TCP_SP> and dst port <TCP_DP>"};
    bool bpfFilterWasModified{false};
    bool hasConfig{false};

    std::vector<Json::Objects::JsonObjectPcap> handlersConfigs;
    std::vector<std::shared_ptr<Network::HandlerAbstract>> handlers{};
    std::vector<std::jthread> workers{};

    cmdHandler.AddKey({"file", nullptr, 1}, [&pcapCfg](auto *p) { pcapCfg.m_Device = std::string{p}; });

    cmdHandler.AddKey({"config", nullptr, 1}, [&pcapCfg, &handlersConfigs, &hasConfig](auto *p) {
        if (!p)
            return;

        hasConfig = true;

        std::filesystem::path path(p);
        if (const auto ext = path.extension(); ext != ".json")
            throw std::runtime_error("Unsupported config file format (" + ext.string() + ")!");

        {
            const auto cTxt = utils::filesystem::ReadBinaryFile(path);
            constexpr auto handlersSectionName = "handlers";

            nlohmann::json j{};
            std::istringstream inputStream(cTxt.data());
            inputStream >> j;

            if (j.contains(handlersSectionName))
                if (!j.at(handlersSectionName).is_array())
                    throw std::runtime_error("Wrong configuration format!");

            for (const auto &jc : j.at(handlersSectionName)) {
                handlersConfigs.push_back(jc.template get<Json::Objects::JsonObjectPcap>());
            }
        }
    });

    cmdHandler.ProcessCmdLine();

    if (helpInvoked)
        return 0;

    if (!hasConfig && !bpfFilterWasModified)
        return 0;

    if (!hasConfig) {
        pcapCfg.m_BpfFilter = bpfFilterString;
        handlersConfigs.push_back(pcapCfg);
    }

    for (const auto &hc : handlersConfigs) {
        auto handler = std::make_shared<Network::HandlerPcap>(hc);
        handler->SetCallback(
            [/*ip = std::move(Network::IpHandler<Network::Ip6>{})*/](const timeval t, const uint8_t *d, const size_t sz) {
                auto ip = Network::IpHandler<Network::Ip6>{};
                auto nd = Network::NetDecoder{};

                auto [ok,iph] = ip.Handle(d + 14, sz - 14);

                return false;
            });
        auto worker = std::jthread([handler](std::stop_token st) {
            handler->Open();
            handler->Loop();
            handler->Stop();
        });
        // std::stop_callback cb(worker.get_stop_token(),[handler]{
        //     handler->Stop();
        // });
        workers.push_back(std::move(worker));
        handlers.push_back(std::move(handler));
    }

    return 0;
}
