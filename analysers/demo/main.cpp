#include <GetOptPP/ConsoleKeyOption.h>
#include <GetOptPP/ConsoleOptionsHandler.h>
#include <HandlerPcap.h>
#include <JsonObjectPcap.h>
#include <Poco/ActiveThreadPool.h>
#include <Poco/ThreadPool.h>
#include <decoder.h>
#include <filesystem>
#include <fstream>
#include <ip/NwaIp6Handler.h>
#include <pcap/pcap.h>
// #include <queue>
#include <string.h> //strlen
// #include <thread>

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

class DecodeTask : public Poco::Runnable {
  public:
    DecodeTask(std::function<void()> h) : m_Handler(h) {}

    void run() override {
        if (m_Handler)
            m_Handler(/*m_Data, m_Size*/);
    }

    void SetData(const uint8_t *d) noexcept { m_Data = d; }
    void SetSize(const size_t size) noexcept { m_Size = size; }

  private:
    std::function<void()> m_Handler{};
    const uint8_t *m_Data{nullptr};
    size_t m_Size{0};
};

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
    // std::vector<std::shared_ptr<Network::IpHandler<Network::HandlerResult>>> handlersIp4{};
    // std::vector<std::jthread> workers{};
    // Poco::ActiveThreadPool decode;

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
    size_t cntr;
    Poco::ThreadPool decode;
    std::vector<DecodeTask> workers;
    // decode.addCapacity(1);
    for (const auto &hc : handlersConfigs) {
        // for (const auto& handler : handlers) {
        auto handler = std::make_shared<Network::HandlerPcap>(hc);
        handler->SetCallback([&cntr](const timeval t, const uint8_t *d, const size_t sz) { cntr++;return false; });

        workers.push_back(DecodeTask{[handler] {
            handler->Open();
            handler->Loop();
            handler->Close();
        }});
    };

    for (auto &w : workers) {
        decode.start(w);
        /*std::cerr << "Taask" << std::endl;*/
    };
    decode.joinAll();
        return 0;

        /*
        for (const auto &hc : handlersConfigs) {
            auto handler = std::make_shared<Network::HandlerPcap>(hc);
            handler->SetCallback([](const timeval t, const uint8_t *d, const size_t sz) { return false; });
            handlers.push_back(std::move(handler));
        }

        {
            bool isRunned = true;
            while (isRunned) {
                for (auto &h : handlers) {
                    h->Open();
                    isRunned = h->SingleShot();
                }
            }
        }
        return 0;
    */
}

#include "Poco/Observer.h"
#include "Poco/Task.h"
#include "Poco/TaskManager.h"
#include "Poco/TaskNotification.h"
using Poco::Observer;
class SampleTask : public Poco::Task {
  public:
    SampleTask(const std::string &name) : Task(name) {}
    void runTask() {
        for (int i = 0; i < 100; ++i) {
            setProgress(float(i) / 100); // report progress
            if (sleep(1000))
                break;
        }
    }
};

class ProgressHandler {
  public:
    void onProgress(Poco::TaskProgressNotification *pNf) {
        std::cout << pNf->task()->name() << " progress: " << pNf->progress() << std::endl;
        pNf->release();
    }
    void onFinished(Poco::TaskFinishedNotification *pNf) {
        std::cout << pNf->task()->name() << " finished." << std::endl;
        pNf->release();
    }
};

int main0(int argc, char **argv) {
    Poco::TaskManager tm;
    ProgressHandler pm;
    tm.addObserver(Observer<ProgressHandler, Poco::TaskProgressNotification>(pm, &ProgressHandler::onProgress));
    tm.addObserver(Observer<ProgressHandler, Poco::TaskFinishedNotification>(pm, &ProgressHandler::onFinished));
    tm.start(new SampleTask("Task 1")); // tm takes ownership
    tm.start(new SampleTask("Task 2"));
    tm.joinAll();
    return 0;
}
