#include "Handlers/Pcap/HandlerPcap.h"

#include "Handlers/Pcap/JsonObjectPcap.h"
#include <array>
#include <bits/types/struct_timeval.h>
#include <functional>
#include <memory>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <pcap/vlan.h>
#include <regex>

namespace Nta::Network {

// https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html
static constexpr size_t DefaultSnaplen{128 * 1024 * 1024};
static constexpr std::string_view FileExtensionRegex("(\\.[pcangPCANG]{3,6})");

struct HandlerPcap::Impl {
    pcap_t *m_PcapFdPtr{nullptr};
    bool m_Opened{false};
    bool m_Stopped{true};
    Json::Objects::JsonObjectPcap mConfig;
    // https://www.man7.org/linux/man-pages/man3/pcap_open_live.3pcap.html
    int m_PcapPromiscMode{1};
    int m_PcapPacketBufferTimeout{500};
    std::array<char, PCAP_ERRBUF_SIZE> m_PcapErrorBuffer;
    struct bpf_program m_PcapBpfProgram = {};
    bool m_BreakOnEmtyDispatchFlag{false};
    std::function<HandlerPcap::CallBackFunctionType> m_Callback{nullptr};
    // PcapHandler::Source mSource{PcapHandler::Source::Unset};
};

HandlerPcap::HandlerPcap(const Json::Objects::JsonObjectPcap &config)
    : m_Impl{new HandlerPcap::Impl(), [](auto p) { delete p; }} {
    m_Impl->mConfig = config;
}

HandlerPcap::~HandlerPcap() noexcept {
    Close();
}

void HandlerPcap::Open() {
    this->OpenPcap();
}

void HandlerPcap::Close() {
    if (!m_Impl->m_Stopped) {
        m_Impl->m_Stopped = true;
        if (m_Impl->m_Opened) {
            pcap_breakloop(m_Impl->m_PcapFdPtr);
            pcap_close(m_Impl->m_PcapFdPtr);
            m_Impl->m_PcapFdPtr = nullptr;
            m_Impl->m_Opened = false;
        }
    }
}

void HandlerPcap::SetCallback(std::function<CallBackFunctionType> &&f) {
    m_Impl->m_Callback = std::move(f);
}

auto HandlerPcap::GetCallback() -> std::function<CallBackFunctionType> {
    return m_Impl->m_Callback;
}

void HandlerPcap::Loop() {
    m_Impl->m_Stopped = false;

    while (!m_Impl->m_Stopped) {
        if (!this->SingleShot())
            break;
    }
}

bool HandlerPcap::SingleShot() {    
    if (auto ret = pcap_dispatch(
            m_Impl->m_PcapFdPtr,
            -1,
            [](u_char *user, const pcap_pkthdr *pkth, const uint8_t *data) {
                auto sniffer = reinterpret_cast<HandlerPcap *>(user);

                if (auto &cb = sniffer->m_Impl->m_Callback; cb)
                    cb(
                        timeval{
                            pkth->ts.tv_sec,                //
                            pkth->ts.tv_usec},              //
                        data,                               //
                        static_cast<size_t>(pkth->caplen)); //

                struct pcap_stat ps {};
                pcap_stats(sniffer->m_Impl->m_PcapFdPtr, &ps);
            },
            reinterpret_cast<u_char *>(this));
        ret == 0) {
        if (m_Impl->m_BreakOnEmtyDispatchFlag) {
            m_Impl->m_Stopped = true;
            return false;
        }
    } else if (ret == -1) {
        m_Impl->m_Stopped = true;
        throw std::runtime_error("Pcap error: " + std::string{pcap_geterr(m_Impl->m_PcapFdPtr)});
    }    
    return true;
}

void HandlerPcap::OpenPcap() {
    if (m_Impl->m_Opened)
        return;

    if (const auto &src = m_Impl->mConfig.m_Device; src.empty()) {
        throw std::runtime_error("Empty source!");
    }

    if (const bool isFileDevice = std::regex_search(m_Impl->mConfig.m_Device, std::regex(FileExtensionRegex.data()));
        !isFileDevice) {
        m_Impl->m_PcapFdPtr = pcap_open_live(
            m_Impl->mConfig.m_Device.c_str(),
            DefaultSnaplen,
            m_Impl->m_PcapPromiscMode,
            m_Impl->m_PcapPacketBufferTimeout,
            m_Impl->m_PcapErrorBuffer.data());
        m_Impl->m_BreakOnEmtyDispatchFlag = false;
    } else {
        m_Impl->m_PcapFdPtr = pcap_open_offline(m_Impl->mConfig.m_Device.c_str(), m_Impl->m_PcapErrorBuffer.data());
        m_Impl->m_BreakOnEmtyDispatchFlag = true;
    }
    // file_or_net = false;

    if (m_Impl->m_PcapFdPtr == NULL) {
        throw std::runtime_error("pcap_open_live error: \"" + std::string{m_Impl->m_PcapErrorBuffer.data()} + "\"");
    }

    if (!m_Impl->mConfig.m_BpfFilter.empty()) {
        if (pcap_compile(m_Impl->m_PcapFdPtr, &m_Impl->m_PcapBpfProgram, m_Impl->mConfig.m_BpfFilter.c_str(), 0, 0) ==
            -1) {
            throw std::runtime_error(
                "pcap_compile: Couldn't parse filter \"" + m_Impl->mConfig.m_BpfFilter +
                "\": " + std::string{pcap_geterr(m_Impl->m_PcapFdPtr)});
        }
        if (pcap_setfilter(m_Impl->m_PcapFdPtr, &m_Impl->m_PcapBpfProgram) == -1) {
            throw std::runtime_error(
                "pcap_setfilter: Couldn't set filter \"" + m_Impl->mConfig.m_BpfFilter +
                "\": " + pcap_geterr(m_Impl->m_PcapFdPtr));
        }
        pcap_freecode(&m_Impl->m_PcapBpfProgram);
    }

    m_Impl->m_Opened = true;
}
} // namespace Nta::Network
