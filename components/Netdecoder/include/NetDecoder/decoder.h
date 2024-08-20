#pragma once

#include "decoderbase.h"

#include <functional>
#include <memory>

namespace Nta::Network {

enum class LinkLayer : uint16_t {
    Eth = 0x0,
    Vlan = 0x0081,
    Mpls = 0x4788,
    PPpoEd = 0x6488, // https://datatracker.ietf.org/doc/html/rfc2516
    PPPoEs = 0x6388,
    Ip4 = 0x0008,
    Ip6 = 0xDD86
};

class NetDecoder : protected NetDecoderBase {
  public:
    using Result = std::tuple<bool, PacketBase>;

    NetDecoder();
    virtual ~NetDecoder() = default;

    virtual bool HandleEth(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandleVlan(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandlePPPoE(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandleMpls(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandleIp4(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandleIp6(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandleTcp(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandleUdp(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandleSctp(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandleGtp(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool FullProcessing(const LinkLayer layer, const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool ProcessTransportLayers(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;

    virtual Result HandleEth(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandleVlan(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandlePPPoE(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandleMpls(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandleIp4(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandleIp6(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandleTcp(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandleUdp(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandleSctp(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandleGtp(const uint8_t *&d, size_t &size) noexcept;
    virtual Result FullProcessing(const LinkLayer type, const uint8_t *&d, size_t &size) noexcept;
    virtual Result ProcessTransportLayers(const uint8_t *&d, size_t &size) noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl, std::function<void(Impl *)>> m_Impl;
};
} // namespace Nta::Network
