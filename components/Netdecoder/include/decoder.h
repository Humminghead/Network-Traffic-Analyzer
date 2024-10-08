#pragma once

#include "decoderbase.h"

#include <functional>
#include <memory>

namespace Nta::Network {

class NetDecoder : protected NetDecoderBase {
  public:
    using Result = std::tuple<bool, PacketBase>;

    NetDecoder();
    virtual ~NetDecoder() = default;

    virtual bool HandleEth(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandleVlan(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandlePPPoE(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandleMpls(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandleIp(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandleTcp(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandleUdp(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandleSctp(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool HandleGtp(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool FullProcessing(const uint16_t type, const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;
    virtual bool ProcessTransportLayers(const uint8_t *&d, size_t &sz, PacketBase &pkt) noexcept;

    virtual Result HandleEth(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandleVlan(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandlePPPoE(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandleMpls(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandleIp(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandleTcp(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandleUdp(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandleSctp(const uint8_t *&d, size_t &size) noexcept;
    virtual Result HandleGtp(const uint8_t *&d, size_t &size) noexcept;
    virtual Result FullProcessing(const uint16_t type, const uint8_t *&d, size_t &size) noexcept;
    virtual Result ProcessTransportLayers(const uint8_t *&d, size_t &size) noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl, std::function<void(Impl *)>> m_Impl;
};
} // namespace Nta::Network
