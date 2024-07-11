#pragma once

#include "decoderbase.h"

namespace protocols {

class Decoder : protected DecoderBase{
public:
    using Result = std::tuple<bool, PacketBase>;

    Decoder() : DecoderBase() {}
    virtual ~Decoder() {}

    virtual bool treatEth(const uint8_t *&data, size_t& size, PacketBase &packet) noexcept;
    virtual bool treatVlan(const uint8_t *&data, size_t& size, PacketBase &packet) noexcept;
    virtual bool treatPPPoE(const uint8_t *&data, size_t& size, PacketBase &packet) noexcept;
    virtual bool treatMpls(const uint8_t *&data, size_t& size, PacketBase& packet) noexcept;
    virtual bool treatIp(const uint8_t *&data, size_t& size, PacketBase& packet) noexcept;
    virtual bool treatTcp(const uint8_t*& data, size_t& size, PacketBase& packet) noexcept;
    virtual bool treatUdp(const uint8_t*& data, size_t& size, PacketBase& packet) noexcept;
    virtual bool treatSctp(const uint8_t*& data, size_t& size, PacketBase& packet) noexcept;
    virtual bool treatGtp(const uint8_t *&data, size_t& size, PacketBase& packet) noexcept;    
    virtual bool treatHeaders(const uint16_t type,  const uint8_t*& data, size_t& size, PacketBase &packet) noexcept;
    virtual bool treatTransportLayers(const uint8_t *&data, size_t &size, PacketBase& packet) noexcept;

    virtual Result treatEth(const uint32_t& tm, const uint32_t& tm_ns, const uint8_t*& data, size_t& size) noexcept;
    virtual Result treatVlan(const uint32_t& tm, const uint32_t& tm_ns, const uint8_t*& data, size_t& size) noexcept;
    virtual Result treatPPPoE(const uint32_t& tm, const uint32_t& tm_ns, const uint8_t*& data, size_t& size) noexcept;
    virtual Result treatMpls(const uint32_t& tm, const uint32_t& tm_ns, const uint8_t*& data, size_t& size) noexcept;
    virtual Result treatIp(const uint32_t& tm, const uint32_t& tm_ns, const uint8_t*& data, size_t& size) noexcept;
    virtual Result treatTcp(const uint32_t& tm, const uint32_t& tm_ns, const uint8_t*& data, size_t& size) noexcept;
    virtual Result treatUdp(const uint32_t& tm, const uint32_t& tm_ns, const uint8_t*& data, size_t& size) noexcept;
    virtual Result treatSctp(const uint32_t& tm, const uint32_t& tm_ns, const uint8_t*& data, size_t& size) noexcept;
    virtual Result treatGtp(const uint32_t& tm, const uint32_t& tm_ns, const uint8_t*& data, size_t& size) noexcept;
    virtual Result treatHeaders(const uint32_t& tm, const uint32_t& tm_ns,const uint16_t type,  const uint8_t*& data, size_t& size) noexcept;
    virtual Result treatTransportLayers(const uint32_t& tm, const uint32_t& tm_ns,const uint8_t *&data, size_t &size) noexcept;
};
}
