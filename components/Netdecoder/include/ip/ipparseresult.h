#pragma once
#include <cstdint>
namespace Nta::Network
{
struct IpParseResult {
    uint8_t version = 0;
    const uint8_t* hdr = nullptr;
    const uint8_t* frag_hdr = nullptr;
    uint16_t hdr_len = 0;
    const uint8_t* payload = nullptr;
    uint8_t payload_proto = 0xff;
    uint16_t payload_len = 0;
    uint16_t total_len = 0;
    struct {
        uint32_t id = 0;
        uint16_t offset = 0;
        uint8_t more = 0;
        uint8_t reserved = 0;
    } fragment;
    void reset() { *this = IpParseResult(); }
    bool good() const { return hdr && total_len; }
    bool fragmented() const { return fragment.offset || fragment.more; }
};
}  // namespace protocols
