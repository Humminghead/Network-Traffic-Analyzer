#pragma once

#include <cstdint>

namespace Nwa::Network {
#pragma pack(push, 1)
struct PppoeHeader {
    uint8_t version : 4, type : 4;
    uint8_t code;
    uint16_t sessionId; // PPPoE session identifier (относится только к пакетам сеанса PPPoE) */
    uint16_t payloadLength; // Length includes PPPoE header */
};
#pragma pack(pop)
} // namespace Nwa::Network
