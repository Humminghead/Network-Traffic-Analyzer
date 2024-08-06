#pragma once

#include <linux/types.h>

namespace Nwa::Network {

enum class ChunkType : __u8 {
    DATA = 0,
    INIT,
    INIT_ACK,
    SACK,
    HEARTBEAT,
    HEARTBEAT_ACK,
    ABORT,
    SHUTDOWN,
    SHUTDOWN_ACK,
    ERROR,
    COOKIE_ECHO,
    COOKIE_ACK,
    ECNE,
    CWR,
    SHUTDOWN_COMPLETE,
    AUTH,
    IDATA = 64,
    ASCONF_ACK = 128,
    RE_CONFIG = 130,
    PAD = 132,
    FORWARD_TSN = 192,
    ASCONF,
    IFORWARD_TSN
};

struct SctpHdr {
    __be16 source;
    __be16 dest;
    __be32 vtag;
    __le32 checksum;
} __attribute__((packed));

struct SctpChunkHdr {
    __u8 type;
    __u8 flags;
    __be16 length;
} __attribute__((packed));
} // namespace Nwa::Nwa::Network
