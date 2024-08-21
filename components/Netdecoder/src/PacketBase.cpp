#include "NetDecoder/PacketBase.h"

#include <algorithm>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>

#include "NetDecoder/Gtp/Gtp1Defs.h"
#include "NetDecoder/Gtp/GtpHeader.h"

namespace Nta::Network {

void Packet::Reset() {
    vlanCounter = 0;
    mplsCounter = 0;

    ethHeader = nullptr;
    pppoeHeader = nullptr;
    std::for_each(std::begin(vlansTags), std::end(vlansTags), [](auto *&p) { p = nullptr; });
    std::for_each(std::begin(mplsLabels), std::end(mplsLabels), [](auto *&p) { p = nullptr; });
    ip4Header = nullptr;
    ip6Header = nullptr;
    ip6Fragment = nullptr;
    udpHeader = nullptr;
    icmpHeader = nullptr;
    gtpHeader = nullptr;
    sctpHeader = nullptr;

    bytes.L2 = 0;
    bytes.L3 = 0;
    bytes.L4 = 0;
    bytes.L5 = 0;
    bytes.L6 = 0;
    bytes.L7 = 0;
}

void Packet::ResetLowerLevels() {
    tcpHeader = nullptr;
    sctpHeader = nullptr;
    gtpHeader = nullptr;
    bytes.L4 = {0};
    bytes.L5 = {0};
    bytes.L6 = {0};
    bytes.L7 = {0};
}

} // namespace Nta::Network
