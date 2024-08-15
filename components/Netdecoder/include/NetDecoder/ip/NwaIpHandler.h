#pragma once

#include <NetDecoder/NwaNetworkHandlerBase.h>
#include <NetDecoder/ip/NwaIpHandlerResult.h>
#include <NetDecoder/ip/NwaIpVersion.h>

namespace Nta::Network {

struct Ip4 {};
struct Ip6 {};

template <typename Ip> class IpHandler;
} // namespace Nta::Network

#include <NetDecoder/ip/NwaIp4Handler.h>
#include <NetDecoder/ip/NwaIp6Handler.h>
