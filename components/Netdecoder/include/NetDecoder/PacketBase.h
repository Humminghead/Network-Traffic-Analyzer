#pragma once

#include <array>
#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/vlan.h>

/*RFC8200 4.1.  Extension Header Order
  IPv6 header                           |
  Hop-by-Hop Options header             |_Per-Fragment Headers
  Destination Options header (note 1)   |
  Routing header                        |
  Fragment header
  Authentication header (note 2)                    |
  Encapsulating Security Payload header (note 2)    |_Extension (ESP is not considered
  Destination Options header (note 3)               |           an extension header)
  Upper-Layer header                                |-Upper-Layer Headers and ESP
  --------------------------------------------------------------------------
  Original:
  +-----------------+-----------------+--------+--------+-//-+--------+
  |  Per-Fragment   |Ext & Upper-Layer|  first | second |    |  last  |
  |    Headers      |    Headers      |fragment|fragment|....|fragment|
  +-----------------+-----------------+--------+--------+-//-+--------+
  Fragmented:
   +------------------+---------+-------------------+----------+
   |  Per-Fragment    |Fragment | Ext & Upper-Layer |  first   |
   |    Headers       | Header  |   Headers         | fragment |
   +------------------+---------+-------------------+----------+
   ....
   +------------------+--------+----------+
   |  Per-Fragment    |Fragment|   last   |
   |    Headers       | Header | fragment |
   +------------------+--------+----------+
  */

// Linux
struct mpls_label;

static constexpr const size_t MAX_MPLS_CNT = 4;         //!< Max mpls label count in packet
static constexpr const size_t MAX_VLAN_CNT = 8;         //!< Max vlan label count in packet
static constexpr const size_t MAX_LAYER_PROTO_CNT = 64; //!< Max value of protols on each osi layer

namespace Nta::Network {

/* Forward declarations */
struct PppoeHeader;
struct SctpHdr;
class OsiLayer;
enum class LinkLayerProto : uint32_t;

/* OSI model levels enum */
enum class OsiLevel : int {
    Phy = 0, // Temporary unused
    Data,
    Network,
    Transport,
    Session,
    Present,
    App
};

/* Layer's protol array */
using LayerProtocols = std::array<LinkLayerProto, MAX_LAYER_PROTO_CNT>;

/* OSI model levels type */
using OsiLevelArr = std::array<OsiLayer, sizeof(OsiLevel)>;

/* Util function for accerc to layer's protol array */
template <OsiLevel L, class OsiArray> auto &GetOsiLayer(OsiArray &levels) {
    static_assert(std::is_convertible_v<OsiArray, OsiLevelArr>);
    return std::get<static_cast<int>(L)>(levels);
}

/* Layer proto store */
class OsiLayer {
  public:
    auto& Set(const LinkLayerProto &layer) {
        m_Protos |= static_cast<uint32_t>(layer);
        return *this;
    }

    auto& Reset() noexcept { m_Protos = 0; return *this;}

    auto& ResetL2() noexcept {
        m_Protos = m_Protos & ~0xf;
        return *this;
    }
    auto& ResetL3() noexcept {
        m_Protos = m_Protos & ~0xf0;
        return *this;
    }
    auto& ResetL4() noexcept {
        m_Protos = m_Protos & ~0xf00;
        return *this;
    }
    auto& ResetTunnel() noexcept {
        m_Protos = m_Protos & ~0xf000;
        return *this;
    }

    auto Get() const noexcept { return static_cast<LinkLayerProto>(m_Protos); }

  private:
    uint32_t m_Protos{0x00};
};

/* OSI model levels type */
using OsiLevelArr = std::array<OsiLayer, sizeof(OsiLevel)>;

/* Payload store */
struct Payload {
    const uint8_t *data{nullptr};
    size_t size{0};

    void Reset() { *this = {}; }
};

/* Packet representation */
struct Packet {
    using MplsArray = std::array<const mpls_label *, MAX_MPLS_CNT>;
    using VlansArray = std::array<const vlan_tag *, MAX_VLAN_CNT>;

    const struct ether_header *ethHeader{nullptr};
    const struct PppoeHeader *pppoeHeader{nullptr};

    VlansArray vlansTags{};
    MplsArray mplsLabels{};

    const struct iphdr *ip4Header{nullptr};
    const struct ip6_hdr *ip6Header{nullptr};

    const struct udphdr *udpHeader{nullptr};
    const struct tcphdr *tcpHeader{nullptr};

    const struct SctpHdr *sctpHeader{nullptr};

    const struct icmphdr *icmpHeader{nullptr};
    const struct icmp6_hdr *icmp6Header{nullptr};

    Payload payload{};
    OsiLevelArr *protoList{nullptr};

    void Reset();
    void ResetLowerLevels();
};
} // namespace Nta::Network
