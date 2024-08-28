#include "TransportSubsystem.h"
#include "ConfigureSubsystem.h"
#include "NetDecoder/PacketBase.h"
#include "NetDecoder/Sctp/Sctp.h"

#include <TPfrSerializer.h>

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>
#include <ThriftModels/FlowModel.h>

using namespace std;
using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;

namespace Nta::Network {

template <class Field, class Model> struct FieldFiller;

template <> struct FieldFiller<ether_header, FlowModel> {
    static void Fill(const ether_header *eth, FlowModel &m) {}
};

template <> struct FieldFiller<Nta::Network::PppoeHeader, FlowModel> {
    static void Fill(const Nta::Network::PppoeHeader *, FlowModel &) {}
};

template <> struct FieldFiller<Nta::Network::Packet::VlansArray, FlowModel> {
    static void Fill(const Nta::Network::Packet::VlansArray &, FlowModel &) {}
};

template <> struct FieldFiller<Nta::Network::Packet::MplsArray, FlowModel> {
    static void Fill(const Nta::Network::Packet::MplsArray &, FlowModel &) {}
};

template <> struct FieldFiller<iphdr, FlowModel> {
    static void Fill(const iphdr *iph, FlowModel &m) {
        if (!iph) {
            m.m_SourceAddrIp4.SetEmpty(true);
            m.m_DesinationAddrIp4.SetEmpty(true);
            m.m_Protocol.SetEmpty(true);
            return;
        }

        m.m_SourceAddrIp4.SetValue(iph->saddr);
        m.m_DesinationAddrIp4.SetValue(iph->daddr);
        m.m_Protocol.SetValue(iph->protocol);
    }
};

template <> struct FieldFiller<ip6_hdr, FlowModel> {
    static void Fill(const ip6_hdr *ip6h, FlowModel &m) {
        if (!ip6h) {
            m.m_SourceAddrIp6.SetEmpty(true);
            m.m_DesinationAddrIp6.SetEmpty(true);
            m.m_Protocol.SetEmpty(true);
            return;
        }

        m.m_SourceAddrIp6.Value().clear();
        m.m_DesinationAddrIp6.Value().clear();

        std::copy(
            &(ip6h->ip6_src.s6_addr[0]),
            &(ip6h->ip6_src.s6_addr[0]) + sizeof(in6_addr::s6_addr),
            std::back_inserter(m.m_SourceAddrIp6.Value()));

        std::copy(
            &(ip6h->ip6_dst.s6_addr[0]),
            &(ip6h->ip6_dst.s6_addr[0]) + sizeof(in6_addr::s6_addr),
            std::back_inserter(m.m_DesinationAddrIp6.Value()));

        m.m_Protocol.SetValue(ip6h->ip6_nxt);
    }
};

template <> struct FieldFiller<ip6_frag, FlowModel> {
    static void Fill(const ip6_frag *, FlowModel &) {}
};

template <> struct FieldFiller<udphdr, FlowModel> {
    static void Fill(const udphdr *udp, FlowModel &m) {
        if (!udp) {
            m.m_SrcPort.SetEmpty(true);
            m.m_DstPort.SetEmpty(true);
            return;
        }
        m.m_SrcPort.SetValue(udp->source);
        m.m_DstPort.SetValue(udp->dest);
    }
};

template <> struct FieldFiller<tcphdr, FlowModel> {
    static void Fill(const tcphdr *tcp, FlowModel &m) {
        if (!tcp) {
            m.m_SrcPort.SetEmpty(true);
            m.m_DstPort.SetEmpty(true);
            return;
        }
        m.m_SrcPort.SetValue(tcp->source);
        m.m_DstPort.SetValue(tcp->dest);
    }
};

template <> struct FieldFiller<Nta::Network::SctpHdr, FlowModel> {
    static void Fill(const Nta::Network::SctpHdr *sctp, FlowModel &m) {
        if (!sctp) {
            m.m_SrcPort.SetEmpty(true);
            m.m_DstPort.SetEmpty(true);
            return;
        }
        m.m_SrcPort.SetValue(sctp->source);
        m.m_DstPort.SetValue(sctp->dest);
    }
};

template <> struct FieldFiller<icmphdr, FlowModel> {
    static void Fill(const icmphdr *, FlowModel &) {}
};

template <> struct FieldFiller<icmp6_hdr, FlowModel> {
    static void Fill(const icmp6_hdr *icmpv6, FlowModel &m) {}
};


class TransportSubsystem::Impl {
  public:
    // std::vector<apache::thrift::transport::TTransport> m_Transports;

    std::shared_ptr<TTransport> socket{new TSocket("localhost", 9090)};
    std::shared_ptr<TTransport> transport{new TBufferedTransport(socket)};
    std::shared_ptr<TProtocol> m_protocol{new TBinaryProtocol(transport)};

    serialize::TPfrSerializer<FlowModel> m_Serialzer{m_protocol};

    FlowModel m_FlowData{};

    concurrency::ThreadFactory m_Tf{};
};

TransportSubsystem::ImplPointer::~ImplPointer() {}

TransportSubsystem::TransportSubsystem(const ConfigureSubsystem *cSubSys) : m_Pimpl{std::make_unique<Impl>()} {}

const char *TransportSubsystem::name() const {
    return "";
}

bool TransportSubsystem::Send(Result &&result) {

    auto [ok, packet] = result;

    boost::pfr::for_each_field(std::move(packet), [&](const auto field) {
        using field_t = std::remove_const_t<std::remove_pointer_t<decltype(field)>>;
        FieldFiller<field_t, FlowModel>::Fill(field, m_Pimpl->m_FlowData);
    });

    // m_Pimpl->m_Data.m_Payload.SetValue(std::vector<char>{0x31, 0x31, 0x30, 0x33,'\n'});
    m_Pimpl->m_Serialzer.serialize(m_Pimpl->m_FlowData);

    return false;
}

void TransportSubsystem::initialize(Poco::Util::Application &app) {
    m_Pimpl->transport->open();
}

void TransportSubsystem::uninitialize() {
    m_Pimpl->transport->close();
}
} // namespace Nta::Network
