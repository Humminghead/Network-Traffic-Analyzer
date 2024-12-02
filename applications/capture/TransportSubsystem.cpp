#include "TransportSubsystem.h"
#include "ConfigureSubsystem.h"
#include "FieldFiller.hpp"
#include "JsonObjectTransportSubsystem.h"
#include "Util/Misc.h"

#include <TPfrSerializer.h>
#include <ThriftModels/FlowModel.h>

#include <boost/lockfree/spsc_queue.hpp>

#include <fcntl.h>
#include <thread>

#include <thrift/TConfiguration.h>

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/protocol/TCompactProtocol.h>
#include <thrift/protocol/TDebugProtocol.h>
#include <thrift/protocol/THeaderProtocol.h>
#include <thrift/protocol/TJSONProtocol.h>
#include <thrift/protocol/TMultiplexedProtocol.h>

#include <thrift/transport/TBufferTransports.h>
#include <thrift/transport/TFDTransport.h>
#include <thrift/transport/THttpClient.h>
#include <thrift/transport/TSSLSocket.h>
#include <thrift/transport/TSimpleFileTransport.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TZlibTransport.h>

#include <unistd.h>

using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;

namespace Nta::Network {

class TransportSubsystemFlowProducer {
  public:
    TransportSubsystemFlowProducer(std::shared_ptr<boost::lockfree::spsc_queue<FlowModel>> pq)
        : m_Queue{std::move(pq)} {}

    bool Produce(Result &&result) {
        auto &[ok, packet] = result;

        FlowModel flowData{};
        flowData.m_Success.SetValue(ok);

        boost::pfr::for_each_field(std::move(packet), [&](const auto field) {
            using field_t = std::remove_const_t<std::remove_pointer_t<decltype(field)>>;
            FieldFiller<field_t, FlowModel>::Fill(field, flowData);
        });

        return m_Queue->push(std::move(flowData));
    }

  private:
    std::shared_ptr<boost::lockfree::spsc_queue<FlowModel>> m_Queue{nullptr};
};

class TransportSubsystemFlowConsumer {
  public:
    TransportSubsystemFlowConsumer(
        std::shared_ptr<serialize::TPfrSerializer<FlowModel>> serializer,
        std::shared_ptr<boost::lockfree::spsc_queue<FlowModel>> pq)
        : m_Serializer{serializer}, m_Queue{std::move(pq)} {}

    void Consume() {
        m_Queue->consume_all([this](auto &&el) { m_Serializer->serialize(el); });
    }

  private:
    std::shared_ptr<boost::lockfree::spsc_queue<FlowModel>> m_Queue{nullptr};
    std::shared_ptr<serialize::TPfrSerializer<FlowModel>> m_Serializer{nullptr};
};

class TransportSubsystem::Impl {
  public:
    const ConfigureSubsystem *m_ConfigureSubsystem{nullptr};

    std::shared_ptr<TTransport> m_Pipe{nullptr};
    std::shared_ptr<TTransport> m_Transport{nullptr};
    std::shared_ptr<TProtocol> m_Protocol{nullptr};
    std::shared_ptr<serialize::TPfrSerializer<FlowModel>> m_Serialzer{nullptr};

    std::shared_ptr<boost::lockfree::spsc_queue<FlowModel>> m_Queue{nullptr};
    std::shared_ptr<TransportSubsystemFlowProducer> m_Producer{nullptr};
    std::shared_ptr<TransportSubsystemFlowConsumer> m_Consumer{nullptr};

    std::unique_ptr<std::jthread> m_ConsumerThread{nullptr};
    std::atomic_bool m_ConsumerThreadActive{false};
    std::size_t m_FramesCount{0};
};

TransportSubsystem::ImplPointer::~ImplPointer() {}

TransportSubsystem::TransportSubsystem(const ConfigureSubsystem *cSubSys) : m_Pimpl{std::make_unique<Impl>()} {
    m_Pimpl->m_ConfigureSubsystem = cSubSys;
}

TransportSubsystem::~TransportSubsystem() {
    if (!m_Pimpl->m_ConsumerThread)
        return;

    m_Pimpl->m_ConsumerThread->request_stop();
    m_Pimpl->m_ConsumerThreadActive.store(true);
    m_Pimpl->m_ConsumerThreadActive.notify_all();
}

const char *TransportSubsystem::name() const {
    return "";
}

bool TransportSubsystem::Send(Result &&result) {
    if (false == m_Pimpl->m_ConsumerThreadActive.load() && m_Pimpl->m_Queue->read_available() > m_Pimpl->m_FramesCount) {
        m_Pimpl->m_ConsumerThreadActive.store(true);
        m_Pimpl->m_ConsumerThreadActive.notify_one();
    }
    return m_Pimpl->m_Producer->Produce(std::move(result));
}

void TransportSubsystem::initialize(Poco::Util::Application &app) {
    auto obj = Util::Json::GetTo<Json::Objects::JsonObjectTransport>(
        "transport", m_Pimpl->m_ConfigureSubsystem->GetRawJsonConfig());

    auto tc = std::make_shared<TConfiguration>(
        static_cast<int>(obj.m_MaxMessageSize),
        static_cast<int>(obj.m_MaxFrameSize),
        static_cast<int>(obj.m_RecursionLimit));

    InitializeTransport(obj, tc);
    InitializeBuffer(obj, tc);
    InitializeProtocol(obj, tc);

    if (!m_Pimpl->m_Protocol)
        throw std::runtime_error("Protocol should be initialized!");

    if (!obj.m_MsgQueueSize)
        throw std::runtime_error("Message queue size should be greater than 0!");

    if (m_Pimpl->m_FramesCount = obj.m_FramesCount; !m_Pimpl->m_FramesCount)
        throw std::runtime_error("Frames count should be greater than 0!");

    m_Pimpl->m_Serialzer = std::make_shared<serialize::TPfrSerializer<FlowModel>>(m_Pimpl->m_Protocol);
    m_Pimpl->m_Queue = std::make_shared<boost::lockfree::spsc_queue<FlowModel>>(obj.m_MsgQueueSize);
    m_Pimpl->m_Producer = std::make_shared<TransportSubsystemFlowProducer>(m_Pimpl->m_Queue);
    m_Pimpl->m_Consumer = std::make_shared<TransportSubsystemFlowConsumer>(m_Pimpl->m_Serialzer, m_Pimpl->m_Queue);

    m_Pimpl->m_Transport->open();

    m_Pimpl->m_ConsumerThread = std::make_unique<std::jthread>([&](const std::stop_token token) {
        if (const auto core = m_Pimpl->m_ConfigureSubsystem->GetAppCore<int>(-1); core >= 0)
            Util::Thread::Stick2Core(core);

        while (!token.stop_requested()) {
            m_Pimpl->m_ConsumerThreadActive.wait(false);
            m_Pimpl->m_Consumer->Consume();
            m_Pimpl->m_ConsumerThreadActive.store(false);
        }
        m_Pimpl->m_Consumer->Consume();
    });
}

void TransportSubsystem::uninitialize() {
    if (m_Pimpl->m_ConsumerThread && m_Pimpl->m_ConsumerThread->joinable()) {
        m_Pimpl->m_ConsumerThread->request_stop();
        m_Pimpl->m_ConsumerThreadActive.store(true);
        m_Pimpl->m_ConsumerThreadActive.notify_one();
        m_Pimpl->m_ConsumerThread->join();
    }

    if (m_Pimpl->m_Transport->isOpen()) {
        m_Pimpl->m_Transport->close();
    }
}

void TransportSubsystem::InitializeTransport(
    const Json::Objects::JsonObjectTransport &obj,
    std::shared_ptr<apache::thrift::TConfiguration> tc) {

    if (obj.m_Type.empty())
        throw std::runtime_error("Type of transport is empty!");

    if (const auto &type = obj.m_Type; type == "file") {
        if (obj.m_WorkDir.empty())
            throw std::runtime_error("Work directory path is empty!");
        m_Pimpl->m_Pipe = std::make_shared<TSimpleFileTransport>(obj.m_WorkDir + "/file.txt", false, true, tc);
    } else if (type == "socket") {
        m_Pimpl->m_Pipe = std::make_shared<TSocket>(obj.m_Host, obj.m_Port);
    } else if (type == "socket_ssl") {
        // m_Pimpl->m_Pipe = std::make_shared<TSSLSocket>();
    } else if (type == "shm") {
        ///\todo
    } else if (type == "http") {
        m_Pimpl->m_Pipe = std::make_shared<THttpClient>(obj.m_Host, obj.m_Port, "/service", tc);
    } else if (type == "descriptor") {
        ///\todo
    } else {
        throw std::runtime_error("Unsupported transport: " + std::string{type});
    }

    /// See example in thrift/test/cpp/src/TestClient.cpp
    if (obj.m_UseZlib) {
        ///\todo
        // m_Pimpl->m_Pipe = std::make_shared<TZlibTransport>(m_Pimpl->m_Pipe);
    }
}

void TransportSubsystem::InitializeBuffer(
    const Json::Objects::JsonObjectTransport &obj,
    std::shared_ptr<apache::thrift::TConfiguration>) {

    if (obj.m_BufferType.empty())
        throw std::runtime_error("Type of buffer is empty!");

    if (m_Pimpl->m_Pipe == nullptr)
        throw std::runtime_error("Uninitialized pipe! Take a look on transport type in config!");

    if (const auto &type = obj.m_BufferType; type == "buffered") {
        m_Pimpl->m_Transport = std::make_shared<TBufferedTransport>(m_Pimpl->m_Pipe);
    } else if (type == "framed") {
        m_Pimpl->m_Transport = std::make_shared<TFramedTransport>(m_Pimpl->m_Pipe);
    } else if (type == "none") {
        m_Pimpl->m_Transport = m_Pimpl->m_Pipe;
    } else {
        throw std::runtime_error("Unsupported buffer type!");
    }
}

void TransportSubsystem::InitializeProtocol(
    const Json::Objects::JsonObjectTransport &obj,
    std::shared_ptr<TConfiguration>) {

    if (m_Pimpl->m_Transport == nullptr)
        throw std::runtime_error("Uninitialized transport!");

    if (const auto &type = obj.m_Protocol; type == "binary") {
        m_Pimpl->m_Protocol = std::make_shared<TBinaryProtocol>(m_Pimpl->m_Transport);
    } else if (type == "compact") {
        m_Pimpl->m_Protocol = std::make_shared<TCompactProtocol>(m_Pimpl->m_Transport);
    } else if (type == "debug") {
        m_Pimpl->m_Protocol = std::make_shared<TDebugProtocol>(m_Pimpl->m_Transport);
    } else if (type == "json") {
        m_Pimpl->m_Protocol = std::make_shared<TJSONProtocol>(m_Pimpl->m_Transport);
    } else if (type == "header") {
        ///\todo Fix undefined reference to `vtable for apache::thrift::transport::THeaderTransport'
        // m_Pimpl->m_Protocol = std::make_shared<THeaderProtocol>(m_Pimpl->m_Transport);
    }

    if (obj.m_UseMultiplexed) {
        ///\todo add unique service name
        m_Pimpl->m_Protocol = std::make_shared<TMultiplexedProtocol>(m_Pimpl->m_Protocol, "capture");
    }
}
} // namespace Nta::Network
