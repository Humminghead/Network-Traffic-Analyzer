#include "JsonObjectTransportSubsystem.h"
#include <thrift/TConfiguration.h>

Nta::Json::Objects::JsonObjectTransport::JsonObjectTransport()
    : m_MaxMessageSize{apache::thrift::TConfiguration::DEFAULT_MAX_MESSAGE_SIZE},
      m_MaxFrameSize{apache::thrift::TConfiguration::DEFAULT_MAX_FRAME_SIZE},
      m_RecursionLimit{apache::thrift::TConfiguration::DEFAULT_RECURSION_DEPTH} {}
