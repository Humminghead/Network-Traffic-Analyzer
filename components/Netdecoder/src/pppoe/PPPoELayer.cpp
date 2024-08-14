#include "PPPoELayer.h"
#include "PppoeHeader.h"

namespace Nta::Network {

PPPoELayer::PPPoELayer(const uint8_t *data, size_t size, Layer *prevLayer, Layer *nextLayer)
    : Layer(data, size, prevLayer, nextLayer) {
    m_Protocol = 0x8863;
}

PppoeHeader *PPPoELayer::getPPPoEHeader() const {
    return (PppoeHeader *)m_Data;
}

size_t PPPoELayer::getHeaderLen() const {
    return sizeof(PppoeHeader);
}

size_t PPPoELayer::getLayerPayloadSize() const {
    return static_cast<size_t>(htobe16(getPPPoEHeader()->payloadLength));
}

PPPoECode PPPoELayer::getHeaderCode() const {
    return static_cast<PPPoECode>(getPPPoEHeader()->code);
}
} // namespace Nta::Network
