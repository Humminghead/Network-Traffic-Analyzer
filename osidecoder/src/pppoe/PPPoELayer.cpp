#include "PPPoELayer.h"
#include "PppoeHeader.h"

PPPoELayer::PPPoELayer(const uint8_t *data, size_t dataLen, Layer *prevLayer, Layer *nextLayer) : Layer(data, dataLen, prevLayer, nextLayer) {
    m_Protocol = 0x8863;
}

pppoe_header *PPPoELayer::getPPPoEHeader() const { return (pppoe_header*)m_Data; }

size_t PPPoELayer::getHeaderLen() const { return sizeof(pppoe_header); }

size_t PPPoELayer::getLayerPayloadSize() const { return static_cast<size_t>(htobe16(getPPPoEHeader()->payloadLength));}

PPPoECode PPPoELayer::getHeaderCode() const {return static_cast<PPPoECode>(getPPPoEHeader()->code);}
