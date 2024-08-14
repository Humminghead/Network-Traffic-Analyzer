#pragma once

#include "Layer.h"
#include <cstdint>
#include <string.h>

namespace Nta::Network {

struct PppoeHeader;

/**
 * Коды PPPoE
 */
enum class PPPoECode : uint8_t {
    /** PPPoE session code */
    PPPOE_CODE_SESSION = 0x00,
    /** PPPoE discovery PADO */
    PPPOE_CODE_PADO = 0x07,
    /** PPPoE discovery PADI */
    PPPOE_CODE_PADI = 0x09,
    /** PPPoE discovery PADG */
    PPPOE_CODE_PADG = 0x0a,
    /** PPPoE discovery PADC */
    PPPOE_CODE_PADC = 0x0b,
    /** PPPoE discovery PADQ */
    PPPOE_CODE_PADQ = 0x0c,
    /** PPPoE discovery PADR */
    PPPOE_CODE_PADR = 0x19,
    /** PPPoE discovery PADS */
    PPPOE_CODE_PADS = 0x65,
    /** PPPoE discovery PADT */
    PPPOE_CODE_PADT = 0xa7,
    /** PPPoE discovery PADM */
    PPPOE_CODE_PADM = 0xd3,
    /** PPPoE discovery PADN */
    PPPOE_CODE_PADN = 0xd4
};

/**
 * @class PPPoELayer
 * Класс, описывающий протокол PPPoE.
 */
class PPPoELayer : public Layer {
  public:
    PPPoELayer(const uint8_t *data, size_t size, Layer *prevLayer = nullptr, Layer *nextLayer = nullptr);

    size_t getHeaderLen() const override;
    size_t getLayerPayloadSize() const override;

    PppoeHeader *getPPPoEHeader() const;
    PPPoECode getHeaderCode() const;
};
} // namespace Nta::Network
