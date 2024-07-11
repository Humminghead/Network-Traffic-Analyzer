#pragma once

#include <cstdint>

/**
 * @struct Заголовок протокола PPPoE.
 */
#pragma pack(push, 1)

struct pppoe_header {
#if (BYTE_ORDER == LITTLE_ENDIAN)
  /** PPPoE версия */
  uint8_t version : 4,
      /** PPPoE тип */
      type : 4;
  /** PPPoE код */
  uint8_t code;
#else
  /** PPPoE version */
  uint16_t version : 4,
      /** PPPoE type */
      type : 4,
      /** PPPoE code */
      code : 8;
#endif
  /** Идентификатор сеанса PPPoE (относится только к пакетам сеанса PPPoE) */
  uint16_t sessionId;
  /** Длина включая заголовок PPPoE */
  uint16_t payloadLength;
};

#pragma pack(pop)
