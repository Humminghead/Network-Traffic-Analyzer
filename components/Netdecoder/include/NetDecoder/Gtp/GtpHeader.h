#pragma once

#include <stdint.h>

namespace Nta::Network {

#define GTP_VERSION_0 0
#define GTP_VERSION_1 1
#define GTP_VERSION_2 2

/*! Заголовок протокола GTPv1*/
struct Gtp1Hdr {
    uint32_t teid; //Есть всегда в Gtp1
    uint16_t seqno;
    uint8_t npduno;
    uint8_t nexthdr;
} __attribute__((packed));

/*! Заголовок протокола GTPv2*/
struct Gtp2Hdr {
    union {
        uint32_t teid; // Наличие зависит от флага T в заголовке Gtp2
        uint32_t seq0; /*!< Номер последовательности (на самом деле 16 бит, следом 2 зарезервированных октета)*/
    } t_field;

    // 3GPP TS 29.274 version 16.5.0 Release 16
    // Figure 5.1-1: General format of GTPv2 Header for Control Plane
    uint32_t seq1; // Sequence Number + Spare

    /*!
     * \brief Return sequence number
     * \param GTPv2 header bytes
     * \return Pure sequence number without spare
     */
    uint32_t seq(const uint8_t &flags) const {
        return (((flags & 0b00001000 ? seq1 : t_field.seq0) & 0x00FFFFFF) << 8);
    };

    /*!
     * \brief Return teid
     * \param GTPv2 header bytes
     * \return If teid present, returns teid, overwise return 0
     */
    uint32_t teid(const uint8_t &flags) const { return flags & 0b00001000 ? t_field.teid : 0; };

} __attribute__((packed));

struct GtpCommon {
    uint8_t flags;
    uint8_t msgtype;
    uint16_t length;
} __attribute__((packed));

struct GtpHeader {
    GtpCommon common;
    union {
        struct Gtp1Hdr gtpv1_hdr;
        struct Gtp2Hdr gtpv2_hdr;
    } in;
} __attribute__((packed));
} // namespace Nta::Network
