#pragma once

#include "Handlers/Dpdk/Power/RtePower.h"
#include <rte_cycles.h>

namespace Nta::Network::Power {

struct Dummy : PowerManagmentVirt<Dummy> {

    void Enable(const uint16_t, const uint16_t, const unsigned int) {}

    void Disable(const uint16_t, const uint16_t, const unsigned int) {}

    bool Idle(const size_t) { return false; }
};

struct Legacy : PowerManagmentVirt<Legacy> {
  private:
    const unsigned int m_EmptyPolls;
    const unsigned int m_Duration;
    unsigned int m_EmptyPollsActual{0};
    bool m_Enabled{false};

  public:
    /*!
     * \brief Legacy power policy. Wait at least (duration x polls) microseconds.
     * \param polls
     * \param The number of microseconds to wait.
     */
    Legacy(unsigned int polls, unsigned int duration) : m_EmptyPolls{polls}, m_Duration{duration} {}

    void Enable(const uint16_t, const uint16_t, const unsigned int) { m_Enabled = true; }

    void Disable(const uint16_t, const uint16_t, const unsigned int) { m_Enabled = false; }

    bool Idle(const size_t nbPkts) {
        if (!m_Enabled) {
            return false;
        }

        if (m_Duration == 0) {
            return false;
        }

        if (nbPkts > 0) {
            m_EmptyPollsActual = 0;
            return false;
        }

        // No packets received
        m_EmptyPollsActual++;

        if (m_EmptyPollsActual < m_EmptyPolls)
            return false;

        rte_delay_us_sleep(m_Duration);

        return true;
    }
};
} // namespace Nta::Network::Power
