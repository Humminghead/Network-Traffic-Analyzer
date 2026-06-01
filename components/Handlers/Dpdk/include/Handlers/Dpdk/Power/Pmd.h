#pragma once

#include "Handlers/Dpdk/Power/RtePower.h"
#include <format>
#include <rte_power_pmd_mgmt.h>
#include <stdexcept>

namespace Nta::Network::Power {

struct Pmd : public PowerManagmentVirt<Pmd> {
  private:
    unsigned int m_MaxEmptyPolls{3};
    unsigned int m_PauseDuration{1000};
    unsigned int m_Type{RTE_POWER_MGMT_TYPE_PAUSE};
    unsigned int m_ScaleFreqMin{0};
    unsigned int m_ScaleFreqMax{0};
public:
    /*!
     * \brief Init power managment
     * \param portId
     * \param queueId
     * \param lcore
     */
    void Enable(const uint16_t portId, const uint16_t queueId, const unsigned int lcore) {        
        auto pmgmtType = static_cast<rte_power_pmd_mgmt_type>(m_Type);

        m_ScaleFreqMin = rte_power_pmd_mgmt_get_scaling_freq_max(lcore);
        m_ScaleFreqMax = rte_power_pmd_mgmt_get_scaling_freq_max(lcore);

        // Set user config passed by user
        rte_power_pmd_mgmt_set_emptypoll_max(m_MaxEmptyPolls);
        auto ret = rte_power_pmd_mgmt_set_pause_duration(m_PauseDuration);
        if (ret < 0)
            throw std::runtime_error(std::format("Error setting pause_duration: err={}, lcore={}\n", ret, lcore));

        ret = rte_power_pmd_mgmt_set_scaling_freq_min(lcore, m_ScaleFreqMin);
        if (ret < 0)
            throw std::runtime_error(std::format("Error setting scaling freq min: err={}, lcore={}\n", ret, lcore));

        ret = rte_power_pmd_mgmt_set_scaling_freq_max(lcore, m_ScaleFreqMax);
        if (ret < 0)
            throw std::runtime_error(std::format("Error setting scaling freq max: err={}, lcore {}\n", ret, lcore));

        ret = rte_power_ethdev_pmgmt_queue_enable(lcore, portId, queueId, pmgmtType);
        if (ret < 0)
            throw std::runtime_error(std::format(
                "rte_power_ethdev_pmgmt_queue_enable: err={}, port={}\n", ret, static_cast<unsigned int>(portId)));
    }

    void Disable(const uint16_t portId, const uint16_t queueId, const unsigned int lcore){
        auto ret = rte_power_ethdev_pmgmt_queue_disable(lcore, portId, queueId);
        if (ret < 0)
            throw std::runtime_error(std::format(
                "rte_power_ethdev_pmgmt_queue_enable: err={}, port={}\n", ret, static_cast<unsigned int>(portId)));
    }

    bool Idle(const size_t){
        // No idle is needed. The framework inserts a power‑saving callback that automatically pauses or monitors the
        // CPU when the queue is empty.
        return false;
    }

  public:
    /*!
     * \brief The DPDK framework inserts a power‑saving callback that automatically pauses or monitors the CPU when the queue is empty.
     * \param max empty polls
     * \param pause duration in microseconds
     * \param PMD Power Management Type (rte_power_pmd_mgmt_type)
     */
    Pmd(unsigned int polls, unsigned int duration, unsigned int type)
        : m_MaxEmptyPolls{polls}, m_PauseDuration{duration}, m_Type{type} {}
};
} // namespace Nta::Network::Power
