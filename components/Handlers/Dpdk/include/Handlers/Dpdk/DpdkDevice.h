#pragma once

#include <DpdkDevice.h>
#include <functional>

namespace Nta::Network {
class DpdkDevice {
public:
    using DpdkDevicePtr = std::unique_ptr<pcpp::DpdkDevice, std::function<void(pcpp::DpdkDevice *)>>;
    using MbufArray = std::vector<rte_mbuf *>;

    DpdkDevice(pcpp::DpdkDevice *dev) { m_Dev.reset(dev); }

    DpdkDevice(DpdkDevicePtr dev) : m_Dev{std::move(dev)} {}

    /*!
     * \brief RecivePackets
     * \param device
     * \param queueId
     * \return
     */
    uint16_t RecivePackets(const uint16_t queueId);

    /*!
     * \brief SendPackets
     * \param device
     * \param queueId
     * \param bufArray
     * \return
     */
    uint16_t SendPackets(const uint16_t queueId, MbufArray &bufArray);

    auto GetMbufArray() const noexcept -> const MbufArray & { return m_BufArray; }

    uint16_t GetTotalNumOfRxQueues() const noexcept {
        if (!m_Dev)
            return 0;
        return m_Dev->getTotalNumOfRxQueues();
    }

    uint16_t GetTotalNumOfTxQueues() const noexcept {
        if (!m_Dev)
            return 0;
        return m_Dev->getTotalNumOfRxQueues();
    }

    bool OpenMultiQueues(const uint16_t numOfRxQueuesToOpen, const uint16_t numOfTxQueuesToOpen) noexcept {
        if (!m_Dev)
            return false;
        return m_Dev->openMultiQueues(numOfRxQueuesToOpen, numOfTxQueuesToOpen, m_Config);
    }

    int GetDeviceId() const noexcept {
        if (!m_Dev)
            return -1;
        return m_Dev->getDeviceId();
    }

    std::string GetPMDName() const {
        if (!m_Dev)
            return {"PMD: nullptr"};
        return m_Dev->getPMDName();
    }

private:
    MbufArray m_BufArray{64};
    DpdkDevicePtr m_Dev{nullptr, [](auto *) {}};
    pcpp::DpdkDevice::DpdkDeviceConfiguration
        m_Config{128, 512, 100, pcpp::DpdkDevice::DpdkRssHashFunction::RSS_NONE, nullptr, 0};
};
}
