#pragma once

#include <DpdkDevice.h>
#include <Util/Misc.h>
#include <functional>
#include <rte_build_config.h>
#include <rte_config.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

namespace Nta::Network {
class DpdkDevice {
  public:
    using DpdkDevicePtr = std::unique_ptr<pcpp::DpdkDevice, std::function<void(pcpp::DpdkDevice *)>>;
    using MbufArray = std::array<rte_mbuf *, RTE_MAX_LCORE>;

    DpdkDevice(pcpp::DpdkDevice *dev, const size_t nbRx = Util::Std::ArraySize<MbufArray>::size)
        : m_BufArray(RTE_MAX_LCORE) {
        m_Dev.reset(dev);
    }

    DpdkDevice(DpdkDevicePtr dev, const size_t nbRx = Util::Std::ArraySize<MbufArray>::size)
        : m_BufArray(RTE_MAX_LCORE), m_Dev{std::move(dev)} {}

    /*!
     * \brief RecivePackets
     * \param device
     * \param queueId
     * \return
     */
    uint16_t RecivePackets(const uint16_t queueId, MbufArray &m_BufArray);

    /*!
     * \brief SendPackets
     * \param device
     * \param queueId
     * \param bufArray
     * \return
     */
    uint16_t SendPackets(const uint16_t queueId, MbufArray &bufArray, const uint16_t nbPkts);

    auto GetMbufArray(const int coreId) -> MbufArray & {
        if (constexpr auto mbSize = Util::Std::ArraySize<MbufArray>::size; coreId > mbSize)
            throw std::runtime_error(
                "core id: " + std::to_string(coreId) + "is out of device buffer range:" + std::to_string(mbSize) + "!");
        return m_BufArray[coreId];
    }

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

    auto GetNumberRxPacketsMax() const noexcept -> size_t { return m_BufArray.size(); }

    auto GetRawDevecePtr() -> const pcpp::DpdkDevice * { return m_Dev.get(); }

  private:
    std::vector<MbufArray> m_BufArray{};
    DpdkDevicePtr m_Dev{nullptr, [](auto *) {}};
    pcpp::DpdkDevice::DpdkDeviceConfiguration
        m_Config{128, 512, 100, pcpp::DpdkDevice::DpdkRssHashFunction::RSS_NONE, nullptr, 0};
};

auto PrefetchCpuCache(const DpdkDevice::MbufArray &rxPkts, const size_t prefetchCount) -> void;

} // namespace Nta::Network
