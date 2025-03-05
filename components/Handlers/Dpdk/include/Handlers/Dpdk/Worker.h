#pragma once

#include "Handlers/Dpdk/Acl/LookupAcl.h"
#include <DpdkDevice.h>
#include <DpdkDeviceList.h>
#include <atomic>
#include <rte_build_config.h>
#include <thread>
#include <vector>

namespace Nta::Network {

class Dummy : public pcpp::DpdkWorkerThread {
  private:
    std::atomic_bool m_Stop{true};
    uint32_t m_CoreId{RTE_MAX_LCORE};

  public:
    Dummy() = default;
    virtual ~Dummy() = default;

    /*!
     * \brief start running the worker thread
     * \param coreId
     * \return
     */
    bool run(uint32_t coreId) override {
        m_CoreId = coreId;
        m_Stop.exchange(false);

        while (!m_Stop.load()) {
            using namespace std::chrono;
            std::this_thread::sleep_for(1s);
        }
        return true;
    }

    /*!
     * \brief ask the worker thread to stop
     */
    void stop() override { m_Stop.exchange(true); }

    /*!
     * \brief getCoreId
     * \return
     */
    uint32_t getCoreId() const override { return m_CoreId; }
};

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

    auto GetMbufArray() const noexcept -> MbufArray { return m_BufArray; }

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

    bool OpenMultiQueues(const uint16_t numOfRxQueuesToOpen, const uint16_t numOfTxQueuesToOpen) noexcept{
        if (!m_Dev)
            return false;
        return m_Dev->openMultiQueues(numOfRxQueuesToOpen,numOfTxQueuesToOpen,m_Config);
    }

    int GetDeviceId() const noexcept {
        if (!m_Dev)
            return -1;
        return m_Dev->getDeviceId();
    }

    std::string GetPMDName() const
    {
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

class Worker : public pcpp::DpdkWorkerThread {
  private:
    std::shared_ptr<DpdkDevice> m_RxDevice{nullptr};
    std::shared_ptr<DpdkDevice> m_TxDevice{nullptr};
    std::atomic_bool m_Stop{true};
    uint32_t m_CoreId{RTE_MAX_LCORE};
    RteAclContext m_AclContext{};
    RteLookupAcl m_AclLookUp{};
    DpdkDevice::MbufArray m_MatchPackets;

  public:
    Worker(std::shared_ptr<DpdkDevice> rxDevice, std::shared_ptr<DpdkDevice> txDevice, RteAclContext &&context);

    virtual ~Worker() = default;

    /*!
     * \brief start running the worker thread
     * \param coreId
     * \return
     */
    bool run(uint32_t coreId) override;

    /*!
     * \brief ask the worker thread to stop
     */
    void stop() override;

    /*!
     * \brief getCoreId
     * \return
     */
    uint32_t getCoreId() const override;
};
} // namespace Nta::Network
