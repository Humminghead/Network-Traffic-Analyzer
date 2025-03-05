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

class Worker : public pcpp::DpdkWorkerThread {
  private:
    pcpp::DpdkDevice *m_RxDevice{nullptr};
    pcpp::DpdkDevice *m_TxDevice{nullptr};
    std::atomic_bool m_Stop{true};
    uint32_t m_CoreId{RTE_MAX_LCORE};
    RteAclContext m_AclContext{};
    RteLookupAcl m_AclLookUp{};
    // std::unique_ptr<std::array<pcpp::MBufRawPacket, 64>> pack;

    std::vector<rte_mbuf *> m_BufArray{};

    uint16_t RecivePackets(pcpp::DpdkDevice *rxDevice, const uint16_t rxQueueId);

  public:
    Worker(
        pcpp::DpdkDevice *rxDevice,
        pcpp::DpdkDevice *txDevice,
        RteAclContext &&context,
        const size_t rxPacketMaxCount = 64);

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
