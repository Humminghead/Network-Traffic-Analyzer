#pragma once

#include "Handlers/Dpdk/Acl/LookupAcl.h"
#include "Handlers/Dpdk/DpdkDevice.h"
#include <DpdkDeviceList.h>
#include <NetDecoder/Decoder.h>
#include <atomic>

namespace Nta::Network {
class WorkerAcl : public pcpp::DpdkWorkerThread {
  private:
    std::shared_ptr<DpdkDevice> m_RxDevice{nullptr};
    std::shared_ptr<DpdkDevice> m_TxDevice{nullptr};
    std::atomic_bool m_Stop{true};
    uint32_t m_CoreId{RTE_MAX_LCORE};
    std::shared_ptr<RteAclContext> m_AclContext{nullptr};
    RteLookupAcl m_AclLookUp{};
    DpdkDevice::MbufArray m_MatchPackets;
    NetDecoder m_Decoder{};
    RteLookupAcl::PacketPointers m_AclDataPtrs;
    std::vector<int> m_QueueIndicesRx{};
    std::vector<int> m_QueueIndicesTx{};

  public:
    WorkerAcl(
        std::shared_ptr<DpdkDevice> rxDevice,
        std::shared_ptr<DpdkDevice> txDevice,
        std::shared_ptr<RteAclContext> context,
        const uint32_t core = RTE_MAX_LCORE);

    virtual ~WorkerAcl() = default;

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

    /*!
     * \brief SetCoreId
     * \param id
     */
    void SetCoreId(const uint32_t id);

    /*!
     * \brief SetQueueIdxsRx
     * \param idxs
     */
    void SetQueueIdxsRx(const std::vector<int> &idxs);

    /*!
     * \brief SetQueueIdxsTx
     * \param idxs
     */
    void SetQueueIdxsTx(const std::vector<int> &idxs);
};
} // namespace Nta::Network
