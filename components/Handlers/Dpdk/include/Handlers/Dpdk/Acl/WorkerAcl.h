#pragma once

#include "Handlers/Dpdk/Acl/AbstractWorker.h"
#include "Handlers/Dpdk/Acl/LookupAcl.h"
#include "Handlers/Dpdk/DpdkDevice.h"
#include "Handlers/Dpdk/Power/RtePower.h"
#include <NetDecoder/Decoder.h>
#include <atomic>
// #include <pcapplusplus/DpdkDeviceList.h>

namespace Nta::Network {

class WorkerAcl : public AbstractWorker {
  private:
    struct RuntimeVariable {
        uint16_t numRxPackets{0};
        uint16_t numTxPackets{0};
        size_t n{0};
        uint16_t matchPacketsCounter{0};

        void Reset() {
            numRxPackets = 0;
            numTxPackets = 0;
            n = 0;
            matchPacketsCounter = 0;
        }
    };

    std::shared_ptr<DpdkDevice> m_RxDevice{nullptr};
    std::shared_ptr<DpdkDevice> m_TxDevice{nullptr};
    std::atomic_bool m_Stop{true};
    uint32_t m_CoreId{RTE_MAX_LCORE};
    std::shared_ptr<RteAclContext> m_AclContext{nullptr};
    RteLookupAcl m_AclLookUp;
    std::vector<MbufArray> m_PacketBuffers{};
    std::vector<MbufArray> m_MatchPackets{};
    NetDecoder m_Decoder{};
    RteLookupAcl::PacketPointers m_AclDataPtrs;
    std::vector<int> m_QueueIndicesRx{};
    std::vector<int> m_QueueIndicesTx{};
    RuntimeVariable m_Rv{};
    bool m_StopAtEmptyRx{false};
    uint16_t m_LinkLayer{};    
    std::unique_ptr<Power::PowerManagment> m_PowerManagment{nullptr};

  public:
    WorkerAcl(
        std::shared_ptr<DpdkDevice> rxDevice,
        std::shared_ptr<DpdkDevice> txDevice,
        std::shared_ptr<RteAclContext> context,
        const size_t categories,
        const uint16_t linkLayer,
        const uint32_t core,
        const uint16_t nbPkts);

    virtual ~WorkerAcl() = default;

    /*!
     * \brief start running the worker thread
     * \param coreId
     * \return
     */
    int Run(void *) override;

    /*!
     * \brief ask the worker thread to Stop
     */
    void Stop() override;

    /*!
     * \brief GetCoreId
     * \return
     */
    uint32_t GetCoreId() const override;    

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

    /*!
     * \brief SetQueueIdxRx
     * \param idx
     */
    void SetQueueIdxRx(const int &idx);

    /*!
     * \brief SetQueueIdxTx
     * \param idx
     */
    void SetQueueIdxTx(const int &idx);

    /*!
     * \brief Enables the worker thread to stop if the rx queue is empty
     * \param true or false
     */
    void StopAtEmptyRxEnable(const bool enable) noexcept;

    /*!
     * \brief Set power mamagment policy
     * \param managment pointer
     */
    void SetPowerMgmt(decltype(m_PowerManagment)&& mgmt);
};
} // namespace Nta::Network
