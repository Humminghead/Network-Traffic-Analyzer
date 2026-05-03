#pragma once

#include "Handlers/Dpdk/Acl/LookupAcl.h"
#include "Handlers/Dpdk/DpdkDevice.h"
#include <NetDecoder/Decoder.h>
#include <atomic>
// #include <pcapplusplus/DpdkDeviceList.h>

namespace Nta::Network {

class DpdkWorker {
  public:
    virtual ~DpdkWorker() = default;
    /*!
     * \brief start running the worker thread
     * \param args
     * \return
     */
    virtual int Run(void *args) = 0; //{return false;}

    /*!
     * \brief ask the worker thread to Stop
     */
    virtual auto Stop() -> void = 0; //{}

    /*!
     * \brief GetCoreId
     * \return
     */
    virtual auto GetCoreId() const -> uint32_t = 0; //{ return {};}
};

class WorkerAcl : public DpdkWorker {
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
    RteLookupAcl m_AclLookUp{};
    std::vector<MbufArray> m_PacketBuffers{};
    std::vector<MbufArray> m_MatchPackets{};
    NetDecoder m_Decoder{};
    RteLookupAcl::PacketPointers m_AclDataPtrs;
    std::vector<int> m_QueueIndicesRx{};
    std::vector<int> m_QueueIndicesTx{};
    RuntimeVariable m_Rv{};

  public:
    WorkerAcl(
        std::shared_ptr<DpdkDevice> rxDevice,
        std::shared_ptr<DpdkDevice> txDevice,
        std::shared_ptr<RteAclContext> context,
        const uint32_t core = RTE_MAX_LCORE,
        const uint16_t nbPkts = 64);

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
};
} // namespace Nta::Network
