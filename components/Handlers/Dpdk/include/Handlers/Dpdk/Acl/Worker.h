#pragma once

#include "Handlers/Dpdk/Acl/LookupAcl.h"
#include "Handlers/Dpdk/DpdkDevice.h"
#include <DpdkDeviceList.h>
#include <NetDecoder/Decoder.h>
#include <atomic>

namespace Nta::Network {
class Worker : public pcpp::DpdkWorkerThread {
  private:
    std::shared_ptr<DpdkDevice> m_RxDevice{nullptr};
    std::shared_ptr<DpdkDevice> m_TxDevice{nullptr};
    std::atomic_bool m_Stop{true};
    uint32_t m_CoreId{RTE_MAX_LCORE};
    RteAclContext m_AclContext{};
    RteLookupAcl m_AclLookUp{};
    DpdkDevice::MbufArray m_MatchPackets;
    NetDecoder m_Decoder{};
    RteLookupAcl::PacketPointers m_AclDataPtrs;

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
