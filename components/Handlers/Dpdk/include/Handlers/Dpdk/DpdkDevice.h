#pragma once

#include <DpdkDevice.h>
#include <Util/Misc.h>
#include <functional>

struct rte_mbuf;

namespace Nta::Network {
class DpdkDevice {
  public:
    using DpdkDevicePtr = std::unique_ptr<pcpp::DpdkDevice, std::function<void(pcpp::DpdkDevice *)>>;
    using MbufArray = std::array<rte_mbuf *, 128>; //RTE_MAX_LCORE

    DpdkDevice(pcpp::DpdkDevice *dev, const size_t nbRx = Util::Std::ArraySize<MbufArray>::size);

    DpdkDevice(DpdkDevicePtr dev, const size_t nbRx = Util::Std::ArraySize<MbufArray>::size);

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

    auto GetMbufArray(const int coreId) -> MbufArray &;

    uint16_t GetTotalNumOfRxQueues() const noexcept;

    uint16_t GetTotalNumOfTxQueues() const noexcept;

    bool OpenMultiQueues(const uint16_t numOfRxQueuesToOpen, const uint16_t numOfTxQueuesToOpen) noexcept;

    int GetDeviceId() const noexcept;

    std::string GetPMDName() const;

    auto GetNumberRxPacketsMax() const noexcept -> size_t;

    DpdkDevicePtr::element_type *GetRawDevecePtr();

  private:
    struct Impl;
    std::unique_ptr<Impl, void (*)(Impl *)> m_Impl;
};

auto PrefetchCpuCache(const DpdkDevice::MbufArray &rxPkts, const size_t prefetchCount) -> void;

} // namespace Nta::Network
