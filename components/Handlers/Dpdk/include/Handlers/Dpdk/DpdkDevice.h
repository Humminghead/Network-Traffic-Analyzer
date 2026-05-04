#pragma once

#include <Device.h>
#include <Util/Misc.h>
#include <cstdint>
#include <memory>

struct rte_mempool;

namespace Nta::Network {

class DpdkDevice : public Device::AbstractDevice {
  public:
    explicit DpdkDevice(const uint16_t id, bool promisc = false);

    /*!
     * \brief DpdkDevice::Configure
     */
    auto Configure() -> void;

    /*!
     * \brief SetupRxQueue
     * \param queueId
     */
    auto SetupRxQueue(const uint16_t queueId) -> void;

    /*!
     * \brief SetupTxQueue
     * \param queueId
     */
    auto SetupTxQueue(const uint16_t queueId) -> void;

    /*!
     * \brief Open the device
     */
    auto Open() -> void override;

    /*!
     * \brief Closes the device
     */
    auto Close() -> void override;

    /*!
     * \brief Check whether the device is open or not
     * \return true if open. Otherwise, false.
     */
    auto IsOpen() const -> bool override;

    /*!
     * \brief RecivePackets
     * \param device
     * \param queueId
     * \return
     */
    uint16_t RecivePackets(const uint16_t queueId, MbufArray &m_BufArray) override;

    /*!
     * \brief SendPackets
     * \param device
     * \param queueId
     * \param bufArray
     * \return
     */
    uint16_t SendPackets(const uint16_t queueId, MbufArray &bufArray, const uint16_t nbPkts) override;

    /*!
     * \brief GetMbufArray
     * \param coreId
     * \return
     */
    std::string_view GetDeviceName() const noexcept;

    /*!
     * \brief GetDeviceId
     * \return
     */
    int GetDeviceId() const noexcept;

    /*!
     * \brief GetSocketId
     * \return
     */
    int GetSocketId() const noexcept;

    /*!
     * \brief GetTotalNumOfRxQueues
     * \return
     */
    int GetTotalNumOfRxQueues() const noexcept;

    /*!
     * \brief GetTotalNumOfTxQueues
     * \return
     */
    int GetTotalNumOfTxQueues() const noexcept;

    /*!
     * \brief SetRteMemPoll
     * \param mp
     */
    void SetRteMemPool(rte_mempool *mp) noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl, void (*)(Impl *)> m_Impl;
};

auto PrefetchCpuCache(const MbufArray &rxPkts, const size_t prefetchCount) -> void;

} // namespace Nta::Network
