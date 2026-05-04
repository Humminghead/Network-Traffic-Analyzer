#include "Handlers/Dpdk/DpdkDevice.h"
#include <rte_ethdev.h>
#include <rte_memory.h>

namespace Nta::Network {

struct DpdkDevice::Impl {
    bool m_IsStarted{false};
    bool m_PromiscModeEn{false};
    uint16_t m_PortId{0};
    int m_SocketId{SOCKET_ID_ANY};
    uint16_t m_NbRxDesc{128}; // DPDK's default (RX_DESC_PER_QUEUE)
    uint16_t m_NbTxDesc{512}; // DPDK's default (TX_DESC_PER_QUEUE)
    struct rte_eth_conf m_EthConf {};
    struct rte_eth_dev_info m_DevInfo {};
    struct rte_mempool *m_MbPool{nullptr};
};

DpdkDevice::DpdkDevice(const uint16_t id, bool promisc)
    : m_Impl{new DpdkDevice::Impl(), [](auto *impl) { delete impl; }} {

    if (!rte_eth_dev_is_valid_port(id))
        throw std::runtime_error("Device(" + std::to_string(id) + ") has invalid port!");

    m_Impl->m_PromiscModeEn = promisc;
    m_Impl->m_PortId = id;
    m_Impl->m_SocketId = rte_eth_dev_socket_id(id);

    if (rte_eth_dev_info_get(m_Impl->m_PortId, &m_Impl->m_DevInfo) != 0)
        throw std::runtime_error("Error during getting device (" + std::to_string(id) + ") info!");
}

auto DpdkDevice::Configure() -> void {
    const auto portId = m_Impl->m_PortId;

    if (auto ret = rte_eth_dev_configure(
            portId, m_Impl->m_DevInfo.max_rx_queues, m_Impl->m_DevInfo.max_tx_queues, &m_Impl->m_EthConf);
        ret < 0)
        throw std::runtime_error(
            "Cannot configure device: ret=" + std::to_string(ret) + ", port:=" + std::to_string(portId) + "\n");
}

auto DpdkDevice::SetupRxQueue(const uint16_t queueId) -> void {
    const auto portId = m_Impl->m_PortId;
    const auto rxqConf = m_Impl->m_DevInfo.default_rxconf;

    if (auto ret =
            rte_eth_rx_queue_setup(portId, queueId, m_Impl->m_NbRxDesc, m_Impl->m_SocketId, &rxqConf, m_Impl->m_MbPool);
        ret != 0) {
        throw std::runtime_error("Device(" + std::to_string(portId) + ") RX queue setup failed!");
    }
}

auto DpdkDevice::SetupTxQueue(const uint16_t queueId) -> void {
    const auto portId = m_Impl->m_PortId;
    const auto txqConf = m_Impl->m_DevInfo.default_txconf;

    if (auto ret = rte_eth_tx_queue_setup(portId, queueId, m_Impl->m_NbTxDesc, m_Impl->m_SocketId, &txqConf); ret != 0)
        throw std::runtime_error("Device(" + std::to_string(portId) + ") TX queue setup failed!");
}

auto DpdkDevice::Open() -> void {
    if (m_Impl->m_IsStarted)
        return;

    const auto portId = m_Impl->m_PortId;

    if (auto ret = rte_eth_dev_start(portId); ret < 0)
        throw std::runtime_error("Device(" + std::to_string(portId) + ") start failed!");

    if (m_Impl->m_PromiscModeEn) {
        if (auto ret = rte_eth_promiscuous_enable(portId); ret != 0)
            throw std::runtime_error("Error during enabling promiscuous mode for port " + std::to_string(portId));
    }

    m_Impl->m_IsStarted = true;
}

auto DpdkDevice::Close() -> void {
    if (!m_Impl->m_IsStarted)
        return;

    if (auto ret = rte_eth_dev_stop(m_Impl->m_PortId); ret != 0)
        throw std::runtime_error("Device(" + std::to_string(m_Impl->m_PortId) + ") stop failed!");

    m_Impl->m_IsStarted = false;
}

auto DpdkDevice::IsOpen() const -> bool {
    return m_Impl->m_IsStarted;
}

uint16_t DpdkDevice::RecivePackets(const uint16_t queueId, MbufArray &m_BufArray) {
    if (unlikely(!IsOpen())) {
        throw std::runtime_error("Device(" + std::to_string(m_Impl->m_PortId) + ") is not opened!");
    }

    if (unlikely(queueId >= m_Impl->m_DevInfo.max_rx_queues)) {
        ///\todo log  throw std::runtime_error("RX queue ID #" + std::to_string(queueId) + " not available for this
        /// device");
        return 0;
    }

    return rte_eth_rx_burst(m_Impl->m_PortId, queueId, m_BufArray.data(), m_BufArray.size());
}

uint16_t DpdkDevice::SendPackets(const uint16_t queueId, MbufArray &bufArray, const uint16_t nbPkts) {
    if (unlikely(!IsOpen())) {
        throw std::runtime_error("Device(" + std::to_string(m_Impl->m_PortId) + ") is not opened!");
    }

    if (unlikely(queueId >= m_Impl->m_DevInfo.max_tx_queues)) {
        ///\todo log  throw std::runtime_error("TX queue isn't opened in device!");
        return 0;
    }

    return rte_eth_tx_burst(m_Impl->m_PortId, queueId, bufArray.data(), nbPkts);
}

auto PrefetchCpuCache(const MbufArray &rxPkts, const size_t prefetchCount) -> void {
    for (auto i = 0; i < prefetchCount && i < rxPkts.size(); i++) {
        rte_prefetch0(rte_pktmbuf_mtod(rxPkts[i], void *));
    }
}

std::string_view DpdkDevice::GetDeviceName() const noexcept {
    return {rte_dev_name(m_Impl->m_DevInfo.device)};
}

int DpdkDevice::GetDeviceId() const noexcept {
    return m_Impl->m_PortId;
}

int DpdkDevice::GetSocketId() const noexcept {
    return m_Impl->m_SocketId;
}

int DpdkDevice::GetTotalNumOfRxQueues() const noexcept {
    return m_Impl->m_DevInfo.max_rx_queues;
}

int DpdkDevice::GetTotalNumOfTxQueues() const noexcept {
    return m_Impl->m_DevInfo.max_tx_queues;
}

void DpdkDevice::SetRteMemPool(rte_mempool *mp) noexcept {
    m_Impl->m_MbPool = mp;
}

} // namespace Nta::Network
