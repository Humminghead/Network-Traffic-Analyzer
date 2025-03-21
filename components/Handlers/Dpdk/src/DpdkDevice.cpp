#include "Handlers/Dpdk/DpdkDevice.h"
#include "Util/Misc.h"
#include <rte_branch_prediction.h>
#include <rte_ethdev.h>

namespace Nta::Network {
uint16_t DpdkDevice::RecivePackets(const uint16_t queueId, MbufArray &m_BufArray) {
    if (unlikely(!m_Dev->isOpened())) {
        throw std::runtime_error("Device is not opened!");
    }

    if (unlikely(queueId >= m_Dev->getTotalNumOfRxQueues())) {
        ///\todo log  throw std::runtime_error("RX queue ID #" + std::to_string(queueId) + " not available for this
        /// device");
        return 0;
    }

    return rte_eth_rx_burst(m_Dev->getDeviceId(), queueId, m_BufArray.data(), Util::Std::ArraySize<MbufArray>::size);
}

uint16_t DpdkDevice::SendPackets(const uint16_t queueId, MbufArray &bufArray, const uint16_t nbPkts) {
    if (unlikely(!m_Dev->isOpened())) {
        throw std::runtime_error("Device is not opened!");
    }

    if (unlikely(queueId >= m_Dev->getNumOfOpenedTxQueues())) {
        ///\todo log  throw std::runtime_error("TX queue isn't opened in device!");
        return 0;
    }

    return rte_eth_tx_burst(m_Dev->getDeviceId(), queueId, bufArray.data(), nbPkts);
}

auto PrefetchCpuCache(const DpdkDevice::MbufArray &rxPkts, const size_t prefetchCount) -> void {
    for (auto i = 0; i < prefetchCount && i < Util::Std::ArraySize<DpdkDevice::MbufArray>::size; i++) {
        rte_prefetch0(rte_pktmbuf_mtod(rxPkts[i], void *));
    }
}

} // namespace Nta::Network
