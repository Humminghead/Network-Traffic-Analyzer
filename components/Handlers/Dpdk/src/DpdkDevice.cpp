#include "Handlers/Dpdk/DpdkDevice.h"
#include <rte_branch_prediction.h>
#include <rte_ethdev.h>

namespace Nta::Network {
uint16_t DpdkDevice::RecivePackets(const uint16_t queueId, const int coreId) {    
    if (coreId > m_BufArray.size()) {
        throw std::runtime_error("core id: " + std::to_string(coreId) + "is out of device buffer range!");
    }

    if (unlikely(!m_Dev->isOpened())) {
        throw std::runtime_error("Device is not opened!");
    }

    if (unlikely(queueId >= m_Dev->getTotalNumOfRxQueues())) {
        ///\todo log  throw std::runtime_error("RX queue ID #" + std::to_string(queueId) + " not available for this
        /// device");
        return 0;
    }

    return rte_eth_rx_burst(m_Dev->getDeviceId(), queueId, m_BufArray[coreId].data(), m_BufArray[coreId].size());
}

uint16_t DpdkDevice::SendPackets(const uint16_t queueId, MbufArray &bufArray) {
    if (unlikely(!m_Dev->isOpened())) {
        throw std::runtime_error("Device is not opened!");
    }

    if (unlikely(queueId >= m_Dev->getNumOfOpenedTxQueues())) {
        ///\todo log  throw std::runtime_error("TX queue isn't opened in device!");
        return 0;
    }

    rte_mbuf **mBufArr = bufArray.data();
    return rte_eth_tx_burst(m_Dev->getDeviceId(), queueId, mBufArr, bufArray.size());
}
} // namespace Nta::Network
