#include "Handlers/Dpdk/Worker.h"
#include <rte_ethdev.h>

namespace Nta::Network {

uint16_t DpdkDevice::RecivePackets(const uint16_t queueId) {
    if (unlikely(!m_Dev->isOpened())) {
        throw std::runtime_error("Device not opened!");
    }

    if (unlikely(queueId >= m_Dev->getTotalNumOfRxQueues())) {
        throw std::runtime_error("RX queue ID #" + std::to_string(queueId) + " not available for this device");
    }

    return rte_eth_rx_burst(m_Dev->getDeviceId(), queueId, m_BufArray.data(), m_BufArray.size());
}

uint16_t DpdkDevice::SendPackets(const uint16_t queueId, MbufArray &bufArray) {
    if (unlikely(!m_Dev->isOpened())) {
        throw std::runtime_error("Device not opened!");
    }

    if (unlikely(queueId >= m_Dev->getNumOfOpenedTxQueues())) {
        throw std::runtime_error("TX queue isn't opened in device!");
    }

    rte_mbuf **mBufArr = bufArray.data();

    return rte_eth_tx_burst(m_Dev->getDeviceId(), queueId, mBufArr, bufArray.size());
}

Worker::Worker(std::shared_ptr<DpdkDevice> rxDevice, std::shared_ptr<DpdkDevice> txDevice, RteAclContext &&context)
    : m_RxDevice{rxDevice}, m_TxDevice{txDevice}, m_AclContext{std::move(context)} // , m_BufArray{rxPacketMaxCount}
{
    m_MatchPackets.reserve(64);//Eq to DpdkDevice::m_BufArray{64};
}

bool Worker::run(uint32_t coreId) {
    if (!m_RxDevice || !m_TxDevice)
        return false;

    m_CoreId = coreId;
    m_Stop.exchange(false);

    while (!m_Stop.load()) {
        // receive packets from RX device
        if (uint16_t numOfPackets = m_RxDevice->RecivePackets(0); numOfPackets > 0) {

            auto mBufArray = m_RxDevice->GetMbufArray();

            PrefetchCpuCache(mBufArray, 3); ///\todo add 2 cfg
            if (auto [ok, pktIdxs] = m_AclLookUp.Classify(m_AclContext, mBufArray); ok) {
                std::for_each_n(std::begin(pktIdxs), numOfPackets, [&](auto &idx) {
                    if (idx != 0)
                        m_MatchPackets.push_back(mBufArray[idx]);
                });

                // send received packet on the TX device
                m_TxDevice->SendPackets(0, m_MatchPackets);
                m_MatchPackets.clear();
            }

            auto erased = std::erase_if(mBufArray, [](rte_mbuf *buf) {
                if (likely(buf != nullptr)) {
                    rte_pktmbuf_free(buf);
                    return true;
                }
                return false;
            });
            mBufArray.insert(std::end(mBufArray), erased, nullptr);
        }
    }
    return m_Stop.load();
}

void Worker::stop() {
    m_Stop.exchange(true);
}

uint32_t Worker::getCoreId() const {
    return m_CoreId;
}

} // namespace Nta::Network
