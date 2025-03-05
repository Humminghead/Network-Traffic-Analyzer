#include "Handlers/Dpdk/Worker.h"
#include <rte_ethdev.h>

namespace Nta::Network {

uint16_t Worker::RecivePackets(pcpp::DpdkDevice *device, const uint16_t queueId /*, pcpp::MBufRawPacket **packets*/) {
    if (unlikely(!device->isOpened())) {
        throw std::runtime_error("Device not opened!");
    }

    if (unlikely(queueId >= device->getTotalNumOfRxQueues())) {
        throw std::runtime_error("RX queue ID #" + std::to_string(queueId) + " not available for this device");
    }

    // if (unlikely(packets == nullptr)) {
    //     throw std::runtime_error("Provided address of array to store packets is nullptr");
    // }

    return rte_eth_rx_burst(device->getDeviceId(), queueId, m_BufArray.data(), m_BufArray.size());
}

Worker::Worker(pcpp::DpdkDevice *rxDevice, pcpp::DpdkDevice *txDevice, RteAclContext &&context, const size_t rxPacketMaxCount)
    : m_RxDevice{rxDevice}
    , m_TxDevice{txDevice}
    , m_AclContext{std::move(context)}
    , m_BufArray{rxPacketMaxCount}
{}

bool Worker::run(uint32_t coreId) {
    if (!m_RxDevice || !m_TxDevice)
        return false;

    m_CoreId = coreId;
    m_Stop.exchange(false);

    while (!m_Stop.load()) {
        // receive packets from RX device
        if (uint16_t numOfPackets = RecivePackets(m_RxDevice, 0); numOfPackets > 0) {

            PrefetchCpuCache(m_BufArray,3);
            m_AclLookUp.Classify(m_AclContext,m_BufArray);;

            // send received packet on the TX device
            // m_TxDevice->sendPackets(mbufArr, numOfPackets, 0);
            auto erased = std::erase_if(m_BufArray, [](rte_mbuf *buf) {
                if (likely(buf != nullptr)) {
                    rte_pktmbuf_free(buf);
                    return true;
                }
                return false;
            });
            m_BufArray.insert(std::end(m_BufArray), erased, nullptr);
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
