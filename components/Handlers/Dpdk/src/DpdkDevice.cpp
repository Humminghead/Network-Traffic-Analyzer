#include "Handlers/Dpdk/DpdkDevice.h"
#include "Util/Misc.h"
#include <iostream>
#include <rte_branch_prediction.h>
#include <rte_build_config.h>
#include <rte_config.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

namespace Nta::Network {

struct DpdkDevice::Impl {
    std::vector<MbufArray> m_BufArray{RTE_MAX_LCORE};
    DpdkDevicePtr m_Dev{nullptr, [](auto *) {}};
    pcpp::DpdkDevice::DpdkDeviceConfiguration
        m_Config{128, 512, 100, pcpp::DpdkDevice::DpdkRssHashFunction::RSS_NONE, nullptr, 0};
};

uint16_t DpdkDevice::RecivePackets(const uint16_t queueId, MbufArray &m_BufArray) {
    if (unlikely(!m_Impl->m_Dev)) {
        throw std::runtime_error("Device doesn't exist!");
    }

    if (unlikely(!m_Impl->m_Dev->isOpened())) {
        throw std::runtime_error("Device is not opened!");
    }

    if (unlikely(queueId >= m_Impl->m_Dev->getTotalNumOfRxQueues())) {
        ///\todo log  throw std::runtime_error("RX queue ID #" + std::to_string(queueId) + " not available for this
        /// device");
        return 0;
    }

    return rte_eth_rx_burst(
        m_Impl->m_Dev->getDeviceId(), queueId, m_BufArray.data(), Util::Std::ArraySize<MbufArray>::size);
}

uint16_t DpdkDevice::SendPackets(const uint16_t queueId, MbufArray &bufArray, const uint16_t nbPkts) {
    if (unlikely(!m_Impl->m_Dev)) {
        throw std::runtime_error("Device doesn't exist!");
    }

    if (unlikely(!m_Impl->m_Dev->isOpened())) {
        throw std::runtime_error("Device is not opened!");
    }

    if (unlikely(queueId >= m_Impl->m_Dev->getNumOfOpenedTxQueues())) {
        ///\todo log  throw std::runtime_error("TX queue isn't opened in device!");
        return 0;
    }

    return rte_eth_tx_burst(m_Impl->m_Dev->getDeviceId(), queueId, bufArray.data(), nbPkts);
}

auto PrefetchCpuCache(const DpdkDevice::MbufArray &rxPkts, const size_t prefetchCount) -> void {
    for (auto i = 0; i < prefetchCount && i < Util::Std::ArraySize<DpdkDevice::MbufArray>::size; i++) {
        rte_prefetch0(rte_pktmbuf_mtod(rxPkts[i], void *));
    }
}

DpdkDevice::DpdkDevicePtr::element_type *DpdkDevice::GetRawDevecePtr() {
    return m_Impl->m_Dev.get();
}

auto DpdkDevice::GetNumberRxPacketsMax() const noexcept -> size_t {
    return m_Impl->m_BufArray.size();
}

std::string DpdkDevice::GetPMDName() const {
    if (!m_Impl->m_Dev)
        return {"PMD: nullptr"};
    return m_Impl->m_Dev->getPMDName();
}

int DpdkDevice::GetDeviceId() const noexcept {
    if (!m_Impl->m_Dev)
        return -1;
    return m_Impl->m_Dev->getDeviceId();
}

bool DpdkDevice::OpenMultiQueues(const uint16_t numOfRxQueuesToOpen, const uint16_t numOfTxQueuesToOpen) noexcept {
    if (!m_Impl->m_Dev)
        return false;
    return m_Impl->m_Dev->openMultiQueues(numOfRxQueuesToOpen, numOfTxQueuesToOpen, m_Impl->m_Config);
}

uint16_t DpdkDevice::GetTotalNumOfTxQueues() const noexcept {
    if (!m_Impl->m_Dev)
        return 0;
    return m_Impl->m_Dev->getTotalNumOfRxQueues();
}

uint16_t DpdkDevice::GetTotalNumOfRxQueues() const noexcept {
    if (!m_Impl->m_Dev)
        return 0;
    return m_Impl->m_Dev->getTotalNumOfRxQueues();
}

DpdkDevice::MbufArray &DpdkDevice::GetMbufArray(const int coreId) {
    if (constexpr auto mbSize = Util::Std::ArraySize<MbufArray>::size; coreId > mbSize)
        throw std::runtime_error(
            "core id: " + std::to_string(coreId) + "is out of device buffer range:" + std::to_string(mbSize) + "!");
    return m_Impl->m_BufArray[coreId];
}

DpdkDevice::DpdkDevice(pcpp::DpdkDevice *dev, const size_t nbRx)
    : m_Impl{new Impl(), [](DpdkDevice::Impl *p) { delete p; }} {
    m_Impl->m_Dev.reset(dev);
}

DpdkDevice::DpdkDevice(DpdkDevicePtr dev, const size_t nbRx)
    : m_Impl{new DpdkDevice::Impl(), [](DpdkDevice::Impl *p) { delete p; }} {
    m_Impl->m_Dev = std::move(dev);
}

} // namespace Nta::Network
