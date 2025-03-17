#include "Handlers/Dpdk/Acl/WorkerAcl.h"
#include "Handlers/Dpdk/Acl/Util/Offset.h"
#include <NetDecoder/PacketBase.h>
#include <rte_ethdev.h>

namespace Nta::Network {

WorkerAcl::WorkerAcl(
    std::shared_ptr<DpdkDevice> rxDevice,
    std::shared_ptr<DpdkDevice> txDevice,
    std::shared_ptr<RteAclContext> context,
    const uint32_t core)
    : m_RxDevice{rxDevice}, m_TxDevice{txDevice}, m_AclContext{context}, m_CoreId{core} {
    m_MatchPackets.reserve(64); // Eq to DpdkDevice::m_BufArray{64};
    m_QueueIndicesRx.reserve(RTE_MAX_QUEUES_PER_PORT);
    m_QueueIndicesTx.reserve(RTE_MAX_QUEUES_PER_PORT);
}

bool WorkerAcl::run(uint32_t coreId) {
    if (!m_RxDevice)
        return false;

    if (m_CoreId >= RTE_MAX_LCORE) {
        throw std::runtime_error("Illegal core id: " + std::to_string(coreId) + "!");
    }

    if (m_QueueIndicesRx.empty()) {
        for (auto n = 0; n < m_RxDevice->GetRawDevecePtr()->getTotalNumOfRxQueues(); n++) {
            m_QueueIndicesRx.push_back(n);
        }
    }

    if (m_TxDevice && m_QueueIndicesTx.empty()) {
        for (auto n = 0; n < m_TxDevice->GetRawDevecePtr()->getTotalNumOfTxQueues(); n++) {
            m_QueueIndicesTx.push_back(n);
        }
    }

    m_Stop.exchange(false);

    while (!m_Stop.load()) {
        for (const auto &queueIdRx : m_QueueIndicesRx) {
            // receive packets from RX device
            if (uint16_t numOfPackets = m_RxDevice->RecivePackets(queueIdRx, m_CoreId); numOfPackets > 0) {

                auto mBufArray = m_RxDevice->GetMbufArray(m_CoreId);

                PrefetchCpuCache(mBufArray, 3); ///\todo add 2 cfg

                std::for_each_n(std::begin(mBufArray), numOfPackets, [&](auto pktMbuf) {
                    auto data = rte_pktmbuf_mtod_offset(pktMbuf, const uint8_t *, 0);
                    auto len = static_cast<size_t>(rte_pktmbuf_pkt_len(pktMbuf));
                    auto [ok, packet] = m_Decoder.FullProcessing(LinkLayer::Eth, data, len);

                    (void)ok;
                    (void)packet;

                    m_AclDataPtrs.push_back(
                        GetRtePktMbufMtodOffset<IpV4HeaderPtoto>(pktMbuf, m_Decoder.GetHandledBytesL2()));
                    m_Decoder.ResetHandledBytes();
                });

                if (auto [ok, matchedRuleIdxs] = m_AclLookUp.Classify(*m_AclContext, m_AclDataPtrs); ok) {
                    std::for_each_n(
                        std::begin(matchedRuleIdxs), numOfPackets, [&, pktIndex = size_t{}](auto &ruleIdx) mutable {
                            if (ruleIdx != 0)
                                m_MatchPackets.push_back(mBufArray[pktIndex]);
                            pktIndex++;
                        });

                    // Send received packets if it needed
                    if (m_TxDevice) {
                        m_TxDevice->SendPackets(0, m_MatchPackets);
                    }
                    m_MatchPackets.clear();
                    m_AclDataPtrs.clear();
                } else {
                    ///\todo log
                }

                auto erased = std::erase_if(mBufArray, [](rte_mbuf *buf) {
                    if (likely(buf != nullptr)) {
                        rte_pktmbuf_free(buf);
                        return true;
                    }
                    return false;
                });
                mBufArray.insert(std::end(mBufArray), erased, nullptr);
            } else {
                ///\todo log
            }
        }
    }
    return m_Stop.load();
}

void WorkerAcl::stop() {
    m_Stop.exchange(true);
}

uint32_t WorkerAcl::getCoreId() const {
    return m_CoreId;
}

void WorkerAcl::SetCoreId(const uint32_t id) {
    m_CoreId = id;
}

void WorkerAcl::SetQueueIdxsRx(const std::vector<int> &idxs) {
    m_QueueIndicesRx = idxs;
}

void WorkerAcl::SetQueueIdxsTx(const std::vector<int> &idxs) {
    m_QueueIndicesTx = idxs;
}

} // namespace Nta::Network
