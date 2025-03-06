#include "Handlers/Dpdk/Acl/Worker.h"
#include "Handlers/Dpdk/Acl/Util/Offset.h"
#include <NetDecoder/PacketBase.h>
#include <rte_ethdev.h>

namespace Nta::Network {

Worker::Worker(std::shared_ptr<DpdkDevice> rxDevice, std::shared_ptr<DpdkDevice> txDevice, RteAclContext &&context)
    : m_RxDevice{rxDevice}, m_TxDevice{txDevice}, m_AclContext{std::move(context)} // , m_BufArray{rxPacketMaxCount}
{
    m_MatchPackets.reserve(64); // Eq to DpdkDevice::m_BufArray{64};
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

            std::for_each_n(std::begin(mBufArray), numOfPackets, [&](auto pktMbuf) {
                auto data = rte_pktmbuf_mtod_offset(pktMbuf, const uint8_t *, 0);
                auto len = static_cast<size_t>(rte_pktmbuf_pkt_len(pktMbuf));
                // m_DecoderResults.push_back(m_Decoder.FullProcessing(LinkLayer::Eth, data, len));
                auto [ok, packet] = m_Decoder.FullProcessing(LinkLayer::Eth, data, len);

                (void)ok;
                (void)packet;

                m_AclDataPtrs.push_back(
                    GetRtePktMbufMtodOffset<IpV4HeaderPtoto>(pktMbuf, m_Decoder.GetHandledBytesL2()));
                m_Decoder.ResetHandledBytes();
            });

            if (auto [ok, pktIdxs] = m_AclLookUp.Classify(m_AclContext, m_AclDataPtrs); ok) {
                std::for_each_n(std::begin(pktIdxs), numOfPackets, [&](auto &idx) {
                    if (idx != 0)
                        m_MatchPackets.push_back(mBufArray[idx]);
                });

                // send received packet on the TX device
                m_TxDevice->SendPackets(0, m_MatchPackets);
                m_MatchPackets.clear();
                m_AclDataPtrs.clear();
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
