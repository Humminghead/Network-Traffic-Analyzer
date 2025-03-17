#pragma once

#include <Handlers/Common/HandlerIface.h>
#include <memory>

namespace pcpp
{
class DpdkWorkerThread;
}

namespace Nta::Json::Objects {
struct DpdkObject;
}

namespace Nta::Network {

class HandlerDpdk : public HandlerAbstract {
public:

    HandlerDpdk(const Json::Objects::DpdkObject &config);
    virtual ~HandlerDpdk() noexcept;

    /*!
     * \brief Open
     */
    void Open() override;

    /*!
     * \brief Close
     */
    void Close() override;

    /*!
     * \brief Loop
     * \param stop
     */
    void Loop() override;

    /*!
     * \brief SingleShot
     */
    bool SingleShot() override;

    /*!
     * \brief SetCallback
     * \param f
     */
    void SetCallback(std::function<CallBackFunctionType> &&f) override;

    /*!
     * \brief GetCallback
     * \return std::function<CallBackFunctionType>
     */
    auto GetCallback() -> std::function<CallBackFunctionType> override;

    /*!
     * \brief GetIfaceType
     * \return
     */
    auto GetIfaceType() const -> const HandlerIfaces override { return HandlerIfaces::Pcap; }

private:
    bool StartDpdkWorkerThreads(const uint32_t coreMask, std::vector<pcpp::DpdkWorkerThread*>& workerThreadsVec);

    void StopDpdkWorkerThreads();

    struct Impl;
    std::unique_ptr<Impl, void (*)(Impl *)> m_Impl;
};

} // namespace Nta::Network
