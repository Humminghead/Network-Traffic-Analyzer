#pragma once

#include <Common/HandlerIface.h>
#include <memory>

namespace Nta::Json::Objects {
struct JsonObjectPcap;
}

namespace Nta::Network {

class HandlerPcap : public HandlerAbstract {
  public:
    // enum class Source { File, Hw, Unset };

    HandlerPcap(const Json::Objects::JsonObjectPcap &config);
    virtual ~HandlerPcap() noexcept;

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
    /*!
     * \brief openPcap
     * \param source
     */
    void OpenPcap();

    struct Impl;
    std::unique_ptr<Impl, void (*)(Impl *)> m_Impl;
};

} // namespace Nta::Network
