#pragma once

#include "CaptureSubsystem.h"
#include "ConfigureSubsystem.h"
#include <Poco/Util/HelpFormatter.h>
#include <Poco/Util/ServerApplication.h>
#include <filesystem>
#include <memory>

class CaptureApp : public Poco::Util::ServerApplication {    
  public:
    CaptureApp();

    auto GetConfigPath() const noexcept -> std::filesystem::path;

private:
    std::unique_ptr<ConfigureSubsystem> m_Configure{nullptr};
    std::unique_ptr<CaptureSubsystem> m_Capture{nullptr};
    std::filesystem::path m_ConfigPath{""};
    bool m_HelpRequested{false};

    int main(const std::vector<std::string> &args) override;

    void defineOptions(Poco::Util::OptionSet &options) override;

    void handleOption(const std::string &name, const std::string &value) override;

    void DisplayHelp();    
};
