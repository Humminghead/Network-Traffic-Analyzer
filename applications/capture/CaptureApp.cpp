#include "CaptureApp.h"
#include "Handlers/Common/HandlerIface.h"
#include "Util/Filesystem.h"
#include <iostream>

namespace Nta::Network {

struct HandlerAbstract;

constexpr std::string_view help{R"(Help)"};

int CaptureApp::main(const std::vector<std::string> &args) {
    if (m_HelpRequested || m_ConfigPath.empty()) {
        DisplayHelp();
        return 0;
    }

    addSubsystem(m_Configure.get());
    addSubsystem(m_Capture.get());
    addSubsystem(m_Decode.get());
    // addSubsystem(m_Stat.get());
    // addSubsystem(m_Out.get());

    this->initialize(*this);

    return Run();
}

void CaptureApp::defineOptions(Poco::Util::OptionSet &options) {
    ServerApplication::defineOptions(options);

    options.addOption(Poco::Util::Option("help", "h", "display help information on command line arguments")
                          .required(false)
                          .repeatable(false)
                          .noArgument());

    options.addOption(Poco::Util::Option("config", "c", "application config file")
                          .required(false)
                          .repeatable(false)
                          .argument("<file path>", true));
}

void CaptureApp::handleOption(const std::string &name, const std::string &value) {
    if (name == "help")
        m_HelpRequested = true;
    else if (name == "config") {
        m_ConfigPath = Nta::Util::Filesystem::IsValidJsonPath(std::filesystem::path{value});
    } else {
        ServerApplication::handleOption(name, value);
    }
}

void CaptureApp::DisplayHelp() {
    Poco::Util::HelpFormatter helpFormatter(options());
    helpFormatter.setCommand(commandName());
    helpFormatter.setUsage("OPTIONS");
    helpFormatter.setHeader("A traffic capture application that captures incoming trafic from device");
    helpFormatter.format(std::cout);
}

int CaptureApp::Run() {
    m_Capture->GetHandler()->Open();
    m_Capture->GetHandler()->Loop();
    m_Capture->GetHandler()->Close();
    return Application::EXIT_OK;
}

CaptureApp::CaptureApp()
    : ServerApplication(),                                 //
      m_Configure{std::make_unique<ConfigureSubsystem>()}, //
      m_Capture{std::make_unique<CaptureSubsystem>()},     //
      m_Decode{std::make_unique<DecodeSubsystem>()}        //
{}

auto CaptureApp::GetConfigPath() const noexcept -> std::filesystem::path {
    return m_ConfigPath;
}
} // namespace Nta::Network
