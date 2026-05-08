#include "CaptureApp.h"
#include "Handlers/Common/HandlerIface.h"
#include "Util/Filesystem.h"
#include "Util/Misc.h"
#include <csignal>
#include <iostream>
#include <print>

namespace Nta::Network {

auto stopWarn = [](int sig) {
    std::println("{}: stopped because signal {} has been catched!", "APP", sig);
    std::fflush(stdout);
};

CaptureApp::CaptureApp()
    : ServerApplication(),                                                 //
      m_Configure{std::make_unique<ConfigureSubsystem>()},                 //
      m_Capture{std::make_unique<CaptureSubsystem>(m_Configure.get())},    //
      m_Decode{std::make_unique<DecodeSubsystem>(m_Configure.get())},      //
      m_Transport{std::make_unique<TransportSubsystem>(m_Configure.get())} //
{
    Util::PosixSignal::AddHandler([this](int signal) {
        stopWarn(signal);
        return this->Stop();
    });
}

CaptureApp::~CaptureApp() {
    Poco::Util::ServerApplication::uninitialize();
    this->subsystems().clear();

    // It's needed because class Poco::Util::SubsystemSubsystem derrived from Poco::RefCountedObject (AutoPtr)
    m_Configure.release();
    m_Capture.release();
    m_Decode.release();
    m_Transport.release();
}

int CaptureApp::main(const std::vector<std::string> &args) {
    // Intercept signals
    std::signal(SIGINT, Util::PosixSignal::SyncHandler);
    std::signal(SIGTERM, Util::PosixSignal::SyncHandler);
    std::signal(SIGQUIT, Util::PosixSignal::SyncHandler);

    if (m_HelpRequested || m_ConfigPath.empty()) {
        DisplayHelp();
        return 0;
    }

    const auto exitCode = Run();
    this->uninitialize();

    return exitCode;
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
    if (m_AppCore >= 0)
        Util::Thread::Stick2Core(m_AppCore);

    try {
        m_Capture->GetHandler()->Open();
        m_Capture->GetHandler()->Loop();
    } catch (const std::exception &e) {
        Stop();
        ///\todo LOG
        std::cerr << e.what() << std::endl;
        return Application::EXIT_SOFTWARE;
    }

    Stop();

    return Application::EXIT_OK;
}

int CaptureApp::Stop() {
    try {
        m_Capture->GetHandler()->Close();
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        return Application::EXIT_SOFTWARE;
    }
    return Application::EXIT_OK;
}

void CaptureApp::initialize(Application &self) {
    m_Decode->SetLinkedSubSystem(m_Capture.get());
    m_Decode->SetLinkedSubSystem(m_Transport.get());

    addSubsystem(m_Configure.get());
    addSubsystem(m_Capture.get());
    addSubsystem(m_Decode.get());
    addSubsystem(m_Transport.get());

    Poco::Util::Application::initialize(self);

    m_AppCore = m_Configure->GetAppCore<decltype(m_AppCore)>(-1);
}

auto CaptureApp::GetConfigPath() const noexcept -> std::filesystem::path {
    return m_ConfigPath;
}
} // namespace Nta::Network
