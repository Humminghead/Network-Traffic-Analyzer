#include "CaptureApp.h"
#include "Handlers/Common/HandlerIface.h"
#include "Util/Filesystem.h"
#include "Util/Misc.h"
#include <csignal>
#include <functional>
#include <iostream>
#include <print>

namespace Nta::Network {

namespace SigHandler {

class Storage {
  private:
    using func_t = std::function<int(int)>;

    template <typename F> using is_function = std::enable_if<std::is_function_v<std::remove_reference_t<F>>>;

    std::vector<func_t> m_StopFunctions{};

  public:
    constexpr auto operator()(int signal) -> void {
        for (auto &f : m_StopFunctions) {
            f(signal);
        }
    };

    template <typename... F, is_function<F>...> constexpr Storage(F &&...f) {
        (m_StopFunctions.push_back(func_t{std::move(f)}), ...);
    }

    template <typename... F, is_function<F>...> constexpr auto Add(F &&...f) {
        return (m_StopFunctions.push_back(func_t{std::move(f)}), ...);
    }
};

namespace {
thread_local static std::unique_ptr<Storage> storage;
}

template <class T> static constexpr auto Add(T &&f) {
    if (storage == nullptr) {
        storage = std::make_unique<Storage>(std::move(f));
        return;
    }
    storage->Add(std::move(f));
}

static auto HandlerFunc(int s) {
    if (!storage)
        return;

    (*storage)(s);
}

} // namespace SigHandler

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
    SigHandler::Add([this](int signal) {
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
    std::signal(SIGINT, SigHandler::HandlerFunc);
    std::signal(SIGTERM, SigHandler::HandlerFunc);
    std::signal(SIGQUIT, SigHandler::HandlerFunc);
    std::signal(SIGABRT, SigHandler::HandlerFunc);
    std::signal(SIGHUP, SigHandler::HandlerFunc);
    std::signal(SIGKILL, SigHandler::HandlerFunc);

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
