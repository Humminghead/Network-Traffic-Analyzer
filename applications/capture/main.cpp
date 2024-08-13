#include "Poco/Dynamic/Struct.h"
#include <Poco/Util/ServerApplication.h>
#include <Poco/Util/HelpFormatter.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Object.h>
#include <filesystem>

// #include <nlohmann/json.hpp>

#include "Filesystem.h"

using namespace Poco::Util;

class SubsustemConfigIface {
  public:
    virtual void Configure(const std::filesystem::path &) = 0;
};

class ConfigureSubsystem : public Subsystem, public SubsustemConfigIface {
public:
    const char *name() const override { return "configure"; }

    void Configure(const std::filesystem::path & p) override {
        if (p.empty())
            throw std::runtime_error("Empty config path!");

        if (p.extension() != "json")
            throw std::runtime_error(std::string{"Unknown config extension: "} + std::string{p.extension()});

        m_Data = Nta::Util::Filesystem::ReadBinaryFile(p);
        // m_Data.push_back(0x0);

        // if(data.empty()) throw "";

        // std::string json = data.data();
        // Poco::JSON::Parser parser;
        // auto result = parser.parse(json);

        // // use pointers to avoid copying
        // Poco::JSON::Object::Ptr object = result.extract<Poco::JSON::Object::Ptr>();
        // auto test = object->get("handlers");
        // auto subObject = test.extract<Poco::JSON::Array::Ptr>();

        // for(const auto& el :*subObject){
        //     std::cout<<el.toString();
        //     // int a = 0;
        // }
    }

  protected:
    void initialize(Application &app) override {
        printf("Init %s", m_Data.data());
    }
    void uninitialize() override {
        printf("UnInit");
    }
private:
    std::vector<char> m_Data{};
};

class CaptureSubsystem : public Subsystem {
    const char *name() const override { return "capture"; }

    // CaptureSubsystem(Poco::DynamicStruct&cfg):Subsystem(){}

  protected:
    void initialize(Application &app) override { printf("Init"); }
    void uninitialize() override { printf("UnInit"); }
};

constexpr std::string_view help{R"(Help)"};

class Worker : public ServerApplication {

    std::unique_ptr<ConfigureSubsystem> m_Configure{nullptr};
    // std::unique_ptr<CaptureSubsystem> capture;
    std::filesystem::path m_ConfigPath{""};
    bool m_HelpRequested{false};

    int main(const std::vector<std::string> &args) override {

        if (m_HelpRequested) {
            std::cout << help << std::endl;
            return 0;
        }
        m_Configure->Configure(m_ConfigPath);
        addSubsystem(m_Configure.get());

        reinitialize(*this);
        // auto &ss = getSubsystem<CaptureSubsystem>();

        return 0;
    }

    void defineOptions(OptionSet &options) override {
        ServerApplication::defineOptions(options);

        options.addOption(Option("help", "h", "display help information on command line arguments")
                              .required(false)
                              .repeatable(false).noArgument());

        options.addOption(Option("config", "c", "application config file")
                              .required(true)
                              .repeatable(false).argument("file path",true));
    }

    void handleOption(const std::string &name, const std::string &value) override {
        ServerApplication::handleOption(name, value);

        if (name == "help")
            m_HelpRequested = true;
        else if (name == "config") {
            m_ConfigPath = std::filesystem::path{value};
        }
    }

    void displayHelp()///todo
    {
        HelpFormatter helpFormatter(options());
        helpFormatter.setCommand(commandName());
        helpFormatter.setUsage("OPTIONS");
        helpFormatter.setHeader("A web server that shows how to work with HTML forms.");
        helpFormatter.format(std::cout);
    }

  public:
    Worker() : ServerApplication(), m_Configure{std::make_unique<ConfigureSubsystem>()} {

        // capture = std::make_unique<CaptureSubsystem>();
    }
};

POCO_SERVER_MAIN(Worker)
