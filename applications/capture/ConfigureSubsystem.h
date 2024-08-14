#pragma once

#include <Poco/Util/Subsystem.h>
#include <nlohmann/json.hpp>

class ConfigureSubsystem : public Poco::Util::Subsystem {
  public:
    const char *name() const override;

    auto GetRawJsonConfig() const noexcept -> const nlohmann::json & { return m_JsonCfg; }

  protected:
    void initialize(Poco::Util::Application &app) override;
    void uninitialize() override;

  private:
    nlohmann::json m_JsonCfg{};
};
