// GUI-side config access helpers (load/save + rule persistence + autostart).
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "aps/config.hpp"

namespace aps::gui {

struct GuiConfigState {
    std::wstring path;
    Config cfg;
    bool loaded = false;
};

// Loads (or creates) the config at the default location.
GuiConfigState loadOrCreateConfig();

// Saves atomically; returns false + error on failure.
bool saveConfig(GuiConfigState& state, std::string* err);

// Adds/replaces a rule and saves.
bool upsertRule(GuiConfigState& state, const Rule& rule, std::string* err);
bool deleteRule(GuiConfigState& state, const std::string& ruleId, std::string* err);
std::optional<Rule> findRule(const GuiConfigState& state, const std::string& ruleId);

// HKCU Run key autostart (visible, user-initiated only).
bool setAutostart(bool enable);
bool autostartEnabled();

}  // namespace aps::gui
