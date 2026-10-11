#include "gui_config.hpp"

#include <windows.h>

#include "aps/log.hpp"
#include "aps/path_util.hpp"
#include "aps/string_util.hpp"
#include "aps/time_util.hpp"

namespace aps::gui {

GuiConfigState loadOrCreateConfig() {
    GuiConfigState st;
    st.path = defaultConfigPath();
    if (st.path.empty()) return st;
    std::string err;
    std::vector<std::string> warnings;
    bool wasDefault = false;
    if (loadConfigFile(st.path, st.cfg, &err, &warnings, &wasDefault)) {
        st.loaded = true;
        if (!wasDefault) {
            for (const auto& w : warnings) log::wf("config: {}", w);
        }
    } else {
        // Back up the unparseable file (COPY, keep the original in place
        // for inspection) and continue with defaults. NOTE: with empty
        // region/class entries now tolerated by the parser, this path is
        // reserved for genuinely broken files; the data loss incident of
        // 2026-08-31 (whole config wiped by a lone "" entry) must not
        // recur.
        CopyFileW(st.path.c_str(),
                  (st.path + L"." + utf8ToWide(fileTimestamp()) + L".bak").c_str(),
                  FALSE);
        st.cfg = Config::makeDefault();
        st.loaded = true;
        log::wf("config invalid ({}); backed up in place, using defaults", err);
    }
    return st;
}

bool saveConfig(GuiConfigState& state, std::string* err) {
    if (!saveConfigFile(state.path, state.cfg, err)) return false;
    return true;
}

bool upsertRule(GuiConfigState& state, const Rule& rule, std::string* err) {
    for (auto& r : state.cfg.rules) {
        if (r.id == rule.id) {
            r = rule;
            return saveConfig(state, err);
        }
    }
    state.cfg.rules.push_back(rule);
    return saveConfig(state, err);
}

bool deleteRule(GuiConfigState& state, const std::string& ruleId, std::string* err) {
    auto& rules = state.cfg.rules;
    for (auto it = rules.begin(); it != rules.end(); ++it) {
        if (it->id == ruleId) {
            rules.erase(it);
            return saveConfig(state, err);
        }
    }
    if (err) *err = "rule not found";
    return false;
}

std::optional<Rule> findRule(const GuiConfigState& state, const std::string& ruleId) {
    for (const auto& r : state.cfg.rules) {
        if (r.id == ruleId) return r;
    }
    return std::nullopt;
}

static const wchar_t* kRunKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
static const wchar_t* kRunValue = L"AppProxySwitch";

bool setAutostart(bool enable) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRunKey, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS) {
        return false;
    }
    bool ok = true;
    if (enable) {
        std::wstring exe = currentModulePath();
        ok = RegSetValueExW(key, kRunValue, 0, REG_SZ,
                            reinterpret_cast<const BYTE*>(exe.c_str()),
                            static_cast<DWORD>((exe.size() + 1) * sizeof(wchar_t))) ==
             ERROR_SUCCESS;
    } else {
        ok = RegDeleteValueW(key, kRunValue) == ERROR_SUCCESS ||
             GetLastError() == ERROR_FILE_NOT_FOUND;
    }
    RegCloseKey(key);
    return ok;
}

bool autostartEnabled() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRunKey, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
        return false;
    }
    DWORD type = 0;
    bool present = RegQueryValueExW(key, kRunValue, nullptr, &type, nullptr, nullptr) ==
                   ERROR_SUCCESS;
    RegCloseKey(key);
    return present;
}

}  // namespace aps::gui
