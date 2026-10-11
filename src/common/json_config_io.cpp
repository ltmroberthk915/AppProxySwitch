// Config file persistence with atomic writes.
#include <windows.h>
#include <shlobj.h>

#include <cstdio>

#include "aps/config.hpp"
#include "aps/path_util.hpp"
#include "aps/string_util.hpp"
#include "aps/time_util.hpp"

namespace aps {

// Shadow-copy location OUTSIDE the data directory (%APPDATA% = Roaming).
// If a hostile/erroneous recursive delete hits the Local data directory
// (a real incident: another AI agent wiped C:\Users\<user> up to
// AppData\Local\hclaw...), the Roaming copy survives because R sorts after L.
std::wstring defaultConfigPathUnsafe() {
    std::wstring dir = appDataDir();
    if (dir.empty()) return {};
    return dir + L"\\config.json";
}

std::wstring defaultConfigPath() { return defaultConfigPathUnsafe(); }

// The Roaming shadow copy is a SINGLE per-user file; only the real config
// path may use it (tests save to temp paths and must stay isolated).
std::wstring roamingBackupPath(const std::wstring& path) {
    if (path.empty() || path != defaultConfigPathUnsafe()) return {};
    PWSTR roaming = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &roaming)) ||
        !roaming) {
        return {};
    }
    std::wstring dir = roaming;
    CoTaskMemFree(roaming);
    dir += L"\\AppProxySwitch";
    if (!ensureDirectory(dir)) return {};
    return dir + L"\\config.json.bak";
}

static bool readFileAll(const std::wstring& path, std::string& out) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(f, &size) || size.QuadPart > (16 << 20)) {
        CloseHandle(f);
        return false;
    }
    out.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    BOOL ok = ReadFile(f, out.empty() ? nullptr : out.data(),
                       static_cast<DWORD>(out.size()), &read, nullptr);
    CloseHandle(f);
    if (!ok) return false;
    out.resize(read);
    return true;
}

bool loadConfigFile(const std::wstring& path, Config& out, std::string* error,
                    std::vector<std::string>* warnings, bool* wasDefault) {
    out = Config::makeDefault();
    if (wasDefault) *wasDefault = false;
    if (path.empty()) {
        if (error) *error = "empty config path";
        return false;
    }
    std::string text;
    if (!readFileAll(path, text)) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            // Self-heal: the data directory may have been deleted (cleanup
            // tools or, once, an AI agent's recursive delete gone wrong).
            // Restore from the shadow copies written by saveConfigFile: the
            // sibling .bak first, then the Roaming copy (survives whole-
            // directory deletion because it lives outside this folder).
            std::vector<std::wstring> baks = {path + L".bak"};
            std::wstring roaming = roamingBackupPath(path);
            if (!roaming.empty()) baks.push_back(roaming);
            for (const auto& bak : baks) {
                std::string bakText;
                if (!readFileAll(bak, bakText)) continue;
                json::Value bakV;
                std::string bakErr;
                Config bakCfg;
                std::vector<std::string> bakWarnings;
                if (json::Value::parse(bakText, bakV, &bakErr) &&
                    Config::fromJson(bakV, bakCfg, &bakErr, &bakWarnings)) {
                    ensureDirectory(dirName(path));
                    CopyFileW(bak.c_str(), path.c_str(), FALSE);
                    out = std::move(bakCfg);
                    if (warnings) warnings->push_back(
                        "config.json was missing and has been restored from the "
                        "automatic backup");
                    return true;
                }
            }
            if (wasDefault) *wasDefault = true;
            return true;  // first run (no backup either)
        }
        if (error) *error = "cannot read config file (error " + std::to_string(err) + ")";
        return false;
    }
    json::Value v;
    std::string perr;
    if (!json::Value::parse(text, v, &perr)) {
        if (error) *error = "invalid JSON: " + perr;
        return false;
    }
    return Config::fromJson(v, out, error, warnings);
}

bool saveConfigFile(const std::wstring& path, const Config& cfg, std::string* error) {
    if (path.empty()) {
        if (error) *error = "empty config path";
        return false;
    }
    std::wstring dir = dirName(path);
    if (!ensureDirectory(dir)) {
        if (error) *error = "cannot create config directory";
        return false;
    }
    // Serialize first so a serialization failure never truncates the original.
    std::string text = cfg.toJson().dump();
    text.push_back('\n');

    std::wstring tmp = dir + L"\\config.json.tmp";
    HANDLE f = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        if (error) *error = "cannot create temp config (error " + std::to_string(GetLastError()) + ")";
        return false;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(f, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
    BOOL flushed = FlushFileBuffers(f);
    CloseHandle(f);
    if (!ok || !flushed || written != text.size()) {
        DeleteFileW(tmp.c_str());
        if (error) *error = "write of temp config failed";
        return false;
    }
    if (!MoveFileExW(tmp.c_str(), path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DWORD err = GetLastError();
        DeleteFileW(tmp.c_str());
        if (error) *error = "atomic replace failed (error " + std::to_string(err) + ")";
        return false;
    }
    // Shadow copies for self-healing (see loadConfigFile): sibling + Roaming.
    CopyFileW(path.c_str(), (path + L".bak").c_str(), FALSE);
    std::wstring roaming = roamingBackupPath(path);
    if (!roaming.empty()) CopyFileW(path.c_str(), roaming.c_str(), FALSE);
    return true;
}

}  // namespace aps
