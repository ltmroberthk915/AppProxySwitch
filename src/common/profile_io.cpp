// Config profile export/import. See profile_io.hpp for the semantics.
#include "aps/profile_io.hpp"

#include <windows.h>

#include "aps/json.hpp"

namespace aps {

namespace {

constexpr int64_t kMaxProfileBytes = 1 << 20;  // matches the JSON parser cap

}  // namespace

std::string exportProfileJson(const Config& cfg) {
    json::Value j = cfg.toJson();
    // Strip every DPAPI field (const_cast: toJson just built a fresh tree;
    // the same idiom the engine uses for its mutable caches).
    auto* root = const_cast<json::Value*>(&j);
    if (json::Value* proxy = const_cast<json::Value*>(root->find("proxy"))) {
        proxy->erase("password_enc");
        if (json::Value* api = const_cast<json::Value*>(proxy->find("clash_api"))) {
            api->erase("secret_enc");
        }
    }
    if (json::Value* outlets = const_cast<json::Value*>(root->find("outlets"))) {
        for (size_t i = 0; i < outlets->size(); ++i) {
            json::Value& o = const_cast<json::Value&>(outlets->at(i));
            o.erase("password_enc");
            if (json::Value* api = const_cast<json::Value*>(o.find("clash_api"))) {
                api->erase("secret_enc");
            }
        }
    }
    return j.dump();
}

bool importProfileJson(const std::string& text, const Config& current, Config& out,
                       std::string* error, std::vector<std::string>* warnings) {
    json::Value v;
    std::string perr;
    if (!json::Value::parse(text, v, &perr)) {
        if (error) *error = "invalid JSON: " + perr;
        return false;
    }
    Config imported;
    if (!Config::fromJson(v, imported, error, warnings)) return false;

    // Keep LOCAL secrets where the file carries none.
    if (imported.proxy.passwordEnc.empty()) {
        imported.proxy.passwordEnc = current.proxy.passwordEnc;
    }
    if (imported.proxy.clashApi.secretEnc.empty()) {
        imported.proxy.clashApi.secretEnc = current.proxy.clashApi.secretEnc;
    }
    for (auto& o : imported.outlets) {
        if (!o.passwordEnc.empty() && !o.clashApi.secretEnc.empty()) continue;
        for (const auto& cur : current.outlets) {
            if (cur.id != o.id) continue;
            if (o.passwordEnc.empty()) o.passwordEnc = cur.passwordEnc;
            if (o.clashApi.secretEnc.empty()) o.clashApi.secretEnc = cur.clashApi.secretEnc;
            break;
        }
    }
    // Activation is machine-local (kernel ids differ per machine).
    imported.routing.autoOutletId.clear();

    std::string verr;
    if (!imported.validate(&verr)) {
        if (error) *error = "profile rejected: " + verr;
        return false;
    }
    out = std::move(imported);
    return true;
}

bool saveProfileFile(const std::wstring& path, const Config& cfg, std::string* error) {
    if (path.empty()) {
        if (error) *error = "empty profile path";
        return false;
    }
    std::string text = exportProfileJson(cfg);
    text.push_back('\n');
    HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        if (error) *error = "cannot create profile file (error " +
                            std::to_string(GetLastError()) + ")";
        return false;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(f, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
    CloseHandle(f);
    if (!ok || written != text.size()) {
        if (error) *error = "write of profile file failed";
        return false;
    }
    return true;
}

bool loadProfileFile(const std::wstring& path, std::string& text, std::string* error) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        if (error) *error = "cannot open profile file (error " +
                            std::to_string(GetLastError()) + ")";
        return false;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(f, &size) || size.QuadPart > kMaxProfileBytes) {
        CloseHandle(f);
        if (error) *error = "profile file too large (1 MiB max)";
        return false;
    }
    text.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    BOOL ok = ReadFile(f, text.empty() ? nullptr : text.data(),
                       static_cast<DWORD>(text.size()), &read, nullptr);
    CloseHandle(f);
    if (!ok) {
        if (error) *error = "read of profile file failed";
        return false;
    }
    text.resize(read);
    return true;
}

}  // namespace aps
