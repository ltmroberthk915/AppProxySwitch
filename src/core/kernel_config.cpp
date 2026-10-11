#include "aps/kernel_config.hpp"
#include <windows.h>
#include <shellapi.h>
#include <charconv>
#include <fstream>
#include <map>
#include <sstream>
#include "aps/json.hpp"
#include "aps/string_util.hpp"

namespace aps {
namespace {
std::string trim(std::string s) {
    auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    return s.substr(first, s.find_last_not_of(" \t\r\n") - first + 1);
}
std::string scalar(std::string s) {
    s = trim(s);
    if (s.empty()) return {};
    if (s.front() == '\'') {
        std::string value;
        for (size_t i = 1; i < s.size(); ++i) {
            if (s[i] != '\'') { value += s[i]; continue; }
            if (i + 1 < s.size() && s[i + 1] == '\'') {
                value += '\'';
                ++i;
            } else return value;
        }
        return {}; // unterminated quoted scalar
    }
    if (s.front() == '"') {
        bool escape = false;
        for (size_t i = 1; i < s.size(); ++i) {
            if (s[i] == '"' && !escape) {
                json::Value value;
                if (json::Value::parse(s.substr(0, i + 1), value, nullptr) && value.isString())
                    return value.asString();
                return {};
            }
            escape = s[i] == '\\' && !escape;
        }
        return {};
    }
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '#' && (i == 0 || s[i - 1] == ' ' || s[i - 1] == '\t')) {
            s.resize(i);
            break;
        }
    }
    s = trim(s);
    if (s == "null" || s == "~" || s == "|" || s == ">") return {};
    return s;
}
bool localFile(const std::string& path) {
    // Avoid SMB/UNC I/O (and credential leakage) during background discovery.
    return path.size() >= 3 && path[1] == ':' &&
           (path[2] == '\\' || path[2] == '/');
}
uint16_t port(const std::string& s) {
    unsigned n = 0;
    const auto r = std::from_chars(s.data(), s.data() + s.size(), n);
    return r.ec == std::errc{} && r.ptr == s.data() + s.size() && n <= 65535
               ? static_cast<uint16_t>(n) : 0;
}
}

KernelLaunchConfig parseKernelLaunchConfig(const std::string& cmdline,
                                            const std::string& yaml) {
    KernelLaunchConfig out;
    std::map<std::string, std::string> flags;
    if (!cmdline.empty()) {
        int argc = 0;
        auto args = CommandLineToArgvW(utf8ToWide(cmdline).c_str(), &argc);
        if (args) {
            for (int i = 1; i < argc; ++i) {
                auto key = wideToUtf8(args[i]);
                if (key.starts_with("--")) key.erase(0, 1);
                auto eq = key.find('=');
                auto flag = key.substr(0, eq);
                if (flag != "-d" && flag != "-f" && flag != "-secret" &&
                    flag != "-ext-ctl-pipe") continue;
                if (eq != std::string::npos) flags[flag] = key.substr(eq + 1);
                else if (i + 1 < argc) flags[flag] = wideToUtf8(args[++i]);
            }
            LocalFree(args);
        }
    }
    out.configDir = flags["-d"];
    out.configFile = flags["-f"];
    if (out.configFile.empty() && !out.configDir.empty())
        out.configFile = out.configDir + "\\config.yaml";
    if (out.configDir.empty()) {
        auto p = out.configFile.find_last_of("\\/");
        if (p != std::string::npos) out.configDir = out.configFile.substr(0, p);
    }
    // An explicit relative -f is relative to the TARGET process's working
    // directory, not -d or APS's cwd. Leave unresolved rather than read the
    // wrong file. Absolute -f and -d/config.yaml cover normal wrapper launches.
    std::istringstream input(yaml);
    std::string line;
    bool first = true;
    while (std::getline(input, line)) {
        if (first && line.starts_with("\xEF\xBB\xBF")) line.erase(0, 3);
        first = false;
        if (line.empty() || line[0] == ' ' || line[0] == '\t' || line[0] == '#') continue;
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        auto key = trim(line.substr(0, colon));
        auto value = scalar(line.substr(colon + 1));
        if (key == "external-controller-pipe") out.pipe = value;
        else if (key == "secret") out.secret = value;
        else if (key == "mixed-port") out.mixedPort = port(value);
        else if (key == "socks-port") out.socksPort = port(value);
    }
    if (!flags["-ext-ctl-pipe"].empty()) out.pipe = flags["-ext-ctl-pipe"];
    if (!flags["-secret"].empty()) out.secret = flags["-secret"];
    return out;
}

KernelLaunchConfig readKernelLaunchConfig(const std::string& cmdline) {
    auto out = parseKernelLaunchConfig(cmdline);
    if (!localFile(out.configFile)) return out;
    std::ifstream file(utf8ToWide(out.configFile), std::ios::binary | std::ios::ate);
    if (!file) return out;
    auto size = file.tellg();
    if (size < 0 || size > 4 * 1024 * 1024) return out;
    std::string yaml(static_cast<size_t>(size), '\0');
    file.seekg(0);
    if (!file.read(yaml.data(), static_cast<std::streamsize>(yaml.size()))) return out;
    return parseKernelLaunchConfig(cmdline, yaml);
}
}
