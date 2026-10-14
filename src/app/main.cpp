// AppProxySwitch entry point: GUI by default, headless engine with --engine.
#include <windows.h>
#include <shellapi.h>

#include <cstdio>
#include <string>
#include <vector>

#include "aps/engine_main.hpp"
#include "aps/net.hpp"
#include "aps/kernel_discovery.hpp"
#include "aps/json.hpp"
#include "aps/config.hpp"
#include "aps/string_util.hpp"
#include "aps/verge_official.hpp"
#include <thread>

#ifdef APS_BUILD_GUI
#include "gui/app.hpp"
#endif

namespace {

void printUsage() {
    std::printf("AppProxySwitch %s\n"
                "用法:\n"
                "  AppProxySwitch.exe                 启动图形界面\n"
                "  AppProxySwitch.exe --engine        以引擎模式运行(需管理员,由 GUI 自动拉起)\n"
                "  AppProxySwitch.exe --engine --config <path>  指定配置文件\n"
                "  AppProxySwitch.exe --discover      只读发现诊断(JSON，无密钥，不启动引擎)\n"
                "  AppProxySwitch.exe --tls-domain-allow <domain> [--tls-domain-allow <*.domain>] [--config <path>]\n"
                "  AppProxySwitch.exe --clear-tls-domain-allowlist [--config <path>]\n",
                APS_VERSION);
}

std::vector<std::wstring> commandArgs() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::vector<std::wstring> out;
    if (argv) {
        for (int i = 0; i < argc; ++i) out.push_back(argv[i]);
        LocalFree(argv);
    }
    return out;
}

}  // namespace

#ifdef APS_BUILD_GUI
int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
#else
int main() {
    HINSTANCE hInstance = GetModuleHandleW(nullptr);
    int nCmdShow = SW_SHOWNORMAL;
    (void)hInstance;
    (void)nCmdShow;
#endif
    aps::net::initWinsock();
    auto args = commandArgs();
    std::wstring configPath;
    // Explicit config operation, parsed before GUI/engine startup. It never
    // starts interception, changes outlets, or closes existing connections.
    bool setTlsDomains = false;
    bool clearTlsDomains = false;
    std::vector<std::string> tlsDomains;
    for (size_t i = 1; i < args.size(); ++i) {
        if (args[i] == L"--config" && i + 1 < args.size()) configPath = args[++i];
        else if (args[i] == L"--tls-domain-allow") {
            if (i + 1 == args.size() || args[i + 1].starts_with(L"--")) return 2;
            setTlsDomains = true;
            tlsDomains.push_back(aps::wideToUtf8(args[++i]));
        } else if (args[i] == L"--clear-tls-domain-allowlist") { setTlsDomains = true; clearTlsDomains = true; }
    }
    if (setTlsDomains) {
        if (clearTlsDomains && !tlsDomains.empty()) return 2;
        // Refuse ambiguous invocations, including a simultaneous engine
        // launch, rather than silently treating them as settings changes.
        for (size_t i = 1; i < args.size(); ++i) {
            if (args[i] == L"--config" || args[i] == L"--tls-domain-allow") {
                if (i + 1 == args.size() || args[i + 1].starts_with(L"--")) return 2;
                ++i; continue;
            }
            if (args[i] != L"--clear-tls-domain-allowlist") return 2;
        }
        if (configPath.empty()) configPath = aps::defaultConfigPath();
        wchar_t fullPath[32768];
        const DWORD fullLength = GetFullPathNameW(configPath.c_str(), 32768, fullPath, nullptr);
        if (!fullLength || fullLength >= 32768) return 2;
        configPath.assign(fullPath, fullLength);
        if (aps::toLowerAsciiW(configPath) == aps::toLowerAsciiW(aps::defaultConfigPath())) {
            // The GUI keeps a configuration copy. Writing its file while
            // that copy is live would let a later GUI save erase this policy.
            HANDLE gui = OpenMutexW(SYNCHRONIZE, FALSE, L"Local\\AppProxySwitchGui");
            if (gui) {
                CloseHandle(gui);
                std::fprintf(stderr, "Exit the APS GUI normally before updating its TLS domain policy.\n");
                return 3;
            }
        }
        // A typo in --config must not manufacture a fresh configuration.
        if (GetFileAttributesW(configPath.c_str()) == INVALID_FILE_ATTRIBUTES) return 2;
        aps::Config cfg;
        std::string error;
        std::vector<std::string> warnings;
        bool wasDefault = false;
        if (!aps::loadConfigFile(configPath, cfg, &error, &warnings, &wasDefault) || wasDefault || !warnings.empty()) return 2;
        if (clearTlsDomains) cfg.routing.tlsDomainAllowlist.clear();
        for (const auto& domain : tlsDomains) {
            bool present = false;
            for (const auto& old : cfg.routing.tlsDomainAllowlist)
                if (aps::equalsIgnoreCase(old, domain)) { present = true; break; }
            if (!present) cfg.routing.tlsDomainAllowlist.push_back(domain);
        }
        if (!cfg.validate(&error)) { std::fprintf(stderr, "%s\n", error.c_str()); return 2; }
        if (!aps::saveConfigFile(configPath, cfg, &error)) return 1;
        std::printf("TLS domain policy saved: %zu entries; applies to new proxy connections.\n", cfg.routing.tlsDomainAllowlist.size());
        return 0;
    }
    for (size_t i = 1; i < args.size(); ++i) {
        if (args[i] == L"--verify-verge-refresh" && i+2 < args.size()) {
            // Explicit acceptance path, same production implementation, no
            // engine/WinDivert/config changes. Human confirmation before UI Invoke.
            const auto pid=static_cast<uint32_t>(std::wcstoul(args[i+1].c_str(),nullptr,10));
            const auto uid=aps::wideToUtf8(args[i+2]);
            aps::DiscoveredKernel kernel; kernel.pid=pid;
            kernel.configDir=aps::parseConfigDirFromCmdline(aps::processCommandLine(pid));
            const auto prompt=aps::utf8ToWide("仅刷新官方 Verge 订阅 ID："+uid+"。不会激活订阅或启动截流。是否执行一次？");
            if(MessageBoxW(nullptr,prompt.c_str(),L"APS 官方 Verge 刷新验收",MB_YESNO|MB_DEFBUTTON2|MB_ICONQUESTION)!=IDYES)return 2;
            std::string result;
            std::jthread worker([&]{result=aps::refreshOfficialVerge(kernel,{},uid);}); worker.join();
            MessageBoxW(nullptr,aps::utf8ToWide(result).c_str(),L"APS 官方 Verge 刷新结果",MB_OK|(result.starts_with("ok:")?MB_ICONINFORMATION:MB_ICONWARNING));
            return result.starts_with("ok:")?0:1;
        }
        if (args[i] == L"--discover") {
            // Read-only diagnostics: no GUI/driver, cache writes, node changes,
            // subscription requests, or credentials in stdout.
            auto kernels = aps::discoverProxyKernels(250, aps::DiscoveryMode::Full);
            auto result = aps::json::Value::makeArray();
            for (const auto& k : kernels) {
                auto row = aps::json::Value::makeObject();
                row.set("name", k.procName);
                row.set("pid", k.pid);
                row.set("socks_port", static_cast<uint32_t>(k.socksPort));
                row.set("api_port", static_cast<uint32_t>(k.apiPort));
                row.set("controller", !k.apiPipe.empty() ? "pipe" : k.apiPort ? "tcp" : "none");
                row.set("api_pipe", k.apiPipe);
                row.set("needs_secret", k.apiNeedSecret);
                row.set("error", k.discoveryError);
                result.append(std::move(row));
            }
            std::printf("%s\n", result.dump().c_str());
            return 0;
        }
        if (args[i] == L"--diag") {
            // Hidden startup diagnostic: logs each GUI boot step with
            // GetLastError to build\gui-diag.txt next to the repo layout.
            FILE* df = _wfopen(L"gui-diag.txt", L"w");
            if (!df) df = fopen("gui-diag.txt", "w");
            if (!df) return 99;
            std::fprintf(df, "diag: wWinMain enter\n");
            HINSTANCE h = GetModuleHandleW(nullptr);
            WNDCLASSW wc{};
            wc.lpfnWndProc = DefWindowProcW;
            wc.hInstance = h;
            wc.lpszClassName = L"ApsDiagClass";
            wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
            wc.hIcon = LoadIconW(h, MAKEINTRESOURCEW(101));
            ATOM cls = RegisterClassW(&wc);
            std::fprintf(df, "diag: RegisterClassW atom=%u err=%lu\n", cls, GetLastError());
            HWND w = CreateWindowExW(0, L"ApsDiagClass", L"diag", WS_OVERLAPPEDWINDOW,
                                     100, 100, 400, 300, nullptr, nullptr, h, nullptr);
            std::fprintf(df, "diag: CreateWindowExW=%p err=%lu\n", (void*)w, GetLastError());
            std::fclose(df);
            if (w) {
                ShowWindow(w, SW_SHOW);
                MSG m;
                while (GetMessageW(&m, nullptr, 0, 0) > 0) {
                    TranslateMessage(&m);
                    DispatchMessageW(&m);
                }
            }
            return 0;
        }
        if (args[i] == L"--engine") {
            for (size_t j = i + 1; j < args.size(); ++j) {
                if (args[j] == L"--config" && j + 1 < args.size()) {
                    configPath = args[j + 1];
                }
            }
            return aps::runEngineMode(configPath);
        }
        if (args[i] == L"--help" || args[i] == L"-h") {
            printUsage();
            return 0;
        }
        if (args[i] == L"--version") {
            std::printf("%s\n", APS_VERSION);
            return 0;
        }
    }
#ifdef APS_BUILD_GUI
    return aps::gui::runGui(hInstance, nCmdShow);
#else
    printUsage();
    return 0;
#endif
}
