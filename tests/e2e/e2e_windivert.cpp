// End-to-end test with the real WinDivert driver. Requires admin (skips
// with exit code 77 otherwise). Everything runs against local mocks:
//
//   targetapp.exe -> [WinDivert NAT] -> relay -> mock SOCKS5 -> mock HTTP
//
// The mock HTTP server binds 0.0.0.0 and clients connect to the machine's
// LAN address, so the destination is outside 127/8 and thus visible to the
// network filter (loopback-routed but not loopback-addressed).
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

#include "aps/config.hpp"
#include "aps/dpapi.hpp"
#include "aps/engine.hpp"
#include "aps/log.hpp"
#include "aps/net.hpp"
#include "aps/path_util.hpp"
#include "aps/string_util.hpp"
#include "mock_http_server.hpp"
#include "mock_socks_server.hpp"
#include "testlib/appsw_test.h"

using namespace aps;
using aps::test::MockHttpServer;
using aps::test::MockSocks5Server;

namespace {

struct WsaInit {
    WsaInit() { net::initWinsock(); }
};
WsaInit g_wsa;

std::wstring g_tempDir;

bool makeTempDir() {
    wchar_t base[MAX_PATH];
    GetTempPathW(MAX_PATH, base);
    g_tempDir = std::wstring(base) + L"aps-e2e-" + std::to_wstring(GetCurrentProcessId());
    CreateDirectoryW(g_tempDir.c_str(), nullptr);
    return GetFileAttributesW(g_tempDir.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool copySelfAs(const std::wstring& name, std::wstring& out) {
    // Locate aps_test_client.exe next to this test exe.
    wchar_t self[MAX_PATH * 4];
    GetModuleFileNameW(nullptr, self, MAX_PATH * 4);
    std::wstring dir = dirName(self);
    std::wstring src = dir + L"\\aps_test_client.exe";
    out = g_tempDir + L"\\" + name;
    return CopyFileW(src.c_str(), out.c_str(), FALSE) != FALSE;
}

// Returns the machine's LAN IPv4 (host order), or 0.
uint32_t discoverLanIp() {
    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp == INVALID_SOCKET) return 0;
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9);  // discard port; no packet is actually sent
    inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);
    connect(udp, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
    sockaddr_in local{};
    int len = sizeof(local);
    getsockname(udp, reinterpret_cast<sockaddr*>(&local), &len);
    closesocket(udp);
    uint32_t ip = ntohl(local.sin_addr.S_un.S_addr);
    if (ip == 0 || (ip >> 24) == 127) return 0;
    return ip;
}

// Runs a client exe; returns its exit code (-1 on spawn/timeout failure).
// The child's stderr is captured to g_tempDir\client-<n>.txt for diagnosis.
int runClient(const std::wstring& exe, uint32_t ip, uint16_t port) {
    static int callSeq = 0;
    std::wstring out = g_tempDir + L"\\client-" + std::to_wstring(++callSeq) + L".txt";
    std::wstring cmd = L"cmd.exe /c \"\"" + exe + L"\" " + utf8ToWide(formatIpv4(ip)) +
                       L" " + std::to_wstring(port) + L" > \"" + out + L"\" 2>&1\"";
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    std::wstring cmdMutable = cmd;
    if (!CreateProcessW(nullptr, cmdMutable.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return -1;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = static_cast<DWORD>(-1);
    GetExitCodeProcess(pi.hProcess, &code);
    if (code == STILL_ACTIVE) {
        TerminateProcess(pi.hProcess, 1);
        code = static_cast<DWORD>(-1);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    FILE* f = _wfopen(out.c_str(), L"rb");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) std::printf("    [client] %s", line);
        fclose(f);
    }
    return static_cast<int>(code);
}

Config makeE2eConfig(const std::wstring& rulePath, uint16_t socksPort,
                     uint16_t relayPort) {
    Config c = Config::makeDefault();
    c.rules.clear();
    Rule r;
    r.id = "e2e-rule";
    r.name = "targetapp";
    r.path = wideToUtf8(rulePath);
    r.enabled = true;
    c.rules.push_back(r);
    c.proxy.host = "127.0.0.1";
    c.proxy.port = socksPort;
    c.relay.port = relayPort;
    c.routing.bypassPrivate = false;   // targets are the LAN address
    c.routing.blockUdpForRules = false;
    // The copied bystander shares this fixture's directory. These phases
    // test exact executable rules; directory coverage has its own unit tests.
    c.routing.coverAppDirAlways = false;
    c.proxy.healthIntervalS = 30;      // keep health quiet
    c.nodeMonitor.enabled = false;    // do not probe the mock HTTP listener
    c.proxy.clashApi.host.clear();
    return c;
}

void isolateBackgroundWork(Engine& engine) {
    // These phases verify packet routing, not controller discovery. Automatic
    // controller probes would add unrelated requests to the HTTP assertions.
    engine.setKernelDiscoveryEnabled(false);
    engine.setKernelCacheLoader([] { return std::vector<DiscoveredKernel>{}; });
    // Greeting-only health checks keep every phase local and leave SOCKS
    // CONNECT counts specific to the test client. Dead listeners still fail.
    engine.setHealthProbeDstForTest({0, 0});
}

std::atomic<int> g_statusCount{0};

}  // namespace

int main() {
    if (!crypto::isProcessElevated()) {
        std::printf("SKIP: e2e requires admin (run tests from an elevated shell; "
                    "CI runners are elevated)\n");
        return 77;
    }
    uint32_t lanIp = discoverLanIp();
    if (lanIp == 0) {
        std::printf("SKIP: no non-loopback local address (offline machine)\n");
        return 77;
    }
    if (!makeTempDir()) {
        std::printf("FAIL: cannot create temp dir\n");
        return 1;
    }
    // Engine internals (attribution decisions etc.) go to a log we can dump
    // on failure.
    log::init(g_tempDir, log::Level::Debug, 10, 2);
    std::wstring targetExe, bystanderExe;
    if (!copySelfAs(L"targetapp.exe", targetExe) ||
        !copySelfAs(L"bystander.exe", bystanderExe)) {
        std::printf("FAIL: cannot stage client exes (aps_test_client.exe missing)\n");
        return 1;
    }
    std::printf("LAN ip for targets: %s\n", formatIpv4(lanIp).c_str());

    MockHttpServer http;
    http.start(0, 0);  // bind 0.0.0.0
    MockSocks5Server socks;
    socks.start();
    uint16_t relayPort = static_cast<uint16_t>(24000 + (GetCurrentProcessId() % 20000));

    // ---- phase 1: rule traffic goes through SOCKS ----------------------------
    {
        EngineEvents noEvents;
        Engine engine(makeWinDivertDevice(), std::move(noEvents));
        isolateBackgroundWork(engine);
        std::string err;
        Config cfg = makeE2eConfig(targetExe, socks.port(), relayPort);
        if (!engine.start(cfg, &err)) {
            std::printf("FAIL: engine start: %s\n", err.c_str());
            return 1;
        }
        int rc = runClient(targetExe, lanIp, http.port());
        engine.stop();
        bool phase1 = rc == 0 && socks.requestCount() == 1 && http.hits() == 1 &&
                      socks.request(0).dstIp == lanIp &&
                      socks.request(0).dstPort == http.port() &&
                      http.hit(0).requestLine == "GET / HTTP/1.1";
        std::printf("phase1 (rule via socks): rc=%d socks=%zu http=%zu -> %s\n", rc,
                    socks.requestCount(), http.hits(), phase1 ? "OK" : "FAIL");
        if (!phase1) {
            log::shutdown();
            std::printf("--- engine log ---\n");
            FILE* f = _wfopen((g_tempDir + L"\\aps.log").c_str(), L"rb");
            if (f) {
                char line[1024];
                while (fgets(line, sizeof(line), f)) std::fputs(line, stdout);
                fclose(f);
            }
            return 1;
        }
    }

    // ---- phase 2: non-rule traffic stays direct --------------------------------
    {
        EngineEvents noEvents;
        Engine engine(makeWinDivertDevice(), std::move(noEvents));
        isolateBackgroundWork(engine);
        std::string err;
        Config cfg = makeE2eConfig(targetExe, socks.port(), relayPort);
        if (!engine.start(cfg, &err)) {
            std::printf("FAIL: engine start: %s\n", err.c_str());
            return 1;
        }
        size_t socksBefore = socks.requestCount();
        size_t httpBefore = http.hits();
        int rc = runClient(bystanderExe, lanIp, http.port());
        engine.stop();
        bool phase2 = rc == 0 && socks.requestCount() == socksBefore &&
                      http.hits() == httpBefore + 1;
        std::printf("phase2 (non-rule direct): rc=%d socks=%zu(+%zu) http=%zu(+%zu) -> %s\n",
                    rc, socks.requestCount(), socks.requestCount() - socksBefore,
                    http.hits(), http.hits() - httpBefore, phase2 ? "OK" : "FAIL");
        if (!phase2) return 1;
    }

    // ---- phase 3: after stop, rule traffic is direct again ---------------------
    {
        EngineEvents noEvents;
        Engine engine(makeWinDivertDevice(), std::move(noEvents));
        isolateBackgroundWork(engine);
        std::string err;
        Config cfg = makeE2eConfig(targetExe, socks.port(), relayPort);
        if (!engine.start(cfg, &err)) {
            std::printf("FAIL: engine start: %s\n", err.c_str());
            return 1;
        }
        engine.stop();
        size_t socksBefore = socks.requestCount();
        size_t httpBefore = http.hits();
        int rc = runClient(targetExe, lanIp, http.port());
        bool phase3 = rc == 0 && socks.requestCount() == socksBefore &&
                      http.hits() == httpBefore + 1;
        std::printf("phase3 (after stop direct): rc=%d socks(+%zu) http(+%zu) -> %s\n", rc,
                    socks.requestCount() - socksBefore, http.hits() - httpBefore,
                    phase3 ? "OK" : "FAIL");
        if (!phase3) return 1;
    }

    // ---- phase 4: fail-open when the proxy dies ---------------------------------
    {
        EngineEvents ev;
        std::mutex mu;
        std::string lastStatus;
        ev.onStatus = [&](const std::string& s) {
            std::lock_guard<std::mutex> lk(mu);
            lastStatus = s;
        };
        Engine engine(makeWinDivertDevice(), std::move(ev));
        isolateBackgroundWork(engine);
        Config cfg = makeE2eConfig(targetExe, socks.port(), relayPort);
        cfg.proxy.healthIntervalS = 1;
        cfg.proxy.healthTimeoutMs = 500;
        cfg.proxy.healthFailThreshold = 1;
        std::string err;
        if (!engine.start(cfg, &err)) {
            std::printf("FAIL: engine start: %s\n", err.c_str());
            return 1;
        }
        // Kill the previously working endpoint after startup, matching the
        // scenario under test without relying on an unowned fixed port.
        socks.stop();
        bool degraded = false;
        for (int i = 0; i < 160; ++i) {
            {
                std::lock_guard<std::mutex> lk(mu);
                degraded = lastStatus.find("\"DEGRADED\"") != std::string::npos;
            }
            if (degraded) break;
            // Let the status callback acquire mu while waiting for health.
            Sleep(100);
        }
        if (!degraded) {
            engine.stop();
            std::printf("FAIL: engine never entered DEGRADED\n");
            return 1;
        }
        size_t socksBefore = socks.requestCount();
        size_t httpBefore = http.hits();
        int rc = runClient(targetExe, lanIp, http.port());
        engine.stop();
        bool phase4 = rc == 0 && http.hits() == httpBefore + 1 && socksBefore == socks.requestCount();
        std::printf("phase4 (fail-open direct): rc=%d http(+%zu) -> %s\n", rc,
                    http.hits() - httpBefore, phase4 ? "OK" : "FAIL");
        if (!phase4) return 1;
    }

    // Cleanup.
    DeleteFileW(targetExe.c_str());
    DeleteFileW(bystanderExe.c_str());
    RemoveDirectoryW(g_tempDir.c_str());
    http.stop();
    socks.stop();

    std::printf("ALL E2E PHASES PASSED\n");
    return 0;
}
