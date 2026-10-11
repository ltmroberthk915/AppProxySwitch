// Kernel discovery tests: real local mocks stand in for kernels.
// The scanner probes actual sockets, so spin up a mock SOCKS5 and a mock
// Clash API and verify they are found.
#include <winsock2.h>

#include <cstdio>
#include <algorithm>

#include "aps/kernel_discovery.hpp"
#include "aps/clash_api.hpp"
#include "aps/kernel_config.hpp"
#include "aps/path_util.hpp"
#include "aps/string_util.hpp"
#include <fstream>
#include "mock_clash_api.hpp"
#include "mock_clash_pipe.hpp"
#include "mock_socks_server.hpp"
#include "kernel_cache_sandbox.hpp"
#include "testlib/appsw_test.h"

using namespace aps;
using aps::test::MockClashApi;
using aps::test::MockSocks5Server;

namespace {
struct WsaInit {
    WsaInit() { net::initWinsock(); }
};
WsaInit g_wsa;
aps::test::KernelCacheSandbox g_cache;

struct PipeKernelFixture {
    PROCESS_INFORMATION process{};
    HANDLE ready = nullptr;
    HANDLE quit = nullptr;
    std::wstring config;
    std::string pipeName;
    bool started = false;
    PipeKernelFixture(bool socks, uint16_t configuredPort = 0, bool tcp = false,
                      bool opaqueLaunch = false, std::string fixedPipe = {}) {
        static unsigned sequence = 0;
        auto suffix = std::to_string(GetCurrentProcessId()) + "-" +
            std::to_string(GetTickCount64()) + "-" + std::to_string(++sequence);
        pipeName = fixedPipe.empty() ? "\\\\.\\pipe\\aps-discovery-" + suffix : fixedPipe;
        std::wstring readyName = L"Local\\aps-ready-" + utf8ToWide(suffix);
        std::wstring quitName = L"Local\\aps-quit-" + utf8ToWide(suffix);
        ready = CreateEventW(nullptr, TRUE, FALSE, readyName.c_str());
        quit = CreateEventW(nullptr, TRUE, FALSE, quitName.c_str());
        ensureDirectory(g_cache.directory);
        config = g_cache.directory + L"\\fixture config-" + utf8ToWide(suffix) + L".yaml";
        {
            std::ofstream file(config, std::ios::binary);
            file << "mixed-port: " << configuredPort << "\nsecret: 'fixture-secret' # local test\n";
        }
        wchar_t exe[MAX_PATH]{};
        GetModuleFileNameW(nullptr, exe, MAX_PATH);
        std::wstring cmd = L"\"" + std::wstring(exe) + (tcp ? L"\" --tcp-fixture " : L"\" --pipe-fixture ") + readyName + L" " + quitName +
            (socks ? L" yes" : L" no");
        // An opaque service launch exposes neither -f/-d nor -ext-ctl-pipe
        // to the scanner. The fixture-only flag is deliberately not parsed
        // by production code; this also models an inaccessible launch config.
        if (opaqueLaunch) cmd += L" --fixture-endpoint " + utf8ToWide(pipeName);
        else cmd += L" -ext-ctl-pipe " + utf8ToWide(pipeName) + L" -f \"" + config + L"\"";
        STARTUPINFOW startup{}; startup.cb = sizeof(startup);
        if (CreateProcessW(exe, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                           nullptr, nullptr, &startup, &process))
            started = WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0;
    }
    ~PipeKernelFixture() {
        if (quit) SetEvent(quit);
        if (process.hProcess) {
            WaitForSingleObject(process.hProcess, 5000);
            CloseHandle(process.hProcess);
            CloseHandle(process.hThread);
        }
        if (ready) CloseHandle(ready);
        if (quit) CloseHandle(quit);
        DeleteFileW(config.c_str());
    }
};
}  // namespace

APS_TEST(kdiscovery, full_mode_finds_socks_and_api_pair) {
    MockSocks5Server socks;
    EXPECT_TRUE(socks.start());
    MockClashApi api;
    EXPECT_TRUE(api.start());
    // NOTE: mocks run in THIS process, so both ports share our PID. The
    // discovery should group them into ONE kernel with both ports set.
    // Full mode is required: the test exe name matches no kernel pattern.
    auto kernels = discoverProxyKernels(800, DiscoveryMode::Full);
    bool found = false;
    for (const auto& k : kernels) {
        if (k.socksPort == socks.port() && k.apiPort == api.port()) {
            found = true;
            EXPECT_FALSE(k.procName.empty());
            EXPECT_FALSE(k.id.empty());
        }
    }
    EXPECT_TRUE(found);
    api.stop();
    socks.stop();
}

APS_TEST(kdiscovery, quick_mode_skips_unknown_names) {
    // The mocks' process name ("test_kernel_discovery.exe") matches no
    // built-in kernel pattern, so Quick mode must NOT probe (and thus not
    // find) them. This is the filter that makes re-scans instant.
    MockSocks5Server socks;
    EXPECT_TRUE(socks.start());
    MockClashApi api;
    EXPECT_TRUE(api.start());
    auto kernels = discoverProxyKernels(800, DiscoveryMode::Quick);
    for (const auto& k : kernels) {
        EXPECT_TRUE(k.socksPort != socks.port() || k.apiPort != api.port());
    }
    api.stop();
    socks.stop();
}

APS_TEST(kdiscovery, parse_config_dir_from_cmdline) {
    // The identity disambiguator between same-named kernel instances.
    // `-d` wins; else the parent dir of `-f`; quotes stripped; "" when
    // neither flag exists.
    EXPECT_STREQ(parseConfigDirFromCmdline(
                     "com.vortex.helper.exe -d C:\\cfg\\com.vortex.helper"),
                 "C:\\cfg\\com.vortex.helper");
    EXPECT_STREQ(parseConfigDirFromCmdline(
                     "\"C:\\x\\com.vortex.helper.exe\" -d \"C:\\cfg\" -f "
                     "\"C:\\cfg\\config.yaml\""),
                 "C:\\cfg");
    EXPECT_STREQ(parseConfigDirFromCmdline(
                     "helper.exe -f C:\\cfg\\config.yaml -ext-ctl 127.0.0.1:39798"),
                 "C:\\cfg");
    EXPECT_STREQ(parseConfigDirFromCmdline(
                     "helper.exe -ext-ctl 127.0.0.1:39797"),  // no -d/-f
                 "");
    EXPECT_STREQ(parseConfigDirFromCmdline(""), "");
}

APS_TEST(kdiscovery, windows_paths_flags_and_top_level_yaml) {
    auto launch = parseKernelLaunchConfig(
        R"("D:\Program Files\Unknown Shell\core.exe" --d="D:\User Data\代理" -f="live config.yaml" -ext-ctl-pipe \\.\pipe\runtime-name)",
        "\xEF\xBB\xBFmixed-port: 32123 # comment\n"
        "socks-port: 32124\nsecret: 'a # b''c' # trailing\n"
        "external-controller-pipe: '\\\\.\\pipe\\from-config'\n"
        "nested:\n  mixed-port: 9\n  secret: wrong\n");
    EXPECT_STREQ(launch.configDir, R"(D:\User Data\代理)");
    EXPECT_STREQ(launch.configFile, "live config.yaml");
    EXPECT_STREQ(launch.pipe, R"(\\.\pipe\runtime-name)");
    EXPECT_STREQ(launch.secret, "a # b'c");
    EXPECT_EQ(launch.mixedPort, 32123);
    EXPECT_EQ(launch.socksPort, 32124);
    auto invalid = parseKernelLaunchConfig("core.exe", "mixed-port: 70000\nsocks-port: -1\nsecret: \"hello\\nworld\" # note\n");
    EXPECT_EQ(invalid.mixedPort, 0);
    EXPECT_EQ(invalid.socksPort, 0);
    EXPECT_STREQ(invalid.secret, "hello\nworld");
    auto overridden = parseKernelLaunchConfig("core.exe -secret=", "secret: old\n");
    EXPECT_STREQ(overridden.secret, "old");
}

APS_TEST(kdiscovery, dual_stack_socks_listener_is_discovered_by_owner) {
    MockSocks5Server socks;
    EXPECT_TRUE(socks.start(0, true));
    MockClashApi api;
    EXPECT_TRUE(api.start());
    auto ports = listeningPortsOf(GetCurrentProcessId());
    EXPECT_TRUE(std::find(ports.begin(), ports.end(), socks.port()) != ports.end());
    auto kernels = discoverProxyKernels(250, DiscoveryMode::Full);
    bool found = false;
    for (const auto& k : kernels) {
        if (k.pid == GetCurrentProcessId()) {
            found = true;
            EXPECT_EQ(k.socksPort, socks.port());
            EXPECT_EQ(k.apiPort, api.port());
        }
    }
    EXPECT_TRUE(found);
}

APS_TEST(kdiscovery, unknown_pipe_core_found_then_learned_by_quick_scan) {
    PipeKernelFixture fixture(true);
    EXPECT_TRUE(fixture.started);
    auto full = discoverProxyKernels(250, DiscoveryMode::Full);
    bool found = false;
    for (const auto& k : full) {
        if (k.pid != fixture.process.dwProcessId) continue;
        found = true;
        EXPECT_NE(k.socksPort, 0);
        EXPECT_EQ(k.apiPort, 0);
        EXPECT_FALSE(k.apiPipe.empty());
        EXPECT_TRUE(k.discoveryError.empty());
        saveKernelCache({k});
    }
    EXPECT_TRUE(found);
    auto quick = discoverProxyKernels(250, DiscoveryMode::Quick);
    found = false;
    for (const auto& k : quick) if (k.pid == fixture.process.dwProcessId) found = true;
    EXPECT_TRUE(found);
    saveKernelCache({});
}

APS_TEST(kdiscovery, occupied_port_is_reported_never_borrowed_from_other_pid) {
    MockSocks5Server other;
    EXPECT_TRUE(other.start());
    PipeKernelFixture fixture(false, other.port());
    EXPECT_TRUE(fixture.started);
    auto kernels = discoverProxyKernels(250, DiscoveryMode::Full);
    bool found = false;
    for (const auto& k : kernels) {
        if (k.pid != fixture.process.dwProcessId) continue;
        found = true;
        EXPECT_EQ(k.socksPort, 0);
        EXPECT_TRUE(k.hasApi());
        EXPECT_TRUE(k.discoveryError.find("被其他进程占用") != std::string::npos);
    }
    EXPECT_TRUE(found);
}

APS_TEST(kdiscovery, opaque_service_launch_recovers_verified_cached_pipe) {
    PipeKernelFixture fixture(true, 0, false, true);
    EXPECT_TRUE(fixture.started);
    DiscoveredKernel cached;
    cached.procName = processNameOf(fixture.process.dwProcessId);
    cached.configDir = "C:\\old-user\\config";
    cached.socksPort = 1; // stale; never use this as the live data endpoint
    cached.apiPipe = fixture.pipeName;
    saveKernelCache({cached});
    bool found = false;
    for (const auto& k : discoverProxyKernels(250, DiscoveryMode::Quick)) {
        if (k.pid != fixture.process.dwProcessId) continue;
        found = true;
        EXPECT_NE(k.socksPort, 0);
        EXPECT_NE(k.socksPort, cached.socksPort);
        EXPECT_STREQ(k.apiPipe, fixture.pipeName);
        EXPECT_EQ(k.apiPort, 0);
    }
    EXPECT_TRUE(found);
    saveKernelCache({});
}

APS_TEST(kdiscovery, opaque_service_launch_finds_existing_process_named_pipe) {
    // Fresh machine: no learned pipe/config. Use the actual executable stem,
    // not a brand-specific pipe constant. The server PID must still match.
    auto name = processNameOf(GetCurrentProcessId());
    name.resize(name.size() - 4); // test executable's .exe suffix
    PipeKernelFixture fixture(true, 0, false, true, "\\\\.\\pipe\\" + name);
    EXPECT_TRUE(fixture.started);
    saveKernelCache({});
    bool found = false;
    for (const auto& k : discoverProxyKernels(250, DiscoveryMode::Full)) {
        if (k.pid != fixture.process.dwProcessId) continue;
        found = true;
        EXPECT_NE(k.socksPort, 0);
        EXPECT_STREQ(k.apiPipe, fixture.pipeName);
    }
    EXPECT_TRUE(found);
}

APS_TEST(kdiscovery, cached_pipe_owned_by_another_process_is_never_adopted) {
    PipeKernelFixture fixture(true, 0, false, true);
    EXPECT_TRUE(fixture.started);
    aps::test::MockClashPipe other;
    EXPECT_TRUE(other.start());
    std::atomic<unsigned> requests{0};
    other.respond = [&](const std::string&) {
        ++requests;
        return "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 20\r\n\r\n{\"version\":\"mock-1\"}";
    };
    // Check the wrong-owner request in isolation. The later full scanner
    // may legitimately probe the parent fixture as its OWN pipe owner.
    auto wrong = ClashApiClient("127.0.0.1", 0, "must-not-be-sent", other.name,
                                fixture.process.dwProcessId).probeAny(250);
    EXPECT_FALSE(wrong.reachable);
    EXPECT_EQ(requests.load(), 0u);
    DiscoveredKernel cached;
    cached.procName = processNameOf(fixture.process.dwProcessId);
    cached.apiPipe = other.name;
    saveKernelCache({cached});
    bool found = false;
    for (const auto& k : discoverProxyKernels(250, DiscoveryMode::Quick)) {
        if (k.pid != fixture.process.dwProcessId) continue;
        found = true;
        EXPECT_FALSE(k.hasApi());
    }
    EXPECT_TRUE(found);
    saveKernelCache({});
}

APS_TEST(kdiscovery, process_named_pipe_requires_valid_version_not_just_auth_or_http) {
    MockSocks5Server socks;
    EXPECT_TRUE(socks.start());
    auto name = processNameOf(GetCurrentProcessId());
    const auto stem = name.substr(0, name.size() - 4);
    for (bool auth : {false, true}) {
        aps::test::MockClashPipe pipe;
        pipe.respond = [auth](const std::string&) {
            return auth ? "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
                        : "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        };
        EXPECT_TRUE(pipe.start(0, "\\\\.\\pipe\\" + stem));
        for (const auto& k : discoverProxyKernels(250, DiscoveryMode::Full))
            EXPECT_NE(k.pid, GetCurrentProcessId()); // unknown SOCKS-only stays rejected
    }
}

APS_TEST(kdiscovery, opaque_launch_recovers_suffixed_controller_without_cache) {
    const auto name = processNameOf(GetCurrentProcessId());
    const auto stem = name.substr(0, name.size() - 4);
    for (const auto* suffix : {"-production-owner", "-sidecar-release-owner"}) {
        saveKernelCache({});
        PipeKernelFixture fixture(true, 0, false, true, "\\\\.\\pipe\\" + stem + suffix);
        EXPECT_TRUE(fixture.started);
        bool found = false;
        for (const auto& k : discoverProxyKernels(250, DiscoveryMode::Full)) {
            if (k.pid != fixture.process.dwProcessId) continue;
            found = true;
            EXPECT_NE(k.socksPort, 0);
            EXPECT_STREQ(k.apiPipe, fixture.pipeName);
        }
        EXPECT_TRUE(found);
    }
}

APS_TEST(kdiscovery, suffixed_pipe_rejects_other_owner_before_http) {
    const auto name = processNameOf(GetCurrentProcessId());
    const auto stem = name.substr(0, name.size() - 4);
    saveKernelCache({});
    PipeKernelFixture fixture(true, 0, false, true);
    EXPECT_TRUE(fixture.started);
    aps::test::MockClashPipe other;
    std::atomic<unsigned> requests{0};
    other.respond = [&](const std::string&) {
        ++requests;
        return "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n{\"version\":\"mock-1\"}";
    };
    EXPECT_TRUE(other.start(0, "\\\\.\\pipe\\" + stem + "-production-other-owner"));
    auto kernels = discoverProxyKernels(250, DiscoveryMode::Full);
    for (const auto& k : kernels) {
        if (k.pid == fixture.process.dwProcessId) EXPECT_FALSE(k.hasApi());
    }
    // The parent has no SOCKS listener here; the child's discovery must not
    // send even a GET to this parent's pipe.
    EXPECT_EQ(requests.load(), 0u);
}

APS_TEST(kdiscovery, pipe_cache_identity_beats_same_directory_guess) {
    DiscoveredKernel old, wrong;
    old.procName = wrong.procName = "service-core.exe";
    old.configDir = "C:\\user\\config";
    old.apiPipe = "\\\\.\\pipe\\core-one";
    old.socksPort = 19001;
    old.id = "auto-service-core.exe";
    old.apiSecret = "old-secret";
    wrong.configDir = "C:\\Program Files\\Core";
    wrong.apiPipe = "\\\\.\\pipe\\core-two";
    wrong.socksPort = 19002;
    wrong.id = "auto-service-core.exe#2";
    wrong.apiSecret = "other-secret";
    saveKernelCache({wrong, old});
    auto fresh = old;
    fresh.configDir = wrong.configDir; // service launch falls back to exe dir
    fresh.socksPort = 19003;
    fresh.apiSecret = "new-secret";
    mergeDiscoveredIntoCache({fresh});
    auto result = loadKernelCache();
    EXPECT_EQ(result.size(), 2u);
    for (const auto& k : result) {
        EXPECT_EQ(k.socksPort, 0);
        if (k.apiPipe == old.apiPipe) {
            EXPECT_STREQ(k.id, old.id);
            EXPECT_STREQ(k.apiSecret, fresh.apiSecret);
            EXPECT_STREQ(k.configDir, fresh.configDir);
        }
        if (k.apiPipe == wrong.apiPipe) {
            EXPECT_STREQ(k.id, wrong.id);
            EXPECT_STREQ(k.apiSecret, wrong.apiSecret);
        }
    }
    saveKernelCache({});
}

APS_TEST(kdiscovery, unknown_tcp_core_reads_its_own_config_secret) {
    PipeKernelFixture fixture(true, 0, true);
    EXPECT_TRUE(fixture.started);
    bool found = false;
    for (const auto& k : discoverProxyKernels(250, DiscoveryMode::Full)) {
        if (k.pid != fixture.process.dwProcessId) continue;
        found = true;
        EXPECT_NE(k.apiPort, 0);
        EXPECT_FALSE(k.apiNeedSecret);
        EXPECT_STREQ(k.apiSecret, "fixture-secret");
    }
    EXPECT_TRUE(found);
}

APS_TEST(kdiscovery, api_only_responder_is_rejected) {
    // Regression: local HTTP services (node.exe dev servers, DSH Desktop
    // backends, ...) answered GET /version with a 200 and were adopted as
    // kernels. A controller requires a Clash-style /version JSON payload,
    // and a kernel requires a SOCKS port — an API-only responder is junk.
    MockClashApi api;
    EXPECT_TRUE(api.start());
    auto kernels = discoverProxyKernels(800, DiscoveryMode::Full);
    for (const auto& k : kernels) {
        EXPECT_TRUE(k.pid != GetCurrentProcessId());
        EXPECT_TRUE(k.socksPort != 0 || (!k.apiPipe.empty() && !k.discoveryError.empty()));
    }
    api.stop();
}

APS_TEST(kdiscovery, unknown_name_socks_only_is_rejected) {
    // A lone SOCKS responder with a name no filter has ever seen is not
    // evidence of an airport kernel: the Full blind scan requires BOTH
    // ports from unknown names (this also keeps junk out of the cache).
    MockSocks5Server socks;
    EXPECT_TRUE(socks.start());
    auto kernels = discoverProxyKernels(800, DiscoveryMode::Full);
    for (const auto& k : kernels) {
        EXPECT_TRUE(k.pid != GetCurrentProcessId());
    }
    socks.stop();
}

APS_TEST(kdiscovery, cache_remembers_identity_and_secret_without_tcp_ports) {
    std::vector<DiscoveredKernel> in(1);
    in[0].procName = "my-test-clash-win64.exe";
    in[0].socksPort = 47001;
    in[0].apiPort = 47002;
    in[0].apiSecret = "secret-abc-123";
    in[0].cmdline = "core.exe -secret secret-abc-123";
    in[0].apiPipe = "\\\\.\\pipe\\test-cache";
    saveKernelCache(in);
    std::ifstream cache(g_cache.directory + L"\\kernel_cache.json", std::ios::binary);
    std::string raw((std::istreambuf_iterator<char>(cache)), {});
    cache.close();
    EXPECT_TRUE(raw.find("secret-abc-123") == std::string::npos);
    EXPECT_TRUE(raw.find("socksPort") == std::string::npos);
    EXPECT_TRUE(raw.find("apiPort") == std::string::npos);
    EXPECT_TRUE(raw.find("47001") == std::string::npos);
    EXPECT_TRUE(raw.find("47002") == std::string::npos);

    auto out = loadKernelCache();
    bool found = false;
    for (const auto& k : out) {
        if (k.procName == in[0].procName) {
            found = true;
            EXPECT_EQ(k.socksPort, 0);
            EXPECT_EQ(k.apiPort, 0);
            // Secret survives the DPAPI roundtrip.
            EXPECT_TRUE(k.apiSecret == "secret-abc-123");
            EXPECT_STREQ(k.cmdline, in[0].cmdline);
            EXPECT_STREQ(k.apiPipe, in[0].apiPipe);
            EXPECT_FALSE(k.id.empty());
        }
    }
    EXPECT_TRUE(found);
    // Leave no junk behind for later runs.
    saveKernelCache({});
}

APS_TEST(kdiscovery, empty_scan_migrates_legacy_cache_without_renumbering) {
    saveKernelCache({}); // create the isolated directory
    {
        std::ofstream file(g_cache.directory + L"\\kernel_cache.json", std::ios::binary);
        file << R"({"version":2,"kernels":[
            {"procName":"same-core.exe","socksPort":50001,"apiPort":10001,"configDir":"C:\\secondary"},
            {"procName":"same-core.exe","socksPort":50002,"apiPort":10002,"configDir":"C:\\primary","cmdline":"core.exe -f primary.yaml"}
        ]})";
    }
    auto legacy = loadKernelCache();
    EXPECT_EQ(legacy.size(), 2u);
    EXPECT_STREQ(legacy[0].id, "auto-same-core.exe");
    EXPECT_STREQ(legacy[0].configDir, "C:\\primary");
    EXPECT_EQ(legacy[0].socksPort, 50002); // matching hint, never routable by itself
    mergeDiscoveredIntoCache({});
    auto migrated = loadKernelCache();
    EXPECT_EQ(migrated.size(), 2u);
    for (const auto& k : migrated) {
        EXPECT_EQ(k.socksPort, 0);
        EXPECT_EQ(k.apiPort, 0);
        EXPECT_STREQ(k.id, k.configDir == "C:\\primary" ? "auto-same-core.exe" : "auto-same-core.exe#2");
    }
    std::ifstream file(g_cache.directory + L"\\kernel_cache.json", std::ios::binary);
    std::string raw((std::istreambuf_iterator<char>(file)), {});
    file.close();
    EXPECT_TRUE(raw.find("socksPort") == std::string::npos);
    EXPECT_TRUE(raw.find("apiPort") == std::string::npos);
    EXPECT_TRUE(raw.find("\"version\":3") != std::string::npos);
    saveKernelCache({});
}

APS_TEST(kdiscovery, adopted_same_name_instances_keep_ids_across_port_changes) {
    DiscoveredKernel a, b;
    a.procName = b.procName = "same-core.exe";
    a.configDir = b.configDir = "C:\\same-config";
    a.id = "auto-same-core.exe";
    b.id = "auto-same-core.exe#2";
    a.apiSecret = "primary";
    b.apiSecret = "secondary";
    a.socksPort = 40001; b.socksPort = 40002;
    saveKernelCache({a});
    mergeDiscoveredIntoCache({b}); // distinct adopted ID, same directory
    a.socksPort = 50001; b.socksPort = 50002;
    a.apiSecret = "primary-updated";
    mergeDiscoveredIntoCache({a, b});
    auto out = loadKernelCache();
    EXPECT_EQ(out.size(), 2u);
    for (const auto& k : out) {
        EXPECT_EQ(k.socksPort, 0);
        EXPECT_EQ(k.apiPort, 0);
        EXPECT_STREQ(k.apiSecret, k.id == a.id ? "primary-updated" : "secondary");
    }
    saveKernelCache({});
}

APS_TEST(kdiscovery, probe_pid_ports_finds_mock_pair) {
    MockSocks5Server socks;
    EXPECT_TRUE(socks.start());
    MockClashApi api;
    EXPECT_TRUE(api.start());
    auto k = probePidPorts(GetCurrentProcessId(),
                           {socks.port(), api.port()}, 800);
    EXPECT_TRUE(k.socksPort == socks.port());
    EXPECT_TRUE(k.apiPort == api.port());
    EXPECT_TRUE(k.procName == "test_kernel_discovery.exe");
    EXPECT_FALSE(k.id.empty());
    api.stop();
    socks.stop();
}

APS_TEST(kdiscovery, name_lookup_finds_our_own_process) {
    auto pids = findProcessIdsByName({"test_kernel_discovery"});
    bool found = false;
    for (uint32_t pid : pids) {
        if (pid == GetCurrentProcessId()) {
            found = true;
            EXPECT_TRUE(processNameOf(pid) == "test_kernel_discovery.exe");
        }
    }
    EXPECT_TRUE(found);
    auto ports = listeningPortsOf(GetCurrentProcessId());
    EXPECT_TRUE(ports.empty());  // no mock running in this test
}

APS_TEST(kdiscovery, timing_benchmark) {
    // Informational: report Quick vs Full scan durations. Not an assertion —
    // machine load varies. Quick must stay near-instant (production path).
    LARGE_INTEGER t0, t1, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    auto quick = discoverProxyKernels(250, DiscoveryMode::Quick);
    QueryPerformanceCounter(&t1);
    double quickMs = (t1.QuadPart - t0.QuadPart) * 1000.0 / freq.QuadPart;
    QueryPerformanceCounter(&t0);
    auto full = discoverProxyKernels(250, DiscoveryMode::Full);
    QueryPerformanceCounter(&t1);
    double fullMs = (t1.QuadPart - t0.QuadPart) * 1000.0 / freq.QuadPart;
    std::printf("[bench] Quick=%zu kernels %.0f ms | Full=%zu kernels %.0f ms\n",
                quick.size(), quickMs, full.size(), fullMs);
    EXPECT_TRUE(quick.size() <= full.size());
    (void)full;
}

APS_TEST(kdiscovery, cfw_secret_reader_is_safe) {
    // readCfwSecret must never throw; content is machine-dependent. Returning
    // at all (no exception, no crash) is the assertion.
    (void)readCfwSecret();
}

int main(int argc, char** argv) {
    if (argc >= 5 && (std::string(argv[1]) == "--pipe-fixture" || std::string(argv[1]) == "--tcp-fixture")) {
        auto flags = parseKernelLaunchConfig(wideToUtf8(GetCommandLineW()));
        for (int i = 5; i + 1 < argc; ++i)
            if (std::string(argv[i]) == "--fixture-endpoint") flags.pipe = argv[i + 1];
        aps::test::MockClashPipe pipe;
        MockClashApi api;
        api.secret = "fixture-secret";
        MockSocks5Server socks;
        HANDLE ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, utf8ToWide(argv[2]).c_str());
        HANDLE quit = OpenEventW(SYNCHRONIZE, FALSE, utf8ToWide(argv[3]).c_str());
        bool controllerStarted = std::string(argv[1]) == "--tcp-fixture" ? api.start() : pipe.start(0, flags.pipe);
        if (!ready || !quit || !controllerStarted) return 2;
        if (std::string(argv[4]) == "yes" && !socks.start()) return 3;
        SetEvent(ready);
        WaitForSingleObject(quit, 30000);
        CloseHandle(ready);
        CloseHandle(quit);
        return 0;
    }
    return aps::test::runAll(nullptr);
}
