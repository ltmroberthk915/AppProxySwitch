// Engine pipeline tests driven by the fake divert device: attribution,
// whole-flow NAT rewriting, return-path rewriting, race fallback, fail-open,
// flush/stop teardown semantics.
#include <winsock2.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <fstream>
#include <map>
#include <mutex>

#include "aps/engine.hpp"
#include "aps/clash_api.hpp"
#include "aps/pump_watchdog.hpp"
#include "aps/log.hpp"
#include "aps/string_util.hpp"
#include "aps/packet_rewrite.hpp"
#include "fake_divert_device.hpp"
#include "mock_clash_api.hpp"
#include "mock_clash_pipe.hpp"
#include "mock_profile_bridge.hpp"
#include "mock_socks_server.hpp"
#include "tls_fixture.hpp"
#include "kernel_cache_sandbox.hpp"
#include "testlib/appsw_test.h"

using namespace aps;
using aps::test::FakeDivertDevice;
using aps::test::MockClashApi;
using aps::test::MockSocks5Server;
using aps::test::MockSocksBehavior;
using aps::test::buildTcpPacket;
using aps::test::buildTcp6Packet;
using aps::test::buildUdpPacket;

namespace {

json::Value outletStatusFor(const std::string& text, const std::string& id);

struct WsaInit {
    WsaInit() { net::initWinsock(); }
};
WsaInit g_wsa;
aps::test::KernelCacheSandbox g_cache;

constexpr uint32_t kAppIp = 0xC0A80105;    // 192.168.1.5
constexpr uint16_t kAppPort = 50000;
constexpr uint32_t kDstIp = 0x08080808;    // 8.8.8.8
constexpr uint16_t kDstPort = 443;
const wchar_t* kAppPath = L"C:\\Test\\app.exe";

MockSocks5Server& socks() {
    static MockSocks5Server srv;
    static bool started = srv.start();
    (void)started;
    return srv;
}

uint16_t randomRelayPort() {
    static std::atomic<uint16_t> next{24000 + (GetCurrentProcessId() % 5000)};
    return next.fetch_add(7);
}

void removeTree(const std::wstring& dir) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        RemoveDirectoryW(dir.c_str());
        return;
    }
    do {
        if (!lstrcmpW(fd.cFileName, L".") || !lstrcmpW(fd.cFileName, L".."))
            continue;
        std::wstring p = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            removeTree(p);
        } else {
            DeleteFileW(p.c_str());
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    RemoveDirectoryW(dir.c_str());
}

// Hermetic "SakuraCat install dir" for the refresh-flow tests: a temp
// <base>\.config\com.vortex.helper\config.yaml with a scripted listener
// line. Redirected into the engine via setSakuraCatConfigDir.
struct TempSakuraDir {
    std::wstring base;
    std::wstring cfgDir;
    bool ok = false;

    explicit TempSakuraDir(const std::string& configYaml) {
        wchar_t tmp[MAX_PATH];
        if (!GetTempPathW(MAX_PATH, tmp)) return;
        base = std::wstring(tmp) + L"aps-sakura-" +
               std::to_wstring(GetCurrentProcessId()) + L"-" +
               std::to_wstring(GetTickCount64());
        const std::wstring dotConfig = base + L"\\.config";
        cfgDir = dotConfig + L"\\com.vortex.helper";
        if (!CreateDirectoryW(base.c_str(), nullptr) ||
            !CreateDirectoryW(dotConfig.c_str(), nullptr) ||
            !CreateDirectoryW(cfgDir.c_str(), nullptr)) {
            return;
        }
        HANDLE f = CreateFileW((cfgDir + L"\\config.yaml").c_str(), GENERIC_WRITE,
                               0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                               nullptr);
        if (f == INVALID_HANDLE_VALUE) return;
        DWORD written = 0;
        WriteFile(f, configYaml.data(), static_cast<DWORD>(configYaml.size()),
                  &written, nullptr);
        CloseHandle(f);
        ok = true;
    }

    ~TempSakuraDir() {
        if (!base.empty()) removeTree(base);
    }
};

// One deterministic live kernel record for seedDiscoveredKernelsForTest.
DiscoveredKernel makeKernel(const char* proc, uint16_t socks, uint16_t api) {
    DiscoveredKernel k;
    k.procName = proc;
    k.socksPort = socks;
    k.apiPort = api;
    k.pid = 4242000 + socks;
    k.id = "auto-" + k.procName;
    return k;
}

// Local TCP DNS responder: answers any A query with 9.9.9.9 (the unpoisoned
// answer the tests look for). The engine's SOCKS TCP-53 queries reach it
// through the mock SOCKS servers, which splice to this listener.
struct TcpDnsResponder {
    SOCKET sock = INVALID_SOCKET;
    std::atomic<bool> stop{false};
    std::thread th;
    uint16_t port = 0;

    bool start() {
        sock = net::makeTcpSocket();
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_addr.S_un.S_addr = htonl(0x7F000001);
        sa.sin_port = 0;
        if (bind(sock, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0 ||
            listen(sock, 4) != 0) {
            net::closeSocket(sock);
            sock = INVALID_SOCKET;
            return false;
        }
        socklen_t sl = sizeof(sa);
        getsockname(sock, reinterpret_cast<sockaddr*>(&sa), &sl);
        port = ntohs(sa.sin_port);
        th = std::thread([this] { serve(); });
        return true;
    }

    void serve() {
        while (!stop.load()) {
            SOCKET cl = accept(sock, nullptr, nullptr);
            if (cl == INVALID_SOCKET) {
                Sleep(20);
                continue;
            }
            char lenbuf[2];
            int got = recv(cl, lenbuf, 2, 0);
            if (got == 2) {
                size_t qlen = (static_cast<uint8_t>(lenbuf[0]) << 8) |
                              static_cast<uint8_t>(lenbuf[1]);
                std::vector<char> query(qlen);
                size_t off = 0;
                while (off < qlen) {
                    int n = recv(cl, query.data() + off,
                                 static_cast<int>(qlen - off), 0);
                    if (n <= 0) break;
                    off += n;
                }
                if (off >= 12) {
                    // Echo id + question; flags 0x8180; one A answer
                    // (pointer to the question name) = 9.9.9.9.
                    std::vector<uint8_t> resp;
                    resp.push_back(query[0]);
                    resp.push_back(query[1]);
                    const uint8_t hdr[10] = {0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
                                             0x00, 0x00, 0x00, 0x00};
                    resp.insert(resp.end(), hdr, hdr + 10);
                    for (size_t i = 12; i < qlen; ++i)
                        resp.push_back(static_cast<uint8_t>(query[i]));
                    const uint8_t ans[16] = {0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
                                             0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
                                             9, 9, 9, 9};
                    resp.insert(resp.end(), ans, ans + 16);
                    uint8_t lb[2] = {static_cast<uint8_t>(resp.size() >> 8),
                                     static_cast<uint8_t>(resp.size() & 0xFF)};
                    send(cl, reinterpret_cast<const char*>(lb), 2, 0);
                    send(cl, reinterpret_cast<const char*>(resp.data()),
                         static_cast<int>(resp.size()), 0);
                }
            }
            net::closeSocket(cl);
        }
    }

    void shutdown() {
        stop.store(true);
        if (sock != INVALID_SOCKET) {
            net::closeSocket(sock);
            sock = INVALID_SOCKET;
        }
        if (th.joinable()) th.join();
    }
};

struct Harness {
    FakeDivertDevice* device = nullptr;   // owned by engine
    std::unique_ptr<Engine> engine;
    std::mutex mu;
    std::vector<std::string> statuses, stats;
    std::vector<std::pair<std::string, std::string>> logs;
    std::unique_ptr<ITcpTableQuery> fakeTcpTable;   // may stay null
    std::map<uint16_t, uint32_t> tcpTableRows;      // localPort -> pid
    // Optional fake kernel-cache source (start() seeds its kernels as
    // offline rows); empty = the engine's real kernel_cache.json.
    std::function<std::vector<DiscoveredKernel>()> cacheLoader;
    // Optional STATS consumer gate (empty = always push).
    std::function<bool()> wantsStats;
    // Optional scripted discovery scan (replaces the real machine scan in
    // adoptDiscoveries — tests deliver exactly the kernels they want).
    std::function<std::vector<DiscoveredKernel>(DiscoveryMode)> discoveryScan;
    // Install side-effect guards before start() launches background work.
    std::function<void(Engine&)> beforeStart;
    // Local listener the health monitors CONNECT-probe through (the engine
    // must never dial external hosts in tests).
    SOCKET healthProbeSock = INVALID_SOCKET;
    uint16_t healthProbePort = 0;

    Config makeConfig(bool ruleEnabled = true) {
        Config c = Config::makeDefault();
        c.rules.clear();
        Rule r;
        r.id = "r1";
        r.name = "app";
        r.path = wideToUtf8(kAppPath);
        r.enabled = ruleEnabled;
        c.rules.push_back(r);
        c.proxy.port = socks().port();
        c.relay.port = randomRelayPort();
        c.routing.blockUdpForRules = false;
        // Existing resolver failover/cache tests intentionally exercise the
        // retained opt-in global mode. Scope regressions explicitly set false.
        c.routing.dnsCleanupGlobal = true;
        c.proxy.healthIntervalS = 30;   // keep health quiet during fast tests
        // Node monitoring is opt-in per test (default config's clashApi is
        // host=127.0.0.1/port=0 "auto", whose slow full port scan would run
        // on the engine's immediate first round and cost ~3 s per test).
        c.nodeMonitor.enabled = false;
        return c;
    }

    void start(const Config& c, bool discoveryEnabled = false) {
        auto dev = std::make_unique<FakeDivertDevice>();
        device = dev.get();
        EngineEvents ev;
        ev.onStatus = [this](const std::string& s) {
            std::lock_guard<std::mutex> lk(mu);
            statuses.push_back(s);
        };
        ev.onStats = [this](const std::string& s) {
            std::lock_guard<std::mutex> lk(mu);
            stats.push_back(s);
        };
        ev.onLog = [this](const std::string& l, const std::string& m) {
            std::lock_guard<std::mutex> lk(mu);
            logs.emplace_back(l, m);
        };
        ev.wantsStats = wantsStats;
        engine = std::make_unique<Engine>(std::move(dev), std::move(ev));
        // Real proxy kernels running on the dev machine must never leak into
        // deterministic harness assertions.
        if (!discoveryEnabled) engine->setKernelDiscoveryEnabled(false);
        if (cacheLoader) engine->setKernelCacheLoader(cacheLoader);
        if (discoveryScan) engine->setDiscoveryScanForTest(discoveryScan);
        engine->socketMap().setPathResolver([](uint32_t pid) {
            return pid == 100 ? kAppPath
                             : (pid == 200 ? L"C:\\Other\\other.exe" : L"");
        });
        // Deterministic real-CONNECT probe target: a local listener the
        // mocks dial. Without this the health monitors would CONNECT to
        // 1.1.1.1:443 through the mocks — real external traffic in tests.
        healthProbeSock = net::makeTcpSocket();
        sockaddr_in psa{};
        psa.sin_family = AF_INET;
        psa.sin_addr.S_un.S_addr = htonl(0x7F000001);
        psa.sin_port = 0;
        if (healthProbeSock != INVALID_SOCKET &&
            bind(healthProbeSock, reinterpret_cast<sockaddr*>(&psa),
                 sizeof(psa)) == 0 &&
            listen(healthProbeSock, 8) == 0) {
            socklen_t pl = sizeof(psa);
            getsockname(healthProbeSock, reinterpret_cast<sockaddr*>(&psa), &pl);
            healthProbePort = ntohs(psa.sin_port);
            engine->setHealthProbeDstForTest(
                net::Endpoint4{0x7F000001, healthProbePort});
        }
        if (fakeTcpTable) engine->setTcpTable(std::move(fakeTcpTable));
        if (beforeStart) beforeStart(*engine);
        std::string err;
        EXPECT_TRUE(engine->start(c, &err));
        if (!err.empty()) std::printf("    engine start err: %s\n", err.c_str());
    }

    void stop() {
        if (engine) engine->stop();
        if (healthProbeSock != INVALID_SOCKET) {
            net::closeSocket(healthProbeSock);
            healthProbeSock = INVALID_SOCKET;
        }
    }

    std::string lastStatus() {
        std::lock_guard<std::mutex> lk(mu);
        return statuses.empty() ? std::string() : statuses.back();
    }

    bool waitStatus(const std::function<bool(const std::string&)>& pred, int ms) {
        for (int t = 0; t < ms; t += 25) {
            if (pred(lastStatus())) return true;
            Sleep(25);
        }
        if (!pred(lastStatus())) {
            std::string s = lastStatus();
            std::printf("    waitStatus timeout; last status:\n%.800s\n",
                        s.c_str());
            std::printf("    captured logs (tail):\n");
            for (size_t i = logs.size() > 8 ? logs.size() - 8 : 0;
                 i < logs.size(); ++i) {
                std::printf("      [%s] %s\n", logs[i].first.c_str(),
                            logs[i].second.c_str());
            }
        }
        return pred(lastStatus());
    }

    std::string lastStats() {
        std::lock_guard<std::mutex> lk(mu);
        return stats.empty() ? std::string() : stats.back();
    }

    bool waitStats(const std::function<bool(const std::string&)>& pred, int ms) {
        for (int t = 0; t < ms; t += 25) {
            if (pred(lastStats())) return true;
            Sleep(25);
        }
        return pred(lastStats());
    }

    void pushConnectEvent(uint16_t localPort, uint32_t pid = 100, uint32_t dstIp = kDstIp,
                          uint16_t dstPort = kDstPort, uint8_t proto = 6,
                          uint32_t localIp = kAppIp) {
        SocketEventInfo ev;
        ev.kind = SocketEventInfo::Kind::Connect;
        ev.pid = pid;
        ev.localIp = localIp;
        ev.localPort = localPort;
        ev.remoteIp = dstIp;
        ev.remotePort = dstPort;
        ev.protocol = proto;
        device->pushSocket(ev);
        // The socket pump runs on another thread; wait until the mapping is
        // actually visible so the SYN below is attributed via defense line 1
        // deterministically (the race itself is covered by the tcp-table test).
        for (int i = 0; i < 200; ++i) {
            if (engine->socketMap().find(localIp, localPort).has_value()) return;
            Sleep(10);
        }
    }

    // IPv6 SOCKET event (localIp=0 is what the real layer reports for v6).
    void pushConnectEvent6(uint16_t localPort, uint32_t pid = 100) {
        SocketEventInfo ev;
        ev.kind = SocketEventInfo::Kind::Connect;
        ev.pid = pid;
        ev.localIp = 0;
        ev.localPort = localPort;
        ev.remoteIp = 0;
        ev.remotePort = 443;
        ev.protocol = 6;
        device->pushSocket(ev);
        for (int i = 0; i < 200; ++i) {
            if (engine->socketMap().find(0, localPort).has_value()) return;
            Sleep(10);
        }
    }
};

// Minimal DNS A-query payload (classic label form, like test_dns_rewrite's).
std::vector<uint8_t> dnsQueryBytes(const std::string& name, uint16_t id = 0x1234) {
    std::vector<uint8_t> pkt(12 + name.size() + 2 + 4, 0);
    pkt[0] = static_cast<uint8_t>(id >> 8);
    pkt[1] = static_cast<uint8_t>(id & 0xFF);
    pkt[2] = 0x01; pkt[3] = 0x00;  // RD
    pkt[5] = 1;                    // QDCOUNT=1
    size_t pos = 12;
    size_t start = 0;
    while (start <= name.size()) {
        size_t dot = name.find('.', start);
        size_t labelLen =
            dot == std::string::npos ? name.size() - start : dot - start;
        pkt[pos++] = static_cast<uint8_t>(labelLen);
        std::memcpy(&pkt[pos], name.data() + start, labelLen);
        pos += labelLen;
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    pkt[pos++] = 0;                 // root label
    pkt[pos++] = 0; pkt[pos++] = 1; // A
    pkt[pos++] = 0; pkt[pos++] = 1; // IN
    return pkt;
}

pkt::TcpPacket parseSent(const FakeDivertDevice::Sent& s) {
    pkt::TcpPacket p;
    bool ok = pkt::parseTcpPacket(s.data.data(), s.data.size(), p);
    EXPECT_TRUE(ok);
    return p;
}

}  // namespace

APS_TEST(engine, new_flow_of_rule_process_is_redirected) {
    Harness h;
    h.start(h.makeConfig());
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto sent = h.device->sent();
    EXPECT_EQ(sent.size(), 1u);
    auto p = parseSent(sent[0]);
    EXPECT_TRUE(p.dstIp == 0x7F000001u || p.dstIp != kDstIp);  // local relay addr (LAN IP or 127.0.0.1)
    EXPECT_EQ(p.dstPort, h.engine->relay().listenPort());
    EXPECT_EQ(p.srcIp, kAppIp);
    EXPECT_EQ(p.srcPort, kAppPort);
    EXPECT_TRUE(sent[0].meta.loopback);
    EXPECT_EQ(h.engine->nat().size(), 1u);
    h.stop();
}

APS_TEST(engine, whole_flow_subsequent_packets_are_rewritten) {
    Harness h;
    h.start(h.makeConfig());
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    h.device->clearSent();
    // ACK + request data on the same flow: must be rewritten too.
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 101, 500,
                                     0x18, {'G', 'E', 'T'}));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto sent = h.device->sent();
    EXPECT_EQ(sent.size(), 1u);
    auto p = parseSent(sent[0]);
    EXPECT_TRUE(p.dstIp == 0x7F000001u || p.dstIp != kDstIp);  // local relay addr (LAN IP or 127.0.0.1)
    EXPECT_EQ(p.dstPort, h.engine->relay().listenPort());
    EXPECT_EQ(p.payloadLen, 3u);
    h.stop();
}

APS_TEST(engine, relay_address_network_change_and_concurrent_interfaces) {
    Harness h;
    h.start(h.makeConfig());
    // One engine survives Wi-Fi/DHCP changes. Keep both flows present to
    // also cover concurrent adapters; neither flow may borrow the other's IP.
    constexpr uint32_t addresses[] = {0xC0A80523, 0xC0A80105, 0x0A080002};
    const uint16_t relayPort = h.engine->relay().listenPort();
    for (uint32_t ip : addresses) {
        h.pushConnectEvent(kAppPort, 100, kDstIp, kDstPort, 6, ip);
        h.device->clearSent();
        h.device->pushTcp(buildTcpPacket(ip, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
        EXPECT_TRUE(h.device->waitSent(1, 3000));
        auto sent = h.device->sent();
        if (sent.empty()) continue;
        auto p = parseSent(sent[0]);
        EXPECT_EQ(p.dstIp, ip);
        EXPECT_EQ(p.dstPort, relayPort);
        EXPECT_EQ(p.srcIp, ip);
        EXPECT_TRUE(sent[0].meta.loopback);
    }
    EXPECT_EQ(h.engine->nat().size(), 3u);
    for (uint32_t ip : addresses) {
        // Retransmitted SYN and later data must use this flow's address,
        // even after packets from a different interface have arrived.
        for (uint8_t flags : {uint8_t{0x02}, uint8_t{0x18}}) {
            h.device->clearSent();
            h.device->pushTcp(buildTcpPacket(ip, kAppPort, kDstIp, kDstPort, 101, 500, flags));
            EXPECT_TRUE(h.device->waitSent(1, 3000));
            auto sent = h.device->sent();
            if (!sent.empty()) EXPECT_EQ(parseSent(sent[0]).dstIp, ip);
        }
        h.device->clearSent();
        h.device->pushTcp(buildTcpPacket(ip, relayPort, ip, kAppPort, 500, 101, 0x18,
                                         {'o', 'k'}), {true, true, false, false});
        EXPECT_TRUE(h.device->waitSent(1, 3000));
        auto sent = h.device->sent();
        if (sent.empty()) continue;
        auto p = parseSent(sent[0]);
        EXPECT_EQ(p.srcIp, kDstIp);
        EXPECT_EQ(p.srcPort, kDstPort);
        EXPECT_EQ(p.dstIp, ip);
        EXPECT_EQ(p.payloadLen, 2u);
    }
    h.stop();
}

APS_TEST(engine, relay_address_tcp_dns_after_network_change) {
    Harness h;
    h.start(h.makeConfig());
    constexpr uint32_t ip = 0xC0A80523;
    constexpr uint32_t resolver = 0xC0A80501;
    constexpr uint16_t port = 53002;
    h.pushConnectEvent(port, 100, resolver, 53, 6, ip);
    h.device->pushTcp(buildTcpPacket(ip, port, resolver, 53, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto sent = h.device->sent();
    if (!sent.empty()) {
        auto p = parseSent(sent[0]);
        EXPECT_EQ(p.dstIp, ip);
        EXPECT_EQ(p.dstPort, h.engine->relay().listenPort());
    }
    auto entry = h.engine->nat().findByRev(ip, port);
    EXPECT_TRUE(entry && entry->dnsBridge);
    h.stop();
}

APS_TEST(engine, relay_address_unrelated_source_on_relay_port_passes_through) {
    Harness h;
    h.start(h.makeConfig());
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    h.device->clearSent();
    constexpr uint32_t unrelatedIp = 0xC0A80909;
    h.device->pushTcp(buildTcpPacket(unrelatedIp, h.engine->relay().listenPort(),
                                     kAppIp, kAppPort, 500, 101, 0x18));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto sent = h.device->sent();
    if (!sent.empty()) EXPECT_EQ(parseSent(sent[0]).srcIp, unrelatedIp);
    h.stop();
}

APS_TEST(engine, return_path_from_relay_is_untranslated) {
    Harness h;
    h.start(h.makeConfig());
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    h.device->clearSent();
    uint16_t relayPort = h.engine->relay().listenPort();
    // relay -> app (loopback-marked outbound packet)
    h.device->pushTcp(buildTcpPacket(0x7F000001, relayPort, kAppIp, kAppPort, 500, 101,
                                     0x18, {'o', 'k'}),
                      {true, true, false, false});
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto sent = h.device->sent();
    EXPECT_EQ(sent.size(), 1u);
    auto p = parseSent(sent[0]);
    EXPECT_EQ(p.srcIp, kDstIp);          // masquerades as the original target
    EXPECT_EQ(p.srcPort, kDstPort);
    EXPECT_EQ(p.dstIp, kAppIp);
    EXPECT_EQ(p.dstPort, kAppPort);
    EXPECT_EQ(p.payloadLen, 2u);
    h.stop();
}

APS_TEST(engine, non_rule_process_passes_through_untouched) {
    Harness h;
    h.start(h.makeConfig());
    h.pushConnectEvent(50001, /*pid=*/200);   // C:\Other\other.exe
    h.device->pushTcp(buildTcpPacket(kAppIp, 50001, kDstIp, kDstPort, 1, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto sent = h.device->sent();
    EXPECT_EQ(sent.size(), 1u);
    auto p = parseSent(sent[0]);
    EXPECT_EQ(p.dstIp, kDstIp);   // untouched
    EXPECT_EQ(p.dstPort, kDstPort);
    EXPECT_EQ(h.engine->nat().size(), 0u);
    h.stop();
}

APS_TEST(engine, race_syn_before_socket_event_falls_back_to_tcp_table) {
    Harness h;
    // Defense line 2: SYN arrives with no SOCKET event; the fake TCP table
    // reports the SYN_SENT row owner.
    class FakeTable : public ITcpTableQuery {
    public:
        std::optional<uint32_t> findOwnerByLocal(uint32_t, uint16_t) override { return 100; }
    };
    h.fakeTcpTable = std::make_unique<FakeTable>();
    h.start(h.makeConfig());
    // NOTE: socket event deliberately NOT pushed.
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto sent = h.device->sent();
    EXPECT_EQ(sent.size(), 1u);
    auto p = parseSent(sent[0]);
    EXPECT_TRUE(p.dstIp == 0x7F000001u || p.dstIp != kDstIp);  // local relay addr (LAN IP or 127.0.0.1)
    EXPECT_EQ(h.engine->nat().size(), 1u);
    h.stop();
}

APS_TEST(engine, tcp_dns_to_private_resolver_uses_local_bridge) {
    Harness h;
    h.start(h.makeConfig());
    constexpr uint16_t kDnsPort = 53001;
    constexpr uint32_t kLanResolver = 0xC0A80501;  // 192.168.5.1
    h.pushConnectEvent(kDnsPort, /*pid=*/100, kLanResolver, 53);
    h.device->pushTcp(buildTcpPacket(kAppIp, kDnsPort, kLanResolver, 53,
                                     100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto p = parseSent(h.device->sent()[0]);
    EXPECT_TRUE(p.dstIp != kLanResolver);
    EXPECT_TRUE(p.dstPort != 53);  // rewritten to the local relay
    auto entry = h.engine->nat().findByRev(kAppIp, kDnsPort);
    EXPECT_TRUE(entry != nullptr);
    if (entry) {
        EXPECT_TRUE(entry->dnsBridge);
        EXPECT_EQ(entry->origDstIp, kLanResolver);
        EXPECT_EQ(entry->origDstPort, 53);
    }
    h.stop();
}

APS_TEST(engine, unresolved_owner_passes_through) {
    Harness h;
    // No socket event, and the TCP table knows nothing (pid 0 => kernel).
    class EmptyTable : public ITcpTableQuery {
    public:
        std::optional<uint32_t> findOwnerByLocal(uint32_t, uint16_t) override {
            return std::nullopt;
        }
    };
    h.fakeTcpTable = std::make_unique<EmptyTable>();
    h.start(h.makeConfig());
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto sent = h.device->sent();
    EXPECT_EQ(sent.size(), 1u);
    auto p = parseSent(sent[0]);
    EXPECT_EQ(p.dstIp, kDstIp);   // fail-open: unresolved goes direct
    EXPECT_EQ(h.engine->nat().size(), 0u);
    h.stop();
}

APS_TEST(engine, private_destination_bypassed) {
    Harness h;
    h.start(h.makeConfig());
    h.pushConnectEvent(50002, 100, 0xC0A8000A /* 192.168.0.10 */, 80);
    h.device->pushTcp(buildTcpPacket(kAppIp, 50002, 0xC0A8000A, 80, 1, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto sent = h.device->sent();
    auto p = parseSent(sent[0]);
    EXPECT_EQ(p.dstIp, 0xC0A8000Au);
    EXPECT_EQ(h.engine->nat().size(), 0u);
    h.stop();
}

APS_TEST(engine, disabled_rule_goes_direct) {
    Harness h;
    h.start(h.makeConfig(/*ruleEnabled=*/false));
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto sent = h.device->sent();
    auto p = parseSent(sent[0]);
    EXPECT_EQ(p.dstIp, kDstIp);
    h.stop();
}

APS_TEST(engine, set_enabled_false_affects_only_new_connections) {
    Harness h;
    h.start(h.makeConfig());
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    h.device->clearSent();

    h.engine->setEnabled(false);
    // Existing flow keeps flowing (next packet still rewritten).
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 101, 1, 0x10));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    {
        auto p = parseSent(h.device->sent()[0]);
        EXPECT_TRUE(p.dstIp == 0x7F000001u || p.dstIp != kDstIp);  // local relay addr (LAN IP or 127.0.0.1)
    }
    h.device->clearSent();
    // New flow from the same app: direct now.
    h.pushConnectEvent(50003);
    h.device->pushTcp(buildTcpPacket(kAppIp, 50003, kDstIp, kDstPort, 1, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    {
        auto p = parseSent(h.device->sent()[0]);
        EXPECT_EQ(p.dstIp, kDstIp);
    }
    h.stop();
}

APS_TEST(engine, flush_sends_teardown_rst_and_clears_nat) {
    Harness h;
    h.start(h.makeConfig());
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    h.device->clearSent();

    h.engine->flushConnections(std::nullopt);
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto sent = h.device->sent();
    EXPECT_EQ(sent.size(), 1u);
    EXPECT_TRUE(sent[0].synthetic);
    auto p = parseSent(sent[0]);
    EXPECT_TRUE(p.rst);
    EXPECT_EQ(p.srcIp, kDstIp);       // "from" the original destination
    EXPECT_EQ(p.srcPort, kDstPort);
    EXPECT_EQ(p.dstIp, kAppIp);
    EXPECT_EQ(p.dstPort, kAppPort);
    EXPECT_EQ(h.engine->nat().size(), 0u);
    h.stop();
}

APS_TEST(engine, stop_clears_state_and_reports_stopped) {
    Harness h;
    h.start(h.makeConfig());
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    h.stop();
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("\"STOPPED\"") != std::string::npos;
    }, 2000));
    EXPECT_EQ(h.engine->nat().size(), 0u);
    EXPECT_EQ(h.engine->relay().activeSessions(), 0u);
    // Device is stopped: further pushes are not processed (recv unblocked).
    h.device->clearSent();
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 1, 0, 0x02));
    Sleep(300);
    EXPECT_EQ(h.device->sent().size(), 0u);
}

APS_TEST(engine, fail_open_when_proxy_unreachable) {
    Harness h;
    Config c = h.makeConfig();
    c.proxy.port = 1;                    // nothing listens on 127.0.0.1:1
    c.proxy.healthIntervalS = 1;
    c.proxy.healthTimeoutMs = 500;
    c.proxy.healthFailThreshold = 1;
    h.start(c);

    // Wait for the engine to notice the proxy is gone.
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("\"DEGRADED\"") != std::string::npos;
    }, 8000));

    // New rule-process connection must go DIRECT (fail-open).
    h.device->clearSent();
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto sent = h.device->sent();
    EXPECT_EQ(sent.size(), 1u);
    auto p = parseSent(sent[0]);
    EXPECT_EQ(p.dstIp, kDstIp);    // direct, not 127.0.0.1
    h.stop();
}

APS_TEST(engine, rule_process_ipv6_syn_is_dropped) {
    Harness h;
    h.start(h.makeConfig());
    h.pushConnectEvent6(51000, /*pid=*/100);   // C:\Test\app.exe (rule)
    h.device->pushTcp6(buildTcp6Packet(51000, 443, /*SYN*/ 0x02, 1));
    Sleep(400);  // give the v6 pump time to process and (not) emit
    EXPECT_EQ(h.device->sentTcp6Count(), 0u);  // dropped => IPv4 fallback
    h.stop();
}

APS_TEST(engine, ipv6_syn_race_falls_back_to_tcp6_table) {
    Harness h;
    class FakeV6Table : public ITcpTableQuery {
    public:
        std::optional<uint32_t> findOwnerByLocal(uint32_t, uint16_t) override {
            return std::nullopt;
        }
        std::optional<uint32_t> findOwnerByLocal6(
            const std::array<uint8_t, 16>&, uint16_t) override {
            return 100;
        }
    };
    h.fakeTcpTable = std::make_unique<FakeV6Table>();
    h.start(h.makeConfig());
    // Deliberately no SOCKET event: the IPv6 TCB is defense line 2.
    h.device->pushTcp6(buildTcp6Packet(51002, 443, /*SYN*/ 0x02, 1));
    Sleep(400);
    EXPECT_EQ(h.device->sentTcp6Count(), 0u);
    EXPECT_TRUE(h.engine->socketMap().find(0, 51002).has_value());
    h.stop();
}

APS_TEST(engine, ipv6_tcp6_table_non_rule_owner_still_passes) {
    Harness h;
    class FakeV6Table : public ITcpTableQuery {
    public:
        std::optional<uint32_t> findOwnerByLocal(uint32_t, uint16_t) override {
            return std::nullopt;
        }
        std::optional<uint32_t> findOwnerByLocal6(
            const std::array<uint8_t, 16>&, uint16_t) override {
            return 200;
        }
    };
    h.fakeTcpTable = std::make_unique<FakeV6Table>();
    h.start(h.makeConfig());
    h.device->pushTcp6(buildTcp6Packet(51003, 443, /*SYN*/ 0x02, 1));
    for (int i = 0; i < 100 && h.device->sentTcp6Count() == 0; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentTcp6Count(), 1u);
    h.stop();
}

APS_TEST(engine, non_rule_ipv6_passes_through) {
    Harness h;
    h.start(h.makeConfig());
    h.pushConnectEvent6(51001, /*pid=*/200);   // C:\Other\other.exe (no rule)
    h.device->pushTcp6(buildTcp6Packet(51001, 443, /*SYN*/ 0x02, 1));
    for (int i = 0; i < 100 && h.device->sentTcp6Count() == 0; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentTcp6Count(), 1u);  // untouched
    h.stop();
}

APS_TEST(engine, block_rule_syn_is_dropped) {
    Harness h;
    Config c = h.makeConfig();
    c.rules[0].action = "block";
    h.start(c);
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    Sleep(400);  // give the TCP pump time to process and (not) emit
    EXPECT_EQ(h.device->sent().size(), 0u);   // dropped: no reinjection
    EXPECT_EQ(h.engine->nat().size(), 0u);    // no NAT entry
    h.stop();
}

APS_TEST(engine, direct_rule_passes_through) {
    Harness h;
    Config c = h.makeConfig();
    c.rules[0].action = "direct";
    h.start(c);
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto p = parseSent(h.device->sent()[0]);
    EXPECT_EQ(p.dstIp, kDstIp);          // untouched
    EXPECT_EQ(h.engine->nat().size(), 0u);
    h.stop();
}

APS_TEST(engine, block_rule_reload_does_not_affect_existing_flow) {
    Harness h;
    h.start(h.makeConfig());  // r1 action=proxy
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    h.device->clearSent();

    // Switch the rule to block: only NEW connections are affected.
    Config c2 = h.makeConfig();
    c2.rules[0].action = "block";
    h.engine->reloadConfig(c2);

    // The existing flow's next packet is still rewritten (decision frozen).
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 101, 1, 0x10));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    {
        auto p = parseSent(h.device->sent()[0]);
        EXPECT_TRUE(p.dstIp == 0x7F000001u || p.dstIp != kDstIp);  // relay addr
    }
    h.device->clearSent();
    // A NEW flow from the same app is now blocked.
    h.pushConnectEvent(50004);
    h.device->pushTcp(buildTcpPacket(kAppIp, 50004, kDstIp, kDstPort, 1, 0, 0x02));
    Sleep(400);
    EXPECT_EQ(h.device->sent().size(), 0u);
    h.stop();
}

APS_TEST(engine, stats_blocked_counter_increments) {
    Harness h;
    Config c = h.makeConfig();
    c.rules[0].action = "block";
    h.start(c);
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    Sleep(400);
    EXPECT_EQ(h.engine->stats().get("r1")->blockedConns.load(), 1u);
    h.stop();
}

APS_TEST(engine, dhcp_udp_passes_untouched) {
    Harness h;
    Config c = h.makeConfig();
    c.routing.blockUdpForRules = true;   // UDP pump must be running
    h.start(c);
    h.pushConnectEvent(51010, /*pid=*/100, kDstIp, 67, /*proto=*/17);
    h.device->pushUdp(buildUdpPacket(kAppIp, 51010, kDstIp, 67));
    for (int i = 0; i < 100 && h.device->sentUdpCount() == 0; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentUdpCount(), 1u);  // untouched, not blocked
    auto sent = h.device->sentUdp()[0];
    PWINDIVERT_IPHDR ip = nullptr;
    PWINDIVERT_UDPHDR udp = nullptr;
    uint32_t srcIp = 0, dstIp = 0;
    uint16_t srcPort = 0, dstPort = 0;
    EXPECT_TRUE(pkt::parseUdpPacket(sent.data.data(), sent.data.size(), ip, udp,
                                    srcIp, srcPort, dstIp, dstPort));
    EXPECT_EQ(dstIp, kDstIp);
    EXPECT_EQ(dstPort, 67u);
    h.stop();
}

APS_TEST(engine, multicast_udp_passes_untouched) {
    Harness h;
    Config c = h.makeConfig();
    c.rules[0].action = "block";         // even a block rule must not touch it
    c.routing.blockUdpForRules = false;  // pump gated by the block rule
    h.start(c);
    h.pushConnectEvent(51011, /*pid=*/100, 0xE00000FB, 5353, /*proto=*/17);
    h.device->pushUdp(buildUdpPacket(kAppIp, 51011, 0xE00000FB, 5353));
    for (int i = 0; i < 100 && h.device->sentUdpCount() == 0; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentUdpCount(), 1u);  // mDNS passes through
    h.stop();
}

APS_TEST(engine, block_rule_udp_dropped_when_global_flag_off) {
    Harness h;
    Config c = h.makeConfig();
    c.rules[0].action = "block";
    c.routing.blockUdpForRules = false;  // pump still runs: block rule gates it
    h.start(c);
    h.pushConnectEvent(51012, /*pid=*/100, kDstIp, 443, /*proto=*/17);
    h.device->pushUdp(buildUdpPacket(kAppIp, 51012, kDstIp, 443));
    Sleep(400);
    EXPECT_EQ(h.device->sentUdpCount(), 0u);  // dropped (QUIC pushed to TCP)
    h.stop();
}

APS_TEST(engine, direct_rule_udp_passes_with_global_flag_on) {
    Harness h;
    Config c = h.makeConfig();
    c.rules[0].action = "direct";
    c.routing.blockUdpForRules = true;
    h.start(c);
    h.pushConnectEvent(51013, /*pid=*/100, kDstIp, 443, /*proto=*/17);
    h.device->pushUdp(buildUdpPacket(kAppIp, 51013, kDstIp, 443));
    for (int i = 0; i < 100 && h.device->sentUdpCount() == 0; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentUdpCount(), 1u);  // direct rule never blocks UDP
    h.stop();
}

APS_TEST(engine, stats_connections_array_contains_active_flow) {
    Harness h;
    h.start(h.makeConfig());
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));

    // The 1s timer tick pushes STATS with the active-flow array.
    EXPECT_TRUE(h.waitStats([](const std::string& s) {
        return s.find("\"connections\":[") != std::string::npos;
    }, 5000));
    std::string s = h.lastStats();
    EXPECT_TRUE(s.find("\"rule_id\":\"r1\"") != std::string::npos);
    EXPECT_TRUE(s.find("\"outlet_id\":\"__default__\"") != std::string::npos);
    EXPECT_TRUE(s.find("\"pid\":100") != std::string::npos);
    h.stop();
}

APS_TEST(engine, stats_connections_capped_at_64) {
    Harness h;
    h.start(h.makeConfig());
    // 70 distinct flows; the array must cap at 64 (pipe line budget).
    for (int i = 0; i < 70; ++i) {
        uint16_t port = static_cast<uint16_t>(51100 + i);
        h.pushConnectEvent(port);
        h.device->pushTcp(buildTcpPacket(kAppIp, port, kDstIp, kDstPort, 100, 0, 0x02));
    }
    EXPECT_TRUE(h.waitStats([](const std::string& s) {
        return s.find("\"connections\":[") != std::string::npos;
    }, 5000));
    EXPECT_TRUE(h.waitStats([](const std::string& s) {
        if (s.find("\"connections\":[") == std::string::npos) return false;
        json::Value v;
        std::string err;
        if (!json::Value::parse(s, v, &err)) return false;
        const json::Value* conns = v.find("connections");
        return conns && conns->isArray() && conns->size() == 64;
    }, 5000));
    h.stop();
}

APS_TEST(engine, stats_connections_removed_after_flush) {
    Harness h;
    h.start(h.makeConfig());
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    EXPECT_TRUE(h.waitStats([](const std::string& s) {
        return s.find("\"rule_id\":\"r1\"") != std::string::npos;
    }, 5000));

    h.engine->flushConnections(std::nullopt);
    EXPECT_TRUE(h.waitStats([](const std::string& s) {
        return s.find("\"connections\":[]") != std::string::npos;
    }, 5000));
    h.stop();
}

APS_TEST(engine, dns_aaaa_is_answered_nodata_without_external_lookup) {
    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    h.start(c);
    auto query = dnsQueryBytes("chatgpt.com", 0xBEEF);
    query[query.size() - 4] = 0;
    query[query.size() - 3] = 28;  // AAAA
    h.device->pushDns(buildUdpPacket(kAppIp, 53128, 0xC0A80501, 53, query));
    for (int i = 0; i < 100 && h.device->sentDnsCount() == 0; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 1u);
    auto sent = h.device->sentDns(0);
    EXPECT_TRUE(sent.size() >= 28 + query.size());
    if (sent.size() >= 28 + query.size()) {
        const size_t d = 28;
        EXPECT_EQ(sent[d], 0xBE);
        EXPECT_EQ(sent[d + 1], 0xEF);
        EXPECT_EQ(sent[d + 2], 0x81);  // response + RD
        EXPECT_EQ(sent[d + 3], 0x80);  // NOERROR
        EXPECT_EQ(sent[d + 7], 0);     // ANCOUNT=0
        EXPECT_EQ(sent[sent.size() - 4], 0);
        EXPECT_EQ(sent[sent.size() - 3], 28);
    }
    h.stop();
}

APS_TEST(engine, dns_stale_cache_served_on_controller_failure) {
    // Robustness: when the controller is unreachable, a recent-but-expired
    // cache entry is served (stale-while-error) instead of leaking the
    // original possibly-polluted query to the app.
    MockClashApi api;
    api.dnsAnswers["x.com"] = {"1.2.3.4"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.proxy.healthIntervalS = 30;
    c.nodeMonitor.enabled = false;
    h.start(c);
    h.engine->setDnsTtlMsForTest(120);   // fresh for ~120ms

    const uint32_t kDns = 0x72727272;    // 114.114.114.114
    const uint8_t pat[4] = {1, 2, 3, 4};
    auto query = dnsQueryBytes("x.com");

    // First query: resolved via the mock controller, cached, answered.
    h.device->pushDns(buildUdpPacket(kAppIp, 53100, kDns, 53, query));
    for (int i = 0; i < 100 && h.device->sentDnsCount() == 0; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 1u);
    {
        auto pkt = h.device->sentDns(0);
        bool hasIp = std::search(pkt.begin(), pkt.end(), pat, pat + 4) != pkt.end();
        EXPECT_TRUE(hasIp);
    }

    // TTL lapses, controller breaks: the stale cache must still answer.
    Sleep(250);
    api.dnsFail.store(true);
    h.device->pushDns(buildUdpPacket(kAppIp, 53101, kDns, 53, query));
    for (int i = 0; i < 100 && h.device->sentDnsCount() < 2; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 2u);
    {
        auto pkt = h.device->sentDns(1);
        bool hasIp = std::search(pkt.begin(), pkt.end(), pat, pat + 4) != pkt.end();
        EXPECT_TRUE(hasIp);   // stale 1.2.3.4 served, not the original query
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, dns_controller_re_picks_after_kernel_dies) {
    // Independence: the DNS cleanup picks its controller from the LIVE
    // kernels (first alive wins without activation) and RE-PICKS when the
    // chosen kernel dies. Stopping SakuraCat must not break DNS while
    // another kernel still runs (2026-08-27 design gap: the controller was
    // latched once and never re-evaluated).
    MockClashApi api1;
    api1.dnsAnswers["x.com"] = {"1.2.3.4"};
    EXPECT_TRUE(api1.start());
    MockClashApi api2;
    api2.dnsAnswers["x.com"] = {"5.6.7.8"};
    EXPECT_TRUE(api2.start());

    // Reserve the SOCKS endpoints and reject CONNECT deterministically.
    // Unowned fixed ports can consume the resolver budget on hosted runners.
    MockSocks5Server socks1, socks2;
    socks1.setBehavior(MockSocksBehavior::RefuseConnect);
    socks2.setBehavior(MockSocksBehavior::RefuseConnect);
    EXPECT_TRUE(socks1.start());
    EXPECT_TRUE(socks2.start());

    Harness h;
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    scripted->push_back(makeKernel("kern-a.exe", socks1.port(), api1.port()));
    scripted->push_back(makeKernel("kern-b.exe", socks2.port(), api2.port()));
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = 0;
    c.proxy.healthIntervalS = 30;
    c.nodeMonitor.enabled = false;
    // Scripted scans are synchronous so mutating the vector cannot race a
    // background scan, and the controller is installed before the query.
    h.start(c);
    h.engine->setDnsSocksDnsServerForTest({0x7F000001, 1});
    h.engine->setDnsTtlMsForTest(120);  // fresh for ~120ms
    h.engine->adoptDiscoveries();

    const uint32_t kDns = 0x72727272;  // 114.114.114.114
    auto query = dnsQueryBytes("x.com");
    const uint8_t pat1[4] = {1, 2, 3, 4};
    const uint8_t pat2[4] = {5, 6, 7, 8};

    // First query: answered by the first live kernel's controller.
    h.device->pushDns(buildUdpPacket(kAppIp, 53100, kDns, 53, query));
    for (int i = 0; i < 100 && h.device->sentDnsCount() == 0; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 1u);
    {
        auto pkt = h.device->sentDns(0);
        EXPECT_TRUE(std::search(pkt.begin(), pkt.end(), pat1, pat1 + 4) !=
                    pkt.end());
    }

    // kern-a dies: the next query must re-pick kern-b's controller.
    Sleep(250);  // let the fresh TTL lapse
    scripted->erase(scripted->begin());  // only kern-b left
    h.engine->adoptDiscoveries();
    Sleep(150);
    h.device->pushDns(buildUdpPacket(kAppIp, 53101, kDns, 53, query));
    for (int i = 0; i < 100 && h.device->sentDnsCount() < 2; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 2u);
    {
        auto pkt = h.device->sentDns(1);
        EXPECT_TRUE(std::search(pkt.begin(), pkt.end(), pat2, pat2 + 4) !=
                    pkt.end());
    }

    h.stop();
    api1.stop();
    api2.stop();
    saveKernelCache({});
}

APS_TEST(engine, dns_falls_back_to_socks_tcp_for_kernels_without_query_api) {
    // Old Clash cores (CFW's 1.18) have NO /dns/query route (404): the
    // cleanup must resolve via TCP 53 THROUGH the kernel's SOCKS tunnel —
    // the nameserver sees the node's exit, so the answer is unpoisoned.
    MockClashApi api;
    api.dnsQuery404.store(true);
    EXPECT_TRUE(api.start());
    MockSocks5Server socks;
    EXPECT_TRUE(socks.start());

    TcpDnsResponder dns;
    EXPECT_TRUE(dns.start());

    Harness h;
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    scripted->push_back(makeKernel("kern-a.exe", socks.port(), api.port()));
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = 0;
    c.proxy.healthIntervalS = 30;
    c.nodeMonitor.enabled = false;
    h.start(c, /*discoveryEnabled=*/true);
    h.engine->setDnsSocksDnsServerForTest(net::Endpoint4{0x7F000001, dns.port});
    h.engine->setDnsTtlMsForTest(120);
    Sleep(250);  // let the initial adoption install the kernel

    const uint32_t kDns = 0x72727272;
    auto query = dnsQueryBytes("x.com");
    const uint8_t pat[4] = {9, 9, 9, 9};
    h.device->pushDns(buildUdpPacket(kAppIp, 53100, kDns, 53, query));
    for (int i = 0; i < 150 && h.device->sentDnsCount() == 0; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 1u);
    {
        auto pkt = h.device->sentDns(0);
        EXPECT_TRUE(std::search(pkt.begin(), pkt.end(), pat, pat + 4) !=
                    pkt.end());
    }

    dns.shutdown();
    h.stop();
    api.stop();
    socks.stop();
    saveKernelCache({});
}

APS_TEST(engine, dns_prefers_socks_tunnel_over_poisoned_controller) {
    // THE 2026-08-28 incident in test form: the kernel's controller answers
    // with well-formed but POISONED records (a mode: direct kernel resolves
    // through rewritten upstreams — no client-side check can tell the
    // answer apart from a real one). The SOCKS TCP-53 path through the
    // kernel's tunnel must be the PRIMARY resolver: the nameserver sees the
    // node's exit, so its answer is clean by construction.
    MockClashApi api;
    api.dnsAnswers["x.com"] = {"6.6.6.6"};  // the poisoned answer
    EXPECT_TRUE(api.start());
    MockSocks5Server socks;
    EXPECT_TRUE(socks.start());

    TcpDnsResponder dns;
    EXPECT_TRUE(dns.start());

    Harness h;
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    scripted->push_back(makeKernel("kern-a.exe", socks.port(), api.port()));
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = 0;
    c.proxy.healthIntervalS = 30;
    c.nodeMonitor.enabled = false;
    h.start(c, /*discoveryEnabled=*/true);
    h.engine->setDnsSocksDnsServerForTest(net::Endpoint4{0x7F000001, dns.port});
    h.engine->setDnsTtlMsForTest(120);
    Sleep(250);

    const uint32_t kDns = 0x72727272;
    auto query = dnsQueryBytes("x.com");
    const uint8_t pat[4] = {9, 9, 9, 9};
    h.device->pushDns(buildUdpPacket(kAppIp, 53100, kDns, 53, query));
    for (int i = 0; i < 150 && h.device->sentDnsCount() == 0; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 1u);
    {
        auto pkt = h.device->sentDns(0);
        // The clean tunnel answer WINS over the poisoned controller answer.
        EXPECT_TRUE(std::search(pkt.begin(), pkt.end(), pat, pat + 4) !=
                    pkt.end());
    }

    dns.shutdown();
    h.stop();
    api.stop();
    socks.stop();
    saveKernelCache({});
}

APS_TEST(engine, dns_socks_resolver_falls_back_to_other_alive_kernel) {
    // A hung kernel must not take DNS down with it (2026-08-28: CFW's core
    // hung — its SOCKS listener accepted TCP but aborted every handshake —
    // while a healthy SakuraCat kernel sat beside it; the pinned-kernel-only
    // resolver leaked every poisoned answer through). The resolver walks ALL
    // alive kernels' SOCKS tunnels — the pinned kernel first, then every
    // other — and adopts the kernel that actually answers.
    MockClashApi apiA;
    EXPECT_TRUE(apiA.start());
    MockSocks5Server hung;
    hung.setBehavior(MockSocksBehavior::RefuseConnect);
    EXPECT_TRUE(hung.start());
    MockClashApi apiB;
    EXPECT_TRUE(apiB.start());
    MockSocks5Server good;
    EXPECT_TRUE(good.start());

    TcpDnsResponder dns;
    EXPECT_TRUE(dns.start());

    Harness h;
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    scripted->push_back(makeKernel("kern-a.exe", hung.port(), apiA.port()));
    scripted->push_back(makeKernel("kern-b.exe", good.port(), apiB.port()));
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = 0;
    c.proxy.healthIntervalS = 30;
    c.nodeMonitor.enabled = false;
    h.start(c, /*discoveryEnabled=*/true);
    h.engine->setDnsSocksDnsServerForTest(net::Endpoint4{0x7F000001, dns.port});
    h.engine->setDnsTtlMsForTest(120);
    Sleep(250);  // let the initial adoption install the kernels

    const uint32_t kDns = 0x72727272;
    auto query = dnsQueryBytes("x.com");
    const uint8_t pat[4] = {9, 9, 9, 9};
    h.device->pushDns(buildUdpPacket(kAppIp, 53100, kDns, 53, query));
    for (int i = 0; i < 150 && h.device->sentDnsCount() == 0; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 1u);
    {
        auto pkt = h.device->sentDns(0);
        EXPECT_TRUE(std::search(pkt.begin(), pkt.end(), pat, pat + 4) !=
                    pkt.end());
    }
    // Adoption proof (behavioral): the first resolution tried the hung
    // pinned kernel and fell through to the healthy one. The second
    // resolution must go STRAIGHT to the adopted kernel — the hung one gets
    // no further DNS attempts. (Health-monitor probes through these mocks
    // target the harness listener, never the DNS port, so counting by
    // destination port is unambiguous.)
    auto dnsAttempts = [&](MockSocks5Server& srv) {
        size_t n = 0;
        for (size_t i = 0; i < srv.requestCount(); ++i) {
            if (srv.request(i).dstPort == dns.port) ++n;
        }
        return n;
    };
    const size_t hungAfterFirst = dnsAttempts(hung);
    const size_t goodAfterFirst = dnsAttempts(good);
    EXPECT_EQ(hungAfterFirst, 1u);   // the failed pinned attempt
    EXPECT_EQ(goodAfterFirst, 1u);   // the successful fallback attempt
    auto query2 = dnsQueryBytes("y.com");
    h.device->pushDns(buildUdpPacket(kAppIp, 53100, kDns, 53, query2));
    for (int i = 0; i < 150 && h.device->sentDnsCount() < 2; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 2u);
    EXPECT_EQ(dnsAttempts(hung), hungAfterFirst);          // adopted: skipped
    EXPECT_EQ(dnsAttempts(good), goodAfterFirst + 1u);     // served directly

    dns.shutdown();
    h.stop();
    apiA.stop();
    hung.stop();
    apiB.stop();
    good.stop();
    saveKernelCache({});
}

APS_TEST(engine, node_switch_flushes_dns_cache) {
    // 2026-08-31: a POISONED answer cached through the old node's path
    // survived a node switch for minutes (the resolution path changed, the
    // cache didn't). A switch must flush the cache so the next query
    // re-resolves through the NEW node immediately.
    MockSocks5Server socks;  // Normal: splices to the local DNS responder
    EXPECT_TRUE(socks.start());
    MockClashApi api;
    api.selectorNow = "node-a";
    api.latencies["node-a"] = 20;   // healthy at first
    api.latencies["node-b"] = 15;
    EXPECT_TRUE(api.start());
    TcpDnsResponder dns;
    EXPECT_TRUE(dns.start());

    Harness h;
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    scripted->push_back(makeKernel("kern-a.exe", socks.port(), api.port()));
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.proxy.healthIntervalS = 30;
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.nodeClasses.clear();
    h.start(c, /*discoveryEnabled=*/true);
    h.engine->setDnsSocksDnsServerForTest(net::Endpoint4{0x7F000001, dns.port});
    h.engine->setDnsTtlMsForTest(60000);  // fresh for the whole test
    Sleep(250);

    const uint32_t kDns = 0x72727272;
    auto query = dnsQueryBytes("x.com");
    auto pushQ = [&]() {
        h.device->pushDns(buildUdpPacket(kAppIp, 53100, kDns, 53, query));
    };
    auto dnsHits = [&]() {  // tunnel resolutions, via the socks mock
        size_t n = 0;
        for (size_t i = 0; i < socks.requestCount(); ++i) {
            if (socks.request(i).dstPort == dns.port) ++n;
        }
        return n;
    };
    pushQ();
    for (int i = 0; i < 150 && h.device->sentDnsCount() < 1; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 1u);
    pushQ();  // served from the cache: no new tunnel resolution
    for (int i = 0; i < 100 && h.device->sentDnsCount() < 2; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 2u);
    EXPECT_EQ(dnsHits(), 1u);

    // Degrade the current node and switch: the cache must be flushed.
    api.latencies["node-a"] = 5000;  // over the 800ms budget -> re-select
    h.engine->requestNodeSwitchRound("__default__");
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("\"node\":\"node-b\"") != std::string::npos;
    }, 8000));
    pushQ();
    for (int i = 0; i < 150 && h.device->sentDnsCount() < 3; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 3u);
    EXPECT_EQ(dnsHits(), 2u);  // re-resolved through the new node's path

    dns.shutdown();
    h.stop();
    api.stop();
    socks.stop();
    saveKernelCache({});
}

APS_TEST(engine, configured_dns_servers_are_tried_before_detected) {
    // User-configured servers (data) come first: the auto-detected ones
    // come from the kernel configs and are often CHINA-hosted — their
    // answers cross the network intermediaries on the way back and arrive poisoned even
    // through an otherwise clean node (measured 2026-08-31). No seam
    // override here: the configured server is the ONLY usable one (the
    // kernel has no config.yaml and the adapter DNS is private-filtered).
    MockSocks5Server socks;
    EXPECT_TRUE(socks.start());
    MockClashApi api;
    EXPECT_TRUE(api.start());
    TcpDnsResponder dns;
    EXPECT_TRUE(dns.start());

    Harness h;
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    scripted->push_back(makeKernel("kern-a.exe", socks.port(), api.port()));
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = 0;
    c.proxy.healthIntervalS = 30;
    c.nodeMonitor.enabled = false;
    c.routing.dnsServers = {"127.0.0.1:" + std::to_string(dns.port)};
    h.start(c, /*discoveryEnabled=*/true);
    h.engine->setDnsTtlMsForTest(120);
    // This test covers the PLAIN-53 server ordering; stub DoH to
    // "unavailable" so the real WinHTTP attempt (whose fast-fail timing
    // against the broken mock proxy is load-dependent under ctest) stays
    // out of scope.
    h.engine->setDohResolverForTest(
        [](uint16_t, uint32_t, const std::string&, std::vector<uint32_t>&,
           int, std::string*) { return false; });
    Sleep(250);

    const uint32_t kDns = 0x72727272;
    auto query = dnsQueryBytes("x.com");
    const uint8_t pat[4] = {9, 9, 9, 9};
    h.device->pushDns(buildUdpPacket(kAppIp, 53100, kDns, 53, query));
    for (int i = 0; i < 150 && h.device->sentDnsCount() == 0; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 1u);
    {
        auto pkt = h.device->sentDns(0);
        EXPECT_TRUE(std::search(pkt.begin(), pkt.end(), pat, pat + 4) !=
                    pkt.end());
    }
    dns.shutdown();
    h.stop();
    api.stop();
    socks.stop();
    saveKernelCache({});
}

APS_TEST(engine, doh_resolver_is_preferred_over_plain_53) {
    // The 17:33 incident: plain TCP-53 answers get swapped wherever the
    // return path passes through network intermediaries — well-formed Facebook IPs came back
    // from 8.8.8.8 itself through a transit node, and were cached as
    // "clean". DoH (encrypted HTTPS body) is the primary resolver now;
    // plain-53 is the fallback when DoH cannot run.
    MockSocks5Server socks;
    EXPECT_TRUE(socks.start());
    MockClashApi api;
    EXPECT_TRUE(api.start());
    TcpDnsResponder plain;   // would answer 9.9.9.9 (the "poisoned" stand-in)
    EXPECT_TRUE(plain.start());

    Harness h;
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    scripted->push_back(makeKernel("kern-a.exe", socks.port(), api.port()));
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = 0;
    c.proxy.healthIntervalS = 30;
    c.nodeMonitor.enabled = false;
    c.routing.dnsServers = {"8.8.8.8"};
    h.start(c, /*discoveryEnabled=*/true);
    h.engine->setDnsSocksDnsServerForTest(net::Endpoint4{0x7F000001, plain.port});
    h.engine->setDnsTtlMsForTest(120);
    // DoH seam: answers 1.2.3.4 (the clean answer only DoH can produce).
    h.engine->setDohResolverForTest(
        [](uint16_t proxyPort, uint32_t serverIp, const std::string& name,
           std::vector<uint32_t>& ips, int, std::string*) {
            if (serverIp != 0x08080808) return false;  // configured only
            ips = {0x01020304};                        // 1.2.3.4
            return true;
        });
    Sleep(250);

    const uint32_t kDns = 0x72727272;
    auto query = dnsQueryBytes("x.com");
    const uint8_t pat[4] = {1, 2, 3, 4};
    h.device->pushDns(buildUdpPacket(kAppIp, 53100, kDns, 53, query));
    for (int i = 0; i < 150 && h.device->sentDnsCount() == 0; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 1u);
    {
        auto pkt = h.device->sentDns(0);
        EXPECT_TRUE(std::search(pkt.begin(), pkt.end(), pat, pat + 4) !=
                    pkt.end());
    }
    // DoH answered: the plain-53 responder was never consulted.
    size_t plain53 = 0;
    for (size_t i = 0; i < socks.requestCount(); ++i) {
        if (socks.request(i).dstPort == plain.port) ++plain53;
    }
    EXPECT_EQ(plain53, 0u);

    h.stop();
    api.stop();
    socks.stop();
    plain.shutdown();
    saveKernelCache({});
}

static void verifySakuraSubscriptionSafety(bool scheduled) {
    // 2026-09-14: a scheduled refresh killed the user's communication
    // core and failed to recover it. Both a legacy auto_refresh=true and
    // a manual button click must leave this client entirely alone.
    const std::string original = "mixed-port: 7333\nmode: rule\n";
    TempSakuraDir tmp(original);
    EXPECT_TRUE(tmp.ok);
    if (!tmp.ok) return;
    std::atomic<int> urls{0}, fetches{0}, applies{0}, cfwLookups{0};
    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.subscription.autoRefresh = scheduled;
    // start() accepts an already-built Config; make this test's first
    // deadline immediate without waiting ten minutes or modifying clocks.
    c.subscription.startDelayMin = 0;
    c.subscription.intervalHours = 24;
    auto k = makeKernel("com.vortex.helper.exe", socks().port(), 0);
    c.routing.autoOutletId = k.id;
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    h.discoveryScan = [k](DiscoveryMode) { return std::vector<DiscoveredKernel>{k}; };
    h.beforeStart = [&](Engine& engine) {
        engine.setSakuraCatUrlFinder([&] {
            ++urls;
            return std::optional<std::string>("https://sub.example.com/s");
        });
        engine.setSakuraCatConfigDir(tmp.cfgDir);
        engine.setSubscriptionFetcher([&](const std::string&, std::string& yaml,
                                         std::string*) {
            ++fetches;
            yaml = "mixed-port: 7890\nmode: rule\nproxies:\n  - name: A\n";
            return true;
        });
        // Even against the old unsafe implementation, tests must NEVER
        // reach a real config write/restart or a real CFW profile.
        engine.setSubApplier([&](const std::string&, const std::string&) {
            ++applies;
        });
        engine.setCfwProfileFinder([&] {
            ++cfwLookups;
            return std::optional<subscription::ActiveProfile>();
        });
    };
    h.start(c, scheduled);
    if (!scheduled) {
        h.engine->seedDiscoveredKernelsForTest({k});
        h.engine->refreshSubscription();
    }
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("请在 SakuraCat 客户端更新订阅") != std::string::npos;
    }, 3000));
    EXPECT_EQ(urls.load(), 0);
    EXPECT_EQ(fetches.load(), 0);
    EXPECT_EQ(applies.load(), 0);
    EXPECT_EQ(cfwLookups.load(), 0);
    std::string after, err;
    EXPECT_TRUE(subscription::loadConfigFile(tmp.cfgDir, after, &err));
    EXPECT_STREQ(after, original);
    EXPECT_EQ(h.engine->outletParams(k.id).proxy.port, k.socksPort);
    h.stop();
    saveKernelCache({});
}

APS_TEST(engine, manual_sakura_refresh_never_writes_or_restarts) {
    verifySakuraSubscriptionSafety(false);
}

APS_TEST(engine, legacy_scheduled_sakura_refresh_never_writes_or_restarts) {
    verifySakuraSubscriptionSafety(true);
}

APS_TEST(engine, sub_refresh_requires_a_selected_kernel) {
    // The refresh targets the SELECTED kernel (哪个圆点选中就更新哪家).
    // With no kernel selected (default row active, its port follows
    // nothing) the refresh must fail with an explicit instruction instead
    // of guessing or touching anyone.
    TempSakuraDir tmp("external-controller: 127.0.0.1:39798\n");
    EXPECT_TRUE(tmp.ok);
    if (!tmp.ok) return;

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.healthIntervalS = 30;
    c.proxy.port = 1;
    h.start(c);
    bool urlFinderCalled = false;
    h.engine->setSakuraCatUrlFinder([&urlFinderCalled] {
        urlFinderCalled = true;
        return std::optional<std::string>("https://sub.example.com/s");
    });
    h.engine->setSakuraCatConfigDir(tmp.cfgDir);
    h.engine->setCfwProfileFinder(
        [] { return std::optional<subscription::ActiveProfile>(); });
    h.engine->setSubscriptionFetcher(
        [](const std::string&, std::string& yaml, std::string*) {
            yaml = "mixed-port: 7890\nproxies:\n  - name: A\n";
            return true;
        });
    std::string applied;
    h.engine->setSubApplier(
        [&applied](const std::string& merged, const std::string& kind) {
            applied += kind + ";";
        });

    h.engine->refreshSubscription();

    EXPECT_FALSE(urlFinderCalled);
    EXPECT_TRUE(applied.empty());
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("当前默认出口没有对应的在线内核") != std::string::npos;
    }, 2000));
    h.stop();
}

namespace {
void checkUnsupportedSubscription(const char* process, bool available, const char* expected) {
    Harness h;
    auto k = makeKernel(process, socks().port(), 0);
    if (std::string(process).find("verge") != std::string::npos) k.apiPipe = "\\\\.\\pipe\\fixture-verge";
    std::atomic<int> sideEffects{0};
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    h.beforeStart = [&](Engine& e) {
        e.setSakuraCatUrlFinder([&] { ++sideEffects; return std::optional<std::string>(); });
        e.setCfwProfileFinder([&] { ++sideEffects; return std::optional<subscription::ActiveProfile>(); });
        e.setSubscriptionFetcher([&](const std::string&, std::string&, std::string*) { ++sideEffects; return false; });
        e.setSubApplier([&](const std::string&, const std::string&) { ++sideEffects; });
        if (available) e.seedDiscoveredKernelsForTest({k});
    };
    auto c = h.makeConfig();
    c.routing.autoOutletId = k.id;
    h.start(c);
    h.engine->refreshSubscription();
    EXPECT_TRUE(h.waitStatus([&](const std::string& s){return s.find(expected)!=std::string::npos;},2000));
    const auto status = h.engine->statusJson();
    EXPECT_TRUE(status.find("请先点选") == std::string::npos);
    EXPECT_EQ(sideEffects.load(), 0);
    h.stop();
    saveKernelCache({});
}
}  // namespace

APS_TEST(engine, selected_verge_refresh_reports_capability_not_missing_selection) {
    checkUnsupportedSubscription("verge-mihomo.exe", true, "error:");
}

APS_TEST(engine, verge_refresh_is_async_and_scheduled_refresh_never_submits) {
    test::MockProfileBridge bridge;
    bridge.respond = [&](const json::Value& request) {
        if (request.find("op")->asString() == "info") return bridge.info();
        auto reply = json::Value::makeObject();
        reply.set("protocol",1); reply.set("request_id",request.find("request_id")->asString());
        if (request.find("op")->asString() == "refresh_current") { reply.set("state","running"); return reply; }
        reply.set("state","ok"); reply.set("downloaded",true); reply.set("saved",true); reply.set("applied",true); reply.set("restarted",false);
        return reply;
    };
    EXPECT_TRUE(bridge.start());
    Harness h;
    auto k = makeKernel("verge-mihomo.exe", socks().port(), 0);
    k.pid = GetCurrentProcessId(); k.apiPipe = bridge.controllerPipe;
    auto cfg = h.makeConfig(); cfg.rules.clear(); cfg.routing.autoOutletId = k.id;
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    h.start(cfg); h.engine->seedDiscoveredKernelsForTest({k});
    h.engine->refreshSubscription(true);
    EXPECT_EQ(bridge.submissions.load(),0);
    const auto start = GetTickCount64();
    h.engine->refreshSubscription();
    EXPECT_LT(GetTickCount64() - start, 1200ull);
    // Click spam must not duplicate the submitted transaction.
    h.engine->refreshSubscription();
    EXPECT_TRUE(h.waitStatus([](const std::string& s) { return s.find("error:") != std::string::npos; },4000));
    EXPECT_EQ(bridge.submissions.load(),0); // No deprecated cooperation endpoint, no guessed GUI/config.
    EXPECT_EQ(h.engine->outletParams(k.id).proxy.port,k.socksPort);
    h.stop();
}
APS_TEST(engine, selected_unknown_refresh_does_not_touch_other_clients) {
    checkUnsupportedSubscription("unbranded-mihomo.exe", true, "已选中内核");
}
APS_TEST(engine, unavailable_selected_refresh_does_not_fall_back_to_sakura) {
    checkUnsupportedSubscription("verge-mihomo.exe", false, "已选中的内核当前不可用");
}

APS_TEST(engine, sub_refresh_cfw_proceeds_without_sakura) {
    // Independence, positive side: with the CFW row SELECTED (and no
    // SakuraCat kernel running at all), the refresh updates CFW's profile
    // and never touches SakuraCat — not even its URL finder.
    TempSakuraDir tmp("external-controller: 127.0.0.1:39798\n");
    EXPECT_TRUE(tmp.ok);
    if (!tmp.ok) return;

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.healthIntervalS = 30;
    c.proxy.port = 1;
    h.start(c);
    h.engine->seedDiscoveredKernelsForTest(
        {makeKernel("clash-win64.exe", 64717, 55831)});
    c.routing.autoOutletId = "auto-clash-win64.exe";
    h.engine->reloadConfig(c);
    bool urlFinderCalled = false;
    h.engine->setSakuraCatUrlFinder([&urlFinderCalled] {
        urlFinderCalled = true;
        return std::optional<std::string>("https://sub.example.com/s");
    });
    h.engine->setSakuraCatConfigDir(tmp.cfgDir);
    // A REAL temp profile file (the CFW branch reads it).
    wchar_t tdir[MAX_PATH];
    GetTempPathW(MAX_PATH, tdir);
    std::wstring profPath = std::wstring(tdir) + L"aps-cfw-refresh-test-" +
                            std::to_wstring(GetCurrentProcessId()) + L".yml";
    {
        std::string prof = "mixed-port: 7890\nproxies:\n  - name: OLD\n";
        HANDLE pf = CreateFileW(profPath.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        EXPECT_TRUE(pf != INVALID_HANDLE_VALUE);
        if (pf != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(pf, prof.data(), static_cast<DWORD>(prof.size()),
                      &written, nullptr);
            CloseHandle(pf);
        }
    }
    h.engine->setCfwProfileFinder([profPath] {
        subscription::ActiveProfile p;
        p.path = profPath;
        p.url = "https://cfw.example.com/sub";
        p.configDir = L"C:\\temp";
        return std::optional<subscription::ActiveProfile>(p);
    });
    h.engine->setSubscriptionFetcher(
        [](const std::string& url, std::string& yaml, std::string*) {
            if (url == "https://cfw.example.com/sub") {
                yaml = "mixed-port: 7890\nproxies:\n  - name: A\n";
                return true;
            }
            return false;
        });
    std::vector<std::string> applied;
    h.engine->setSubApplier(
        [&applied](const std::string& merged, const std::string& kind) {
            applied.push_back(kind);
        });

    h.engine->refreshSubscription();

    EXPECT_FALSE(urlFinderCalled);
    EXPECT_EQ(applied.size(), 1u);
    if (!applied.empty()) EXPECT_STREQ(applied[0], "cfw");
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("\"sub_refresh\":\"ok\"") != std::string::npos;
    }, 2000));
    h.stop();
    DeleteFileW(profPath.c_str());
}

APS_TEST(engine, default_egress_port_auto_follows_sole_live_kernel) {
    // A dead configured default port + exactly one live discovered kernel:
    // the default egress auto-follows the kernel's SOCKS port (no manual
    // port bookkeeping — kernels change ports and the user's config goes
    // stale). The kernel is delivered through the discovery-scan seam, so
    // the pump's OWN adoption installs it — no seed/adoption race.
    Harness h;
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    scripted->push_back(makeKernel("fake-kernel-a.exe", 58347, 59090));
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.port = 59991;  // dead
    h.start(c, /*discoveryEnabled=*/true);

    // The pump's initial adoption rebuilds outlets with the healed port.
    for (int i = 0; i < 300 &&
                    h.engine->outletParams(kDefaultOutletId).proxy.port != 58347;
         ++i) {
        Sleep(10);
    }
    EXPECT_EQ(h.engine->outletParams(kDefaultOutletId).proxy.port,
              static_cast<uint16_t>(58347));
    // Covered by the healed default: the auto id resolves through it too.
    EXPECT_EQ(h.engine->outletParams("auto-fake-kernel-a.exe").proxy.port,
              static_cast<uint16_t>(58347));
    h.stop();
    saveKernelCache({});  // keep the dev machine's cache clean
}

APS_TEST(engine, default_egress_port_follows_activated_kernel) {
    // With several live kernels, the activated one (routing.autoOutletId)
    // is the explicit choice the default egress must follow.
    Harness h;
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    scripted->push_back(makeKernel("fake-kernel-a.exe", 7897, 39798));
    scripted->push_back(makeKernel("fake-kernel-b.exe", 58347, 59090));
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.port = 59991;  // dead
    c.routing.autoOutletId = "auto-fake-kernel-b.exe";
    h.start(c, /*discoveryEnabled=*/true);

    for (int i = 0; i < 300 &&
                    h.engine->outletParams(kDefaultOutletId).proxy.port != 58347;
         ++i) {
        Sleep(10);
    }
    EXPECT_EQ(h.engine->outletParams(kDefaultOutletId).proxy.port,
              static_cast<uint16_t>(58347));
    // The activated kernel keeps its own routable entry.
    EXPECT_EQ(h.engine->outletParams("auto-fake-kernel-b.exe").proxy.port,
              static_cast<uint16_t>(58347));
    EXPECT_TRUE(h.engine->outletEnabled("auto-fake-kernel-b.exe"));
    // The OTHER kernel stays deactivated (explicit choice, not merged).
    EXPECT_FALSE(h.engine->outletEnabled("auto-fake-kernel-a.exe"));
    h.stop();
    saveKernelCache({});  // keep the dev machine's cache clean
}

APS_TEST(engine, default_egress_keeps_configured_live_port) {
    // A configured port that still has a listener is authoritative — even
    // when live kernels exist, the default egress must NOT auto-redirect
    // (the listener may be a deliberate manual proxy). The kernel then
    // keeps its own row/entry.
    SOCKET silent = net::makeTcpSocket();
    EXPECT_TRUE(silent != INVALID_SOCKET);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.S_un.S_addr = htonl(0x7F000001);
    sa.sin_port = 0;
    EXPECT_TRUE(bind(silent, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0 &&
                listen(silent, 4) == 0);
    socklen_t sl = sizeof(sa);
    getsockname(silent, reinterpret_cast<sockaddr*>(&sa), &sl);
    const uint16_t silentPort = ntohs(sa.sin_port);

    Harness h;
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    scripted->push_back(makeKernel("fake-kernel-a.exe", 58347, 59090));
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.port = silentPort;  // LIVE: keeps its port by rule
    c.routing.autoOutletId = "auto-fake-kernel-a.exe";  // own entry visible
    h.start(c, /*discoveryEnabled=*/true);

    for (int i = 0; i < 300 &&
                    h.engine->outletParams("auto-fake-kernel-a.exe").proxy.port != 58347;
         ++i) {
        Sleep(10);
    }
    EXPECT_EQ(h.engine->outletParams(kDefaultOutletId).proxy.port, silentPort);
    // The kernel is NOT covered by the default outlet: own entry.
    EXPECT_EQ(h.engine->outletParams("auto-fake-kernel-a.exe").proxy.port,
              static_cast<uint16_t>(58347));

    h.stop();
    net::closeSocket(silent);
    saveKernelCache({});  // keep the dev machine's cache clean
}

APS_TEST(engine, autodetect_api_port_finds_controller_by_enumeration) {
    // autoDetectClashApiPort must find a real controller purely by
    // enumerating loopback listeners — no hard-coded port list anywhere.
    MockClashApi api;
    EXPECT_TRUE(api.start());
    MockSocks5Server s2;
    EXPECT_TRUE(s2.start());

    bool needSecret = false;
    uint16_t found =
        autoDetectClashApiPort("127.0.0.1", "", s2.port(), &needSecret);
    EXPECT_EQ(found, api.port());
    EXPECT_FALSE(needSecret);

    api.stop();
    s2.stop();
}

APS_TEST(engine, stats_skipped_without_consumer) {
    // Power saving: with no connected GUI, the per-second STATS build/push
    // must not happen at all; it resumes the moment a consumer appears.
    Harness h;
    Config c = h.makeConfig();
    auto gate = std::make_shared<std::atomic<bool>>(false);
    h.wantsStats = [gate] { return gate->load(); };
    h.start(c);
    Sleep(2600);  // 2+ timer ticks with the gate closed
    {
        std::lock_guard<std::mutex> lk(h.mu);
        EXPECT_EQ(h.stats.size(), 0u);
    }
    gate->store(true);
    EXPECT_TRUE(h.waitStats([](const std::string&) { return true; }, 3000));
    h.stop();
}

APS_TEST(engine, multi_outlet_rule_freezes_outlet_and_fails_open_per_outlet) {
    // Outlet "o2" = a SECOND live mock SOCKS5; the default outlet = dead port.
    // app.exe is bound to o2 -> proxied via o2. other.exe uses the default
    // outlet -> dead -> fail-open direct. This proves per-outlet egress AND
    // per-outlet health isolation.
    MockSocks5Server socks2;
    EXPECT_TRUE(socks2.start());

    Harness h;
    Config c = h.makeConfig();
    c.proxy.port = 1;                       // default outlet: dead
    c.proxy.healthIntervalS = 1;
    c.proxy.healthTimeoutMs = 500;
    c.proxy.healthFailThreshold = 1;
    c.rules.clear();
    Rule r1;
    r1.id = "r1";
    r1.name = "app";
    r1.path = wideToUtf8(kAppPath);
    r1.enabled = true;
    r1.outlet = "o2";
    c.rules.push_back(r1);
    Rule r2;
    r2.id = "r2";
    r2.name = "other";
    r2.path = "C:\\Test\\other.exe";
    r2.enabled = true;
    c.rules.push_back(r2);
    Outlet o2;
    o2.id = "o2";
    o2.name = "second";
    o2.host = "127.0.0.1";
    o2.port = socks2.port();
    c.outlets.push_back(o2);
    h.start(c);

    // Wait until the default outlet's monitor reports it down.
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("\"DEGRADED\"") != std::string::npos;
    }, 8000));

    // other.exe (default outlet, dead): SYN goes DIRECT (fail-open).
    h.device->clearSent();
    h.pushConnectEvent(52100, /*pid=*/200);
    h.device->pushTcp(buildTcpPacket(kAppIp, 52100, kDstIp, kDstPort, 1, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    {
        auto p = parseSent(h.device->sent()[0]);
        EXPECT_EQ(p.dstIp, kDstIp);  // untouched: direct
    }

    // app.exe (outlet o2, alive): SYN is redirected, NAT entry freezes "o2".
    h.device->clearSent();
    h.pushConnectEvent(52101, /*pid=*/100);
    h.device->pushTcp(buildTcpPacket(kAppIp, 52101, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    {
        auto p = parseSent(h.device->sent()[0]);
        EXPECT_TRUE(p.dstIp == 0x7F000001u || p.dstIp != kDstIp);  // redirected
    }
    auto entry = h.engine->nat().findByRev(kAppIp, 52101);
    EXPECT_TRUE(entry != nullptr);
    if (entry) {
        EXPECT_STREQ(entry->outletId, "o2");
    }
    h.stop();
    socks2.stop();
}

APS_TEST(engine, node_monitor_targeted_round_switches_controller_dead_node) {
    // Mock controller: current node-a is DEAD, node-b alive at 100ms.
    MockClashApi api;
    api.selectorNow = "node-a";
    api.latencies["node-b"] = 100;  // node-a absent => dead
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();  // no rules needed; only the monitor runs
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;   // minimum; the pump also wakes on events
    c.nodeMonitor.failThreshold = 1;
    c.nodeMonitor.nodeClasses.clear(); // opaque mock nodes deliberately have no type filter
    c.nodeMonitor.delayUrl = "http://www.gstatic.com/generate_204";
    c.proxy.healthIntervalS = 30;   // keep the health monitor quiet
    h.start(c);

    // Trigger a targeted round (the GUI's "测试并连接" path). A bare timed
    // controller-delay failure is now corroborated by the real tunnel; the
    // explicit user test remains actionable immediately.
    h.engine->requestNodeSwitchRound("__default__");
    bool switched = false;
    for (int i = 0; i < 160; ++i) {  // up to ~8s (node-a probe times out in 3s)
        if (!api.switches().empty()) {
            switched = true;
            break;
        }
        Sleep(50);
    }
    EXPECT_TRUE(switched);
    if (switched) {
        auto sw = api.switches();
        EXPECT_STREQ(sw[0], "auto::node-b");
    }
    h.stop();
    api.stop();
}

static void checkDefaultControllerAlias(bool usePipe) {
    TempSakuraDir diagnostic("");
    log::init(diagnostic.base, log::Level::Debug, 5, 1);
    // Production regression (2026-09-04 23:45 / 2026-09-05 00:04): when
    // __default__ auto-followed the activated discovered kernel, a full round
    // launched TWO workers against the same controller. Both could PUT a
    // node to the same selector milliseconds apart and tear down live browser
    // connections twice. The discovered id is canonical while it is active;
    // the default row receives a mirrored status without a second API probe.
    MockSocks5Server kernelSocks;
    EXPECT_TRUE(kernelSocks.start());
    MockClashApi api;
    api.selectorNow = "node-slow";
    api.nodes = {"node-slow", "node-fast"};
    api.latencies["node-slow"] = 1200;
    api.latencies["node-fast"] = 100;
    EXPECT_TRUE(api.start());

    DiscoveredKernel kernel =
        makeKernel("fake-kernel.exe", kernelSocks.port(), api.port());
    aps::test::MockClashPipe pipe;
    if (usePipe) {
        EXPECT_TRUE(pipe.start(api.port()));
        kernel.apiPort = 0;
        kernel.apiPipe = pipe.name;
        kernel.pid = GetCurrentProcessId();
    }
    const std::string autoId = kernel.id;
    auto scripted =
        std::make_shared<std::vector<DiscoveredKernel>>(1, kernel);

    Harness h;
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.port = 1;               // dead: default follows the active kernel
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = 0;      // pair controller from discovered kernel
    c.routing.autoOutletId = autoId;
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 1;
    c.nodeMonitor.regions.clear();
    c.nodeMonitor.nodeClasses.clear();
    c.proxy.healthIntervalS = 30;
    h.start(c, /*discoveryEnabled=*/true);

    bool bothRowsUpdated = false;
    for (int i = 0; i < 240; ++i) {
        const std::string status = h.engine->statusJson();
        const std::string needle = "\"node\":\"node-fast\"";
        const size_t first = status.find(needle);
        const size_t second =
            first == std::string::npos
                ? std::string::npos
                : status.find(needle, first + needle.size());
        if (second != std::string::npos) {
            bothRowsUpdated = true;
            break;
        }
        Sleep(25);
    }
    EXPECT_TRUE(bothRowsUpdated);

    // Let a pre-fix duplicate worker finish before counting requests.
    Sleep(250);
    if (api.versionHits() != 1u) {
        log::shutdown();
        std::ifstream trace(diagnostic.base + L"\\aps.log");
        std::ostringstream text;
        text << trace.rdbuf();
        std::printf("    alias diagnostic:\n%s\n", text.str().c_str());
    }
    EXPECT_EQ(api.versionHits(), 1u);
    auto switches = api.switches();
    EXPECT_EQ(switches.size(), 1u);
    if (!switches.empty()) {
        EXPECT_STREQ(switches[0], "auto::node-fast");
    }

    h.stop();
    api.stop();
    kernelSocks.stop();
    saveKernelCache({});
    log::shutdown();
}

APS_TEST(engine, packet_flood_preserves_flow_evidence_and_reinjects_every_packet) {
    TempSakuraDir diagnostic("");
    EXPECT_TRUE(log::init(diagnostic.base, log::Level::Debug, 1, 1));
    Harness h;
    auto c = h.makeConfig();
    c.logging.level = "debug";
    c.routing.dnsCleanup = false;
    h.start(c);
    log::ifmt("critical-flow-evidence-marker");
    // Pass-through loopback fixtures isolate logging from rule/NAT behavior.
    // Previously these ACK/data records rotated away the critical marker.
    constexpr size_t packets = 15000;
    const std::vector<uint8_t> payload(16, 0x71);
    for (size_t i = 0; i < packets; ++i) {
        h.device->pushTcp(buildTcpPacket(0x7F000001, 52000, 0x7F000001, 443,
                                         static_cast<uint32_t>(i), 1, 0x10, payload));
    }
    h.device->pushTcp(buildTcpPacket(0x7F000001, 52000, 0x7F000001, 443, 15000, 1, 0x11));
    EXPECT_TRUE(h.device->waitSent(packets + 1, 10000));
    EXPECT_EQ(h.device->sent().size(), packets + 1);
    h.stop();
    log::shutdown();
    std::ifstream trace(diagnostic.base + L"\\aps.log");
    std::ostringstream text;
    text << trace.rdbuf();
    const auto lines = text.str();
    EXPECT_TRUE(lines.find("critical-flow-evidence-marker") != std::string::npos);
    EXPECT_TRUE(lines.find("fin=1") != std::string::npos);
    EXPECT_TRUE(lines.size() < 65536);
}

APS_TEST(engine, node_monitor_deduplicates_default_alias_of_active_kernel) {
    checkDefaultControllerAlias(false);
}

APS_TEST(engine, pipe_controller_has_one_monitor_and_one_switch_for_default_alias) {
    checkDefaultControllerAlias(true);
}

APS_TEST(engine, pipe_controller_serves_dns_without_tcp_api_port) {
    MockSocks5Server kernelSocks;
    kernelSocks.setBehavior(MockSocksBehavior::RefuseConnect);
    EXPECT_TRUE(kernelSocks.start());
    MockClashApi api;
    api.dnsAnswers["pipe.invalid"] = {"1.2.3.4"};
    EXPECT_TRUE(api.start());
    aps::test::MockClashPipe pipe;
    EXPECT_TRUE(pipe.start(api.port()));
    auto k = makeKernel("unknown-core.exe", kernelSocks.port(), 0);
    k.pid = GetCurrentProcessId();
    k.apiPipe = pipe.name;
    Harness h;
    h.discoveryScan = [k](DiscoveryMode) { return std::vector<DiscoveredKernel>{k}; };
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    auto c = h.makeConfig();
    c.rules.clear();
    c.routing.autoOutletId = k.id;
    c.proxy.clashApi.port = 0;
    h.start(c, true);
    h.engine->adoptDiscoveries();
    h.engine->setDnsSocksDnsServerForTest({0x7F000001, 1}); // no external DNS
    auto query = dnsQueryBytes("pipe.invalid");
    h.device->pushDns(buildUdpPacket(kAppIp, 53100, 0x72727272, 53, query));
    for (int i = 0; i < 150 && h.device->sentDnsCount() == 0; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 1u);
    if (h.device->sentDnsCount()) {
        auto response = h.device->sentDns(0);
        const uint8_t expected[4] = {1, 2, 3, 4};
        EXPECT_TRUE(std::search(response.begin(), response.end(), expected, expected + 4) != response.end());
    }
    h.stop();
    saveKernelCache({});
}

APS_TEST(engine, pipe_dns_answer_is_correlated_with_tls_and_selected_domain_outlet) {
    MockSocks5Server kernelSocks;
    kernelSocks.setBehavior(MockSocksBehavior::EchoConnect);
    EXPECT_TRUE(kernelSocks.start());
    MockClashApi api;
    api.dnsAnswers["api.example.invalid"] = {"192.0.2.1"};
    api.dnsAnswers["another.example.invalid"] = {"192.0.2.1"};
    EXPECT_TRUE(api.start());
    aps::test::MockClashPipe pipe;
    EXPECT_TRUE(pipe.start(api.port()));
    auto k = makeKernel("verge-mihomo.exe", kernelSocks.port(), 0);
    k.pid = GetCurrentProcessId();
    k.apiPipe = pipe.name;
    Harness h;
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    h.beforeStart = [&](Engine& e) {
        e.seedDiscoveredKernelsForTest({k});
        e.setDnsSocksDnsServerForTest({0x7F000001, 1});
    };
    auto c = h.makeConfig();
    c.routing.autoOutletId = k.id;
    c.routing.dnsCleanup = true;
    c.routing.dnsServers.clear();  // exactly the remote empty-config case
    h.start(c);
    for (const std::string name : {"api.example.invalid", "another.example.invalid"}) {
        const auto before = h.device->sentDnsCount();
        h.device->pushDns(buildUdpPacket(kAppIp, 53100, 0x72727272, 53, dnsQueryBytes(name)));
        for (int i = 0; i < 150 && h.device->sentDnsCount() == before; ++i) Sleep(20);
        EXPECT_EQ(h.device->sentDnsCount(), before + 1);
    }
    SOCKET client = net::makeTcpSocket();
    auto local = net::toSockaddr({0x7F000001, 0});
    EXPECT_EQ(bind(client, reinterpret_cast<sockaddr*>(&local), sizeof(local)), 0);
    int addrLen = sizeof(local);
    getsockname(client, reinterpret_cast<sockaddr*>(&local), &addrLen);
    const uint16_t appPort = ntohs(local.sin_port);
    h.pushConnectEvent(appPort, 100, 0xC0000201, 8443);
    h.device->pushTcp(buildTcpPacket(kAppIp, appPort, 0xC0000201, 8443, 1, 0, 0x02));
    for (int i = 0; i < 100 && !h.engine->nat().findByPort(appPort); ++i) Sleep(20);
    EXPECT_TRUE(h.engine->nat().findByPort(appPort) != nullptr);
    EXPECT_EQ(net::connectWithTimeout(client, {0x7F000001, h.engine->relay().listenPort()}, 2000, nullptr), 0);
    const auto hello = aps::test::tlsHello("api.example.invalid", true);
    EXPECT_EQ(net::sendAll(client, reinterpret_cast<const char*>(hello.data()), hello.size(), 2000), 0);
    std::vector<uint8_t> reply(hello.size());
    EXPECT_EQ(net::recvExact(client, reinterpret_cast<char*>(reply.data()), reply.size(), 3000), static_cast<int>(reply.size()));
    EXPECT_TRUE(reply == hello);
    size_t domainRequests = 0;
    for (size_t i = 0; i < kernelSocks.requestCount(); ++i) {
        const auto req = kernelSocks.request(i);
        if (req.addressType != 3) continue;
        ++domainRequests;
        EXPECT_STREQ(req.dstDomain, "api.example.invalid");
        EXPECT_EQ(req.dstPort, 8443);
    }
    EXPECT_EQ(domainRequests, 1u);
    EXPECT_TRUE(api.switches().empty());
    net::closeSocket(client);
    h.stop();
    saveKernelCache({});
}

APS_TEST(engine, explicit_tls_policy_recovers_unobserved_cached_ip_on_selected_outlet) {
    for (bool allowed : {false, true}) {
        MockSocks5Server selected;
        selected.setBehavior(MockSocksBehavior::EchoConnect);
        EXPECT_TRUE(selected.start());
        Harness h;
        auto c = h.makeConfig();
        Outlet outlet;
        outlet.id = "selected-policy";
        outlet.host = "127.0.0.1";
        outlet.port = selected.port();
        c.outlets.push_back(outlet);
        c.routing.autoOutletId = outlet.id;
        if (allowed) c.routing.tlsDomainAllowlist = {"*.example.invalid"};
        h.start(c);
        SOCKET client = net::makeTcpSocket();
        auto local = net::toSockaddr({0x7F000001, 0});
        EXPECT_EQ(bind(client, reinterpret_cast<sockaddr*>(&local), sizeof(local)), 0);
        int length = sizeof(local);
        getsockname(client, reinterpret_cast<sockaddr*>(&local), &length);
        const auto port = ntohs(local.sin_port);
        h.pushConnectEvent(port, 100, 0xC0000201, 8443);
        h.device->pushTcp(buildTcpPacket(kAppIp, port, 0xC0000201, 8443, 1, 0, 0x02));
        for (int i = 0; i < 100 && !h.engine->nat().findByPort(port); ++i) Sleep(10);
        EXPECT_TRUE(h.engine->nat().findByPort(port) != nullptr);
        EXPECT_EQ(net::connectWithTimeout(client, {0x7F000001, h.engine->relay().listenPort()}, 2000, nullptr), 0);
        const auto hello = aps::test::tlsHello("cached.example.invalid", true);
        EXPECT_EQ(net::sendAll(client, reinterpret_cast<const char*>(hello.data()), hello.size(), 2000), 0);
        shutdown(client, SD_SEND);
        std::vector<uint8_t> reply(hello.size());
        EXPECT_EQ(net::recvExact(client, reinterpret_cast<char*>(reply.data()), reply.size(), 3000), static_cast<int>(reply.size()));
        EXPECT_TRUE(reply == hello);
        int requests = 0;
        for (size_t i = 0; i < selected.requestCount(); ++i) {
            const auto request = selected.request(i);
            if (request.dstPort != 8443) continue;
            ++requests;
            EXPECT_EQ(request.addressType, allowed ? 3 : 1);
            EXPECT_STREQ(request.dstDomain, allowed ? "cached.example.invalid" : "");
            if (!allowed) EXPECT_EQ(request.dstIp, 0xC0000201u);
        }
        EXPECT_EQ(requests, 1);
        net::closeSocket(client);
        h.stop();
    }
}

APS_TEST(engine, pipe_core_port_conflict_keeps_row_and_cannot_be_activated) {
    auto k = makeKernel("unknown-core.exe", 0, 0);
    k.apiPipe = "\\\\.\\pipe\\test-core";
    k.discoveryError = "代理端口被其他进程占用";
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>(1, k);
    Harness h;
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    auto c = h.makeConfig();
    c.routing.autoOutletId = k.id;
    // This test mutates the scripted vector between synchronous scans.
    // A simultaneous startup scan can re-publish the old port-conflict row.
    h.start(c);
    h.engine->adoptDiscoveries();
    EXPECT_FALSE(h.engine->outletEnabled(k.id));
    EXPECT_TRUE(h.engine->statusJson().find(k.discoveryError) != std::string::npos);
    EXPECT_TRUE(h.engine->statusJson().find("\"has_api\":true") != std::string::npos);
    // Same process recovers: preserve the row id, enable the verified port.
    (*scripted)[0].socksPort = socks().port();
    (*scripted)[0].discoveryError.clear();
    h.engine->adoptDiscoveries();
    EXPECT_TRUE(h.engine->outletEnabled(k.id));
    EXPECT_TRUE(h.engine->statusJson().find("#2") == std::string::npos);
    scripted->clear();
    h.engine->adoptDiscoveries();
    EXPECT_FALSE(h.engine->outletEnabled(k.id));
    EXPECT_TRUE(h.engine->statusJson().find("内核未启动") != std::string::npos);
    h.stop();
    saveKernelCache({});
}

APS_TEST(engine, verified_pipe_restart_keeps_identity_across_config_access_change) {
    auto old = makeKernel("service-core.exe", 19001, 0);
    old.pid = 101;
    old.configDir = "C:\\user\\config";
    old.cmdline = "service-core.exe -f C:\\user\\config\\live.yaml";
    old.apiPipe = "\\\\.\\pipe\\owned-core";
    auto fresh = old;
    fresh.pid = 102;
    fresh.socksPort = socks().port();
    fresh.configDir = "C:\\Program Files\\Core"; // image fallback, not a new instance
    fresh.cmdline.clear();
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>(1, fresh);
    Harness h;
    h.cacheLoader = [old] { return std::vector<DiscoveredKernel>{old}; };
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    auto c = h.makeConfig();
    c.routing.autoOutletId = old.id;
    h.start(c, true);
    h.engine->adoptDiscoveries();
    auto status = h.engine->statusJson();
    EXPECT_TRUE(status.find("#2") == std::string::npos);
    EXPECT_TRUE(status.find("\"has_api\":true") != std::string::npos);
    EXPECT_TRUE(h.engine->outletEnabled(old.id));
    EXPECT_EQ(h.engine->outletParams(old.id).proxy.port, fresh.socksPort);
    h.stop();
    saveKernelCache({});
}

APS_TEST(engine, tcp_kernel_restart_readopts_active_outlet_after_offline_scan) {
    // Remote 2026-09-14 report: the active TCP-controlled core restarted,
    // retaining its SOCKS port while PID/controller port changed. An
    // intervening offline scan alone must not strand the activated id.
    // This checks adoption, not whether a real scan can find that process.
    MockSocks5Server otherSocks;
    MockClashApi oldApi, newApi;
    EXPECT_TRUE(otherSocks.start());
    EXPECT_TRUE(oldApi.start());
    EXPECT_TRUE(newApi.start());
    auto active = makeKernel("com.vortex.helper.exe", socks().port(), oldApi.port());
    active.pid = 101;
    active.configDir = "C:\\Test\\restart-core-config";
    active.cmdline = "mock-core -d C:\\Test\\restart-core-config -ext-ctl " +
                     std::to_string(oldApi.port());
    auto other = makeKernel("other-core.exe", otherSocks.port(), 0);
    other.pid = 201;
    other.configDir = "C:\\Test\\other-core-config";
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    Harness h;
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    auto c = h.makeConfig();
    c.routing.autoOutletId = active.id;
    c.subscription.autoRefresh = false;
    // Keep the background scanner disabled; each adoption is synchronous
    // and scripted. No real kernel, config, driver or remote endpoint is used.
    h.start(c);

    auto expectRow = [&](const DiscoveredKernel& expected, bool alive) {
        json::Value status;
        std::string err;
        EXPECT_TRUE(json::Value::parse(h.engine->statusJson(), status, &err));
        const auto* rows = status.find("kernels");
        EXPECT_TRUE(rows && rows->isArray());
        if (!rows) return;
        EXPECT_EQ(rows->size(), 2u);
        bool found = false;
        for (const auto& row : rows->array()) {
            const auto* id = row.find("id");
            if (!id || id->asString() != expected.id) continue;
            found = true;
            auto number = [&](const char* key) -> int64_t {
                const auto* value = row.find(key);
                return value ? value->asInt(-1) : -1;
            };
            EXPECT_EQ(number("pid"), expected.pid);
            EXPECT_EQ(number("socks_port"), alive ? expected.socksPort : 0);
            EXPECT_EQ(number("api_port"), alive ? expected.apiPort : 0);
            const auto* online = row.find("alive");
            EXPECT_TRUE(online != nullptr);
            if (online) EXPECT_EQ(online->asBool(), alive);
        }
        EXPECT_TRUE(found);
    };

    *scripted = {active, other};
    h.engine->adoptDiscoveries();
    expectRow(active, true);
    EXPECT_TRUE(h.engine->outletEnabled(active.id));

    // The old process is absent during a completed scan. Its remembered
    // row stays offline; this is not itself proof of a permanently dead
    // route, since disabled auto outlets fall back to the default endpoint.
    *scripted = {other};
    h.engine->adoptDiscoveries();
    expectRow(active, false);
    EXPECT_FALSE(h.engine->outletEnabled(active.id));
    EXPECT_EQ(h.engine->outletParams(active.id).proxy.port, c.proxy.port);

    active.pid = 102;
    active.apiPort = newApi.port();
    active.cmdline = "mock-core -d C:\\Test\\restart-core-config -ext-ctl " +
                     std::to_string(newApi.port());
    *scripted = {other, active}; // enumeration order must not change identity
    h.engine->adoptDiscoveries();
    h.engine->adoptDiscoveries(); // unchanged follow-up must remain stable
    expectRow(active, true);
    expectRow(other, true);
    EXPECT_TRUE(h.engine->outletEnabled(active.id));
    EXPECT_FALSE(h.engine->outletEnabled(other.id));
    EXPECT_EQ(h.engine->outletParams(active.id).proxy.port, active.socksPort);

    // A fresh unbound rule connection still targets the original active
    // outlet without a GUI click, config reload or cache deletion.
    h.pushConnectEvent(53120);
    h.device->pushTcp(buildTcpPacket(kAppIp, 53120, kDstIp, kDstPort, 200, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto entry = h.engine->nat().findByRev(kAppIp, 53120);
    EXPECT_TRUE(entry != nullptr);
    if (entry) EXPECT_STREQ(entry->outletId, active.id);

    h.stop();
    oldApi.stop();
    newApi.stop();
    otherSocks.stop();
    saveKernelCache({});
}

APS_TEST(engine, node_monitor_prefers_iepl_node) {
    // All nodes dead except two alive ones: node-b at 50ms and an IEPL node
    // at 300ms. Policy: IEPL class wins (even though slower).
    MockClashApi api;
    api.selectorNow = "node-a";                    // dead (no latency entry)
    api.latencies["node-b"] = 50;
    api.latencies["🇭🇰|HK-IEPL 01"] = 300;
    api.nodes = {"node-a", "node-b", "🇭🇰|HK-IEPL 01"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 1;
    c.proxy.healthIntervalS = 30;
    h.start(c);
    h.engine->requestNodeSwitchRound("__default__");
    bool switched = false;
    for (int i = 0; i < 160; ++i) {
        if (!api.switches().empty()) { switched = true; break; }
        Sleep(50);
    }
    EXPECT_TRUE(switched);
    if (switched) {
        auto sw = api.switches();
        EXPECT_STREQ(sw[0], "auto::🇭🇰|HK-IEPL 01");   // IEPL chosen over 50ms node-b
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, node_monitor_history_prefers_stable_relay_over_flaky_iepl) {
    // Production regression (2026-09-05): the preferred IEPL nodes often
    // passed one fresh /delay while failing 4-7 of the controller's last 10
    // checks. A stable same-region relay must outrank that flaky IEPL; one
    // switch tears down every long-lived browser/agent connection.
    MockSocks5Server brokenTunnel;
    brokenTunnel.setBehavior(MockSocksBehavior::RefuseConnect);
    EXPECT_TRUE(brokenTunnel.start());
    MockClashApi api;
    api.selectorNow = "台湾-当前节点";  // controller-dead; targeted round below
    api.nodes = {"台湾-当前节点", "台湾-IEPL 03", "台湾-中转 02"};
    api.latencies["台湾-IEPL 03"] = 100;  // faster and preferred, but flaky
    api.latencies["台湾-中转 02"] = 260;  // slower, but 10/10 available
    api.histories["台湾-IEPL 03"] =
        {100, 0, 100, 0, 100, 0, 100, 0, 100, 100};
    api.histories["台湾-中转 02"] =
        {260, 250, 270, 255, 265, 245, 275, 260, 250, 265};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.port = brokenTunnel.port();
    c.proxy.healthFailThreshold = 1;
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 1;
    c.nodeMonitor.regions = {"TW"};
    c.nodeMonitor.nodeClasses = {"IEPL"};
    c.nodeMonitor.realFailThreshold = 4;
    c.nodeMonitor.realFailRatioPct = 40;
    c.proxy.healthIntervalS = 30;
    h.start(c);
    EXPECT_TRUE(h.waitStatus([&](const std::string&) { return !h.engine->outletHealthy("__default__"); },3000));
    h.engine->requestNodeSwitchRound("__default__", false);

    bool switched = false;
    for (int i = 0; i < 160; ++i) {
        if (!api.switches().empty()) { switched = true; break; }
        Sleep(50);
    }
    EXPECT_TRUE(switched);
    if (switched) {
        EXPECT_STREQ(api.switches()[0], "auto::台湾-中转 02");
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, node_monitor_excludes_slow_candidates) {
    // Current node dead; candidates: fast (150ms), slow (900ms) and a very
    // slow IEPL (1200ms). Both slow nodes exceed the 800ms budget and must
    // be excluded — the switch goes to the only within-budget node.
    MockSocks5Server brokenTunnel;
    brokenTunnel.setBehavior(MockSocksBehavior::RefuseConnect);
    EXPECT_TRUE(brokenTunnel.start());
    MockClashApi api;
    api.selectorNow = "node-a";                     // dead
    api.latencies["node-fast"] = 150;
    api.latencies["node-slow"] = 900;
    api.latencies["🇭🇰|HK-IEPL 99"] = 1200;
    api.nodes = {"node-a", "node-fast", "node-slow", "🇭🇰|HK-IEPL 99"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.port = brokenTunnel.port();
    c.proxy.healthFailThreshold = 1;
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 1;
    c.proxy.healthIntervalS = 30;
    h.start(c);
    EXPECT_TRUE(h.waitStatus([&](const std::string&) { return !h.engine->outletHealthy("__default__"); },3000));
    h.engine->requestNodeSwitchRound("__default__", false);
    bool switched = false;
    for (int i = 0; i < 160; ++i) {
        if (!api.switches().empty()) { switched = true; break; }
        Sleep(50);
    }
    EXPECT_TRUE(switched);
    if (switched) {
        auto sw = api.switches();
        EXPECT_STREQ(sw[0], "auto::node-fast");  // slow + slow-IEPL excluded
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, node_monitor_slow_current_reselects_better_node) {
    // Current node is ALIVE but over budget (1200ms): the monitor must
    // re-select without waiting for it to die, and must not pick a worse
    // fallback (1500ms) when a better node (300ms) exists.
    MockClashApi api;
    api.selectorNow = "node-slow";
    api.latencies["node-slow"] = 1200;             // current: over 800ms budget
    api.latencies["node-better"] = 300;
    api.latencies["node-worse"] = 1500;
    api.nodes = {"node-slow", "node-better", "node-worse"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.proxy.healthIntervalS = 30;
    h.start(c);
    h.engine->requestNodeSwitchRound();
    bool switched = false;
    for (int i = 0; i < 160; ++i) {
        if (!api.switches().empty()) { switched = true; break; }
        Sleep(50);
    }
    EXPECT_TRUE(switched);
    if (switched) {
        auto sw = api.switches();
        EXPECT_STREQ(sw[0], "auto::node-better");
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, concurrent_reloads_do_not_kill_the_engine) {
    // Regression: the pipe RELOAD handler, the config-file watcher and the
    // discovery adoption could rebuild health monitors concurrently; one
    // rebuild destroyed another's freshly started monitor while its thread
    // was running -> silent engine death on "测试并连接". Three threads
    // hammering reloadConfig must leave the engine alive and functional.
    Harness h;
    h.start(h.makeConfig());

    std::atomic<bool> go{false};
    auto hammer = [&](int n) {
        while (!go.load()) Sleep(1);
        for (int i = 0; i < n; ++i) {
            h.engine->reloadConfig(h.makeConfig());
            Sleep(1);
        }
    };
    std::thread t1(hammer, 12), t2(hammer, 12), t3(hammer, 12);
    go.store(true);
    t1.join();
    t2.join();
    t3.join();

    // Engine still alive: status builds, and a new flow still gets proxied.
    std::string st = h.engine->statusJson();
    EXPECT_TRUE(st.find("\"type\":\"STATUS\"") != std::string::npos);
    h.device->clearSent();
    h.pushConnectEvent(53200, /*pid=*/100);
    h.device->pushTcp(buildTcpPacket(kAppIp, 53200, kDstIp, kDstPort, 300, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    EXPECT_TRUE(h.engine->nat().findByRev(kAppIp, 53200) != nullptr);
    h.stop();
}

APS_TEST(engine, node_monitor_manual_round_switches_immediately) {
    // A manual "测试并连接" round evaluates and switches on the FIRST
    // click even when failThreshold is high — the threshold is a timed
    // monitor concept, not a user-click limiter.
    MockClashApi api;
    api.selectorNow = "node-a";                    // dead
    api.latencies["node-b"] = 100;
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 5;               // timed rounds would wait
    c.nodeMonitor.nodeClasses.clear();            // no type filter for opaque mock nodes
    c.proxy.healthIntervalS = 30;
    h.start(c);
    h.engine->requestNodeSwitchRound("__default__");   // targeted = manual
    bool switched = false;
    for (int i = 0; i < 160; ++i) {
        if (!api.switches().empty()) { switched = true; break; }
        Sleep(50);
    }
    EXPECT_TRUE(switched);
    if (switched) {
        auto sw = api.switches();
        EXPECT_STREQ(sw[0], "auto::node-b");
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, region_prefers_matching_node) {
    // Region=JP. Current TW node is alive but out of region -> re-select.
    // A faster HK node (30ms) must LOSE to the in-region JP node (200ms):
    // the region is the first ranking key (soft preference).
    MockClashApi api;
    api.selectorNow = "台湾-IEPL 03";
    api.latencies["台湾-IEPL 03"] = 78;
    api.latencies["日本-IEPL 01"] = 200;
    api.latencies["香港-IEPL 01"] = 30;
    api.nodes = {"台湾-IEPL 03", "日本-IEPL 01", "香港-IEPL 01"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 1;
    c.nodeMonitor.regions = {"JP"};
    c.proxy.healthIntervalS = 30;
    h.start(c);
    h.engine->requestNodeSwitchRound();
    bool switched = false;
    for (int i = 0; i < 160; ++i) {
        if (!api.switches().empty()) { switched = true; break; }
        Sleep(50);
    }
    EXPECT_TRUE(switched);
    if (switched) {
        auto sw = api.switches();
        EXPECT_STREQ(sw[0], "auto::日本-IEPL 01");  // region beats latency
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, region_falls_back_when_region_dead) {
    // Region=JP but the only JP node is DEAD: fail open to the best alive
    // node (HK), and then STOP flapping — the region is remembered as
    // unavailable until it changes.
    MockClashApi api;
    api.selectorNow = "台湾-01";
    api.latencies["台湾-01"] = 50;
    // "日本-01" has no latency entry => dead.
    api.latencies["香港-01"] = 100;
    api.nodes = {"台湾-01", "日本-01", "香港-01"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 1;
    c.nodeMonitor.regions = {"JP"};
    c.proxy.healthIntervalS = 30;
    h.start(c);
    // The pump's immediate first round and an explicit request may run
    // concurrently (both switching to the same fallback node — harmless
    // duplicates); wait until the switch count settles before asserting.
    bool switched = false;
    for (int i = 0; i < 200; ++i) {  // dead JP node probe costs ~3s
        if (!api.switches().empty()) { switched = true; break; }
        Sleep(50);
    }
    EXPECT_TRUE(switched);
    if (switched) {
        auto sw = api.switches();
        EXPECT_STREQ(sw[0], "auto::香港-01");  // fail-open fallback
    }
    // Settle: wait until no NEW switch has happened for a full second.
    size_t quiet = 0, last = api.switches().size();
    for (int i = 0; i < 200 && quiet < 20; ++i) {
        size_t now = api.switches().size();
        quiet = (now == last) ? quiet + 1 : 0;
        last = now;
        Sleep(50);
    }
    const size_t n = api.switches().size();
    // No flapping: a further round must NOT switch again (current is HK,
    // out of region, but a re-select already proved JP unavailable).
    h.engine->requestNodeSwitchRound();
    Sleep(1500);
    {
        auto sw = api.switches();
        EXPECT_EQ(sw.size(), n);
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, region_manual_round_respects_region) {
    // Manual "测试并连接" with region=SG: the current HK node is alive and
    // fast, but the user wants SG — the round must re-evaluate the region
    // and switch to the in-region node despite its higher latency.
    MockClashApi api;
    api.selectorNow = "香港-IEPL 01";
    api.latencies["香港-IEPL 01"] = 50;
    api.latencies["新加坡-IEPL 02"] = 120;
    api.latencies["香港-IEPL 02"] = 40;
    api.nodes = {"香港-IEPL 01", "新加坡-IEPL 02", "香港-IEPL 02"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 1;
    c.nodeMonitor.regions = {"SG"};
    c.proxy.healthIntervalS = 30;
    h.start(c);
    h.engine->requestNodeSwitchRound("__default__");   // targeted = manual
    bool switched = false;
    for (int i = 0; i < 160; ++i) {
        if (!api.switches().empty()) { switched = true; break; }
        Sleep(50);
    }
    EXPECT_TRUE(switched);
    if (switched) {
        auto sw = api.switches();
        EXPECT_STREQ(sw[0], "auto::新加坡-IEPL 02");
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, class_prefers_matching_node) {
    // Node-class preference (explicit form of the old hard-coded IEPL bit):
    // class=RES (家宽), current node is plain IEPL (alive, fast) -> the
    // class no longer matches -> re-select must pick the 家宽 node even
    // though a faster non-class node exists.
    MockClashApi api;
    api.selectorNow = "香港-IEPL 01";
    api.latencies["香港-IEPL 01"] = 50;
    api.latencies["韩国家宽-IEPL 01"] = 200;   // in-class, slower
    api.latencies["香港-IEPL 02"] = 30;        // out-of-class, fastest
    api.nodes = {"香港-IEPL 01", "韩国家宽-IEPL 01", "香港-IEPL 02"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 1;
    c.nodeMonitor.nodeClasses = {"RES"};
    c.proxy.healthIntervalS = 30;
    h.start(c);
    h.engine->requestNodeSwitchRound();
    bool switched = false;
    for (int i = 0; i < 160; ++i) {
        if (!api.switches().empty()) { switched = true; break; }
        Sleep(50);
    }
    EXPECT_TRUE(switched);
    if (switched) {
        auto sw = api.switches();
        EXPECT_STREQ(sw[0], "auto::韩国家宽-IEPL 01");  // class beats latency
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, dead_current_never_blocks_switch) {
    // Regression: a DEAD current node must never be "kept" by the
    // region/class keep-guards just because its name matches the
    // preference. Measured in the wild: a dead 家宽-IEPL node was pinned
    // forever ("keeping in-class node"), killing the whole outlet.
    // Case 1: class guard. Current 香港-IEPL (dead), only alive candidate
    // is a non-IEPL 家宽 node -> must switch to it.
    // Automatic recovery requires real tunnel failure, not only missing
    // controller metadata. A refusing local SOCKS peer proves that failure.
    MockSocks5Server brokenTunnel;
    brokenTunnel.setBehavior(MockSocksBehavior::RefuseConnect);
    EXPECT_TRUE(brokenTunnel.start());
    MockClashApi api;
    api.selectorNow = "香港-IEPL 01";                 // dead: no latency entry
    api.latencies["韩国家宽-01"] = 100;               // alive, NOT IEPL
    api.nodes = {"香港-IEPL 01", "韩国家宽-01"};
    EXPECT_TRUE(api.start());
    {
        Harness h;
        Config c = h.makeConfig();
        c.rules.clear();
        c.proxy.port = brokenTunnel.port();
        c.proxy.healthFailThreshold = 1;
        c.proxy.clashApi.host = "127.0.0.1";
        c.proxy.clashApi.port = api.port();
        c.nodeMonitor.enabled = true;
        c.nodeMonitor.intervalS = 10;
        c.nodeMonitor.failThreshold = 1;
        c.nodeMonitor.nodeClasses = {"IEPL"};         // default
        c.proxy.healthIntervalS = 30;
        h.start(c);
        EXPECT_TRUE(h.waitStatus([&](const std::string&) {
            return !h.engine->outletHealthy("__default__");
        }, 3000));
        h.engine->requestNodeSwitchRound("__default__", false); // automatic recovery may fall back
        bool switched = false;
        for (int i = 0; i < 160; ++i) {
            if (!api.switches().empty()) { switched = true; break; }
            Sleep(50);
        }
        EXPECT_TRUE(switched);
        if (switched) {
            auto sw = api.switches();
            EXPECT_STREQ(sw[0], "auto::韩国家宽-01");  // dead node NOT kept
        }
        h.stop();
    }
    api.stop();
    // Case 2: region guard. Current TW (dead), region JP, only alive
    // candidate is HK -> must switch to HK.
    MockClashApi api2;
    api2.selectorNow = "台湾-01";                     // dead
    api2.latencies["香港-01"] = 100;
    api2.nodes = {"台湾-01", "香港-01"};
    EXPECT_TRUE(api2.start());
    {
        Harness h;
        Config c = h.makeConfig();
        c.rules.clear();
        c.proxy.port = brokenTunnel.port();
        c.proxy.healthFailThreshold = 1;
        c.proxy.clashApi.host = "127.0.0.1";
        c.proxy.clashApi.port = api2.port();
        c.nodeMonitor.enabled = true;
        c.nodeMonitor.intervalS = 10;
        c.nodeMonitor.failThreshold = 1;
        c.nodeMonitor.regions = {"JP"};
        c.proxy.healthIntervalS = 30;
        h.start(c);
        EXPECT_TRUE(h.waitStatus([&](const std::string&) {
            return !h.engine->outletHealthy("__default__");
        }, 3000));
        h.engine->requestNodeSwitchRound("__default__", false); // automatic recovery may fall back
        bool switched = false;
        for (int i = 0; i < 160; ++i) {
            if (!api2.switches().empty()) { switched = true; break; }
            Sleep(50);
        }
        EXPECT_TRUE(switched);
        if (switched) {
            auto sw = api2.switches();
            EXPECT_STREQ(sw[0], "auto::香港-01");
        }
        h.stop();
    }
    api2.stop();
}

APS_TEST(engine, region_upgrade_bypasses_class_veto) {
    // Measured in the wild: region=SG kept the engine on an alive Korean
    // IEPL node because the class keep-guard vetoed every out-of-region
    // re-select (and the veto never suppressed the trigger -> 7s
    // re-measure -> veto loop). Region anchoring outranks class preference:
    // an in-region candidate must win even when it is NOT in-class.
    MockClashApi api;
    api.selectorNow = "韩国-IEPL 01";                 // alive, in-class, out-of-region
    api.latencies["韩国-IEPL 01"] = 80;
    api.latencies["新加坡-家宽-01"] = 120;            // in-region, out-of-class
    api.nodes = {"韩国-IEPL 01", "新加坡-家宽-01"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 1;
    c.nodeMonitor.regions = {"SG"};
    c.nodeMonitor.nodeClasses = {"IEPL"};
    c.proxy.healthIntervalS = 30;
    h.start(c);
    h.engine->requestNodeSwitchRound();
    bool switched = false;
    for (int i = 0; i < 160; ++i) {
        if (!api.switches().empty()) { switched = true; break; }
        Sleep(50);
    }
    EXPECT_TRUE(switched);
    if (switched) {
        auto sw = api.switches();
        EXPECT_STREQ(sw[0], "auto::新加坡-家宽-01");  // region beats class
    }
    // And it must be STABLE: a second round does not switch again.
    h.engine->requestNodeSwitchRound();
    Sleep(1200);
    {
        auto sw = api.switches();
        EXPECT_EQ(sw.size(), 1u);
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, veto_suppresses_remeasure_loop) {
    // No in-region candidate at all: the region preference is UNSATISFIABLE
    // on this controller. The current node is healthy — a lateral switch
    // would only kill the kernel's connections for zero preference gain
    // (the old behavior did exactly that, then re-measured every round).
    // The inert latch must keep the engine quiet.
    MockClashApi api;
    api.selectorNow = "韩国-IEPL 01";                 // alive, in-class
    api.latencies["韩国-IEPL 01"] = 80;
    api.latencies["香港-IEPL 02"] = 90;               // in-class, out-of-region
    api.nodes = {"韩国-IEPL 01", "香港-IEPL 02"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 1;
    c.nodeMonitor.regions = {"SG"};
    c.nodeMonitor.nodeClasses = {"IEPL"};
    c.proxy.healthIntervalS = 30;
    h.start(c);
    h.engine->requestNodeSwitchRound();
    h.engine->requestNodeSwitchRound();
    Sleep(2000);
    // No switch may happen: the current node is healthy, and nothing in
    // the group can satisfy [SG] — laterally swapping KR->HK every window
    // is pure connection churn.
    EXPECT_TRUE(api.switches().empty());
    h.stop();
    api.stop();
}

APS_TEST(engine, stabilization_window_skips_slow_reselect) {
    // Every switch kills the kernel's existing connections; degraded nodes
    // hovering near the budget used to cause a switch per minute and an
    // endless agent "reconnecting" loop. The stabilization window must
    // SKIP non-dead re-selections for minSwitchIntervalS after a switch.
    MockClashApi api;
    api.selectorNow = "node-a";                 // dead (no latency entry)
    api.latencies["node-b"] = 50;               // best alive
    api.latencies["node-c"] = 100;
    api.nodes = {"node-a", "node-b", "node-c"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 1;
    c.nodeMonitor.nodeClasses.clear();       // mock nodes carry no type signal
    c.nodeMonitor.minSwitchIntervalS = 2;       // 2s window
    c.proxy.healthIntervalS = 30;
    h.start(c);

    // Round 1: dead current -> switch to node-b (lastSwitchAt = now).
    h.engine->requestNodeSwitchRound("__default__"); // explicit test proves controller failure
    bool switched = false;
    for (int i = 0; i < 160; ++i) {
        if (!api.switches().empty()) { switched = true; break; }
        Sleep(50);
    }
    EXPECT_TRUE(switched);
    // node-b becomes "too slow" (1200ms): within the 2s window the re-select
    // must be SKIPPED.
    api.latencies["node-b"] = 1200;
    Sleep(200);
    h.engine->requestNodeSwitchRound();
    Sleep(1000);
    {
        auto sw = api.switches();
        EXPECT_EQ(sw.size(), 1u);               // no switch within the window
    }
    // After the window: too slow again -> switches to node-c.
    Sleep(2200);
    h.engine->requestNodeSwitchRound();
    bool switched2 = false;
    for (int i = 0; i < 160; ++i) {
        if (api.switches().size() >= 2) { switched2 = true; break; }
        Sleep(50);
    }
    EXPECT_TRUE(switched2);
    if (switched2) {
        auto sw = api.switches();
        EXPECT_STREQ(sw[1], "auto::node-c");
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, periodic_controller_delay_failure_keeps_healthy_tunnel) {
    // A controller /delay request is metadata, not the user's data path.
    // When it alone fails but the independent SOCKS CONNECT stays healthy,
    // timed rounds must keep the node instead of tearing down live sessions.
    MockClashApi api;
    api.selectorNow = "node-a";
    api.nodes = {"node-a", "node-b"};
    api.latencies["node-a"] = 50;
    api.latencies["node-b"] = 20;
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 1;
    c.nodeMonitor.failThreshold = 1;  // old logic would switch on next tick
    c.nodeMonitor.regions.clear();
    c.nodeMonitor.nodeClasses.clear();
    c.proxy.healthIntervalS = 1;
    c.proxy.healthTimeoutMs = 1000;
    c.proxy.healthFailThreshold = 1;
    h.start(c);
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("\"node\":\"node-a\"") != std::string::npos &&
               s.find("\"latency_ms\":50") != std::string::npos;
    }, 5000));

    // Only the current node's controller delay now fails. Candidate node-b
    // still answers, so the pre-fix engine would definitely switch to it.
    api.latencies.erase("node-a");
    Sleep(2500);  // at least two timed rounds
    EXPECT_TRUE(api.switches().empty());
    const std::string status = h.engine->statusJson();
    EXPECT_TRUE(status.find("\"node\":\"node-a\"") != std::string::npos);
    EXPECT_TRUE(status.find("\"latency_ms\":50") != std::string::npos);
    EXPECT_TRUE(status.find("\"alive\":true") != std::string::npos);
    // A client-side node change must not label node-b with node-a's delay.
    // Its failed metadata probe still does not invalidate the healthy tunnel.
    api.latencies.erase("node-b");
    api.selectorNow = "node-b";
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        const auto row=outletStatusFor(s,"__default__");
        return row.find("node") && row.find("node")->asString()=="node-b" &&
               row.find("latency_ms") && row.find("latency_ms")->asInt()==-1;
    },5000));
    EXPECT_TRUE(api.switches().empty());
    h.stop();
    api.stop();
}

APS_TEST(engine, region_multi_select_any_of_set) {
    // Multi-select: regions {JP, SG}. Current KR is out of the set; an
    // alive SG candidate must win even though JP has no candidate at all
    // (single-select would have fallen back to "any alive").
    MockClashApi api;
    api.selectorNow = "韩国-IEPL 01";
    api.latencies["韩国-IEPL 01"] = 60;
    api.latencies["新加坡-IEPL 01"] = 150;
    api.nodes = {"韩国-IEPL 01", "新加坡-IEPL 01"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 1;
    c.nodeMonitor.regions = {"JP", "SG"};
    c.proxy.healthIntervalS = 30;
    h.start(c);
    h.engine->requestNodeSwitchRound();
    bool switched = false;
    for (int i = 0; i < 160; ++i) {
        if (!api.switches().empty()) { switched = true; break; }
        Sleep(50);
    }
    EXPECT_TRUE(switched);
    if (switched) {
        auto sw = api.switches();
        EXPECT_STREQ(sw[0], "auto::新加坡-IEPL 01");
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, group_membership_class_selection) {
    // "GROUP:<name>" class entries use ACTUAL group membership, transitive
    // over sub-group references — a provider's grouping can be selected as
    // a type even when its nodes carry no naming signal (measured: xmrth's
    // 🤖AI服务 group holds 美国63x 中继 nodes without "AI" in their names).
    MockClashApi api;
    // The live group is GLOBAL (lists every node); AI服务 is a sub-group
    // whose membership reaches 美国632 transitively via 🔰国外流量.
    api.groups = {
        // GLOBAL's member list includes a GROUP name ("🔰国外流量") — the
        // engine must skip it as a candidate (groups are filters, not
        // selectable nodes; measured: it once "switched" to 苹果服务).
        {"GLOBAL",
         {"香港-IEPL 01", "美国631 中继", "美国632 中继", "美国633 中继",
          "🔰国外流量"}},
        {"🤖AI服务", {"🔰国外流量", "美国631 中继"}},
        {"🔰国外流量", {"美国631 中继", "美国632 中继"}},
    };
    api.selectorNow = "香港-IEPL 01";                 // alive, out of class
    api.latencies["香港-IEPL 01"] = 50;
    api.latencies["美国632 中继"] = 150;              // in AI服务 (transitive)
    api.latencies["美国633 中继"] = 40;               // NOT in AI服务, faster
    api.nodes = {"香港-IEPL 01", "美国632 中继", "美国633 中继"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 1;
    c.nodeMonitor.nodeClasses = {"GROUP:🤖AI服务"};
    c.proxy.healthIntervalS = 30;
    h.start(c);
    h.engine->requestNodeSwitchRound();
    bool switched = false;
    for (int i = 0; i < 160; ++i) {
        if (!api.switches().empty()) { switched = true; break; }
        Sleep(50);
    }
    EXPECT_TRUE(switched);
    if (switched) {
        auto sw = api.switches();
        // Transitive membership beats raw speed.
        EXPECT_STREQ(sw[0], "GLOBAL::美国632 中继");
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, rule_mode_monitors_and_recovers_preferred_service_group) {
    // Both policies are used by rules and share nodes. The larger general
    // selector is healthy, but it says nothing about the independently
    // selected service node. GROUP preferences must choose the service's
    // switching target as well as filter its candidates.
    for (const bool serviceDead : {false, true}) {
        MockClashApi api;
        api.mode = "rule";
        api.groups = {{"General route", {"SG relay", "US relay", "JP relay"}},
                      {"Service route", {"US relay", "JP relay"}}};
        api.groupSelections = {{"General route", "SG relay"},
                               {"Service route", "US relay"}};
        api.rulePolicies = {"Service route", "General route"};
        api.latencies = {{"SG relay", 5}, {"JP relay", 60}};
        if (!serviceDead) api.latencies["US relay"] = 40;
        EXPECT_TRUE(api.start());
        Harness h;
        Config c = h.makeConfig();
        c.rules.clear();
        c.proxy.clashApi.host = "127.0.0.1";
        c.proxy.clashApi.port = api.port();
        c.nodeMonitor.nodeClasses = {"GROUP:Service route"};
        c.nodeMonitor.regions.clear();
        c.nodeMonitor.failThreshold = 1;
        h.start(c);
        h.engine->requestNodeSwitchRound("__default__", true, "service-route");
        EXPECT_TRUE(h.waitStatus([](const std::string& text) {
            auto row = outletStatusFor(text, "__default__");
            return row.find("test_request_id") &&
                   row.find("test_request_id")->asString() == "service-route" &&
                   row.find("switching") && !row.find("switching")->asBool();
        }, 8000));
        auto row = outletStatusFor(h.lastStatus(), "__default__");
        EXPECT_TRUE(row.find("group") && row.find("group")->asString() == "Service route");
        EXPECT_TRUE(row.find("node") && row.find("node")->asString() ==
                    (serviceDead ? "JP relay" : "US relay"));
        const auto switches = api.switches();
        EXPECT_EQ(switches.size(), serviceDead ? 1u : 0u);
        if (serviceDead && !switches.empty())
            EXPECT_STREQ(switches.front(), ClashApiClient::urlEncode("Service route") + "::JP relay");
        h.stop();
        api.stop();
    }
}

APS_TEST(engine, preferred_service_can_select_existing_nested_region_without_editing_child) {
    for (const bool manual : {false, true}) {
        MockClashApi api;
        api.mode = "rule";
        api.groups = {{"Service route", {"US relay", "Shared route"}},
                      {"Shared route", {"Automatic route", "JP relay"}},
                      {"Automatic route", {"SG IEPL", "JP relay"}}};
        api.groupTypes["Automatic route"] = "URLTest";
        api.groupSelections = {{"Service route", "US relay"},
                               {"Shared route", "Automatic route"},
                               {"Automatic route", "SG IEPL"}};
        api.rulePolicies = {"Service route", "Shared route"};
        api.latencies = {{"US relay", 100}, {"SG IEPL", 80}, {"JP relay", 20}};
        EXPECT_TRUE(api.start());
        Harness h;
        auto c = h.makeConfig();
        c.rules.clear();
        c.proxy.clashApi.host = "127.0.0.1";
        c.proxy.clashApi.port = api.port();
        c.nodeMonitor.enabled = true;
        c.nodeMonitor.regions = {"SG"};
        c.nodeMonitor.nodeClasses = {"IEPL", "GROUP:Service route"};
        c.nodeMonitor.intervalS = 30;
        h.start(c);
        if (manual) h.engine->requestNodeSwitchRound("__default__", true, "nested-choice");
        EXPECT_TRUE(h.waitStatus([](const std::string& text) {
            auto row = outletStatusFor(text, "__default__");
            return row.find("group") && row.find("group")->asString() == "Service route" &&
                   row.find("node") && row.find("node")->asString() == "SG IEPL" &&
                   row.find("switching") && !row.find("switching")->asBool();
        }, 5000));
        h.stop();
        const auto switches = api.switches();
        EXPECT_EQ(switches.size(), 1u);
        if (!switches.empty()) EXPECT_STREQ(switches.front(), "Service%20route::Shared route");
        EXPECT_STREQ(api.groupSelections["Shared route"], "Automatic route");
        EXPECT_STREQ(api.groupSelections["Automatic route"], "SG IEPL");
        api.stop();
    }
}

APS_TEST(engine, preferred_nested_choices_skip_invalid_unselected_and_current_leaves) {
    for (const bool currentInRegion : {false, true}) {
        MockClashApi api;
        api.mode = "rule";
        const std::string current = currentInRegion ? "SG IEPL" : "US relay";
        api.groups = {{"Service route", {current, "Shared route", "SG cycle", "SG direct", "SG empty"}},
                      {"Shared route", {"SG IEPL", "JP relay"}},
                      {"SG cycle", {"Service route"}},
                      {"SG direct", {"DIRECT"}}, {"SG empty", {"SG IEPL"}}};
        const std::string shared = currentInRegion ? "SG IEPL" : "JP relay";
        api.groupSelections = {{"Service route", current}, {"Shared route", shared},
                               {"SG cycle", "Service route"}, {"SG direct", "DIRECT"}, {"SG empty", ""}};
        api.rulePolicies = {"Service route"};
        api.latencies = {{current, 50}, {"SG IEPL", 1}, {"JP relay", 5}, {"DIRECT", 1}};
        EXPECT_TRUE(api.start());
        Harness h;
        auto c = h.makeConfig();
        c.rules.clear();
        c.proxy.clashApi.host = "127.0.0.1";
        c.proxy.clashApi.port = api.port();
        c.nodeMonitor.enabled = true;
        c.nodeMonitor.regions = {"SG"};
        c.nodeMonitor.nodeClasses = {"IEPL", "GROUP:Service route"};
        c.nodeMonitor.intervalS = 30;
        h.start(c);
        h.engine->requestNodeSwitchRound("__default__", true, "invalid-nested");
        EXPECT_TRUE(h.waitStatus([](const std::string& text) {
            const auto row = outletStatusFor(text, "__default__");
            return row.find("test_request_id") && row.find("test_request_id")->asString() == "invalid-nested" &&
                   row.find("switching") && !row.find("switching")->asBool();
        }, 5000));
        h.stop();
        EXPECT_TRUE(api.switches().empty());
        EXPECT_STREQ(api.groupSelections["Shared route"], shared);
        api.stop();
    }
}

APS_TEST(engine, group_absent_class_is_inert) {
    // A wanted "GROUP:<name>" that THIS controller does not expose at all is
    // unsatisfiable (measured: GROUP:AI服务 selected globally while the
    // SakuraCat controller has no such group — the old code re-triggered a
    // re-select every round and flip-flopped between the fastest nodes
    // forever). The class preference must be INERT here: no switch, no
    // churn — and it re-arms by itself when the group appears.
    MockClashApi api;
    api.selectorNow = "node-a";                     // alive, "out of class"
    api.latencies["node-a"] = 40;
    api.latencies["node-b"] = 30;                   // faster; must NOT be picked
    api.nodes = {"node-a", "node-b"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 1;
    c.nodeMonitor.nodeClasses = {"GROUP:AI服务"};  // absent on this controller
    c.proxy.healthIntervalS = 30;
    h.start(c);

    // Two full rounds: no switch either time (inert + latched).
    h.engine->requestNodeSwitchRound();
    Sleep(1800);
    EXPECT_TRUE(api.switches().empty());
    h.engine->requestNodeSwitchRound();
    Sleep(1800);
    EXPECT_TRUE(api.switches().empty());

    // The group appears (the user switched the kernel's profile/provider):
    // the preference re-arms and the next round switches to a member.
    api.groups = {{"auto", {"node-a", "node-b", "美国631 中继"}},
                  {"AI服务", {"美国631 中继"}}};
    api.latencies["美国631 中继"] = 60;
    h.engine->requestNodeSwitchRound();
    bool switched = false;
    for (int i = 0; i < 160 && !switched; ++i) {
        if (!api.switches().empty()) switched = true;
        Sleep(50);
    }
    EXPECT_TRUE(switched);
    if (switched) {
        EXPECT_STREQ(api.switches()[0], "auto::美国631 中继");
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, region_inferred_from_group_names) {
    // Auto-inference: a group whose name carries a region signal teaches
    // that region to its (opaque-named) member nodes — no per-provider
    // keyword additions needed.
    MockClashApi api;
    api.groups = {
        {"GLOBAL",
         {"新加坡-IEPL 01", "Node-A1", "Node-A2", "Node-X"}},
        {"香港节点", {"Node-A1", "Node-A2"}},
    };
    api.selectorNow = "新加坡-IEPL 01";               // alive, out of region HK
    api.latencies["新加坡-IEPL 01"] = 50;
    api.latencies["Node-A1"] = 200;                   // inferred HK, slower
    api.latencies["Node-A2"] = 300;
    api.latencies["Node-X"] = 30;                     // no region, fastest
    api.nodes = {"新加坡-IEPL 01", "Node-A1", "Node-A2", "Node-X"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 1;
    c.nodeMonitor.regions = {"HK"};
    c.proxy.healthIntervalS = 30;
    h.start(c);
    h.engine->requestNodeSwitchRound();
    bool switched = false;
    for (int i = 0; i < 160; ++i) {
        if (!api.switches().empty()) { switched = true; break; }
        Sleep(50);
    }
    EXPECT_TRUE(switched);
    if (switched) {
        auto sw = api.switches();
        // Inferred HK membership beats raw speed (Node-X is not "in HK").
        EXPECT_STREQ(sw[0], "GLOBAL::Node-A1");
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, region_full_round_switches_all_outlets) {
    // A region change must re-measure EVERY outlet at once (parallel full
    // round), not just the default one — the user's trigger means "both
    // kernels now", and a serial round made the second kernel wait ~30s.
    MockClashApi api1;
    api1.selectorNow = "香港-01";
    api1.latencies["香港-01"] = 50;
    api1.latencies["台湾-01"] = 120;
    api1.nodes = {"香港-01", "台湾-01"};
    EXPECT_TRUE(api1.start());
    MockClashApi api2;
    api2.selectorNow = "香港-01";
    api2.latencies["香港-01"] = 50;
    api2.latencies["台湾-01"] = 140;
    api2.nodes = {"香港-01", "台湾-01"};
    EXPECT_TRUE(api2.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api1.port();
    Outlet o1;
    o1.id = "o1";
    o1.name = "second-kernel";
    o1.host = "127.0.0.1";
    o1.port = 59001;                 // unused SOCKS port; controller is api2
    o1.enabled = true;
    o1.clashApi.host = "127.0.0.1";
    o1.clashApi.port = api2.port();
    c.outlets.push_back(o1);
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.failThreshold = 1;
    c.nodeMonitor.regions = {"TW"};
    c.proxy.healthIntervalS = 30;
    h.start(c);

    h.engine->requestNodeSwitchRound("");   // full round = both outlets
    bool ok = h.waitStatus([](const std::string& s) {
        return s.find("地区切换") != std::string::npos;
    }, 8000);
    // Both controllers must have been switched to the in-region node.
    EXPECT_TRUE(ok);
    {
        auto sw1 = api1.switches();
        auto sw2 = api2.switches();
        EXPECT_EQ(sw1.size(), 1u);
        EXPECT_EQ(sw2.size(), 1u);
        if (!sw1.empty()) EXPECT_STREQ(sw1[0], "auto::台湾-01");
        if (!sw2.empty()) EXPECT_STREQ(sw2[0], "auto::台湾-01");
    }
    h.stop();
    api1.stop();
    api2.stop();
}

APS_TEST(engine, stats_reflect_connections) {
    Harness h;
    h.start(h.makeConfig());
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    // Timer pushes stats every second.
    std::string found;
    for (int t = 0; t < 40 && found.empty(); ++t) {
        {
            std::lock_guard<std::mutex> lk(h.mu);
            for (auto it = h.stats.rbegin(); it != h.stats.rend(); ++it) {
                if (it->find("\"total\":1") != std::string::npos ||
                    it->find("\"total\": 1") != std::string::npos) {
                    found = *it;
                    break;
                }
            }
        }
        if (found.empty()) Sleep(250);
    }
    EXPECT_TRUE(!found.empty());
    h.stop();
}

APS_TEST(engine, node_monitor_rapid_round_is_async) {
    // The "测试并连接" path must not block the caller (pipe thread): the
    // request returns immediately and the probe runs on the pump thread.
    MockClashApi api;
    api.selectorNow = "node-a";
    api.latencies["node-a"] = 50;
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.proxy.healthIntervalS = 30;
    h.start(c);

    ULONGLONG t0 = GetTickCount64();
    h.engine->requestNodeSwitchRound("");
    ULONGLONG elapsed = GetTickCount64() - t0;
    EXPECT_TRUE(elapsed < 500);  // async: no network I/O on the caller

    // The round still happens (on the pump thread) and reports the node.
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("\"api\":true") != std::string::npos &&
               s.find("\"latency_ms\":50") != std::string::npos;
    }, 5000));
    h.stop();
    api.stop();
}

APS_TEST(engine, dead_tunnel_health_auto_reselects_without_click) {
    // The dead-node recovery case, 2026-08-28: the SOCKS listener answers
    // greetings but the outbound tunnel is dead (every real CONNECT is
    // refused) because the CURRENT node is bad. The health monitor must
    // report that honestly AND queue the same targeted round as the UI's
    // "测试并连接": switching the kernel to another node is exactly the
    // recovery for a dead current node. A gate that skipped rounds while
    // the real probe failed
    // deadlocked a dead-node kernel forever (measured: SakuraCat stayed on
    // a TLS-reset node; the row showed 出口不健康 and no candidate was
    // ever tested).
    MockSocks5Server sick;
    sick.setBehavior(MockSocksBehavior::RefuseConnect);
    EXPECT_TRUE(sick.start());

    MockClashApi api;
    api.selectorNow = "node-a";     // current node: dead (no latency entry)
    api.latencies["node-b"] = 15;   // candidate: alive
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.port = sick.port();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.proxy.healthIntervalS = 1;
    c.proxy.healthTimeoutMs = 1000;
    c.proxy.healthFailThreshold = 1;
    // The built-in initial FULL round is a normal timed evaluation and only
    // records fail 1/2. The health transition queues a targeted immediate
    // evaluation, which bypasses that debounce exactly like the UI button.
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 300;
    c.nodeMonitor.failThreshold = 2;
    h.start(c);
    // The real-CONNECT probe flips the health state (it dials through the
    // dead tunnel) — the round must run DESPITE the unhealthy report.
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("\"proxy_reachable\":false") != std::string::npos;
    }, 5000));
    // The round re-selects onto the alive candidate.
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("\"node\":\"node-b\"") != std::string::npos;
    }, 8000));
    bool switched = false;
    for (const auto& s : api.switches()) {
        if (s.find("node-b") != std::string::npos) switched = true;
    }
    EXPECT_TRUE(switched);

    // Discovery/config reloads rebuild monitor objects. Their first false
    // announcement is not another logical healthy->down transition and must
    // not start a second manual-style controller round.
    const size_t apiHitsAfterRecovery = api.versionHits();
    h.engine->reloadConfig(c);
    Sleep(1500);
    EXPECT_EQ(api.versionHits(), apiHitsAfterRecovery);
    h.stop();
    sick.stop();
    api.stop();
}

namespace {
// Drives ONE real relay session: seeds the socket map, pushes the SYN (the
// NAT entry is created by the engine), waits for the entry, then makes a
// REAL loopback TCP connection to the relay — the relay resolves it via
// findByPort (the loopback-delivery fallback) and tunnels through the
// configured outlet. Returns true when the session was driven.
bool driveRelayFlow(Harness& h, uint16_t appPort, uint32_t dstIp = kDstIp,
                    uint16_t dstPort = kDstPort) {
    // The socket-map event must carry the SAME destination as the SYN below
    // (attribution cross-checks the remote), so pass dst through.
    h.pushConnectEvent(appPort, /*pid=*/100, dstIp, dstPort);
    h.device->pushTcp(
        buildTcpPacket(kAppIp, appPort, dstIp, dstPort, 100, 0, 0x02));
    for (int i = 0; i < 300; ++i) {
        if (h.engine->nat().findByPort(appPort)) break;
        Sleep(10);
    }
    if (!h.engine->nat().findByPort(appPort)) {
        std::printf("    [driveRelayFlow] no NAT entry for port %u (nat=%zu)\n",
                    appPort, h.engine->nat().size());
        std::printf("    [driveRelayFlow] sent=%zu state=%d enabled=%d healthy=%d\n",
                    h.device->sent().size(), static_cast<int>(h.engine->state()),
                    h.engine->enabled() ? 1 : 0,
                    h.engine->outletHealthy("__default__") ? 1 : 0);
        if (!h.device->sent().empty()) {
            auto s = h.device->sent()[0];
            auto p = parseSent(s);
            std::printf("    [driveRelayFlow] sent[0] dst=%u:%u src=%u:%u lb=%d\n",
                        p.dstIp, p.dstPort, p.srcIp, p.srcPort,
                        s.meta.loopback ? 1 : 0);
        }
        return false;
    }
    SOCKET c = net::makeTcpSocket();
    if (c == INVALID_SOCKET) return false;
    // The relay resolves the peer by its SOURCE port (the loopback
    // delivery fallback): bind the helper socket to the flow's app port so
    // the NAT entry is found — an ephemeral port would be an unknown peer.
    sockaddr_in la{};
    la.sin_family = AF_INET;
    la.sin_addr.S_un.S_addr = htonl(0x7F000001);
    la.sin_port = htons(appPort);
    if (bind(c, reinterpret_cast<sockaddr*>(&la), sizeof(la)) != 0) {
        std::printf("    [driveRelayFlow] bind local port %u failed\n", appPort);
        net::closeSocket(c);
        return false;
    }
    net::Endpoint4 relay{0x7F000001, h.engine->relay().listenPort()};
    int rc = net::connectWithTimeout(c, relay, 3000, nullptr);
    if (rc != 0) {
        std::printf("    [driveRelayFlow] connect to relay failed rc=%d\n", rc);
        net::closeSocket(c);
        return false;
    }
    // The session fails fast (mock refuses the CONNECT): the RST arrives
    // here; give the relay thread a beat to report before returning.
    Sleep(100);
    net::closeSocket(c);
    return true;
}
}  // namespace

APS_TEST(engine, real_traffic_failures_trigger_auto_reselect) {
    // The 2026-08-28 incident in test form: the current node passes the
    // controller's /delay (gstatic) with flying colors while EVERY real
    // connection through it fails (the exit TLS-resets blocked sites). The
    // user's own flows are the probe: enough failures in the window must
    // self-trigger a node re-selection with NO click and NO scheduled
    // round. No hard-coded probe URL — the verification dials the exact
    // destination that failed.
    MockSocks5Server sick;
    sick.setBehavior(MockSocksBehavior::RefuseConnect);
    EXPECT_TRUE(sick.start());
    MockClashApi api;
    api.selectorNow = "node-a";
    api.latencies["node-a"] = 20;   // healthy per /delay!
    api.latencies["node-b"] = 15;
    api.nodes = {"node-a", "node-b", "node-c"};
    // Trusted-destination seeding (see the chain test): the failures that
    // drive the signal must be to an address WE resolved.
    api.dnsAnswers["x.com"] = {"9.9.9.9"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.proxy.port = sick.port();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.nodeClasses.clear();
    c.nodeMonitor.realFailThreshold = 2;
    c.nodeMonitor.realFailRatioPct = 50;
    c.nodeMonitor.realFailWindowS = 60;
    c.nodeMonitor.minSwitchIntervalS = 300;
    c.nodeMonitor.badNodeCooldownS = 0;  // no verify chain in this test
    c.proxy.healthIntervalS = 1;  // repeat-failure coalescing cadence
    h.start(c);
    // Greeting-only health probe (the mock answers greetings but refuses
    // CONNECTs): the outlet stays healthy so flows NAT — their SOCKS-level
    // failures are exactly the real-traffic signal under test. The
    // monitor's FIRST probe is authoritative (!announced), so rebuild it
    // with the new target right away.
    h.engine->setHealthProbeDstForTest(net::Endpoint4{0, 0});
    h.engine->reloadConfig(c);
    h.engine->setDnsTtlMsForTest(60000);
    Sleep(300);

    const uint32_t kDns = 0x72727272;
    const uint32_t kTrusted = 0x09090909;  // 9.9.9.9, from our resolver
    h.device->pushDns(buildUdpPacket(kAppIp, 53100, kDns, 53,
                                     dnsQueryBytes("x.com")));
    for (int i = 0; i < 150 && h.device->sentDnsCount() < 1; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 1u);

    EXPECT_TRUE(driveRelayFlow(h, 50101, kTrusted, kDstPort));
    EXPECT_TRUE(driveRelayFlow(h, 50102, kTrusted, kDstPort));

    // The auto-round fires and re-selects onto the alive candidate.
    bool switched = false;
    for (int i = 0; i < 400 && !switched; ++i) {
        for (const auto& s : api.switches()) {
            if (s.find("node-b") != std::string::npos) switched = true;
        }
        if (!switched) Sleep(25);
    }
    EXPECT_TRUE(switched);

    // The newly selected node can be bad too. Make a third candidate alive,
    // wait only the independent health cadence (far below the 300s soft
    // stabilization window), then feed one more trusted failure. The engine
    // must reselect again instead of pinning the bad node for five minutes.
    api.latencies["node-c"] = 10;
    Sleep(1200);
    EXPECT_TRUE(driveRelayFlow(h, 50103, kTrusted, kDstPort));
    bool switchedAgain = false;
    for (int i = 0; i < 400 && !switchedAgain; ++i) {
        auto switches = api.switches();
        if (switches.size() >= 2 &&
            switches.back().find("node-c") != std::string::npos) {
            switchedAgain = true;
        }
        if (!switchedAgain) Sleep(25);
    }
    EXPECT_TRUE(switchedAgain);
    h.stop();
    sick.stop();
    api.stop();
}

APS_TEST(engine, connect_refused_triggers_quick_rescan) {
    // The kernel restarted with new random ports: the outlet's SOCKS port
    // dies while flows are already NAT'd. Every relay session's CONNECT to
    // the old port is refused at the TCP level — the engine must re-scan
    // for kernels IMMEDIATELY (not on the next scheduled tick) so the
    // outlet re-pairs with the port the kernel actually serves NOW.
    MockSocks5Server doomed;
    EXPECT_TRUE(doomed.start());

    Harness h;
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    scripted->push_back(makeKernel("kern-a.exe", doomed.port(), 0));
    std::atomic<int> scanCalls{0};
    h.discoveryScan = [scripted, &scanCalls](DiscoveryMode) {
        scanCalls.fetch_add(1);
        return *scripted;
    };
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    Config c = h.makeConfig();
    c.proxy.port = doomed.port();
    c.nodeMonitor.enabled = false;
    h.start(c, /*discoveryEnabled=*/true);
    // Greeting-only probe keeps the outlet healthy while the port is alive.
    h.engine->setHealthProbeDstForTest(net::Endpoint4{0, 0});
    h.engine->reloadConfig(c);
    Sleep(300);
    const int baseline = scanCalls.load();

    // Freeze a NAT entry while the port is alive, THEN kill the port (the
    // kernel "restarted"): the relay session below hits connection refused.
    h.pushConnectEvent(50201);
    h.device->pushTcp(
        buildTcpPacket(kAppIp, 50201, kDstIp, kDstPort, 100, 0, 0x02));
    bool natReady = false;
    for (int i = 0; i < 300 && !natReady; ++i) {
        natReady = h.engine->nat().findByPort(50201) != nullptr;
        if (!natReady) Sleep(10);
    }
    EXPECT_TRUE(natReady);
    if (!natReady) {
        h.stop();
        doomed.stop();
        return;
    }
    doomed.stop();  // nothing listens on the outlet port anymore
    SOCKET cl = net::makeTcpSocket();
    EXPECT_TRUE(cl != INVALID_SOCKET);
    if (cl == INVALID_SOCKET) {
        h.stop();
        return;
    }
    // Same source-port bind as driveRelayFlow: the relay must resolve the
    // peer to the NAT entry.
    sockaddr_in la{};
    la.sin_family = AF_INET;
    la.sin_addr.S_un.S_addr = htonl(0x7F000001);
    la.sin_port = htons(50201);
    if (bind(cl, reinterpret_cast<sockaddr*>(&la), sizeof(la)) != 0) {
        net::closeSocket(cl);
        h.stop();
        return;
    }
    net::Endpoint4 relay{0x7F000001, h.engine->relay().listenPort()};
    EXPECT_EQ(net::connectWithTimeout(cl, relay, 3000, nullptr), 0);
    Sleep(100);
    net::closeSocket(cl);

    // The port-heal re-scan runs on the node pump (single-threaded with
    // discovery), well before any 60s tick.
    bool rescanned = false;
    for (int i = 0; i < 200 && !rescanned; ++i) {
        if (scanCalls.load() > baseline) rescanned = true;
        if (!rescanned) Sleep(25);
    }
    EXPECT_TRUE(rescanned);
    h.stop();
}

APS_TEST(engine, application_reset_does_not_trigger_kernel_rescan) {
    // Production regression, 2026-09-05: Chrome routinely resets/abandons
    // speculative connections. The relay reported "app recv/send" and the
    // engine guessed from the text that the local SOCKS port had vanished,
    // causing a Quick discovery + wholesale health-monitor rebuild about
    // every 30 seconds. Only an actual ProxyEndpoint failure may do that.
    MockSocks5Server liveProxy;
    liveProxy.setBehavior(MockSocksBehavior::AcceptConnect);
    EXPECT_TRUE(liveProxy.start());

    Harness h;
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    scripted->push_back(makeKernel("kern-a.exe", liveProxy.port(), 0));
    std::atomic<int> scanCalls{0};
    h.discoveryScan = [scripted, &scanCalls](DiscoveryMode) {
        scanCalls.fetch_add(1);
        return *scripted;
    };
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    Config c = h.makeConfig();
    c.proxy.port = liveProxy.port();
    c.nodeMonitor.enabled = false;
    c.nodeMonitor.intervalS = 30;
    h.start(c, /*discoveryEnabled=*/true);
    for (int i = 0; i < 100 && scanCalls.load() == 0; ++i) Sleep(25);
    Sleep(500);  // initial discovery/adoption has settled
    const int baseline = scanCalls.load();
    EXPECT_TRUE(baseline > 0);

    constexpr uint16_t appPort = 50231;
    h.pushConnectEvent(appPort, /*pid=*/100, kDstIp, kDstPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, appPort, kDstIp, kDstPort,
                                     100, 0, 0x02));
    bool natReady = false;
    for (int i = 0; i < 200 && !natReady; ++i) {
        natReady = h.engine->nat().findByPort(appPort) != nullptr;
        if (!natReady) Sleep(10);
    }
    EXPECT_TRUE(natReady);

    const size_t requestsBefore = liveProxy.requestCount();
    SOCKET cl = net::makeTcpSocket();
    EXPECT_TRUE(cl != INVALID_SOCKET);
    sockaddr_in la{};
    la.sin_family = AF_INET;
    la.sin_addr.S_un.S_addr = htonl(0x7F000001);
    la.sin_port = htons(appPort);
    EXPECT_EQ(bind(cl, reinterpret_cast<sockaddr*>(&la), sizeof(la)), 0);
    net::Endpoint4 relay{0x7F000001, h.engine->relay().listenPort()};
    EXPECT_EQ(net::connectWithTimeout(cl, relay, 3000, nullptr), 0);
    for (int i = 0; i < 200 && liveProxy.requestCount() <= requestsBefore; ++i) {
        Sleep(10);
    }
    EXPECT_TRUE(liveProxy.requestCount() > requestsBefore);
    Sleep(100);  // SOCKS CONNECT reply reached the relay; pump is active
    net::enableAbortiveClose(cl);
    net::closeSocket(cl);
    for (int i = 0; i < 200 && h.engine->relay().activeSessions() != 0; ++i) {
        Sleep(10);
    }
    EXPECT_EQ(h.engine->relay().activeSessions(), static_cast<size_t>(0));

    // An old text-based classifier wakes the node pump and increments this
    // within milliseconds. Leave ample time while staying far below the
    // configured 30-second periodic discovery tick.
    Sleep(1000);
    EXPECT_EQ(scanCalls.load(), baseline);

    h.stop();
    liveProxy.stop();
}

APS_TEST(engine, verify_failed_nodes_are_cooled_down_and_chain_settles) {
    // The retry chain: /delay says every node is healthy, but the REAL
    // verification (dialing the destination the user's traffic just failed
    // to reach) fails for each switch target — the engine must walk the
    // candidate list, cooling each failed node down, and SETTLE (no
    // infinite switch churn) once the whole list is in cooldown.
    MockSocks5Server sick;
    sick.setBehavior(MockSocksBehavior::RefuseConnect);
    EXPECT_TRUE(sick.start());
    MockClashApi api;
    api.selectorNow = "node-a";
    api.latencies["node-a"] = 20;
    api.latencies["node-b"] = 15;
    api.latencies["node-c"] = 10;
    // The controller resolves x.com -> 9.9.9.9: the engine's cache then
    // holds OUR answer, making 9.9.9.9 a TRUSTED verification target (the
    // trust-gated verify ignores destinations we never handed out — those
    // may be poisoned real-Facebook IPs that CONNECT fine through any
    // node and must never "confirm" one).
    api.dnsAnswers["x.com"] = {"9.9.9.9"};
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.proxy.port = sick.port();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.nodeClasses.clear();
    c.nodeMonitor.realFailThreshold = 2;
    c.nodeMonitor.realFailRatioPct = 50;
    c.nodeMonitor.realFailWindowS = 60;
    c.nodeMonitor.minSwitchIntervalS = 300;
    c.nodeMonitor.badNodeCooldownS = 600;
    h.start(c);
    // Greeting-only health probe (same rationale as the auto-reselect
    // test): flows must NAT so their SOCKS-level failures drive the chain.
    h.engine->setHealthProbeDstForTest(net::Endpoint4{0, 0});
    h.engine->reloadConfig(c);
    h.engine->setDnsTtlMsForTest(60000);
    Sleep(300);

    // Seed the clean cache: query x.com through the engine's UDP:53 hook.
    const uint32_t kDns = 0x72727272;
    const uint32_t kTrusted = 0x09090909;  // 9.9.9.9
    h.device->pushDns(buildUdpPacket(kAppIp, 53100, kDns, 53,
                                     dnsQueryBytes("x.com")));
    for (int i = 0; i < 150 && h.device->sentDnsCount() < 1; ++i) Sleep(20);
    EXPECT_EQ(h.device->sentDnsCount(), 1u);

    EXPECT_TRUE(driveRelayFlow(h, 50301, kTrusted, kDstPort));
    EXPECT_TRUE(driveRelayFlow(h, 50302, kTrusted, kDstPort));

    // The chain: switch -> verify fail -> cooldown -> switch ... until the
    // whole list is in cooldown and the fallback settles. Deterministic
    // walk with latencies a=20/b=15/c=10: current a is cooled immediately,
    // then c (verify fail) -> b (fail) -> fallback c (no verify) = 3
    // switches. The proven-bad original a must never be selected again.
    bool chained = false;
    for (int i = 0; i < 600; ++i) {
        if (api.switches().size() >= 3) {
            chained = true;
            break;
        }
        Sleep(25);
    }
    EXPECT_TRUE(chained);
    if (chained) {
        Sleep(2500);  // any churn would add switches inside this window
        EXPECT_EQ(api.switches().size(), 3u);
        for (const auto& sw : api.switches()) {
            EXPECT_TRUE(sw.find("node-a") == std::string::npos);
        }
    }
    h.stop();
    sick.stop();
    api.stop();
}

APS_TEST(engine, poisoned_destination_failures_do_not_churn_nodes) {
    // The 2026-08-31 incident: the app (browser) held rewritten answers —
    // REAL Facebook/Twitter IPs — and every connection to them failed or
    // "succeeded" meaninglessly. Counting those failures against the NODE
    // re-selected a healthy kernel in a loop. Failures to destinations WE
    // never resolved must be ignored by the signal entirely.
    MockSocks5Server sick;
    sick.setBehavior(MockSocksBehavior::RefuseConnect);
    EXPECT_TRUE(sick.start());
    MockClashApi api;
    api.selectorNow = "node-a";
    api.latencies["node-a"] = 20;
    api.latencies["node-b"] = 15;
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.proxy.port = sick.port();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.nodeClasses.clear();
    c.nodeMonitor.realFailThreshold = 2;
    c.nodeMonitor.realFailRatioPct = 50;
    c.nodeMonitor.realFailWindowS = 60;
    c.nodeMonitor.minSwitchIntervalS = 0;
    // Install greeting-only health BEFORE Engine::start starts its threads.
    // Setting it after start races a real CONNECT to this deliberately
    // refusing mock: that DOWN transition legitimately queues a forced
    // switch, unrelated to the untrusted-IP failures this test is isolating.
    h.beforeStart = [](Engine& e) { e.setHealthProbeDstForTest({0, 0}); };
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    h.start(c);
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("\"proxy_reachable\":true") != std::string::npos &&
               s.find("\"latency_ms\":20") != std::string::npos;
    }, 5000));
    EXPECT_TRUE(api.switches().empty());

    // Flood failures to a destination we never resolved (the "poisoned"
    // IP shape: not in our clean cache, kernel port alive). Ports stay out
    // of both the relay range (24000+) and the OS ephemeral range (49152+)
    // — relay sessions' outbound source ports would collide in TIME_WAIT.
    for (int i = 0; i < 6; ++i) {
        EXPECT_TRUE(driveRelayFlow(h, 31000 + i, 0x8C10F27E /* 140.16.242.126 */));
    }
    // No switch may result — the node is not to blame.
    Sleep(3000);
    EXPECT_TRUE(api.switches().empty());
    h.stop();
    sick.stop();
    api.stop();
}

APS_TEST(engine, direct_pseudo_node_is_never_selected) {
    // DIRECT appears as a selector member with the lowest latency — but it
    // is a routing target, not a node: selecting it "breaks" the tunnel
    // for proxied traffic and the next region round immediately drops it,
    // ping-ponging GLOBAL (measured 2026-08-31 16:45:16). The sweep must
    // skip the built-in pseudo-proxies.
    MockClashApi api;
    api.selectorNow = "node-a";
    api.nodes = {"node-a", "node-b", "DIRECT"};
    api.latencies["node-a"] = 20;
    api.latencies["node-b"] = 15;
    api.latencies["DIRECT"] = 5;   // would win every latency-based sweep
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.proxy.port = socks().port();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = api.port();
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.nodeMonitor.nodeClasses.clear();
    c.nodeMonitor.regions.clear();
    h.start(c);

    // Force a re-select away from the current node: mark it dead.
    api.latencies["node-a"] = -1;  // absent = dead
    api.latencies.erase("node-a");
    h.engine->requestNodeSwitchRound("__default__");
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("\"node\":\"node-b\"") != std::string::npos;
    }, 8000));
    for (const auto& s : api.switches()) {
        EXPECT_TRUE(s.find("DIRECT") == std::string::npos);
    }
    h.stop();
    api.stop();
}

APS_TEST(engine, node_status_prefilled_at_start) {
    // A slow-to-answer controller: the engine must push "检测中…" rows at
    // start (before the first probe completes), not leave the GUI with
    // nothing to show.
    SOCKET silent = net::makeTcpSocket();
    EXPECT_TRUE(silent != INVALID_SOCKET);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.S_un.S_addr = htonl(0x7F000001);
    sa.sin_port = 0;
    bool bound = bind(silent, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0 &&
                 listen(silent, 4) == 0;
    EXPECT_TRUE(bound);
    if (!bound) {
        net::closeSocket(silent);
        return;
    }
    socklen_t sl = sizeof(sa);
    getsockname(silent, reinterpret_cast<sockaddr*>(&sa), &sl);
    uint16_t silentPort = ntohs(sa.sin_port);

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = silentPort;   // accepts, never answers HTTP
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.proxy.healthIntervalS = 30;
    h.start(c);

    // The immediate round is still probing (3 s timeout); the pre-seeded
    // status must already be visible.
    std::string st = h.engine->statusJson();
    EXPECT_TRUE(st.find("检测中") != std::string::npos);

    h.stop();
    net::closeSocket(silent);
}

APS_TEST(engine, discovery_adopts_kernels_and_marks_them_offline) {
    // A mock SOCKS5 + mock controller pair in THIS process: a Full adoption
    // must find them, make the kernel routable, and later mark it offline
    // when the mocks stop (row kept with "内核未启动"). NOTE: the harness's
    // static socks() mock also lives in this process, so the discovered
    // SOCKS port may be either mock. The default egress is pointed at a LIVE
    // but silent listener: auto-follow only kicks in for DEAD configured
    // ports, so the kernel stays uncovered and keeps its own row.
    MockSocks5Server socks2;
    EXPECT_TRUE(socks2.start());
    MockClashApi api;
    EXPECT_TRUE(api.start());

    SOCKET silent = net::makeTcpSocket();
    EXPECT_TRUE(silent != INVALID_SOCKET);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.S_un.S_addr = htonl(0x7F000001);
    sa.sin_port = 0;
    EXPECT_TRUE(bind(silent, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0 &&
                listen(silent, 4) == 0);
    socklen_t sl = sizeof(sa);
    getsockname(silent, reinterpret_cast<sockaddr*>(&sa), &sl);
    const uint16_t silentPort = ntohs(sa.sin_port);

    Harness h;
    Config c = h.makeConfig();
    c.proxy.port = silentPort;  // live non-kernel listener: no auto-follow
    h.start(c);
    h.engine->setKernelDiscoveryEnabled(true);
    h.engine->adoptDiscoveries(DiscoveryMode::Full);

    const std::string autoId = "auto-test_engine_harness.exe";
    EXPECT_TRUE(h.waitStatus([&](const std::string& s) {
        return s.find(autoId) != std::string::npos;
    }, 3000));
    // (Disabled by default — opt-in via activation.)
    EXPECT_FALSE(h.engine->outletEnabled(autoId));
    // After activation the kernel is routable via whichever of the two
    // in-process SOCKS mocks the scanner paired.
    c.routing.autoOutletId = autoId;
    h.engine->reloadConfig(c);
    EXPECT_TRUE(h.engine->outletEnabled(autoId));
    auto rp = h.engine->outletParams(autoId);
    EXPECT_TRUE(rp.proxy.port == socks2.port() || rp.proxy.port == socks().port());

    // Kill every in-process listener -> the kernel must go offline, row kept.
    api.stop();
    socks2.stop();
    socks().stop();
    h.engine->adoptDiscoveries(DiscoveryMode::Full);
    EXPECT_TRUE(h.waitStatus([&](const std::string& s) {
        return s.find(autoId) != std::string::npos &&
               s.find("内核未启动") != std::string::npos;
    }, 3000));

    // Restore the shared mock for the tests that follow.
    EXPECT_TRUE(socks().start());
    net::closeSocket(silent);
    h.stop();
    saveKernelCache({});  // keep the dev machine's cache clean
}

APS_TEST(engine, same_name_kernel_instances_keep_separate_rows) {
    // The 2026-08-27 incident, in test form: SakuraCat runs TWO
    // com.vortex.helper.exe backends (main: socks 7897 / controller 39798;
    // second: socks 7899 / controller 39797). The pre-refactor registry
    // keyed entries by image name alone — the second instance overwrote the
    // first one's ports and the default-egress pairing broke for good.
    // Same-named instances must be DIFFERENT kernels: separate ids, separate
    // rows, and no port overwrite.
    // A LIVE configured default port (silent listener) prevents the
    // auto-follow from covering a kernel: rows stay visible in every stage.
    SOCKET silent = net::makeTcpSocket();
    EXPECT_TRUE(silent != INVALID_SOCKET);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.S_un.S_addr = htonl(0x7F000001);
    sa.sin_port = 0;
    bool bound = bind(silent, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0 &&
                 listen(silent, 4) == 0;
    EXPECT_TRUE(bound);
    if (!bound) {
        net::closeSocket(silent);
        return;
    }
    socklen_t sl = sizeof(sa);
    getsockname(silent, reinterpret_cast<sockaddr*>(&sa), &sl);
    const uint16_t silentPort = ntohs(sa.sin_port);

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.port = silentPort;  // live non-kernel listener: no auto-follow
    c.proxy.clashApi.host.clear();  // keep the default outlet silent
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    h.start(c, /*discoveryEnabled=*/true);

    auto makeVortex = [](uint32_t pid, uint16_t socks, uint16_t api,
                         const std::string& cmdline) {
        DiscoveredKernel k;
        k.pid = pid;
        k.procName = "com.vortex.helper.exe";
        k.socksPort = socks;
        k.apiPort = api;
        k.configDir = "C:\\users\\x\\.config\\com.vortex.helper";
        k.cmdline = cmdline;
        return k;
    };
    DiscoveredKernel main =
        makeVortex(101, 7897, 39798,
                   "com.vortex.helper.exe -d C:\\cfg -f C:\\cfg\\config.yaml "
                   "-ext-ctl 127.0.0.1:39798");
    DiscoveredKernel second =
        makeVortex(102, 7899, 39797,
                   "com.vortex.helper.exe -d C:\\cfg -ext-ctl 127.0.0.1:39797");

    // Stage 1: only the main instance exists -> base id.
    *scripted = {main};
    h.engine->adoptDiscoveries();
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        size_t p = s.find("auto-com.vortex.helper.exe");
        return p != std::string::npos &&
               s.find("\"socks_port\":7897", p) != std::string::npos;
    }, 3000));
    std::string s1 = h.lastStatus();
    EXPECT_TRUE(s1.find("auto-com.vortex.helper.exe#2") == std::string::npos);

    // Stage 2: the second instance appears -> its OWN row, base row
    // untouched (7897/39798, NOT overwritten by 7899/39797).
    *scripted = {main, second};
    h.engine->adoptDiscoveries();
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        size_t b = s.find("auto-com.vortex.helper.exe");
        size_t h2 = s.find("auto-com.vortex.helper.exe#2");
        if (h2 == std::string::npos) return false;
        return s.find("\"socks_port\":7897", b) != std::string::npos &&
               s.find("\"socks_port\":7899", h2) != std::string::npos &&
               s.find("\"api_port\":39798", b) != std::string::npos &&
               s.find("\"api_port\":39797", h2) != std::string::npos;
    }, 3000));
    // Both routable via their own SOCKS ports (activation is a single
    // choice; non-activated kernel outlets fall back to the default egress
    // by design — activate the base id to observe its real endpoint).
    EXPECT_FALSE(h.engine->outletEnabled("auto-com.vortex.helper.exe"));
    c.routing.autoOutletId = "auto-com.vortex.helper.exe";
    h.engine->reloadConfig(c);
    EXPECT_TRUE(h.engine->outletEnabled("auto-com.vortex.helper.exe"));
    EXPECT_EQ(h.engine->outletParams("auto-com.vortex.helper.exe").proxy.port,
              static_cast<uint16_t>(7897));
    EXPECT_FALSE(h.engine->outletEnabled("auto-com.vortex.helper.exe#2"));
    EXPECT_EQ(h.engine->outletParams("auto-com.vortex.helper.exe#2").proxy.port,
              static_cast<uint16_t>(silentPort));  // disabled -> default fallback

    // Stage 3: the main instance dies -> its row has no advertised endpoint;
    // the second instance stays alive with its own current port.
    *scripted = {second};
    h.engine->adoptDiscoveries();
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        size_t b = s.find("auto-com.vortex.helper.exe");
        return b != std::string::npos &&
               s.find("\"alive\":false", b) != std::string::npos &&
               s.find("\"socks_port\":0", b) != std::string::npos &&
               s.find("\"seen\":true", b) != std::string::npos &&
               s.find("内核未启动") != std::string::npos;
    }, 3000));

    h.stop();
    saveKernelCache({});  // keep the dev machine's cache clean
}

APS_TEST(engine, offline_duplicates_do_not_shadow_live_controller_on_same_port) {
    MockSocks5Server localSocks;
    MockClashApi api;
    EXPECT_TRUE(localSocks.start());
    api.latencies["node-a"] = 25;
    EXPECT_TRUE(api.start());
    auto old = makeKernel("verge-mihomo.exe", localSocks.port(), 0);
    old.pid = 101;
    old.configDir = "C:\\OldSidecar";
    old.cmdline = "old-sidecar";
    auto old2 = old;
    old2.id += "#2"; old2.pid = 102;
    old2.configDir = "C:\\OldService"; old2.cmdline = "old-service";
    auto live = makeKernel("verge-mihomo.exe", localSocks.port(), api.port());
    live.pid = 103; live.configDir = "C:\\CurrentService"; live.cmdline = "current-service";
    Harness h;
    h.cacheLoader = [old, old2] { return std::vector<DiscoveredKernel>{old, old2}; };
    h.discoveryScan = [live](DiscoveryMode) { return std::vector<DiscoveredKernel>{live}; };
    auto c = h.makeConfig();
    c.rules.clear();
    c.proxy.port = 1;
    c.routing.autoOutletId = "auto-verge-mihomo.exe#3";
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 600;
    c.nodeMonitor.regions.clear(); c.nodeMonitor.nodeClasses.clear();
    h.start(c, true);
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        aps::json::Value v;
        if (!aps::json::Value::parse(s, v, nullptr)) return false;
        const auto* p = v.find("effective_proxy");
        return p && p->find("id") && p->find("id")->asString() == "auto-verge-mihomo.exe#3";
    }, 5000));
    aps::json::Value status;
    EXPECT_TRUE(aps::json::Value::parse(h.engine->statusJson(), status, nullptr));
    EXPECT_EQ(status.find("kernels")->size(), 3u);
    const auto* actual = status.find("effective_proxy");
    EXPECT_TRUE(actual != nullptr);
    if (actual) {
        EXPECT_STREQ(actual->find("id")->asString(), c.routing.autoOutletId);
        EXPECT_EQ(actual->find("port")->asInt(), static_cast<int64_t>(localSocks.port()));
        EXPECT_FALSE(actual->find("fallback")->asBool());
    }
    h.engine->requestNodeSwitchRound("__default__");
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        aps::json::Value v;
        if (!aps::json::Value::parse(s, v, nullptr)) return false;
        const auto* outlets = v.find("outlets");
        if (!outlets) return false;
        for (size_t i = 0; i < outlets->size(); ++i) {
            const auto& outlet = outlets->at(i);
            if (outlet.find("id")->asString() == "__default__")
                return outlet.find("api")->asBool() && !outlet.find("switching")->asBool();
        }
        return false;
    }, 5000));
    EXPECT_GT(api.versionHits(), 0u);
    // A new default port must not inherit the previous port's node/error
    // while the next controller round has not run yet.
    c.proxy.port = socks().port();
    c.nodeMonitor.enabled = false;
    h.engine->reloadConfig(c);
    EXPECT_TRUE(aps::json::Value::parse(h.engine->statusJson(), status, nullptr));
    bool cleared = false;
    for (const auto& outlet : status.find("outlets")->array()) {
        if (outlet.find("id")->asString() != "__default__") continue;
        const auto message = outlet.find("api_msg")->asString();
        cleared = !outlet.find("api")->asBool() && outlet.find("node")->asString().empty() &&
                  (message == "实际出口已变化，等待节点检测" ||
                   message.find(std::to_string(c.proxy.port)) != std::string::npos);
        if (!cleared) std::printf("    updated default row: %s\n", outlet.dump().c_str());
    }
    EXPECT_TRUE(cleared);
    h.stop();
    saveKernelCache({});
}

APS_TEST(engine, effective_proxy_reports_disabled_selection_fallback_without_secrets) {
    Harness h;
    auto c = h.makeConfig();
    Outlet outlet;
    outlet.id = "manual-disabled"; outlet.name = "Disabled outlet";
    outlet.host = "127.0.0.1"; outlet.port = 2; outlet.enabled = false;
    outlet.username = "private-username";
    c.outlets.push_back(outlet);
    c.routing.autoOutletId = outlet.id;
    h.start(c);
    aps::json::Value status;
    EXPECT_TRUE(aps::json::Value::parse(h.engine->statusJson(), status, nullptr));
    const auto* actual = status.find("effective_proxy");
    EXPECT_TRUE(actual != nullptr);
    if (actual) {
        EXPECT_STREQ(actual->find("id")->asString(), "__default__");
        EXPECT_EQ(actual->find("port")->asInt(), static_cast<int64_t>(c.proxy.port));
        EXPECT_TRUE(actual->find("fallback")->asBool());
        EXPECT_TRUE(actual->dump().find("private-username") == std::string::npos);
    }
    h.stop();
}

APS_TEST(engine, inactive_kernel_status_is_bound_to_its_own_proxy_port) {
    MockSocks5Server otherSocks;
    MockClashApi api;
    EXPECT_TRUE(otherSocks.start());
    api.latencies["node-a"] = 25;
    EXPECT_TRUE(api.start());
    auto kernel = makeKernel("inactive-core.exe", otherSocks.port(), api.port());
    Harness h;
    h.cacheLoader = [] { return std::vector<DiscoveredKernel>{}; };
    h.discoveryScan = [kernel](DiscoveryMode) { return std::vector<DiscoveredKernel>{kernel}; };
    auto c = h.makeConfig();
    c.nodeMonitor.enabled = true; c.nodeMonitor.intervalS = 600;
    c.proxy.clashApi.host.clear();
    c.nodeMonitor.regions.clear(); c.nodeMonitor.nodeClasses.clear();
    // A published discovery row can precede the rebuilt egress table. Finish
    // adoption synchronously before checking this outlet's enabled state.
    h.start(c);
    h.engine->adoptDiscoveries();
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("auto-inactive-core.exe") != std::string::npos;
    }, 5000));
    EXPECT_FALSE(h.engine->outletEnabled(kernel.id));
    h.engine->requestNodeSwitchRound(kernel.id);
    EXPECT_TRUE(h.waitStatus([&](const std::string& s) {
        aps::json::Value v;
        if (!aps::json::Value::parse(s, v, nullptr)) return false;
        const auto* outlets = v.find("outlets");
        if (!outlets) return false;
        for (const auto& outlet : outlets->array()) {
            if (outlet.find("id")->asString() == kernel.id)
                return outlet.find("api")->asBool();
        }
        return false;
    }, 5000));
    h.stop();
    saveKernelCache({});
}

APS_TEST(engine, health_probe_uses_configured_socks_credentials) {
    MockSocks5Server localSocks;
    localSocks.setRequireAuth(true, "test-user", "test-password");
    EXPECT_TRUE(localSocks.start());
    Harness h;
    auto c = h.makeConfig();
    c.proxy.port = localSocks.port();
    c.proxy.username = "test-user";
    c.setPlainPassword("test-password");
    h.start(c);
    for (int i = 0; i < 200 && localSocks.requestCount() == 0; ++i) Sleep(10);
    EXPECT_GT(localSocks.requestCount(), 0u);
    EXPECT_TRUE(h.engine->outletHealthy("__default__"));
    h.stop();
}

APS_TEST(engine, second_same_name_instance_does_not_break_default_pairing) {
    // The exact 2026-08-27 failure, end to end: the default egress pairs
    // with the main instance's controller (socks 7897 -> mock API port).
    // When the second same-named instance appears, the pairing must KEEP
    // working (the pre-refactor build lost the 7897 entry entirely and the
    // default outlet errored "no kernel pairs with socks port 7897" forever).
    MockClashApi api;
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.port = 7897;              // == main instance's SOCKS port (dead)
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = 0;        // auto-track via kernel pairing
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.proxy.healthIntervalS = 30;
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    h.start(c, /*discoveryEnabled=*/true);

    // Distinct command lines — exactly like the real machine: the main
    // instance loads config.yaml (-f, -ext-ctl on the pinned controller
    // port), the second instance does not. Identical cmdlines are treated
    // as the SAME restarted kernel (rule 4), which is the designed
    // behavior.
    auto makeVortex = [](uint32_t pid, uint16_t socks, uint16_t api,
                         const std::string& cmdline) {
        DiscoveredKernel k;
        k.pid = pid;
        k.procName = "com.vortex.helper.exe";
        k.socksPort = socks;
        k.apiPort = api;
        k.configDir = "C:\\users\\x\\.config\\com.vortex.helper";
        k.cmdline = cmdline;
        return k;
    };
    *scripted = {makeVortex(101, 7897, api.port(),
                            "com.vortex.helper.exe -d C:\\cfg -f "
                            "C:\\cfg\\config.yaml -ext-ctl 127.0.0.1:" +
                                std::to_string(api.port())),
                 makeVortex(102, 7899, 39797,
                            "com.vortex.helper.exe -d C:\\cfg -ext-ctl "
                            "127.0.0.1:39797")};
    h.engine->adoptDiscoveries();

    // Default outlet round: pairing must reach the main instance's mock
    // controller and report a healthy API.
    h.engine->requestNodeSwitchRound("__default__");
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("\"api\":true") != std::string::npos;
    }, 5000));
    // And the second instance has its own alive row.
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        size_t p = s.find("auto-com.vortex.helper.exe#2");
        return p != std::string::npos &&
               s.find("\"alive\":true", p) != std::string::npos;
    }, 3000));

    h.stop();
    api.stop();
    saveKernelCache({});
}

APS_TEST(engine, v1_cache_entry_matches_live_kernel_by_ports) {
    // 2026-08-27 duplicate-row bug: a v1 kernel_cache.json entry has NO
    // configDir/cmdline. The live kernel's scan fills them in. The old
    // matcher demanded dir equality, failed to match the live instance, and
    // split one kernel into TWO registry entries — a dead cached copy (base
    // id, "内核未启动", clicking it popped the blocking dialog) plus the
    // live instance under "#2". Name+port equality must carry the identity
    // when the existing entry's dir is unknown (two same-named kernels
    // cannot share a SOCKS or API port anyway).
    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.port = 1;  // dead, no auto-follow interference for the rows
    c.proxy.clashApi.host.clear();
    h.cacheLoader = [] {
        std::vector<DiscoveredKernel> v;
        DiscoveredKernel k;  // v1 shape: no configDir, no cmdline, no pid
        k.procName = "com.vortex.helper.exe";
        k.socksPort = 7897;
        k.apiPort = 39798;
        v.push_back(std::move(k));
        return v;
    };
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };
    h.start(c, /*discoveryEnabled=*/true);
    DiscoveredKernel live;
    live.pid = 101;
    live.procName = "com.vortex.helper.exe";
    live.socksPort = 7897;
    live.apiPort = 39798;
    live.configDir = "C:\\users\\ming\\.config\\com.vortex.helper";
    live.cmdline = "com.vortex.helper.exe -d C:\\cfg -f C:\\cfg\\config.yaml";
    *scripted = {live};
    h.engine->adoptDiscoveries();
    // ONE entry, alive, under the base id, with the identity fields filled.
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        size_t b = s.find("auto-com.vortex.helper.exe");
        if (b == std::string::npos) return false;
        return s.find("\"alive\":true", b) != std::string::npos &&
               s.find("auto-com.vortex.helper.exe#2") == std::string::npos;
    }, 3000));
    std::string s = h.lastStatus();
    EXPECT_TRUE(s.find("auto-com.vortex.helper.exe#2") == std::string::npos);
    // The base id appears exactly twice: once in "kernels" and once in
    // "outlets" (its node row). A dead cached copy would add a third.
    size_t cnt = 0;
    for (size_t p = s.find("auto-com.vortex.helper.exe"); p != std::string::npos;
         p = s.find("auto-com.vortex.helper.exe", p + 1)) {
        ++cnt;
    }
    EXPECT_EQ(cnt, static_cast<size_t>(2));
    h.stop();
    saveKernelCache({});
}

APS_TEST(engine, activating_default_keeps_auto_followed_port) {
    // 2026-08-27 snap-back bug: with two live kernels and no activation, the
    // default egress auto-followed CFW (55128). Clicking the DEFAULT row
    // (activates it, clears autoOutletId) made resolveDefaultSocksPort fall
    // back to the dead configured port (7891) — the row flipped
    // 55128（自动）-> 7891 and the proxy died. The resolver must be STICKY:
    // keep the port it already uses while a live kernel still serves it.
    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.port = 1;  // dead configured port
    c.proxy.clashApi.host.clear();
    c.routing.autoOutletId = "auto-clash-win64.exe";
    auto scripted = std::make_shared<std::vector<DiscoveredKernel>>();
    h.discoveryScan = [scripted](DiscoveryMode) { return *scripted; };

    auto makeK = [](uint32_t pid, const std::string& name, uint16_t socks,
                    uint16_t api, const std::string& cmdline) {
        DiscoveredKernel k;
        k.pid = pid;
        k.procName = name;
        k.socksPort = socks;
        k.apiPort = api;
        k.configDir = "C:\\users\\x\\" + name;
        k.cmdline = cmdline;
        return k;
    };
    *scripted = {makeK(101, "com.vortex.helper.exe", 7897, 39798,
                       "vortex -d C:\\cfg -f C:\\cfg\\config.yaml"),
                 makeK(102, "clash-win64.exe", 55128, 55127,
                       "clash-win64.exe -d C:\\cfg2")};
    // Populate before starting the scan thread. Mutating its shared vector
    // and calling adoption concurrently used to race the initial empty scan:
    // the assertion failed, then even its diagnostic re-read showed 55128.
    h.start(c, /*discoveryEnabled=*/true);
    for (int i = 0; i < 120 &&
         h.engine->outletParams("__default__").proxy.port != 55128; ++i) Sleep(25);
    // Auto-follows the activated CFW kernel.
    EXPECT_EQ(h.engine->outletParams("__default__").proxy.port,
              static_cast<uint16_t>(55128));
    // User clicks the default row: activation clears autoOutletId.
    c.routing.autoOutletId.clear();
    h.engine->reloadConfig(c);
    // STICKY: the port stays 55128 (live kernel still serves it) — it must
    // NOT snap back to the dead configured port 1.
    EXPECT_EQ(h.engine->outletParams("__default__").proxy.port,
              static_cast<uint16_t>(55128));
    // And both kernels keep their own rows (no coverage popping).
    std::string s = h.engine->statusJson();
    EXPECT_TRUE(s.find("auto-clash-win64.exe") != std::string::npos);
    EXPECT_TRUE(s.find("auto-com.vortex.helper.exe") != std::string::npos);
    h.stop();
    saveKernelCache({});
}

APS_TEST(engine, cached_kernels_seed_offline_rows_at_start) {
    // Remembered kernels (kernel_cache.json) become rows at engine start
    // even when the kernel is not running: the user's kernels are fixed
    // machines and their rows must not silently disappear across engine
    // restarts. UNTIL the first scan completes they are UNVERIFIED: the row
    // says 检测中… and the GUI must not block clicks (a cached row flashing
    // 内核未启动 for the first second after every engine start produced
    // blocking "not started" dialogs on kernels that were actually running
    // — the 2026-08-27 incident). After the first completed scan the row is
    // CONFIRMED offline: 内核未启动, seen=true.
    Harness h;
    Config c = h.makeConfig();
    c.proxy.port = 1;  // dead: keeps the fake kernel uncovered (own row)
    c.rules.clear();
    h.cacheLoader = [] {
        std::vector<DiscoveredKernel> v;
        DiscoveredKernel k;
        k.procName = "fake-kernel.exe";
        k.socksPort = 59999;
        k.apiPort = 59998;
        v.push_back(std::move(k));
        return v;
    };
    // Deterministic: adoption must not probe the real machine (real kernels
    // run on this dev box). A gate holds the pump's initial scan until the
    // unverified window has been observed — the engine start's own push
    // then deterministically shows the pre-scan state.
    std::atomic<bool> gate{false};
    h.discoveryScan = [&gate](DiscoveryMode) {
        while (!gate.load()) Sleep(10);
        return std::vector<DiscoveredKernel>{};
    };
    h.start(c, /*discoveryEnabled=*/true);
    // The row appears from the very first STATUS push, unverified.
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("auto-fake-kernel.exe") != std::string::npos;
    }, 2000));
    std::string s = h.lastStatus();
    size_t idPos = s.find("auto-fake-kernel.exe");
    EXPECT_TRUE(idPos != std::string::npos);
    EXPECT_TRUE(s.find("\"alive\":false", idPos) != std::string::npos);
    EXPECT_TRUE(s.find("\"socks_port\":0", idPos) != std::string::npos);
    EXPECT_TRUE(s.find("\"api_port\":0", idPos) != std::string::npos);
    // Unverified: the GUI must NOT show a blocking dialog on this row yet.
    EXPECT_TRUE(s.find("\"seen\":false", idPos) != std::string::npos);
    // And the row says "detecting", not "not started".
    EXPECT_TRUE(s.find("检测中…") != std::string::npos);
    EXPECT_TRUE(s.find("内核未启动") == std::string::npos);
    EXPECT_EQ(h.engine->outletParams("auto-fake-kernel.exe").proxy.port,
              static_cast<uint16_t>(c.proxy.port));  // default fallback
    // Release the scan: one completed scan (found nothing) CONFIRMS it
    // dead: 内核未启动 + seen=true.
    gate.store(true);
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        size_t p = s.find("auto-fake-kernel.exe");
        return p != std::string::npos &&
               s.find("\"seen\":true", p) != std::string::npos &&
               s.find("内核未启动") != std::string::npos;
    }, 3000));
    h.stop();
}

APS_TEST(engine, offline_kernel_api_error_names_the_kernel) {
    // Default outlet's controller is on the remembered kernel's API port,
    // but the kernel is NOT running: the node row must name the kernel and
    // say it is not started (the user's "怎么只剩默认了" question answered
    // at the row itself), instead of a generic pairing-failure message.
    Harness h;
    Config c = h.makeConfig();
    c.rules.clear();
    c.proxy.port = 59999;              // == fake kernel's remembered SOCKS port
    c.proxy.clashApi.host = "127.0.0.1";
    c.proxy.clashApi.port = 0;         // auto-track via kernel pairing
    c.nodeMonitor.enabled = true;
    c.nodeMonitor.intervalS = 10;
    c.proxy.healthIntervalS = 30;
    h.cacheLoader = [] {
        std::vector<DiscoveredKernel> v;
        DiscoveredKernel k;
        k.procName = "fake-kernel.exe";
        k.socksPort = 59999;
        k.apiPort = 59998;
        v.push_back(std::move(k));
        return v;
    };
    // Deterministic scan (the click-driven re-scan before the round must
    // not adopt the real machine's kernels and rebuild outlets).
    h.discoveryScan = [](DiscoveryMode) { return std::vector<DiscoveredKernel>{}; };
    h.start(c, /*discoveryEnabled=*/true);
    h.engine->requestNodeSwitchRound("__default__");
    // The FULL message is only produced by the pairing path (the seeded row
    // alone says just "内核未启动").
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        return s.find("启动代理软件后自动恢复") != std::string::npos &&
               s.find("fake-kernel.exe") != std::string::npos;
    }, 3000));
    h.stop();
}

APS_TEST(engine, auto_outlet_id_redirects_default_bound_rules) {
    // routing.autoOutletId redirects rules WITHOUT an explicit outlet
    // binding (outlet=""); explicitly bound rules are untouched, and manual
    // outlets keep their own enabled flags.
    MockSocks5Server socks2;
    EXPECT_TRUE(socks2.start());
    MockClashApi api;
    EXPECT_TRUE(api.start());

    Harness h;
    Config c = h.makeConfig();
    c.proxy.port = 1;  // dead default: proves '' actually resolves elsewhere
    Outlet o2;
    o2.id = "o2";
    o2.name = "second";
    o2.host = "127.0.0.1";
    o2.port = socks2.port();
    o2.enabled = true;
    c.outlets.push_back(o2);
    h.start(c);
    h.engine->setKernelDiscoveryEnabled(true);
    h.engine->adoptDiscoveries(DiscoveryMode::Full);
    const std::string autoId = "auto-test_engine_harness.exe";
    uint16_t kernelPort = h.engine->outletParams(autoId).proxy.port;

    // Activate the discovered kernel via config + reload.
    c.routing.autoOutletId = autoId;
    h.engine->reloadConfig(c);
    EXPECT_TRUE(h.engine->outletEnabled(autoId));
    EXPECT_TRUE(h.engine->outletEnabled("o2"));  // enabled flags untouched

    // A rule without an explicit binding now follows the activated kernel:
    // its SYN must create a NAT entry bound to the auto id.
    h.device->clearSent();
    h.pushConnectEvent(53100, /*pid=*/100);
    h.device->pushTcp(buildTcpPacket(kAppIp, 53100, kDstIp, kDstPort, 200, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto entry = h.engine->nat().findByRev(kAppIp, 53100);
    EXPECT_TRUE(entry != nullptr);
    if (entry) {
        EXPECT_STREQ(entry->outletId, autoId);
    }

    // Explicit binding stays exactly where the rule says.
    h.device->clearSent();
    h.pushConnectEvent(53101, /*pid=*/100);
    h.device->pushTcp(buildTcpPacket(kAppIp, 53101, kDstIp, kDstPort, 201, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 3000));
    auto e2 = h.engine->nat().findByRev(kAppIp, 53101);
    // (rule r1 has outlet='' -> goes to the auto id; there is no explicitly
    //  bound rule in this config, so both entries use the auto id)
    EXPECT_TRUE(e2 != nullptr);
    if (e2) {
        EXPECT_STREQ(e2->outletId, autoId);
    }
    (void)kernelPort;

    h.stop();
    api.stop();
    socks2.stop();
    saveKernelCache({});
}

namespace {
json::Value outletStatusFor(const std::string& text, const std::string& id) {
    json::Value status;
    if (!json::Value::parse(text, status, nullptr)) return json::Value::makeObject();
    const auto* outlets = status.find("outlets");
    if (!outlets || !outlets->isArray()) return json::Value::makeObject();
    for (size_t i=0;i<outlets->size();++i) {
        const auto* value = outlets->at(i).find("id");
        if (value && value->asString()==id) return outlets->at(i);
    }
    return json::Value::makeObject();
}
}

APS_TEST(engine, adaptive_manual_test_optimizes_healthy_node_with_auto_disabled) {
    MockClashApi api;
    api.selectorNow="日本-IEPL current";
    api.nodes={api.selectorNow,"日本-IEPL best","香港-IEPL faster","日本-中转 fastest"};
    api.latencies={{api.selectorNow,300},{"日本-IEPL best",80},{"香港-IEPL faster",10},{"日本-中转 fastest",5}};
    EXPECT_TRUE(api.start());
    Harness h;auto c=h.makeConfig();c.rules.clear();
    c.proxy.clashApi.host="127.0.0.1";c.proxy.clashApi.port=api.port();
    c.nodeMonitor.enabled=false;c.nodeMonitor.regions={"JP"};c.nodeMonitor.nodeClasses={"IEPL"};
    h.start(c);h.engine->requestNodeSwitchRound("__default__",true,"filtered-test-request");
    EXPECT_TRUE(h.waitStatus([](const std::string& s){
        const auto row=outletStatusFor(s,"__default__");const auto* node=row.find("node");
        return node && node->asString()=="日本-IEPL best";
    },5000));
    const auto switches=api.switches();EXPECT_EQ(switches.size(),1u);
    if(!switches.empty())EXPECT_STREQ(switches[0],"auto::日本-IEPL best");
    const auto row=outletStatusFor(h.lastStatus(),"__default__");
    EXPECT_TRUE(row.find("selection_ok") && row.find("selection_ok")->asBool());
    EXPECT_TRUE(row.find("test_request_id") && row.find("test_request_id")->asString()=="filtered-test-request");
    EXPECT_TRUE(row.find("region") && row.find("region")->asString()=="JP");
    EXPECT_TRUE(row.find("node_classes") && row.find("node_classes")->size()==1);
    h.stop();
}

APS_TEST(engine, adaptive_manual_test_keeps_best_current_without_put) {
    MockClashApi api;api.selectorNow="日本-IEPL best";
    api.nodes={api.selectorNow,"日本-IEPL slower"};
    api.latencies={{api.selectorNow,40},{"日本-IEPL slower",100}};EXPECT_TRUE(api.start());
    Harness h;auto c=h.makeConfig();c.rules.clear();c.proxy.clashApi.port=api.port();
    c.nodeMonitor.enabled=false;c.nodeMonitor.regions={"JP"};c.nodeMonitor.nodeClasses={"IEPL"};
    h.start(c);h.engine->requestNodeSwitchRound("__default__");
    EXPECT_TRUE(h.waitStatus([](const std::string& s){return s.find("当前节点已是符合筛选条件的最优线路")!=std::string::npos;},5000));
    EXPECT_TRUE(api.switches().empty());
    h.stop();
}

APS_TEST(engine, adaptive_manual_test_has_no_matching_candidate_keeps_selection) {
    MockClashApi api;api.selectorNow="日本-IEPL current";
    api.nodes={api.selectorNow,"香港-IEPL faster"};
    api.latencies={{api.selectorNow,100},{"香港-IEPL faster",10}};EXPECT_TRUE(api.start());
    Harness h;auto c=h.makeConfig();c.rules.clear();c.proxy.clashApi.port=api.port();
    c.nodeMonitor.enabled=false;c.nodeMonitor.regions={"SG"};c.nodeMonitor.nodeClasses={"IEPL"};
    h.start(c);h.engine->requestNodeSwitchRound("__default__",true,"no-matching-request");
    EXPECT_TRUE(h.waitStatus([](const std::string& s){
        const auto row=outletStatusFor(s,"__default__");
        return s.find("没有符合地区/类型筛选的可用节点")!=std::string::npos &&
               row.find("test_request_id") && row.find("test_request_id")->asString()=="no-matching-request" &&
               row.find("switching") && !row.find("switching")->asBool();
    },5000));
    const auto row=outletStatusFor(h.lastStatus(),"__default__");
    EXPECT_TRUE(row.find("alive") && row.find("alive")->asBool());
    EXPECT_TRUE(row.find("selection_ok") && !row.find("selection_ok")->asBool());
    EXPECT_TRUE(row.find("switching") && !row.find("switching")->asBool());
    EXPECT_TRUE(api.switches().empty());h.stop();
}

APS_TEST(engine, adaptive_disabled_monitor_ignores_automatic_requests_but_accepts_manual_test) {
    MockClashApi api;api.selectorNow="日本-IEPL slow";
    api.nodes={api.selectorNow,"日本-IEPL best"};
    api.latencies={{api.selectorNow,1500},{"日本-IEPL best",20}};EXPECT_TRUE(api.start());
    Harness h;auto c=h.makeConfig();c.rules.clear();c.proxy.clashApi.port=api.port();
    c.nodeMonitor.enabled=false;c.nodeMonitor.intervalS=1;c.nodeMonitor.regions={"JP"};
    h.start(c);h.engine->requestNodeSwitchRound("__default__",false);
    Sleep(1500); // cover startup, explicitly queued recovery and a periodic tick
    EXPECT_TRUE(api.switches().empty());
    h.engine->requestNodeSwitchRound("__default__",true,"explicit-while-disabled");
    EXPECT_TRUE(h.waitStatus([](const std::string& s){
        const auto row=outletStatusFor(s,"__default__");
        return row.find("node") && row.find("node")->asString()=="日本-IEPL best" &&
               row.find("test_request_id") && row.find("test_request_id")->asString()=="explicit-while-disabled" &&
               row.find("switching") && !row.find("switching")->asBool();
    },5000));
    EXPECT_EQ(api.switches().size(),1u);h.stop();
}

APS_TEST(engine, adaptive_automatic_round_does_not_reuse_manual_result_identity) {
    MockClashApi api;api.selectorNow="日本-IEPL best";
    api.nodes={api.selectorNow,"日本-IEPL slower"};
    api.latencies={{api.selectorNow,40},{"日本-IEPL slower",100}};EXPECT_TRUE(api.start());
    Harness h;auto c=h.makeConfig();c.rules.clear();c.proxy.clashApi.port=api.port();
    c.nodeMonitor.enabled=true;c.nodeMonitor.intervalS=60;c.nodeMonitor.regions={"JP"};
    h.start(c);h.engine->requestNodeSwitchRound("__default__",true,"completed-manual-test");
    EXPECT_TRUE(h.waitStatus([](const std::string& s){
        const auto row=outletStatusFor(s,"__default__");
        return row.find("test_request_id") && row.find("test_request_id")->asString()=="completed-manual-test" &&
               row.find("switching") && !row.find("switching")->asBool();
    },5000));
    h.engine->requestNodeSwitchRound("__default__",false);
    EXPECT_TRUE(h.waitStatus([](const std::string& s){
        const auto row=outletStatusFor(s,"__default__");
        return row.find("test_request_id") && row.find("test_request_id")->asString().empty() &&
               row.find("switching") && !row.find("switching")->asBool();
    },5000));
    EXPECT_TRUE(api.switches().empty());h.stop();
}

APS_TEST(engine, adaptive_manual_socks_only_candidate_checks_its_own_port) {
    MockSocks5Server candidate;EXPECT_TRUE(candidate.start());
    Harness h;auto c=h.makeConfig();c.rules.clear();c.proxy.clashApi.host.clear();
    auto kernel=makeKernel("verge-mihomo.exe",candidate.port(),0);
    h.beforeStart=[kernel](Engine& engine){engine.seedDiscoveredKernelsForTest({kernel});};
    h.start(c);
    h.engine->requestNodeSwitchRound(kernel.id);
    EXPECT_TRUE(h.waitStatus([&](const std::string& s){
        auto row=outletStatusFor(s,kernel.id);const auto* msg=row.find("api_msg");
        return msg && msg->asString().find("握手正常")!=std::string::npos;
    },5000));
    const auto row=outletStatusFor(h.lastStatus(),kernel.id);
    EXPECT_TRUE(row.find("alive") && row.find("alive")->asBool());
    EXPECT_TRUE(row.find("selection_ok") && !row.find("selection_ok")->asBool());
    json::Value status;EXPECT_TRUE(json::Value::parse(h.engine->statusJson(),status,nullptr));
    EXPECT_TRUE(status.find("effective_proxy") && status.find("effective_proxy")->find("port") &&
                status.find("effective_proxy")->find("port")->asInt()==socks().port());h.stop();
}

APS_TEST(engine, adaptive_service_prefix_and_directory_change_preserve_active_outlet) {
    Harness h;auto c=h.makeConfig();c.rules.clear();c.proxy.port=1;c.proxy.clashApi.host.clear();
    c.routing.autoOutletId="auto-verge-mihomo.exe";
    DiscoveredKernel old=makeKernel("verge-mihomo.exe",socks().port(),0);
    old.pid=0;old.configDir="C:\\user\\Verge";
    old.apiPipe="\\\\.\\pipe\\verge-mihomo-sidecar-release-0123456789abcdef0123456789abcdef";
    auto fresh=old;fresh.pid=101;fresh.configDir="C:\\ProgramData\\service\\cores";
    fresh.apiPipe="\\\\.\\pipe\\verge-mihomo-future-channel-0123456789abcdef0123456789abcdef";
    h.cacheLoader=[old]{return std::vector<DiscoveredKernel>{old};};
    h.discoveryScan=[fresh](DiscoveryMode){return std::vector<DiscoveredKernel>{fresh};};
    h.start(c,true);h.engine->adoptDiscoveries();
    EXPECT_TRUE(h.waitStatus([&](const std::string& s){
        json::Value value;if(!json::Value::parse(s,value,nullptr))return false;
        const auto* proxy=value.find("effective_proxy");
        return proxy && proxy->find("id") && proxy->find("id")->asString()==c.routing.autoOutletId &&
               proxy->find("fallback") && !proxy->find("fallback")->asBool();
    },5000)); // the pump may still be rebuilding outlets after its first scan
    json::Value status;EXPECT_TRUE(json::Value::parse(h.engine->statusJson(),status,nullptr));
    const auto* proxy=status.find("effective_proxy");
    EXPECT_TRUE(proxy && proxy->find("id") && proxy->find("id")->asString()==c.routing.autoOutletId);
    EXPECT_TRUE(proxy && proxy->find("fallback") && !proxy->find("fallback")->asBool());
    EXPECT_TRUE(h.engine->statusJson().find("auto-verge-mihomo.exe#2")==std::string::npos);
    h.stop();saveKernelCache({});
}

APS_TEST(engine, adaptive_activated_socks_only_identity_beats_old_controller_cache) {
    Harness h;auto c=h.makeConfig();c.rules.clear();c.proxy.port=1;c.proxy.clashApi.host.clear();
    c.routing.autoOutletId="auto-verge-mihomo.exe#2";
    DiscoveredKernel history=makeKernel("verge-mihomo.exe",socks().port(),0);
    history.pid=0;history.configDir="C:\\user\\Verge";
    history.apiPipe="\\\\.\\pipe\\verge-mihomo-sidecar-release-0123456789abcdef0123456789abcdef";
    auto selected=history;selected.apiPipe.clear();selected.configDir="C:\\ProgramData\\service\\cores";
    auto fresh=selected;fresh.pid=102;
    fresh.apiPipe="\\\\.\\pipe\\verge-mihomo-production-0123456789abcdef0123456789abcdef";
    h.cacheLoader=[history,selected]{return std::vector<DiscoveredKernel>{history,selected};};
    h.discoveryScan=[fresh](DiscoveryMode){return std::vector<DiscoveredKernel>{fresh};};
    h.start(c,true);h.engine->adoptDiscoveries();
    EXPECT_TRUE(h.waitStatus([&](const std::string& s){
        json::Value value;if(!json::Value::parse(s,value,nullptr))return false;
        const auto* proxy=value.find("effective_proxy");
        return proxy && proxy->find("id") && proxy->find("id")->asString()==c.routing.autoOutletId &&
               proxy->find("fallback") && !proxy->find("fallback")->asBool();
    },5000));
    json::Value status;EXPECT_TRUE(json::Value::parse(h.engine->statusJson(),status,nullptr));
    const auto* proxy=status.find("effective_proxy");
    EXPECT_TRUE(proxy && proxy->find("id") && proxy->find("id")->asString()==c.routing.autoOutletId);
    EXPECT_TRUE(proxy && proxy->find("fallback") && !proxy->find("fallback")->asBool());
    h.stop();saveKernelCache({});
}

#include "dns_scope_cases.hpp"

APS_TEST(engine, incident_idle_watchdog_keeps_receiving_and_detects_real_stall) {
    PumpWatchdog idle(0);
    // More than 120 s with no packet iterations, but receive-thread progress.
    for (int64_t ms = 1000; ms <= 600000; ms += 1000)
        EXPECT_FALSE(idle.stalled(ms, 1, ms / 1000, true, false));
    for (int64_t ms = 601000; ms <= 720000; ms += 1000)
        EXPECT_FALSE(idle.stalled(ms, 1, 600, true, false));
    EXPECT_TRUE(idle.stalled(721000, 1, 600, true, false));
    PumpWatchdog handling(0);
    EXPECT_FALSE(handling.stalled(1, 1, 0, true, false));
    for (int64_t ms = 1000; ms <= 120000; ms += 1000)
        EXPECT_FALSE(handling.stalled(ms, 1, 0, true, false));
    EXPECT_TRUE(handling.stalled(121000, 1, 0, true, false));
    EXPECT_TRUE(handling.stalled(121001, 1, 0, true, true));
    EXPECT_FALSE(handling.stalled(121002, 1, 0, false, true));
    PumpWatchdog suspended(0);
    EXPECT_FALSE(suspended.stalled(1, 1, 0, true, false));
    EXPECT_FALSE(suspended.stalled(3600000, 1, 0, true, false));
    EXPECT_FALSE(suspended.stalled(3601000, 1, 1, true, false));

    Harness h; auto c = h.makeConfig(); h.start(c);
    EXPECT_TRUE(h.waitStatus([&](const std::string&) {
        return h.device->tcpReceiveWaitTicks() > 0;
    }, 4000));
    const auto before = h.device->tcpReceiveWaitTicks();
    h.pushConnectEvent(kAppPort);
    h.device->pushTcp(buildTcpPacket(kAppIp, kAppPort, kDstIp, kDstPort, 100, 0, 0x02));
    EXPECT_TRUE(h.device->waitSent(1, 2000));
    EXPECT_GE(h.device->tcpReceiveWaitTicks(), before);
    h.stop(); // pending idle receive must unblock promptly on shutdown
}

APS_TEST(engine, incident_direct_mode_invalidates_previously_healthy_node) {
    MockClashApi api; api.mode = "global";
    api.groups = {{"GLOBAL", {"node-a", "node-b"}}};
    api.groupSelections = {{"GLOBAL", "node-a"}};
    api.latencies = {{"node-a", 10}, {"node-b", 20}};
    EXPECT_TRUE(api.start());
    Harness h; auto c = h.makeConfig(); c.rules.clear();
    c.proxy.clashApi.host = "127.0.0.1"; c.proxy.clashApi.port = api.port();
    h.start(c);
    h.engine->requestNodeSwitchRound("__default__", true, "healthy-first");
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        auto row = outletStatusFor(s, "__default__");
        return row.find("test_request_id") && row.find("test_request_id")->asString() == "healthy-first" &&
               row.find("alive") && row.find("alive")->asBool() &&
               row.find("switching") && !row.find("switching")->asBool();
    }, 5000));
    api.stop(); api.mode = "direct";
    EXPECT_TRUE(api.start(static_cast<uint16_t>(c.proxy.clashApi.port)));
    const auto switches = api.switches().size();
    h.engine->requestNodeSwitchRound("__default__", true, "direct-now");
    EXPECT_TRUE(h.waitStatus([](const std::string& s) {
        auto row = outletStatusFor(s, "__default__");
        return row.find("test_request_id") && row.find("test_request_id")->asString() == "direct-now" &&
               row.find("runtime_mode") && row.find("runtime_mode")->asString() == "direct" &&
               row.find("switching") && !row.find("switching")->asBool();
    }, 5000));
    auto row = outletStatusFor(h.lastStatus(), "__default__");
    EXPECT_FALSE(row.find("alive") && row.find("alive")->asBool());
    EXPECT_FALSE(row.find("selection_ok") && row.find("selection_ok")->asBool());
    EXPECT_TRUE(row.find("node") && row.find("node")->asString().empty());
    EXPECT_EQ(api.switches().size(), switches);
    h.stop();
}

APS_TEST(engine, portless_cache_keeps_selected_instance_and_rediscovers_current_port) {
    DiscoveredKernel primary, other;
    primary.procName = other.procName = "portless-core.exe";
    primary.id = "auto-portless-core.exe#4";
    primary.configDir = "C:\\primary-config";
    primary.cmdline = "core.exe -f primary.yaml -ext-ctl 127.0.0.1:50101 -secret old";
    primary.socksPort = 50100; primary.apiPort = 50101;
    other.id = "auto-portless-core.exe";
    other.configDir = primary.configDir; // same image/directory, different config files
    other.cmdline = "core.exe -f other.yaml";
    other.socksPort = 40100; other.apiPort = 40101;
    saveKernelCache({other, primary});
    for (int restart = 0; restart < 2; ++restart) {
        Harness h;
        Config c = h.makeConfig(); c.rules.clear();
        c.proxy.port = 1; c.proxy.clashApi.host.clear();
        c.nodeMonitor.enabled = false;
        c.routing.autoOutletId = primary.id;
        auto live = primary;
        live.id.clear(); live.pid = 1001 + restart;
        live.socksPort = static_cast<uint16_t>(55100 + restart);
        live.apiPort = static_cast<uint16_t>(56100 + restart);
        live.cmdline = "core.exe -f primary.yaml -ext-ctl 127.0.0.1:" +
            std::to_string(live.apiPort) + " -secret new-" + std::to_string(restart);
        h.cacheLoader = [] { return loadKernelCache(); };
        h.discoveryScan = [live](DiscoveryMode) { return std::vector<DiscoveredKernel>{live}; };
        h.start(c, true);
        EXPECT_TRUE(h.waitStatus([&](const std::string& text) {
            json::Value status;
            if (!json::Value::parse(text, status, nullptr) || !status.find("kernels")) return false;
            const auto& rows = status.find("kernels")->array();
            if (rows.size() != 2) return false;
            for (const auto& row : rows) {
                if (row.find("id")->asString() == primary.id)
                    // Discovery metadata is published before the egress
                    // snapshot is rebuilt. Wait for both parts of adoption.
                    return row.find("alive")->asBool() && row.find("socks_port")->asInt() == live.socksPort &&
                           h.engine->outletEnabled(primary.id) &&
                           h.engine->outletParams(primary.id).proxy.port == live.socksPort;
            }
            return false;
        }, 3000));
        EXPECT_EQ(h.engine->outletParams(primary.id).proxy.port, live.socksPort);
        EXPECT_TRUE(h.engine->outletEnabled(primary.id));
        h.stop();
        auto cached = loadKernelCache();
        EXPECT_EQ(cached.size(), 2u);
        for (const auto& k : cached) {
            EXPECT_EQ(k.socksPort, 0);
            EXPECT_EQ(k.apiPort, 0);
        }
    }
    saveKernelCache({});
}

APS_TEST(engine, portless_cache_ambiguous_instances_do_not_steal_selected_outlet) {
    DiscoveredKernel a, b;
    a.procName = b.procName = "ambiguous-core.exe";
    a.configDir = b.configDir = "C:\\shared-config";
    a.cmdline = b.cmdline = "core.exe -f shared.yaml";
    a.id = "auto-ambiguous-core.exe";
    b.id = "auto-ambiguous-core.exe#2";
    a.socksPort = 40100; b.socksPort = 40101;
    saveKernelCache({a, b});
    Harness h;
    Config c = h.makeConfig(); c.rules.clear();
    c.proxy.port = 1; c.proxy.clashApi.host.clear();
    c.nodeMonitor.enabled = false; c.routing.autoOutletId = a.id;
    a.id.clear(); b.id.clear();
    a.pid = 1001; b.pid = 1002;
    a.socksPort = 55120; b.socksPort = 55121;
    h.cacheLoader = [] { return loadKernelCache(); };
    h.discoveryScan = [a, b](DiscoveryMode) { return std::vector<DiscoveredKernel>{a, b}; };
    h.start(c, true);
    EXPECT_TRUE(h.waitStatus([&](const std::string& text) {
        json::Value status;
        if (!json::Value::parse(text, status, nullptr) || !status.find("kernels")) return false;
        const auto& rows = status.find("kernels")->array();
        if (rows.size() != 4) return false;
        int alive = 0;
        for (const auto& row : rows) {
            const bool current = row.find("alive")->asBool();
            const auto id = row.find("id")->asString();
            if (id == "auto-ambiguous-core.exe" || id == "auto-ambiguous-core.exe#2") {
                if (current || row.find("socks_port")->asInt() != 0) return false;
            }
            if (current) ++alive;
        }
        return alive == 2 && !h.engine->outletEnabled("auto-ambiguous-core.exe") &&
               h.engine->outletParams("auto-ambiguous-core.exe").proxy.port == 1;
    }, 3000));
    EXPECT_FALSE(h.engine->outletEnabled("auto-ambiguous-core.exe"));
    EXPECT_EQ(h.engine->outletParams("auto-ambiguous-core.exe").proxy.port, 1);
    h.stop();
    saveKernelCache({});
}

int main(int argc, char** argv) {
    if (argc > 1) {
        const std::string filter = argv[1];
        auto& cases = aps::test::registry();
        std::erase_if(cases, [&](const aps::test::Case& c) {
            return std::string(c.name).find(filter) == std::string::npos;
        });
        if (cases.empty()) {
            std::fprintf(stderr, "No engine test matches: %s\n", filter.c_str());
            return 2;
        }
    }
    return aps::test::runAll(nullptr);
}
