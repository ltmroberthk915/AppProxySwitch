// Relay integration tests over loopback: client -> relay -> mock SOCKS5 ->
// mock HTTP, including half-close, unresolved peers and proxy failure paths.
#include <winsock2.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>

#include "aps/dns_rewrite.hpp"
#include "aps/log.hpp"
#include "aps/net.hpp"
#include "aps/relay_server.hpp"
#include "mock_http_server.hpp"
#include "mock_socks_server.hpp"
#include "tls_fixture.hpp"
#include "testlib/appsw_test.h"

using namespace aps;
using aps::test::MockHttpServer;
using aps::test::MockSocks5Server;

namespace {
struct WsaInit {
    WsaInit() { net::initWinsock(); }
};
WsaInit g_wsa;

struct TestSink : IRelaySessionSink {
    std::atomic<uint64_t> up{0}, down{0}, closed{0};
    void onBytes(uint64_t u, uint64_t d) override {
        up.fetch_add(u);
        down.fetch_add(d);
    }
    void onClosed() override { closed.fetch_add(1); }
};

// Bind a client socket to an explicit ephemeral port so the relay's
// (peer ip:port) -> target resolution can be pre-arranged.
struct PreparedClient {
    SOCKET s = INVALID_SOCKET;
    net::Endpoint4 local;
    bool bind() {
        s = net::makeTcpSocket();
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_addr.S_un.S_addr = htonl(0x7F000001);  // 127.0.0.1
        sa.sin_port = 0;
        if (::bind(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == SOCKET_ERROR) return false;
        sockaddr_in actual{};
        int len = sizeof(actual);
        getsockname(s, reinterpret_cast<sockaddr*>(&actual), &len);
        local.ip = ntohl(actual.sin_addr.S_un.S_addr);
        local.port = static_cast<uint16_t>(ntohs(actual.sin_port));
        return true;
    }
    ~PreparedClient() { net::closeSocket(s); }
};

bool waitUntil(const std::function<bool()>& pred, int timeoutMs) {
    for (int t = 0; t < timeoutMs; t += 25) {
        if (pred()) return true;
        Sleep(25);
    }
    return pred();
}

struct TempRelayLog {
    std::wstring dir;
    bool opened = false;
    TempRelayLog() {
        wchar_t temp[MAX_PATH]{};
        if (!GetTempPathW(MAX_PATH, temp)) return;
        static std::atomic<unsigned> next{0};
        dir = std::wstring(temp) + L"aps-relay-log-" + std::to_wstring(GetCurrentProcessId()) +
              L"-" + std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(next++);
        opened = log::init(dir, log::Level::Info, 1, 1);
    }
    std::string read() {
        log::shutdown();
        std::ifstream file(std::filesystem::path(dir + L"\\aps.log"), std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    }
    ~TempRelayLog() {
        log::shutdown();
        if (!dir.empty()) {
            DeleteFileW((dir + L"\\aps.log").c_str());
            RemoveDirectoryW(dir.c_str());
        }
    }
};

// A single loopback response with intentional idle gaps. The truncated variant
// advertises a longer HTTP body but still sends an orderly TCP FIN.
struct StreamingResponseServer {
    SOCKET listener = INVALID_SOCKET;
    std::atomic<SOCKET> client{INVALID_SOCKET};
    std::atomic<bool> stopping{false};
    std::thread worker;
    uint16_t port = 0;
    bool start(std::string response) {
        listener = net::makeTcpSocket();
        auto address = net::toSockaddr({0x7F000001, 0});
        if (::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
            listen(listener, 1) != 0) return false;
        int len = sizeof(address);
        if (getsockname(listener, reinterpret_cast<sockaddr*>(&address), &len) != 0) return false;
        port = ntohs(address.sin_port);
        worker = std::thread([this, socket = listener, response = std::move(response)] {
            SOCKET accepted = accept(socket, nullptr, nullptr);
            if (accepted == INVALID_SOCKET) return;
            client.store(accepted);
            std::string request;
            char buffer[4096];
            while (!stopping.load() && request.size() < 65536 &&
                   request.find("\r\n\r\n") == std::string::npos) {
                int n = net::recvSome(accepted, buffer, sizeof(buffer), 2000);
                if (n <= 0) break;
                request.append(buffer, static_cast<size_t>(n));
            }
            for (size_t offset = 0; !stopping.load() && offset < response.size(); offset += 16384) {
                if (offset) Sleep(80); // exceeds the relay's per-send timeout
                const auto size = std::min<size_t>(16384, response.size() - offset);
                if (net::sendAll(accepted, response.data() + offset, size, 2000) != 0) break;
            }
            shutdown(accepted, SD_SEND);
            while (!stopping.load() && net::recvSome(accepted, buffer, sizeof(buffer), 1000) > 0) {}
            client.store(INVALID_SOCKET);
            net::closeSocket(accepted);
        });
        return true;
    }
    ~StreamingResponseServer() {
        stopping.store(true);
        const auto accepted = client.load();
        if (accepted != INVALID_SOCKET) shutdown(accepted, SD_BOTH);
        net::closeSocket(listener);
        if (worker.joinable()) worker.join();
    }
};

std::vector<uint8_t> buildDnsQuery(const std::string& name,
                                   uint16_t id = 0x1234) {
    std::vector<uint8_t> pkt(12 + name.size() + 2 + 4, 0);
    pkt[0] = static_cast<uint8_t>(id >> 8);
    pkt[1] = static_cast<uint8_t>(id & 0xFF);
    pkt[2] = 0x01;
    pkt[5] = 1;
    size_t pos = 12;
    size_t start = 0;
    while (start <= name.size()) {
        size_t dot = name.find('.', start);
        size_t labelLen = dot == std::string::npos ? name.size() - start
                                                   : dot - start;
        pkt[pos++] = static_cast<uint8_t>(labelLen);
        std::memcpy(pkt.data() + pos, name.data() + start, labelLen);
        pos += labelLen;
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    pkt[pos++] = 0;
    pkt[pos++] = 0;
    pkt[pos++] = 1;  // A
    pkt[pos++] = 0;
    pkt[pos++] = 1;  // IN
    return pkt;
}

bool exchangeDnsFrame(SOCKET s, const std::vector<uint8_t>& query,
                      std::vector<uint8_t>& response) {
    uint8_t qlen[2] = {static_cast<uint8_t>(query.size() >> 8),
                       static_cast<uint8_t>(query.size() & 0xFF)};
    if (net::sendAll(s, reinterpret_cast<const char*>(qlen), 2, 3000) != 0 ||
        net::sendAll(s, reinterpret_cast<const char*>(query.data()),
                     query.size(), 3000) != 0) {
        return false;
    }
    uint8_t rlen[2] = {};
    if (net::recvExact(s, reinterpret_cast<char*>(rlen), 2, 3000) != 2) {
        return false;
    }
    size_t n = (static_cast<size_t>(rlen[0]) << 8) | rlen[1];
    if (n == 0) return false;
    response.resize(n);
    return net::recvExact(s, reinterpret_cast<char*>(response.data()), n,
                          3000) == static_cast<int>(n);
}

struct TcpDnsFallbackServer {
    SOCKET listener = INVALID_SOCKET;
    uint16_t port = 0;
    std::thread thread;
    std::atomic<uint32_t> queries{0};

    bool start() {
        listener = net::makeTcpSocket();
        if (listener == INVALID_SOCKET) return false;
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_addr.S_un.S_addr = htonl(0x7F000001);
        sa.sin_port = 0;
        if (::bind(listener, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) ==
                SOCKET_ERROR ||
            listen(listener, 4) == SOCKET_ERROR) {
            net::closeSocket(listener);
            return false;
        }
        int len = sizeof(sa);
        getsockname(listener, reinterpret_cast<sockaddr*>(&sa), &len);
        port = ntohs(sa.sin_port);
        thread = std::thread([this] {
            sockaddr_in peer{};
            int peerLen = sizeof(peer);
            SOCKET client =
                accept(listener, reinterpret_cast<sockaddr*>(&peer), &peerLen);
            if (client == INVALID_SOCKET) return;
            uint8_t lenBytes[2] = {};
            if (net::recvExact(client, reinterpret_cast<char*>(lenBytes), 2,
                               3000) == 2) {
                size_t n = (static_cast<size_t>(lenBytes[0]) << 8) | lenBytes[1];
                std::vector<uint8_t> msg(n);
                if (n != 0 &&
                    net::recvExact(client,
                                   reinterpret_cast<char*>(msg.data()), n,
                                   3000) == static_cast<int>(n)) {
                    ++queries;
                    if (msg.size() >= 12) {
                        msg[2] = 0x81;
                        msg[3] = 0x80;  // NOERROR/NODATA stand-in
                        net::sendAll(client,
                                     reinterpret_cast<const char*>(lenBytes),
                                     2, 3000);
                        net::sendAll(client,
                                     reinterpret_cast<const char*>(msg.data()),
                                     msg.size(), 3000);
                    }
                }
            }
            net::closeSocket(client);
        });
        return true;
    }

    void stop() {
        net::closeSocket(listener);
        if (thread.joinable()) thread.join();
    }
    ~TcpDnsFallbackServer() { stop(); }
};
}  // namespace

APS_TEST(relay, end_to_end_get_through_socks) {
    MockHttpServer http;
    http.setResponse("hello-via-relay");
    EXPECT_TRUE(http.start());
    MockSocks5Server socks;
    EXPECT_TRUE(socks.start());

    PreparedClient cli;
    EXPECT_TRUE(cli.bind());
    auto sink = std::make_shared<TestSink>();

    RelayParams params;
    params.proxy = socks.endpoint();
    RelayServer relay;
    EXPECT_TRUE(relay.start(params, 0, [&](uint32_t ip, uint16_t port) {
        if (ip == cli.local.ip && port == cli.local.port) {
            RelayTarget t;
            t.origDst = net::Endpoint4{0x7F000001, http.port()};
            t.ruleId = "rule-1";
            t.sink = sink;
            return std::optional<RelayTarget>(std::move(t));
        }
        return std::optional<RelayTarget>();
    }, nullptr));

    sockaddr_in ra = net::toSockaddr(net::Endpoint4{0x7F000001, relay.listenPort()});
    EXPECT_EQ(::connect(cli.s, reinterpret_cast<sockaddr*>(&ra), sizeof(ra)), 0);
    const char* req = "GET /test HTTP/1.1\r\nHost: unit\r\n\r\n";
    EXPECT_EQ(net::sendAll(cli.s, req, std::strlen(req), 3000), 0);

    std::string resp;
    char buf[4096];
    int n;
    while ((n = net::recvSome(cli.s, buf, sizeof(buf), 5000)) > 0) resp.append(buf, static_cast<size_t>(n));
    EXPECT_TRUE(resp.find("200 OK") != std::string::npos);
    EXPECT_TRUE(resp.find("hello-via-relay") != std::string::npos);

    relay.stop();
    socks.stop();
    http.stop();
    EXPECT_EQ(http.hits(), 1u);
    EXPECT_TRUE(http.hit(0).requestLine.find("GET /test") == 0);
    EXPECT_EQ(socks.requestCount(), 1u);
    EXPECT_EQ(socks.request(0).dstPort, http.port());
    EXPECT_TRUE(waitUntil([&] { return sink->closed.load() == 1; }, 2000));
    EXPECT_TRUE(sink->up.load() > 0);
    EXPECT_TRUE(sink->down.load() > 0);
}

APS_TEST(relay, half_close_propagates) {
    TempRelayLog diagnostic;
    EXPECT_TRUE(diagnostic.opened);
    MockHttpServer http;
    EXPECT_TRUE(http.start());
    MockSocks5Server socks;
    EXPECT_TRUE(socks.start());
    PreparedClient cli;
    EXPECT_TRUE(cli.bind());

    RelayParams params;
    params.proxy = socks.endpoint();
    RelayServer relay;
    EXPECT_TRUE(relay.start(params, 0, [&](uint32_t ip, uint16_t port) {
        if (ip == cli.local.ip && port == cli.local.port) {
            RelayTarget t;
            t.origDst = net::Endpoint4{0x7F000001, http.port()};
            return std::optional<RelayTarget>(std::move(t));
        }
        return std::optional<RelayTarget>();
    }, nullptr));

    sockaddr_in ra = net::toSockaddr(net::Endpoint4{0x7F000001, relay.listenPort()});
    EXPECT_EQ(::connect(cli.s, reinterpret_cast<sockaddr*>(&ra), sizeof(ra)), 0);
    const char* req = "GET /half HTTP/1.1\r\nHost: unit\r\n\r\n";
    EXPECT_EQ(net::sendAll(cli.s, req, std::strlen(req), 3000), 0);
    // Half-close our sending side; we must still receive the full response.
    shutdown(cli.s, SD_SEND);

    std::string resp;
    char buf[4096];
    int n;
    while ((n = net::recvSome(cli.s, buf, sizeof(buf), 5000)) > 0) resp.append(buf, static_cast<size_t>(n));
    EXPECT_TRUE(resp.find("200 OK") != std::string::npos);
    EXPECT_TRUE(waitUntil([&] { return relay.counters.completed.load() == 1; }, 2000));
    relay.stop();
    socks.stop();
    http.stop();
    const auto lines = diagnostic.read();
    EXPECT_TRUE(lines.find("first_eof=application") != std::string::npos);
    EXPECT_TRUE(lines.find("tcp_completed=true") != std::string::npos);
}

APS_TEST(relay, streaming_fin_does_not_claim_http_completion_or_cut_idle_reads) {
    for (const bool truncated : {false, true}) {
        TempRelayLog diagnostic;
        EXPECT_TRUE(diagnostic.opened);
        const std::string body = "PAYLOAD_MUST_NOT_APPEAR" + std::string(128 * 1024, 'x');
        const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: " +
            std::to_string(body.size()) + "\r\n\r\n" + (truncated ? body.substr(0, 22) : body);
        StreamingResponseServer upstream;
        EXPECT_TRUE(upstream.start(response));
        MockSocks5Server socks;
        EXPECT_TRUE(socks.start());
        PreparedClient cli;
        EXPECT_TRUE(cli.bind());
        RelayParams params;
        params.proxy = socks.endpoint();
        params.pumpTimeoutMs = 50;
        RelayServer relay;
        EXPECT_TRUE(relay.start(params, 0, [&](uint32_t ip, uint16_t port) {
            if (ip != cli.local.ip || port != cli.local.port) return std::optional<RelayTarget>();
            RelayTarget target;
            target.origDst = {0x7F000001, upstream.port};
            return std::optional<RelayTarget>(std::move(target));
        }, nullptr));
        const auto address = net::toSockaddr({0x7F000001, relay.listenPort()});
        EXPECT_EQ(::connect(cli.s, reinterpret_cast<const sockaddr*>(&address), sizeof(address)), 0);
        const char* request = "GET /stream HTTP/1.1\r\nHost: unit\r\n\r\n";
        EXPECT_EQ(net::sendAll(cli.s, request, std::strlen(request), 2000), 0);
        std::string received;
        char buffer[8192];
        int n = 0;
        while ((n = net::recvSome(cli.s, buffer, sizeof(buffer), 3000)) > 0)
            received.append(buffer, static_cast<size_t>(n));
        EXPECT_EQ(n, 0);
        EXPECT_STREQ(received, response);
        shutdown(cli.s, SD_SEND);
        EXPECT_TRUE(waitUntil([&] { return relay.counters.completed.load() == 1; }, 2000));
        relay.stop();
        socks.stop();
        const auto lines = diagnostic.read();
        EXPECT_TRUE(lines.find("first_eof=proxy") != std::string::npos);
        EXPECT_TRUE(lines.find("tcp_completed=true") != std::string::npos);
        EXPECT_TRUE(lines.find("application_completion=unverified") != std::string::npos);
        EXPECT_TRUE(lines.find("first_eof_ms=-1") == std::string::npos);
        EXPECT_TRUE(lines.find("duration_ms=") != std::string::npos);
        EXPECT_TRUE(lines.find("PAYLOAD_MUST_NOT_APPEAR") == std::string::npos);
    }
}

APS_TEST(relay, unknown_peer_is_rejected) {
    MockSocks5Server socks;
    EXPECT_TRUE(socks.start());
    RelayParams params;
    params.proxy = socks.endpoint();
    RelayServer relay;
    // Resolver answers nothing.
    EXPECT_TRUE(relay.start(params, 0, [](uint32_t, uint16_t) {
        return std::optional<RelayTarget>();
    }, nullptr));

    SOCKET s = net::makeTcpSocket();
    sockaddr_in ra = net::toSockaddr(net::Endpoint4{0x7F000001, relay.listenPort()});
    EXPECT_EQ(::connect(s, reinterpret_cast<sockaddr*>(&ra), sizeof(ra)), 0);
    char buf[64];
    int n = net::recvSome(s, buf, sizeof(buf), 2000);
    // Abortive close => immediate EOF or reset, and definitely no proxying.
    EXPECT_TRUE(n <= 0);
    net::closeSocket(s);
    relay.stop();
    socks.stop();
    EXPECT_EQ(socks.requestCount(), 0u);
    EXPECT_EQ(relay.counters.unresolved.load(), 1u);
}

APS_TEST(relay, dead_proxy_fails_fast_with_rst) {
    PreparedClient cli;
    EXPECT_TRUE(cli.bind());
    RelayParams params;
    params.proxy = net::Endpoint4{0x7F000001, 1};  // nothing listens here
    params.connectTimeoutMs = 1500;
    RelayServer relay;
    std::atomic<int> failureKind{-1};
    EXPECT_TRUE(relay.start(params, 0, [&](uint32_t ip, uint16_t port) {
        if (ip == cli.local.ip && port == cli.local.port) {
            RelayTarget t;
            t.origDst = net::Endpoint4{0x7F000001, 80};
            t.onResult = [&](const std::string&, uint32_t, uint16_t, bool,
                             RelayFailureKind kind, const std::string&) {
                failureKind.store(static_cast<int>(kind));
            };
            return std::optional<RelayTarget>(std::move(t));
        }
        return std::optional<RelayTarget>();
    }, nullptr));

    sockaddr_in ra = net::toSockaddr(net::Endpoint4{0x7F000001, relay.listenPort()});
    EXPECT_EQ(::connect(cli.s, reinterpret_cast<sockaddr*>(&ra), sizeof(ra)), 0);
    auto t0 = std::chrono::steady_clock::now();
    char buf[64];
    int n = net::recvSome(cli.s, buf, sizeof(buf), 5000);
    auto dt = std::chrono::steady_clock::now() - t0;
    EXPECT_TRUE(n <= 0);  // reset or EOF, quickly
    EXPECT_TRUE(std::chrono::duration_cast<std::chrono::milliseconds>(dt).count() < 4000);
    EXPECT_TRUE(waitUntil([&] { return failureKind.load() >= 0; }, 2000));
    EXPECT_EQ(failureKind.load(),
              static_cast<int>(RelayFailureKind::ProxyEndpoint));
    relay.stop();
    EXPECT_EQ(relay.counters.socksFail.load(), 1u);
}

APS_TEST(relay, refused_connect_reports_tunnel_not_endpoint) {
    MockSocks5Server socks;
    socks.setBehavior(aps::test::MockSocksBehavior::RefuseConnect);
    EXPECT_TRUE(socks.start());
    PreparedClient cli;
    EXPECT_TRUE(cli.bind());
    RelayParams params;
    params.proxy = socks.endpoint();
    RelayServer relay;
    std::atomic<int> failureKind{-1};
    EXPECT_TRUE(relay.start(params, 0, [&](uint32_t ip, uint16_t port) {
        if (ip == cli.local.ip && port == cli.local.port) {
            RelayTarget t;
            t.origDst = net::Endpoint4{0x08080808, 443};
            t.onResult = [&](const std::string&, uint32_t, uint16_t, bool,
                             RelayFailureKind kind, const std::string&) {
                failureKind.store(static_cast<int>(kind));
            };
            return std::optional<RelayTarget>(std::move(t));
        }
        return std::optional<RelayTarget>();
    }, nullptr));

    sockaddr_in ra = net::toSockaddr(
        net::Endpoint4{0x7F000001, relay.listenPort()});
    EXPECT_EQ(::connect(cli.s, reinterpret_cast<sockaddr*>(&ra), sizeof(ra)), 0);
    char buf[16];
    EXPECT_TRUE(net::recvSome(cli.s, buf, sizeof(buf), 3000) <= 0);
    EXPECT_TRUE(waitUntil([&] { return failureKind.load() >= 0; }, 2000));
    EXPECT_EQ(failureKind.load(), static_cast<int>(RelayFailureKind::Tunnel));
    relay.stop();
    socks.stop();
}

APS_TEST(relay, stop_aborts_sessions_and_recovers) {
    MockHttpServer http;
    EXPECT_TRUE(http.start());
    MockSocks5Server socks;
    EXPECT_TRUE(socks.start());
    PreparedClient cli;
    EXPECT_TRUE(cli.bind());
    RelayParams params;
    params.proxy = socks.endpoint();
    RelayServer relay;
    EXPECT_TRUE(relay.start(params, 0, [&](uint32_t ip, uint16_t port) {
        if (ip == cli.local.ip && port == cli.local.port) {
            RelayTarget t;
            t.origDst = net::Endpoint4{0x7F000001, http.port()};
            return std::optional<RelayTarget>(std::move(t));
        }
        return std::optional<RelayTarget>();
    }, nullptr));
    sockaddr_in ra = net::toSockaddr(net::Endpoint4{0x7F000001, relay.listenPort()});
    EXPECT_EQ(::connect(cli.s, reinterpret_cast<sockaddr*>(&ra), sizeof(ra)), 0);
    // The accept thread registers the session asynchronously.
    size_t active = 0;
    for (int i = 0; i < 200; ++i) {
        active = relay.activeSessions();
        if (active == 1) break;
        Sleep(10);
    }
    EXPECT_EQ(active, 1u);

    relay.stop();  // must terminate promptly even mid-session
    char buf[64];
    int n = net::recvSome(cli.s, buf, sizeof(buf), 2000);
    EXPECT_TRUE(n <= 0);
    EXPECT_EQ(relay.activeSessions(), 0u);
    EXPECT_EQ(relay.counters.aborted.load(), 1u);
    EXPECT_EQ(relay.counters.socksFail.load(), 0u);
    socks.stop();
    http.stop();
}

APS_TEST(relay, tcp_dns_bridge_returns_clean_framed_response_without_socks) {
    PreparedClient cli;
    EXPECT_TRUE(cli.bind());
    auto sink = std::make_shared<TestSink>();
    std::atomic<uint32_t> calls{0};
    RelayParams params;
    params.proxy = net::Endpoint4{0x7F000001, 1};  // must never be used
    RelayServer relay;
    EXPECT_TRUE(relay.start(params, 0, [&](uint32_t ip, uint16_t port) {
        if (ip != cli.local.ip || port != cli.local.port) {
            return std::optional<RelayTarget>();
        }
        RelayTarget t;
        t.origDst = net::Endpoint4{0xC0A80501, 53};
        t.sink = sink;
        t.resolveDns = [&](const uint8_t* query, size_t queryLen,
                           std::vector<uint8_t>& response) {
            ++calls;
            auto q = dns::parseAQuery(query, queryLen);
            if (!q) return false;
            uint8_t out[512];
            size_t n = dns::buildAResponse(*q, {0x01020304}, out,
                                           sizeof(out));
            response.assign(out, out + n);
            return n != 0;
        };
        return std::optional<RelayTarget>(std::move(t));
    }, nullptr));

    sockaddr_in ra =
        net::toSockaddr(net::Endpoint4{0x7F000001, relay.listenPort()});
    EXPECT_EQ(::connect(cli.s, reinterpret_cast<sockaddr*>(&ra), sizeof(ra)), 0);
    auto query = buildDnsQuery("chatgpt.com", 0xCAFE);
    std::vector<uint8_t> response;
    EXPECT_TRUE(exchangeDnsFrame(cli.s, query, response));
    EXPECT_TRUE(response.size() > query.size());
    if (response.size() >= 12) {
        EXPECT_EQ(response[0], 0xCA);
        EXPECT_EQ(response[1], 0xFE);
        const uint8_t ip[4] = {1, 2, 3, 4};
        EXPECT_TRUE(std::search(response.begin(), response.end(), ip, ip + 4) !=
                    response.end());
    }
    net::closeSocket(cli.s);
    relay.stop();
    EXPECT_EQ(calls.load(), 1u);
    EXPECT_TRUE(sink->up.load() >= query.size() + 2);
    EXPECT_TRUE(sink->down.load() >= response.size() + 2);
}

APS_TEST(relay, tcp_dns_bridge_falls_back_to_exact_original_resolver) {
    TcpDnsFallbackServer upstream;
    EXPECT_TRUE(upstream.start());
    PreparedClient cli;
    EXPECT_TRUE(cli.bind());
    RelayParams params;
    params.connectTimeoutMs = 1500;
    params.pumpTimeoutMs = 3000;
    RelayServer relay;
    EXPECT_TRUE(relay.start(params, 0, [&](uint32_t ip, uint16_t port) {
        if (ip != cli.local.ip || port != cli.local.port) {
            return std::optional<RelayTarget>();
        }
        RelayTarget t;
        t.origDst = net::Endpoint4{0x7F000001, upstream.port};
        t.resolveDns = [](const uint8_t*, size_t,
                          std::vector<uint8_t>&) { return false; };
        return std::optional<RelayTarget>(std::move(t));
    }, nullptr));

    sockaddr_in ra =
        net::toSockaddr(net::Endpoint4{0x7F000001, relay.listenPort()});
    EXPECT_EQ(::connect(cli.s, reinterpret_cast<sockaddr*>(&ra), sizeof(ra)), 0);
    auto query = buildDnsQuery("unsupported.example", 0x5678);
    // Make it an unsupported MX query so the clean callback declines it.
    query[query.size() - 3] = 15;
    std::vector<uint8_t> response;
    EXPECT_TRUE(exchangeDnsFrame(cli.s, query, response));
    EXPECT_EQ(response.size(), query.size());
    if (response.size() >= 4) {
        EXPECT_EQ(response[0], 0x56);
        EXPECT_EQ(response[1], 0x78);
        EXPECT_EQ(response[2], 0x81);
        EXPECT_EQ(response[3], 0x80);
    }
    net::closeSocket(cli.s);
    relay.stop();
    upstream.stop();
    EXPECT_EQ(upstream.queries.load(), 1u);
}

namespace {
void checkTlsRelay(const std::vector<uint8_t>& bytes, bool permitName,
                   bool expectDomain, bool fragmented = false, bool enabled = true) {
    MockSocks5Server proxy, unusedDefault;
    proxy.setBehavior(aps::test::MockSocksBehavior::EchoConnect);
    unusedDefault.setBehavior(aps::test::MockSocksBehavior::AcceptConnect);
    EXPECT_TRUE(proxy.start());
    EXPECT_TRUE(unusedDefault.start());
    PreparedClient cli;
    EXPECT_TRUE(cli.bind());
    auto sink = std::make_shared<TestSink>();
    RelayParams params;
    params.proxy = unusedDefault.endpoint();
    RelayServer relay;
    std::atomic<int> lookups{0};
    EXPECT_TRUE(relay.start(params, 0, [&](uint32_t, uint16_t) {
        RelayTarget t;
        t.origDst = {0xC0000201, 8443};  // unusable/poisoned original; never dialed
        t.proxy = proxy.endpoint();      // must not fall back to default/Sakura
        t.outletId = "selected-verge-fixture";
        t.sink = sink;
        if (enabled) t.allowTlsDomain = [&](const std::string& name) {
            ++lookups;
            return permitName && name == "api.example.invalid";
        };
        return std::optional<RelayTarget>(std::move(t));
    }, nullptr));
    EXPECT_EQ(net::connectWithTimeout(cli.s, {0x7F000001, relay.listenPort()}, 2000, nullptr), 0);
    if (fragmented) {
        EXPECT_EQ(net::sendAll(cli.s, reinterpret_cast<const char*>(bytes.data()), 3, 2000), 0);
        Sleep(20);
        EXPECT_EQ(net::sendAll(cli.s, reinterpret_cast<const char*>(bytes.data() + 3), bytes.size() - 3, 2000), 0);
    } else {
        EXPECT_EQ(net::sendAll(cli.s, reinterpret_cast<const char*>(bytes.data()), bytes.size(), 2000), 0);
    }
    shutdown(cli.s, SD_SEND);
    std::vector<uint8_t> reply(bytes.size());
    EXPECT_EQ(net::recvExact(cli.s, reinterpret_cast<char*>(reply.data()), reply.size(), 3000),
              static_cast<int>(reply.size()));
    EXPECT_TRUE(reply == bytes);  // no decrypt/rewrite/lost/duplicated ClientHello bytes
    EXPECT_TRUE(waitUntil([&] { return sink->closed.load() == 1; }, 3000));
    EXPECT_EQ(sink->up.load(), bytes.size());
    EXPECT_EQ(sink->down.load(), bytes.size());
    EXPECT_EQ(proxy.requestCount(), 1u);
    if (proxy.requestCount()) {
        const auto req = proxy.request(0);
        EXPECT_EQ(req.addressType, expectDomain ? 3 : 1);
        EXPECT_STREQ(req.dstDomain, expectDomain ? "api.example.invalid" : "");
        EXPECT_EQ(req.dstPort, 8443);
        if (!expectDomain) EXPECT_EQ(req.dstIp, 0xC0000201u);
    }
    EXPECT_EQ(unusedDefault.requestCount(), 0u);
    relay.stop();
    proxy.stop();
    unusedDefault.stop();
}
}  // namespace

APS_TEST(relay, tls_domain_preserved_on_selected_outlet_and_bytes_unchanged) {
    checkTlsRelay(aps::test::tlsHello("Api.Example.INVALID"), true, true);
}
APS_TEST(relay, fragmented_tls_domain_and_half_close_preserved) {
    auto data = aps::test::tlsRecords(aps::test::tlsHandshake("api.example.invalid"), 17);
    data.insert(data.end(), {23, 3, 3, 0, 2, 0x71, 0x72});
    checkTlsRelay(data, true, true, true);
}
APS_TEST(relay, unknown_dns_correlation_never_guesses_domain) {
    checkTlsRelay(aps::test::tlsHello("api.example.invalid"), false, false);
}
APS_TEST(relay, ech_cover_name_keeps_ip_but_correlated_grease_name_works) {
    checkTlsRelay(aps::test::tlsHello("cover.example.invalid", true), true, false);
    checkTlsRelay(aps::test::tlsHello("api.example.invalid", true), true, true);
}
APS_TEST(relay, no_sni_and_non_tls_keep_ip_and_original_payload) {
    checkTlsRelay(aps::test::tlsHello(""), true, false);
    checkTlsRelay({'G','E','T',' ','/','\r','\n'}, true, false);
}
APS_TEST(relay, disabled_domain_recovery_preserves_existing_behavior) {
    checkTlsRelay(aps::test::tlsHello("api.example.invalid"), true, false, false, false);
}
APS_TEST(relay, incomplete_tls_prefix_falls_back_without_waiting_forever) {
    // No EOF here: an app may stall mid-hello. The bounded inspect window
    // must still open the original IP tunnel and return the exact prefix.
    MockSocks5Server proxy;
    proxy.setBehavior(aps::test::MockSocksBehavior::EchoConnect);
    EXPECT_TRUE(proxy.start());
    RelayParams params;
    params.proxy = proxy.endpoint();
    RelayServer relay;
    EXPECT_TRUE(relay.start(params, 0, [](uint32_t, uint16_t) {
        RelayTarget t;
        t.origDst = {0xC0000201, 8443};
        t.allowTlsDomain = [](const std::string&) { return true; };
        return std::optional<RelayTarget>(t);
    }, nullptr));
    PreparedClient cli;
    EXPECT_TRUE(cli.bind());
    EXPECT_EQ(net::connectWithTimeout(cli.s, {0x7F000001, relay.listenPort()}, 2000, nullptr), 0);
    const char partial[] = {22, 3, 3};
    const auto start = std::chrono::steady_clock::now();
    EXPECT_EQ(net::sendAll(cli.s, partial, sizeof(partial), 2000), 0);
    char received[3]{};
    EXPECT_EQ(net::recvExact(cli.s, received, sizeof(received), 1500), 3);
    EXPECT_TRUE(std::memcmp(partial, received, sizeof(partial)) == 0);
    EXPECT_TRUE(std::chrono::steady_clock::now() - start < std::chrono::seconds(1));
    if (proxy.requestCount()) EXPECT_EQ(proxy.request(0).addressType, 1);
    relay.stop();
    proxy.stop();
}
APS_TEST(relay, idle_client_can_be_stopped_during_tls_inspection) {
    MockSocks5Server proxy;
    proxy.setBehavior(aps::test::MockSocksBehavior::AcceptConnect);
    EXPECT_TRUE(proxy.start());
    RelayParams params;
    params.proxy = proxy.endpoint();
    RelayServer relay;
    EXPECT_TRUE(relay.start(params, 0, [](uint32_t, uint16_t) {
        RelayTarget t;
        t.origDst = {0xC0000201, 8443};
        t.allowTlsDomain = [](const std::string&) { return true; };
        return std::optional<RelayTarget>(t);
    }, nullptr));
    PreparedClient cli;
    EXPECT_TRUE(cli.bind());
    EXPECT_EQ(net::connectWithTimeout(cli.s, {0x7F000001, relay.listenPort()}, 2000, nullptr), 0);
    EXPECT_TRUE(waitUntil([&] { return relay.activeSessions() == 1; }, 1000));
    relay.stop();
    EXPECT_EQ(relay.counters.aborted.load(), 1u);
    EXPECT_EQ(proxy.requestCount(), 0u);
    proxy.stop();
}

APS_TEST_MAIN();
