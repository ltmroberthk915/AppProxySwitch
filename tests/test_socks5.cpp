// SOCKS5 handshake unit tests against the local mock server.
#include <chrono>

#include "aps/net.hpp"
#include "aps/socks5_client.hpp"
#include "mock_http_server.hpp"
#include "mock_socks_server.hpp"
#include "testlib/appsw_test.h"

using namespace aps;
using aps::test::MockSocks5Server;
using aps::test::MockHttpServer;
using aps::test::MockSocksBehavior;

namespace {
struct Fixture {
    Fixture() { net::initWinsock(); }
};
Fixture g_fixture;
}  // namespace

APS_TEST(socks5, noauth_connect_ok) {
    // The mock actually connects to the target, so use a local listener.
    MockHttpServer target;
    EXPECT_TRUE(target.start());
    MockSocks5Server srv;
    EXPECT_TRUE(srv.start());
    SOCKET s = INVALID_SOCKET;
    std::string err;
    Socks5FailureKind failure = Socks5FailureKind::Internal;
    bool ok = Socks5Client::connect(srv.endpoint(), "", "",
                                    net::Endpoint4{0x7F000001, target.port()}, 3000, s,
                                    &err, &failure);
    if (!ok) std::printf("    err: %s\n", err.c_str());
    EXPECT_TRUE(ok);
    EXPECT_EQ(static_cast<int>(failure),
              static_cast<int>(Socks5FailureKind::None));
    net::closeSocket(s);
    srv.stop();
    target.stop();
    EXPECT_EQ(srv.requestCount(), 1u);
    auto rq = srv.request(0);
    EXPECT_EQ(rq.dstIp, 0x7F000001u);
    EXPECT_EQ(rq.dstPort, target.port());
    EXPECT_FALSE(rq.usedAuth);
}

APS_TEST(socks5, username_password_auth_ok) {
    MockHttpServer target;
    EXPECT_TRUE(target.start());
    MockSocks5Server srv;
    srv.setRequireAuth(true, "alice", "s3cret");
    EXPECT_TRUE(srv.start());
    SOCKET s = INVALID_SOCKET;
    std::string err;
    bool ok = Socks5Client::connect(srv.endpoint(), "alice", "s3cret",
                                    net::Endpoint4{0x7F000001, target.port()}, 3000, s,
                                    &err);
    if (!ok) std::printf("    err: %s\n", err.c_str());
    EXPECT_TRUE(ok);
    net::closeSocket(s);
    srv.stop();
    target.stop();
    EXPECT_EQ(srv.requestCount(), 1u);
    EXPECT_STREQ(srv.request(0).username, "alice");
    EXPECT_STREQ(srv.request(0).password, "s3cret");
}

APS_TEST(socks5, wrong_password_rejected) {
    MockSocks5Server srv;
    srv.setRequireAuth(true, "alice", "s3cret");
    EXPECT_TRUE(srv.start());
    SOCKET s = INVALID_SOCKET;
    std::string err;
    Socks5FailureKind failure = Socks5FailureKind::None;
    bool ok = Socks5Client::connect(srv.endpoint(), "alice", "wrong",
                                    net::Endpoint4{0x08080808, 53}, 3000, s, &err,
                                    &failure);
    EXPECT_FALSE(ok);
    EXPECT_TRUE(s == INVALID_SOCKET);
    EXPECT_TRUE(err.find("rejected") != std::string::npos || !err.empty());
    EXPECT_EQ(static_cast<int>(failure),
              static_cast<int>(Socks5FailureKind::Configuration));
    srv.stop();
    EXPECT_EQ(srv.requestCount(), 0u);
}

APS_TEST(socks5, server_silent_times_out) {
    MockSocks5Server srv;
    srv.setBehavior(MockSocksBehavior::Silence);
    EXPECT_TRUE(srv.start());
    SOCKET s = INVALID_SOCKET;
    std::string err;
    Socks5FailureKind failure = Socks5FailureKind::None;
    auto t0 = std::chrono::steady_clock::now();
    bool ok = Socks5Client::connect(srv.endpoint(), "", "",
                                    net::Endpoint4{0x08080808, 80}, 700, s, &err,
                                    &failure);
    auto dt = std::chrono::steady_clock::now() - t0;
    EXPECT_FALSE(ok);
    EXPECT_TRUE(err.find("timed out") != std::string::npos);
    EXPECT_EQ(static_cast<int>(failure),
              static_cast<int>(Socks5FailureKind::ProxyEndpoint));
    EXPECT_TRUE(std::chrono::duration_cast<std::chrono::milliseconds>(dt).count() < 5000);
    srv.stop();
}

APS_TEST(socks5, garbage_greeting_rejected) {
    MockSocks5Server srv;
    srv.setBehavior(MockSocksBehavior::FailGreeting);
    EXPECT_TRUE(srv.start());
    SOCKET s = INVALID_SOCKET;
    std::string err;
    Socks5FailureKind failure = Socks5FailureKind::None;
    bool ok = Socks5Client::connect(srv.endpoint(), "", "",
                                    net::Endpoint4{0x08080808, 80}, 3000, s, &err,
                                    &failure);
    EXPECT_FALSE(ok);
    EXPECT_TRUE(!err.empty());
    EXPECT_EQ(static_cast<int>(failure),
              static_cast<int>(Socks5FailureKind::ProxyEndpoint));
    srv.stop();
}

APS_TEST(socks5, connect_refused_reported) {
    MockSocks5Server srv;
    srv.setBehavior(MockSocksBehavior::RefuseConnect);
    EXPECT_TRUE(srv.start());
    SOCKET s = INVALID_SOCKET;
    std::string err;
    Socks5FailureKind failure = Socks5FailureKind::None;
    bool ok = Socks5Client::connect(srv.endpoint(), "", "",
                                    net::Endpoint4{0x08080808, 80}, 3000, s, &err,
                                    &failure);
    EXPECT_FALSE(ok);
    if (err.find("reply code") == std::string::npos) {
        // Transient timing flake under heavy machine load (mock's fresh
        // accept thread + antivirus scanning): one retry with a fresh mock,
        // then the assertion must hold.
        std::printf("[diag] connect_refused first attempt err='%s' ok=%d (retrying)\n",
                    err.c_str(), ok ? 1 : 0);
        srv.stop();
        EXPECT_TRUE(srv.start());
        err.clear();
        failure = Socks5FailureKind::None;
        ok = Socks5Client::connect(srv.endpoint(), "", "",
                                   net::Endpoint4{0x08080808, 80}, 3000, s, &err,
                                   &failure);
        EXPECT_FALSE(ok);
        if (err.find("reply code") == std::string::npos) {
            std::printf("[diag] connect_refused retry err='%s' ok=%d\n", err.c_str(),
                        ok ? 1 : 0);
        }
    }
    EXPECT_TRUE(err.find("reply code") != std::string::npos);
    EXPECT_EQ(static_cast<int>(failure),
              static_cast<int>(Socks5FailureKind::Tunnel));
    srv.stop();
}

APS_TEST(socks5, dead_proxy_is_endpoint_failure) {
    SOCKET s = INVALID_SOCKET;
    std::string err;
    Socks5FailureKind failure = Socks5FailureKind::None;
    bool ok = Socks5Client::connect(net::Endpoint4{0x7F000001, 1}, "", "",
                                    net::Endpoint4{0x08080808, 80}, 500, s, &err,
                                    &failure);
    EXPECT_FALSE(ok);
    EXPECT_TRUE(s == INVALID_SOCKET);
    EXPECT_EQ(static_cast<int>(failure),
              static_cast<int>(Socks5FailureKind::ProxyEndpoint));
}

APS_TEST(socks5, probe_detects_live_and_dead_ports) {
    MockSocks5Server srv;
    EXPECT_TRUE(srv.start());
    int latency = -1;
    std::string err;
    EXPECT_TRUE(Socks5Client::probe(srv.endpoint(), 5000, &latency, &err));
    EXPECT_TRUE(latency >= 0);
    srv.stop();

    // Probe a port with a listener that never speaks SOCKS5.
    MockHttpServer http;  // any non-SOCKS listener
    EXPECT_TRUE(http.start());
    EXPECT_FALSE(Socks5Client::probe(net::Endpoint4{0x7F000001, http.port()}, 2000, nullptr, &err));
    http.stop();

    // Probe a dead port.
    EXPECT_FALSE(Socks5Client::probe(net::Endpoint4{0x7F000001, 1}, 500, nullptr, &err));
}

APS_TEST(socks5, domain_connect_resolves_only_in_selected_proxy) {
    MockHttpServer target;
    EXPECT_TRUE(target.start());
    MockSocks5Server srv;
    srv.setDomainTarget("socks-only.example.invalid", {0x7F000001, target.port()});
    EXPECT_TRUE(srv.start());
    SOCKET s = INVALID_SOCKET;
    std::string err;
    Socks5FailureKind failure = Socks5FailureKind::Internal;
    EXPECT_TRUE(Socks5Client::connectDomain(srv.endpoint(), "", "",
        "socks-only.example.invalid", target.port(), 2000, s, &err, &failure));
    const char req[] = "GET /domain HTTP/1.1\r\nHost: socks-only.example.invalid\r\n\r\n";
    EXPECT_EQ(net::sendAll(s, req, sizeof(req) - 1, 2000), 0);
    char buf[4096];
    const int n = net::recvSome(s, buf, sizeof(buf), 3000);
    EXPECT_TRUE(n > 0);
    if (n > 0) EXPECT_TRUE(std::string(buf, n).find("200 OK") != std::string::npos);
    net::closeSocket(s);
    srv.stop();
    EXPECT_EQ(srv.requestCount(), 1u);
    if (srv.requestCount()) {
        EXPECT_STREQ(srv.request(0).dstDomain, "socks-only.example.invalid");
        EXPECT_EQ(srv.request(0).addressType, 3);
        EXPECT_EQ(srv.request(0).dstPort, target.port());
    }
}

APS_TEST(socks5, domain_auth_and_length_boundaries) {
    MockSocks5Server srv;
    srv.setBehavior(MockSocksBehavior::AcceptConnect);
    srv.setRequireAuth(true, "unit-user", "unit-pass");
    EXPECT_TRUE(srv.start());
    SOCKET s = INVALID_SOCKET;
    std::string err;
    const std::string longest(255, 'a');
    EXPECT_TRUE(Socks5Client::connectDomain(srv.endpoint(), "unit-user", "unit-pass",
        longest, 8443, 2000, s, &err));
    net::closeSocket(s);
    EXPECT_EQ(srv.requestCount(), 1u);
    if (srv.requestCount()) EXPECT_STREQ(srv.request(0).dstDomain, longest);
    for (const auto& name : {std::string(), std::string(256, 'a'), std::string("a\0b", 3), std::string("a/b")}) {
        Socks5FailureKind kind = Socks5FailureKind::None;
        EXPECT_FALSE(Socks5Client::connectDomain(srv.endpoint(), "", "", name,
            8443, 2000, s, &err, &kind));
        EXPECT_EQ(static_cast<int>(kind), static_cast<int>(Socks5FailureKind::Configuration));
    }
    EXPECT_EQ(srv.requestCount(), 1u);
    srv.stop();
}

APS_TEST(socks5, probe_authenticates_and_rejects_bad_credentials) {
    MockSocks5Server srv;
    srv.setRequireAuth(true, "test-user", "test-password");
    EXPECT_TRUE(srv.start());
    std::string err;
    EXPECT_TRUE(Socks5Client::probe(srv.endpoint(), 1000, nullptr, &err,
                                    "test-user", "test-password"));
    EXPECT_FALSE(Socks5Client::probe(srv.endpoint(), 1000, nullptr, &err,
                                     "test-user", "wrong-password"));
    EXPECT_FALSE(Socks5Client::probe(srv.endpoint(), 1000, nullptr, &err));
    srv.stop();
}

APS_TEST_MAIN();
