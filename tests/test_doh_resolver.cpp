// WinHTTP DoH session lifetime tests. The proxy is a loopback-only mock and
// deliberately does not establish a real tunnel, so this test never reaches
// an external DNS or HTTPS endpoint.
#include <winsock2.h>

#include <string>
#include <vector>

#include "aps/doh_resolver.hpp"
#include "aps/net.hpp"
#include "mock_http_server.hpp"
#include "testlib/appsw_test.h"

using aps::test::MockHttpServer;

namespace {

struct WsaInit {
    WsaInit() { aps::net::initWinsock(); }
};
WsaInit g_wsa;

}  // namespace

APS_TEST(doh, session_is_reused_per_proxy_port_and_closed_explicitly) {
    aps::doh::closeHttpProxySessions();
    EXPECT_EQ(aps::doh::cachedHttpProxySessionCountForTest(), 0u);

    MockHttpServer proxyA;
    MockHttpServer proxyB;
    EXPECT_TRUE(proxyA.start());
    EXPECT_TRUE(proxyB.start());

    // 192.0.2.1 is TEST-NET-1. Every attempted CONNECT terminates at the
    // loopback mock above; a deliberately invalid tunnel response makes the
    // resolver fail fast without any external network access.
    constexpr uint32_t kTestNetIp = 0xC0000201;
    std::vector<uint32_t> ips;
    std::string err;
    EXPECT_FALSE(aps::doh::resolveViaHttpProxy(
        proxyA.port(), kTestNetIp, "one.test", ips, 300, &err));
    EXPECT_EQ(aps::doh::cachedHttpProxySessionCountForTest(), 1u);

    err.clear();
    EXPECT_FALSE(aps::doh::resolveViaHttpProxy(
        proxyA.port(), kTestNetIp, "two.test", ips, 300, &err));
    EXPECT_EQ(aps::doh::cachedHttpProxySessionCountForTest(), 1u);

    err.clear();
    EXPECT_FALSE(aps::doh::resolveViaHttpProxy(
        proxyB.port(), kTestNetIp, "three.test", ips, 300, &err));
    EXPECT_EQ(aps::doh::cachedHttpProxySessionCountForTest(), 2u);

    EXPECT_TRUE(proxyA.hits() >= 1u);
    EXPECT_TRUE(proxyB.hits() >= 1u);

    aps::doh::closeHttpProxySessions();
    EXPECT_EQ(aps::doh::cachedHttpProxySessionCountForTest(), 0u);
    aps::doh::closeHttpProxySessions();  // idempotent lifecycle cleanup
}

APS_TEST_MAIN();
