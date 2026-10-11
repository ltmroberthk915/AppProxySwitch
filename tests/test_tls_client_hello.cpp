#include "aps/tls_client_hello.hpp"
#include "tls_fixture.hpp"
#include "testlib/appsw_test.h"

using namespace aps;

APS_TEST(tls, extracts_sni_and_normalizes_case) {
    const auto data = test::tlsHello("Api.Example.INVALID");
    const auto name = tls::inspectClientHello(data.data(), data.size());
    EXPECT_EQ(static_cast<int>(name.state), static_cast<int>(tls::HelloState::Name));
    EXPECT_STREQ(name.name, "api.example.invalid");
}

APS_TEST(tls, every_tcp_prefix_needs_more_until_complete) {
    const auto data = test::tlsHello("fragment.example.invalid");
    for (size_t n = 0; n < data.size(); ++n) {
        EXPECT_EQ(static_cast<int>(tls::inspectClientHello(data.data(), n).state),
                  static_cast<int>(tls::HelloState::NeedMore));
    }
}

APS_TEST(tls, handshake_can_span_many_records) {
    for (size_t fragment : {1u, 3u, 17u, 40u}) {
        const auto data = test::tlsRecords(test::tlsHandshake("record.example.invalid"), fragment);
        const auto name = tls::inspectClientHello(data.data(), data.size());
        EXPECT_STREQ(name.name, "record.example.invalid");
    }
}

APS_TEST(tls, unknown_ech_extension_does_not_authorize_its_outer_name) {
    // Parsing an outer name is not permission to use it. The relay's DNS
    // correlation rejects a cover name that is absent from the DNS answer.
    const auto data = test::tlsHello("cover.example.invalid", true);
    EXPECT_STREQ(tls::inspectClientHello(data.data(), data.size()).name, "cover.example.invalid");
}

APS_TEST(tls, rejects_invalid_hostnames_and_duplicate_sni) {
    for (const std::string name : {"127.0.0.1", "[::1]", "bad/name", "a..b", "a.",
                                  "-a.test", "a-.test", "a b.test", "_a.test"}) {
        const auto data = test::tlsHello(name);
        EXPECT_EQ(static_cast<int>(tls::inspectClientHello(data.data(), data.size()).state),
                  static_cast<int>(tls::HelloState::NoName));
    }
    for (const auto& name : {std::string("a\0b.test", 8), std::string(64, 'a') + ".test"}) {
        const auto data = test::tlsHello(name);
        EXPECT_TRUE(tls::inspectClientHello(data.data(), data.size()).name.empty());
    }
    const auto duplicate = test::tlsRecords(test::tlsHandshake("a.test", false, true));
    EXPECT_TRUE(tls::inspectClientHello(duplicate.data(), duplicate.size()).name.empty());
}

APS_TEST(tls, handles_non_tls_missing_sni_and_oversized_input) {
    const uint8_t http[] = {'G', 'E', 'T', ' '};
    EXPECT_EQ(static_cast<int>(tls::inspectClientHello(http, sizeof(http)).state),
              static_cast<int>(tls::HelloState::NoName));
    const auto noSni = test::tlsHello("");
    EXPECT_TRUE(tls::inspectClientHello(noSni.data(), noSni.size()).name.empty());
    const std::vector<uint8_t> tooBig(tls::kMaxClientHelloBytes + 1, 0);
    EXPECT_TRUE(tls::inspectClientHello(tooBig.data(), tooBig.size()).name.empty());
    const uint8_t hugeRecord[] = {22, 3, 3, 0xff, 0xff};
    EXPECT_EQ(static_cast<int>(tls::inspectClientHello(hugeRecord, sizeof(hugeRecord)).state),
              static_cast<int>(tls::HelloState::NoName));
}

APS_TEST(tls, ignores_trailing_payload_but_rejects_malformed_lengths) {
    auto data = test::tlsHello("a.test");
    data.insert(data.end(), {23, 3, 3, 0, 2, 5, 6});
    EXPECT_STREQ(tls::inspectClientHello(data.data(), data.size()).name, "a.test");
    auto hello = test::tlsHandshake("a.test");
    hello[38] = 255;  // invalid session ID length
    data = test::tlsRecords(hello);
    EXPECT_TRUE(tls::inspectClientHello(data.data(), data.size()).name.empty());
    hello = test::tlsHandshake("a.test");
    hello[2] = 0xff;  // huge handshake size
    data = test::tlsRecords(hello);
    EXPECT_TRUE(tls::inspectClientHello(data.data(), data.size()).name.empty());
}

APS_TEST_MAIN();
