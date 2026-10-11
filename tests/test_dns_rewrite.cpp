// DNS query/response rewrite unit tests (anti-pollution filter core).
#include <cstring>

#include "aps/dns_rewrite.hpp"
#include "testlib/appsw_test.h"

using namespace aps;

namespace {

// Builds a minimal DNS A query packet for `name` (classic root pointer form).
std::vector<uint8_t> buildQuery(const std::string& name, uint16_t id = 0x1234) {
    std::vector<uint8_t> pkt(12 + name.size() + 2 + 4, 0);
    pkt[0] = static_cast<uint8_t>(id >> 8);
    pkt[1] = static_cast<uint8_t>(id & 0xFF);
    pkt[2] = 0x01; pkt[3] = 0x00;  // RD
    pkt[5] = 1;                    // QDCOUNT=1
    size_t pos = 12;
    size_t start = 0;
    while (start <= name.size()) {
        size_t dot = name.find('.', start);
        size_t labelLen = dot == std::string::npos ? name.size() - start : dot - start;
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

}  // namespace

APS_TEST(dnsrw, parse_simple_a_query) {
    auto pkt = buildQuery("chatgpt.com");
    auto q = dns::parseAQuery(pkt.data(), pkt.size());
    EXPECT_TRUE(q.has_value());
    if (q) {
        EXPECT_EQ(q->id, 0x1234);
        EXPECT_STREQ(q->name, "chatgpt.com");
    }
}

APS_TEST(dnsrw, parse_rejects_non_a_and_replies) {
    auto pkt = buildQuery("chatgpt.com");
    // Corrupt QTYPE to AAAA.
    pkt[pkt.size() - 4] = 0; pkt[pkt.size() - 3] = 28;
    EXPECT_FALSE(dns::parseAQuery(pkt.data(), pkt.size()).has_value());
    // QR bit set (a reply, not a query).
    auto pkt2 = buildQuery("chatgpt.com");
    pkt2[2] = 0x81;
    EXPECT_FALSE(dns::parseAQuery(pkt2.data(), pkt2.size()).has_value());
    // Multi-question.
    auto pkt3 = buildQuery("chatgpt.com");
    pkt3[5] = 2;
    EXPECT_FALSE(dns::parseAQuery(pkt3.data(), pkt3.size()).has_value());
    // Truncated.
    EXPECT_FALSE(dns::parseAQuery(pkt.data(), 20).has_value());
    // Garbage.
    std::vector<uint8_t> junk(64, 0xFF);
    EXPECT_FALSE(dns::parseAQuery(junk.data(), junk.size()).has_value());
    // A question name pointing to itself must be rejected, not recurse.
    auto selfPtr = buildQuery("x.com");
    selfPtr[12] = 0xC0;
    selfPtr[13] = 0x0C;
    EXPECT_FALSE(dns::parseQuery(selfPtr.data(), selfPtr.size()).has_value());
}

APS_TEST(dnsrw, parse_aaaa_and_build_nodata_response) {
    auto pkt = buildQuery("chatgpt.com", 0xCAFE);
    pkt[pkt.size() - 4] = 0;
    pkt[pkt.size() - 3] = 28;  // AAAA
    auto q = dns::parseQuery(pkt.data(), pkt.size());
    EXPECT_TRUE(q.has_value());
    if (!q) return;
    EXPECT_EQ(q->id, 0xCAFE);
    EXPECT_EQ(q->type, 28);
    EXPECT_TRUE(q->recursionDesired);
    EXPECT_STREQ(q->name, "chatgpt.com");

    uint8_t resp[512];
    size_t rl = dns::buildNoDataResponse(*q, resp, sizeof(resp));
    EXPECT_EQ(rl, pkt.size());
    EXPECT_EQ(resp[0], 0xCA);
    EXPECT_EQ(resp[1], 0xFE);
    EXPECT_EQ(resp[2], 0x81);  // QR + echoed RD
    EXPECT_EQ(resp[3], 0x80);  // RA + NOERROR
    EXPECT_EQ(resp[5], 1);     // one question
    EXPECT_EQ(resp[7], 0);     // zero answers
    EXPECT_EQ(resp[rl - 4], 0);
    EXPECT_EQ(resp[rl - 3], 28);
    EXPECT_EQ(resp[rl - 2], 0);
    EXPECT_EQ(resp[rl - 1], 1);
    EXPECT_EQ(dns::buildNoDataResponse(*q, resp, 10), 0u);
}

APS_TEST(dnsrw, build_response_roundtrip) {
    auto pkt = buildQuery("chatgpt.com", 0xAB12);
    auto q = dns::parseAQuery(pkt.data(), pkt.size());
    ASSERT_NOT_NEEDED: ;
    EXPECT_TRUE(q.has_value());
    if (!q) return;

    std::vector<uint32_t> ips = {0xAE24C4F2, 0x6816A6A0};  // 174.36.196.242, 104.22.166.160
    uint8_t resp[512];
    size_t rl = dns::buildAResponse(*q, ips, resp, sizeof(resp));
    EXPECT_TRUE(rl > 0);

    // Header: QR=1, RA=1, QDCOUNT=1, ANCOUNT=2, id echoed.
    EXPECT_EQ(resp[0], 0xAB);
    EXPECT_EQ(resp[1], 0x12);
    EXPECT_EQ(resp[2], 0x81);
    EXPECT_EQ(resp[3], 0x80);
    EXPECT_EQ(resp[5], 1);
    EXPECT_EQ(resp[7], 2);

    // Find the first answer's data bytes and verify the IP.
    // Question length: label bytes (name minus dots) + one length byte per
    // label (dots+1) + root (1) + qtype/qclass (4) = name.size() + 6.
    std::string name = q->name;
    size_t qLen = name.size() + 6;
    size_t ans = 12 + qLen;
    EXPECT_EQ(resp[ans], 0xC0);        // compression pointer
    EXPECT_EQ(resp[ans + 1], 0x0C);    // -> offset 12
    EXPECT_EQ(resp[ans + 2], 0); EXPECT_EQ(resp[ans + 3], 1);  // type A
    uint8_t exp1[4] = {0xAE, 0x24, 0xC4, 0xF2};
    EXPECT_EQ(memcmp(&resp[ans + 12], exp1, 4), 0);
    uint8_t exp2[4] = {0x68, 0x16, 0xA6, 0xA0};
    EXPECT_EQ(memcmp(&resp[ans + 28], exp2, 4), 0);
}

APS_TEST(dnsrw, build_response_caps_and_empty) {
    auto pkt = buildQuery("chatgpt.com");
    auto q = dns::parseAQuery(pkt.data(), pkt.size());
    EXPECT_TRUE(q.has_value());
    if (!q) return;
    uint8_t small[10];
    EXPECT_EQ(dns::buildAResponse(*q, {0x01020304}, small, sizeof(small)), 0u);
    EXPECT_EQ(dns::buildAResponse(*q, {}, small, sizeof(small)), 0u);
}

APS_TEST(dnsrw, reverse_lookup_finds_name) {
    dns::DnsCache c;
    c["chatgpt.com"] = {{0xAE24C4F2, 0x6816A6A0}, 1000};
    c["example.com"] = {{0x5DB8D822}, 1000};
    auto r = dns::reverseLookup(c, 0x6816A6A0, 500);
    EXPECT_TRUE(r.has_value());
    if (r) EXPECT_STREQ(*r, "chatgpt.com");
}

APS_TEST(dnsrw, reverse_lookup_skips_expired) {
    dns::DnsCache c;
    c["chatgpt.com"] = {{0xAE24C4F2}, 1000};  // expires at 1000
    EXPECT_FALSE(dns::reverseLookup(c, 0xAE24C4F2, 1000).has_value());
    EXPECT_TRUE(dns::reverseLookup(c, 0xAE24C4F2, 999).has_value());
}

APS_TEST(dnsrw, reverse_lookup_missing_returns_nullopt) {
    dns::DnsCache c;
    c["chatgpt.com"] = {{0xAE24C4F2}, 1000};
    EXPECT_FALSE(dns::reverseLookup(c, 0x01020304, 500).has_value());
    EXPECT_FALSE(dns::reverseLookup({}, 0x01020304, 500).has_value());
}

APS_TEST(dnsrw, parse_a_records_with_pointer_compression) {
    // DNS response: one question, two A answers with pointer-compressed
    // names (0xC00C -> the question name at offset 12).
    std::vector<uint8_t> pkt;
    // Header: id 0x1234, flags 0x8180, qd=1, an=2.
    const uint8_t hdr[12] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02,
                             0x00, 0x00, 0x00, 0x00};
    pkt.insert(pkt.end(), hdr, hdr + 12);
    // Question: x.com A IN.
    const uint8_t q[17] = {1, 'x', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
    pkt.insert(pkt.end(), q, q + 11);
    // Answer 1: pointer name, A, IN, ttl 60, 1.2.3.4.
    const uint8_t a1[16] = {0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
                            0x00, 0x3C, 0x00, 0x04, 1, 2, 3, 4};
    pkt.insert(pkt.end(), a1, a1 + 16);
    // Answer 2: pointer name, A, IN, ttl 60, 5.6.7.8.
    const uint8_t a2[16] = {0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
                            0x00, 0x3C, 0x00, 0x04, 5, 6, 7, 8};
    pkt.insert(pkt.end(), a2, a2 + 16);
    auto ips = dns::parseARecords(pkt.data(), pkt.size());
    EXPECT_EQ(ips.size(), 2u);
    if (ips.size() == 2) {
        EXPECT_EQ(ips[0], 0x01020304u);
        EXPECT_EQ(ips[1], 0x05060708u);
    }
    // Truncated packets must not crash / return nothing.
    EXPECT_TRUE(dns::parseARecords(pkt.data(), 10).empty());
}

APS_TEST(dnsrw, reverse_lookup_prefers_first_match) {
    dns::DnsCache c;
    c["aaa.com"] = {{0xAE24C4F2}, 1000};
    c["zzz.com"] = {{0xAE24C4F2}, 1000};  // same IP under two names
    auto r = dns::reverseLookup(c, 0xAE24C4F2, 500);
    EXPECT_TRUE(r.has_value());
    if (r) EXPECT_STREQ(*r, "aaa.com");  // map order
}

APS_TEST(dnsrw, sni_correlation_does_not_guess_from_shared_or_poisoned_ip) {
    dns::DnsCache c;
    c["a.example.invalid"] = {{0xC0000201}, 1000};
    c["B.Example.Invalid"] = {{0xC0000201, 0xC0000202}, 1000};
    EXPECT_TRUE(dns::nameHasAddress(c, "b.example.invalid", 0xC0000201, 500));
    EXPECT_TRUE(dns::nameHasAddress(c, "B.EXAMPLE.INVALID", 0xC0000202, 500));
    EXPECT_FALSE(dns::nameHasAddress(c, "cover.example.invalid", 0xC0000201, 500));
    EXPECT_FALSE(dns::nameHasAddress(c, "a.example.invalid", 0xC0000202, 500));
    EXPECT_TRUE(dns::nameHasAddress(c, "a.example.invalid", 0xC0000201, 1000 + dns::kStaleGraceMs));
    EXPECT_FALSE(dns::nameHasAddress(c, "a.example.invalid", 0xC0000201, 1001 + dns::kStaleGraceMs));
}

APS_TEST(dnsrw, native_answer_rejects_errors_truncation_and_unrelated_records) {
    uint8_t out[512];
    const size_t n = dns::buildAResponse({0x1234, "Api.Example.com"}, {0x01020304}, out, sizeof(out));
    auto r = dns::parseAResponse(out, n);
    EXPECT_TRUE(r.has_value());
    if (r) {
        EXPECT_STREQ(r->name, "api.example.com");
        EXPECT_EQ(r->ips.size(), 1u);
        EXPECT_EQ(r->ips[0], 0x01020304u);
        EXPECT_EQ(r->ttl, 60u);
    }
    out[3] |= 5;
    EXPECT_FALSE(dns::parseAResponse(out, n).has_value());
    out[3] = 0x80;
    out[2] |= 2;
    EXPECT_FALSE(dns::parseAResponse(out, n).has_value());
    out[2] = 0x81;
    EXPECT_FALSE(dns::parseAResponse(out, n - 1).has_value());
    out[7] = 0; out[11] = 1; // A is additional data, not an answer
    EXPECT_FALSE(dns::parseAResponse(out, n).has_value());
    out[7] = 1; out[11] = 0;
    out[n - 15] = static_cast<uint8_t>(n - 16); // self-referencing name
    EXPECT_FALSE(dns::parseAResponse(out, n).has_value());
}

APS_TEST(dnsrw, native_answer_follows_only_question_cname_chain) {
    auto q = buildQuery("a.com");
    q[2] = 0x81; q[3] = 0x80; q[7] = 3;
    const uint8_t cname[] = {0xC0,12, 0,5, 0,1, 0,0,0,30, 0,7, 1,'b',3,'c','o','m',0};
    q.insert(q.end(), std::begin(cname), std::end(cname));
    const uint8_t related[] = {1,'b',3,'c','o','m',0, 0,1, 0,1, 0,0,0,60, 0,4, 1,2,3,4};
    q.insert(q.end(), std::begin(related), std::end(related));
    const uint8_t unrelated[] = {1,'z',3,'c','o','m',0, 0,1, 0,1, 0,0,0,60, 0,4, 9,9,9,9};
    q.insert(q.end(), std::begin(unrelated), std::end(unrelated));
    auto r = dns::parseAResponse(q.data(), q.size());
    EXPECT_TRUE(r.has_value());
    if (r) {
        EXPECT_EQ(r->ips.size(), 1u);
        EXPECT_EQ(r->ips[0], 0x01020304u);
        EXPECT_EQ(r->ttl, 30u);
    }
}

APS_TEST_MAIN();
