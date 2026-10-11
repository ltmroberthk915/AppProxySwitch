// Packet parse/rewrite/RST-synthesis tests (WinDivert helpers are pure
// user-mode calls; no driver or admin needed).
#include "aps/packet_rewrite.hpp"
#include "fake_divert_device.hpp"
#include "testlib/appsw_test.h"

using namespace aps;
using aps::test::buildTcpPacket;

APS_TEST(pkt, parse_and_rewrite_roundtrip) {
    auto raw = buildTcpPacket(0xC0A80105, 5000, 0x08080808, 443, 100, 0,
                              /*SYN*/ 0x02, {'h', 'i'});
    pkt::TcpPacket p;
    EXPECT_TRUE(pkt::parseTcpPacket(raw.data(), raw.size(), p));
    EXPECT_EQ(p.srcIp, 0xC0A80105u);
    EXPECT_EQ(p.srcPort, 5000);
    EXPECT_EQ(p.dstIp, 0x08080808u);
    EXPECT_EQ(p.dstPort, 443);
    EXPECT_TRUE(p.syn);
    EXPECT_FALSE(p.ackFlag);
    EXPECT_EQ(p.payloadLen, 2u);

    // Redirect: dst becomes the local relay listener.
    pkt::rewriteDst(p, 0x7F000001, 12753);
    pkt::recalcChecksums(raw.data(), raw.size());
    pkt::TcpPacket p2;
    EXPECT_TRUE(pkt::parseTcpPacket(raw.data(), raw.size(), p2));
    EXPECT_EQ(p2.dstIp, 0x7F000001u);
    EXPECT_EQ(p2.dstPort, 12753);
    EXPECT_EQ(p2.srcIp, 0xC0A80105u);   // source untouched
    EXPECT_EQ(p2.srcPort, 5000);
    EXPECT_EQ(p2.payloadLen, 2u);       // payload preserved

    // Return path: src becomes the original destination.
    pkt::rewriteSrc(p2, 0x08080808, 443);
    pkt::recalcChecksums(raw.data(), raw.size());
    pkt::TcpPacket p3;
    EXPECT_TRUE(pkt::parseTcpPacket(raw.data(), raw.size(), p3));
    EXPECT_EQ(p3.srcIp, 0x08080808u);
    EXPECT_EQ(p3.srcPort, 443);
    EXPECT_EQ(p3.dstIp, 0x7F000001u);
}

APS_TEST(pkt, checksums_valid_after_rewrite) {
    auto raw = buildTcpPacket(0xC0A80105, 5000, 0x08080808, 443, 1, 1, 0x18 /*PSH|ACK*/,
                              std::vector<uint8_t>(1400, 'x'));
    pkt::TcpPacket p;
    EXPECT_TRUE(pkt::parseTcpPacket(raw.data(), raw.size(), p));
    pkt::rewriteDst(p, 0x7F000001, 12753);
    pkt::recalcChecksums(raw.data(), raw.size());

    // Recomputing again must not change the packet (idempotence == valid).
    auto after1 = raw;
    pkt::recalcChecksums(raw.data(), raw.size());
    EXPECT_EQ(memcmp(after1.data(), raw.data(), raw.size()), 0);
}

APS_TEST(pkt, next_seq_accounting) {
    // Pure SYN: consumes one sequence number.
    auto syn = buildTcpPacket(1, 1, 2, 2, 500, 0, 0x02);
    pkt::TcpPacket p;
    EXPECT_TRUE(pkt::parseTcpPacket(syn.data(), syn.size(), p));
    EXPECT_EQ(pkt::nextSeq(p), 501u);

    // 100 bytes of data: seq + len.
    auto data = buildTcpPacket(1, 1, 2, 2, 1000, 500, 0x18,
                               std::vector<uint8_t>(100, 0));
    EXPECT_TRUE(pkt::parseTcpPacket(data.data(), data.size(), p));
    EXPECT_EQ(pkt::nextSeq(p), 1100u);

    // FIN consumes one too.
    auto fin = buildTcpPacket(1, 1, 2, 2, 2000, 500, 0x11);
    EXPECT_TRUE(pkt::parseTcpPacket(fin.data(), fin.size(), p));
    EXPECT_EQ(pkt::nextSeq(p), 2001u);
}

APS_TEST(pkt, build_rst_parses_back) {
    uint8_t buf[64];
    size_t n = pkt::buildRst(0x08080808, 443, 0xC0A80105, 5000, 777, true, 0, buf,
                             sizeof(buf));
    EXPECT_EQ(n, 40u);
    pkt::TcpPacket p;
    EXPECT_TRUE(pkt::parseTcpPacket(buf, 40, p));
    EXPECT_TRUE(p.rst);
    EXPECT_TRUE(p.ackFlag);
    EXPECT_EQ(p.srcIp, 0x08080808u);
    EXPECT_EQ(p.srcPort, 443);
    EXPECT_EQ(p.dstIp, 0xC0A80105u);
    EXPECT_EQ(p.dstPort, 5000);
    EXPECT_EQ(p.seq, 777u);
    EXPECT_EQ(p.payloadLen, 0u);
}

APS_TEST(pkt, rejects_non_tcp_and_garbage) {
    pkt::TcpPacket p;
    std::vector<uint8_t> junk(60, 0xAB);
    EXPECT_FALSE(pkt::parseTcpPacket(junk.data(), junk.size(), p));
    EXPECT_FALSE(pkt::parseTcpPacket(nullptr, 0, p));
    // Truncated TCP header.
    auto raw = buildTcpPacket(1, 1, 2, 2, 0, 0, 0x02);
    EXPECT_FALSE(pkt::parseTcpPacket(raw.data(), 30, p));
}

APS_TEST_MAIN();
