// NAT table: dual-key lookup, state-machine sweeps, port reuse replacement.
#include "aps/nat_table.hpp"
#include "aps/time_util.hpp"
#include "testlib/appsw_test.h"

using namespace aps;

APS_TEST(nat, create_find_both_directions) {
    NatTable t;
    auto e = t.create(0xC0A80105, 5000, 0x08080808, 443, "r1", "", 42, nowMs());
    EXPECT_TRUE(e != nullptr);
    EXPECT_EQ(t.size(), 1u);

    auto fwd = t.findByFwd(0xC0A80105, 5000, 0x08080808, 443);
    EXPECT_TRUE(fwd == e);
    // Wrong original destination must NOT match forward.
    EXPECT_TRUE(t.findByFwd(0xC0A80105, 5000, 0x08080808, 80) == nullptr);
    // Reverse key is the (app ip:port) two-tuple.
    auto rev = t.findByRev(0xC0A80105, 5000);
    EXPECT_TRUE(rev == e);
}

APS_TEST(nat, find_by_port_fallback) {
    // The relay's fallback when loopback delivery reports the rewritten
    // SYN's source as 127.0.0.1 (kernels' TUN down): the app port is
    // unique among active flows, so a port-only lookup must find the entry
    // regardless of the reported source IP (2026-08-27 incident: every
    // proxied flow died the moment the SakuraCat TUN went away).
    NatTable t;
    auto a = t.create(0xC0A80504, 62092, 0x08080808, 443, "r1", "", 100, 0);
    auto b = t.create(0xC0A80504, 62093, 0x08080808, 443, "r1", "", 100, 0);
    EXPECT_TRUE(a != nullptr && b != nullptr);
    // Direct reverse lookup still works.
    EXPECT_TRUE(t.findByRev(0xC0A80504, 62092) == a);
    // Port-only fallback finds the right entry per port.
    EXPECT_TRUE(t.findByPort(62092) == a);
    EXPECT_TRUE(t.findByPort(62093) == b);
    EXPECT_TRUE(t.findByPort(62094) == nullptr);
}

APS_TEST(nat, port_reuse_replaces_stale_entry) {
    NatTable t;
    auto e1 = t.create(0xC0A80105, 5000, 0x08080808, 443, "r1", "", 1, nowMs());
    auto e2 = t.create(0xC0A80105, 5000, 0x09090909, 80, "r2", "", 2, nowMs());
    EXPECT_EQ(t.size(), 1u);
    EXPECT_TRUE(t.findByRev(0xC0A80105, 5000) == e2);
    EXPECT_TRUE(t.findByFwd(0xC0A80105, 5000, 0x09090909, 80) == e2);
    EXPECT_TRUE(t.findByFwd(0xC0A80105, 5000, 0x08080808, 443) == nullptr);
    (void)e1;
}

APS_TEST(nat, sweep_synsent_timeout) {
    NatTable t;
    NatSweepConfig cfg;
    cfg.synTimeoutMs = 30000;
    int64_t now = nowMs();
    t.create(0xC0A80105, 5000, 0x08080808, 443, "r1", "", 1, now);
    EXPECT_EQ(t.sweep(now + 1000, cfg).size(), 0u);
    auto removed = t.sweep(now + 31000, cfg);
    EXPECT_EQ(removed.size(), 1u);
    EXPECT_EQ(t.size(), 0u);
}

APS_TEST(nat, sweep_relay_closed_removes_established) {
    NatTable t;
    NatSweepConfig cfg;
    int64_t now = nowMs();
    auto e = t.create(0xC0A80105, 5000, 0x08080808, 443, "r1", "", 1, now);
    e->state.store(static_cast<int32_t>(NatState::Established));
    EXPECT_EQ(t.sweep(now + 1000, cfg).size(), 0u);   // idle timeout is huge
    e->onClosed();                                     // relay session finished
    EXPECT_EQ(t.sweep(now + 1000, cfg).size(), 1u);
}

APS_TEST(nat, sweep_rst_and_fin_grace) {
    NatTable t;
    NatSweepConfig cfg;
    cfg.rstGraceMs = 2000;
    cfg.finGraceMs = 30000;
    int64_t now = nowMs();

    auto e1 = t.create(0xC0A80105, 5001, 0x08080808, 443, "r1", "", 1, now);
    e1->state.store(static_cast<int32_t>(NatState::Established));
    e1->rstSeen.store(true);
    EXPECT_EQ(t.sweep(now + 1000, cfg).size(), 0u);   // inside RST grace
    EXPECT_EQ(t.sweep(now + 3000, cfg).size(), 1u);

    auto e2 = t.create(0xC0A80105, 5002, 0x08080808, 443, "r1", "", 1, now);
    e2->state.store(static_cast<int32_t>(NatState::Established));
    e2->appFin.store(true);
    e2->state.store(static_cast<int32_t>(NatState::Closing));
    EXPECT_EQ(t.sweep(now + 1000, cfg).size(), 0u);   // inside FIN grace
    EXPECT_EQ(t.sweep(now + 31000, cfg).size(), 1u);
}

APS_TEST(nat, remove_returns_entry) {
    NatTable t;
    auto e = t.create(0xC0A80105, 5000, 0x08080808, 443, "r1", "", 1, nowMs());
    auto removed = t.remove(0xC0A80105, 5000);
    EXPECT_TRUE(removed == e);
    EXPECT_TRUE(t.remove(0xC0A80105, 5000) == nullptr);
}

APS_TEST(nat, bytes_counters_via_sink) {
    NatTable t;
    auto e = t.create(0xC0A80105, 5000, 0x08080808, 443, "r1", "", 1, nowMs());
    e->onBytes(100, 50);
    e->onBytes(10, 5);
    EXPECT_EQ(e->bytesUp.load(), 110u);
    EXPECT_EQ(e->bytesDown.load(), 55u);
}

APS_TEST_MAIN();
