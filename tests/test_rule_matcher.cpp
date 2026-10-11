// Rule matching + loop-exclusion logic.
#include "aps/rule_matcher.hpp"
#include "testlib/appsw_test.h"

using namespace aps;

namespace {
Config baseConfig() {
    Config c = Config::makeDefault();
    c.rules.clear();
    Rule r;
    r.id = "r1";
    r.name = "App";
    r.path = "C:\\Apps\\App\\App.exe";
    r.enabled = true;
    c.rules.push_back(r);
    return c;
}
}  // namespace

APS_TEST(rules, exact_path_match_case_insensitive) {
    auto m = RuleMatcher::compile(baseConfig(), L"C:\\Self\\AppProxySwitch.exe");
    auto d = m->decideTcp(L"c:\\apps\\app\\APP.exe", 0x08080808, 443);
    EXPECT_TRUE(d.action == RuleMatcher::Decision::Action::Proxy);
    EXPECT_STREQ(d.ruleId, "r1");
}

APS_TEST(rules, same_basename_different_dir_not_matched) {
    auto m = RuleMatcher::compile(baseConfig(), L"C:\\Self\\AppProxySwitch.exe");
    auto d = m->decideTcp(L"C:\\Other\\App.exe", 0x08080808, 443);
    EXPECT_TRUE(d.action == RuleMatcher::Decision::Action::Direct);
}

APS_TEST(rules, loop_protection_excludes_cores_and_self) {
    Config c = baseConfig();
    Rule clash;
    clash.id = "r2";
    clash.path = "C:\\Tools\\clash.exe";   // user tries to add clash itself
    c.rules.push_back(clash);
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");

    // clash.exe is excluded by builtin name even though a rule exists.
    EXPECT_TRUE(m->decideTcp(L"C:\\Tools\\clash.exe", 0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Direct);
    EXPECT_TRUE(m->decideTcp(L"C:\\Program Files\\mihomo.exe", 0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Direct);
    // The engine itself.
    EXPECT_TRUE(m->decideTcp(L"c:\\self\\appproxyswitch.exe", 0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Direct);
    // A differently-placed clash.exe with extra path exclusion.
    EXPECT_TRUE(m->isExcluded(L"C:\\Tools\\clash.exe"));
}

APS_TEST(rules, disabled_rule_is_direct) {
    Config c = baseConfig();
    c.rules[0].enabled = false;
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\App.exe", 0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Direct);
}

APS_TEST(rules, bypass_loopback_and_private) {
    auto m = RuleMatcher::compile(baseConfig(), L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\App.exe", 0x7F000001, 8080).action ==
                RuleMatcher::Decision::Action::Direct);   // 127/8
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\App.exe", 0xC0A80001, 80).action ==
                RuleMatcher::Decision::Action::Direct);   // 192.168/16
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\App.exe", 0x0A000001, 80).action ==
                RuleMatcher::Decision::Action::Direct);   // 10/8
    // With bypass_private off, LAN traffic is proxied.
    Config c = baseConfig();
    c.routing.bypassPrivate = false;
    auto m2 = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_TRUE(m2->decideTcp(L"C:\\Apps\\App\\App.exe", 0xC0A80001, 80).action ==
                RuleMatcher::Decision::Action::Proxy);
    // Public addresses always proxy.
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\App.exe", 0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Proxy);
}

APS_TEST(rules, tcp_dns_bridge_ignores_only_address_bypass) {
    Config c = baseConfig();
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    auto proxy = m->decideTcpDns(L"C:\\Apps\\App\\App.exe");
    EXPECT_TRUE(proxy.action == RuleMatcher::Decision::Action::Proxy);
    EXPECT_STREQ(proxy.ruleId, "r1");

    c.rules[0].action = "direct";
    auto direct = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe")
                      ->decideTcpDns(L"C:\\Apps\\App\\App.exe");
    EXPECT_TRUE(direct.action == RuleMatcher::Decision::Action::Direct);

    c.rules[0].action = "block";
    auto block = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe")
                     ->decideTcpDns(L"C:\\Apps\\App\\App.exe");
    EXPECT_TRUE(block.action == RuleMatcher::Decision::Action::Block);

    auto unrelated = m->decideTcpDns(L"C:\\Other\\other.exe");
    EXPECT_TRUE(unrelated.action == RuleMatcher::Decision::Action::Direct);
}

APS_TEST(rules, include_children_dir_prefix) {
    Config c = baseConfig();
    c.rules[0].includeChildren = true;
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\helper.exe", 0x08080808, 80).action ==
                RuleMatcher::Decision::Action::Proxy);
    // Outside the directory: no.
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App2\\helper.exe", 0x08080808, 80).action ==
                RuleMatcher::Decision::Action::Direct);
}

APS_TEST(rules, udp_blocking_semantics) {
    auto m = RuleMatcher::compile(baseConfig(), L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_TRUE(m->shouldBlockUdp(L"C:\\Apps\\App\\App.exe", 443));   // QUIC
    EXPECT_FALSE(m->shouldBlockUdp(L"C:\\Apps\\App\\App.exe", 53));   // DNS
    EXPECT_FALSE(m->shouldBlockUdp(L"C:\\Tools\\clash.exe", 443));    // excluded
    EXPECT_FALSE(m->shouldBlockUdp(L"C:\\Other\\unrelated.exe", 443));

    Config c = baseConfig();
    c.routing.blockUdpForRules = false;
    auto m2 = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_FALSE(m2->shouldBlockUdp(L"C:\\Apps\\App\\App.exe", 443));
}

APS_TEST(rules, static_exclusion_check_for_gui) {
    Config c = baseConfig();
    EXPECT_TRUE(RuleMatcher::isExcludedPath(c, L"C:\\Self\\AppProxySwitch.exe",
                                            L"C:\\Tools\\mihomo.exe"));
    EXPECT_FALSE(RuleMatcher::isExcludedPath(c, L"C:\\Self\\AppProxySwitch.exe",
                                             L"C:\\Apps\\App\\App.exe"));
}

APS_TEST(rules, block_rule_returns_block) {
    Config c = baseConfig();
    c.rules[0].action = "block";
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    auto d = m->decideTcp(L"C:\\Apps\\App\\App.exe", 0x08080808, 443);
    EXPECT_TRUE(d.action == RuleMatcher::Decision::Action::Block);
    EXPECT_STREQ(d.ruleId, "r1");  // ruleId set for stats/log attribution
}

APS_TEST(rules, direct_rule_returns_direct) {
    Config c = baseConfig();
    c.rules[0].action = "direct";
    // bypass flags OFF: a direct rule still forces direct.
    c.routing.bypassLoopback = false;
    c.routing.bypassPrivate = false;
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    auto d = m->decideTcp(L"C:\\Apps\\App\\App.exe", 0x08080808, 443);
    EXPECT_TRUE(d.action == RuleMatcher::Decision::Action::Direct);
    EXPECT_STREQ(d.ruleId, "r1");
}

APS_TEST(rules, block_wins_over_private_bypass) {
    Config c = baseConfig();
    c.rules[0].action = "block";
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    // bypass_private would normally short-circuit to Direct; an explicit
    // block rule still blocks (user intent beats bypass).
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\App.exe", 0xC0A80001, 80).action ==
                RuleMatcher::Decision::Action::Block);
}

APS_TEST(rules, disabled_block_rule_is_direct) {
    Config c = baseConfig();
    c.rules[0].action = "block";
    c.rules[0].enabled = false;
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\App.exe", 0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Direct);
}

APS_TEST(rules, excluded_process_never_blocked) {
    Config c = baseConfig();
    Rule clash;
    clash.id = "r2";
    clash.path = "C:\\Tools\\clash.exe";
    clash.action = "block";
    c.rules.push_back(clash);
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    // Exclusion (loop protection) beats even an explicit block rule.
    EXPECT_TRUE(m->decideTcp(L"C:\\Tools\\clash.exe", 0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Direct);
}

APS_TEST(rules, udp_block_action_drops_without_global_flag) {
    Config c = baseConfig();
    c.rules[0].action = "block";
    c.routing.blockUdpForRules = false;
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_TRUE(m->shouldBlockUdp(L"C:\\Apps\\App\\App.exe", 443));
}

APS_TEST(rules, udp_direct_action_never_drops) {
    Config c = baseConfig();
    c.rules[0].action = "direct";
    c.routing.blockUdpForRules = true;
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_FALSE(m->shouldBlockUdp(L"C:\\Apps\\App\\App.exe", 443));
}

APS_TEST(rules, udp_block_rule_still_exempts_dns) {
    Config c = baseConfig();
    c.rules[0].action = "block";
    c.routing.blockUdpForRules = false;
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_FALSE(m->shouldBlockUdp(L"C:\\Apps\\App\\App.exe", 53));
}

APS_TEST(rules, ipv6_classification_by_action) {
    Config c = baseConfig();  // action proxy
    c.rules[0].action = "proxy";
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_TRUE(m->isEnabledRuleProcess(L"C:\\Apps\\App\\App.exe"));
    Config b = baseConfig();
    b.rules[0].action = "block";
    auto mb = RuleMatcher::compile(b, L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_TRUE(mb->isEnabledRuleProcess(L"C:\\Apps\\App\\App.exe"));
    Config d = baseConfig();
    d.rules[0].action = "direct";
    auto md = RuleMatcher::compile(d, L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_FALSE(md->isEnabledRuleProcess(L"C:\\Apps\\App\\App.exe"));
}

APS_TEST(rules, rule_action_defaults_to_proxy_when_absent) {
    Config c = baseConfig();
    c.rules[0].action = "";  // legacy configs / hand-edited files
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\App.exe", 0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Proxy);
}

APS_TEST(rules, has_enabled_block_rule) {
    Config c = baseConfig();  // r1 action proxy
    EXPECT_FALSE(RuleMatcher::hasEnabledBlockRule(c));
    c.rules[0].action = "block";
    EXPECT_TRUE(RuleMatcher::hasEnabledBlockRule(c));
    c.rules[0].enabled = false;
    EXPECT_FALSE(RuleMatcher::hasEnabledBlockRule(c));
}

APS_TEST(rules, never_proxy_beats_proxy_rule) {
    auto m = RuleMatcher::compile(baseConfig(), L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\App.exe", 0xE00000FB, 5353).action ==
                RuleMatcher::Decision::Action::Direct);   // 224.0.0.251 mDNS
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\App.exe", 0xFFFFFFFF, 80).action ==
                RuleMatcher::Decision::Action::Direct);   // limited broadcast
}

APS_TEST(rules, never_proxy_beats_block_rule) {
    Config c = baseConfig();
    c.rules[0].action = "block";
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    // Network-critical traffic passes even under an explicit block rule.
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\App.exe", 0xE00000FB, 5353).action ==
                RuleMatcher::Decision::Action::Direct);
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\App.exe", 0xFFFFFFFF, 80).action ==
                RuleMatcher::Decision::Action::Direct);
    // ...but normal destinations are still blocked.
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\App.exe", 0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Block);
}

APS_TEST(rules, wildcard_matches_versioned_store_path) {
    // The rule that survives Store app auto-updates: the versioned install
    // dir is replaced by '*'.
    Config c = baseConfig();
    c.rules[0].path =
        "C:\\Program Files\\WindowsApps\\OpenAI.Codex*\\app\\ChatGPT.exe";
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    // Old and new versions both match.
    EXPECT_TRUE(m->decideTcp(
                    L"C:\\Program Files\\WindowsApps\\OpenAI.Codex_26.818.3698.0_x64__2p2nqsd0c76g0\\app\\ChatGPT.exe",
                    0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Proxy);
    EXPECT_TRUE(m->decideTcp(
                    L"C:\\Program Files\\WindowsApps\\OpenAI.Codex_99.999.9999.0_x64__2p2nqsd0c76g0\\app\\ChatGPT.exe",
                    0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Proxy);
    // includeChildren covers the whole app dir — including the Codex agent
    // sub-process that runs the "work mode" (chat mode vs work mode run on
    // DIFFERENT processes; a rule that misses the child = endless
    // "正在重新连接").
    EXPECT_TRUE(m->decideTcp(
                    L"C:\\Program Files\\WindowsApps\\OpenAI.Codex_26.818.3698.0_x64__2p2nqsd0c76g0\\app\\Helper.exe",
                    0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Proxy);
    EXPECT_TRUE(m->decideTcp(
                    L"C:\\Program Files\\WindowsApps\\OpenAI.Codex_26.818.3698.0_x64__2p2nqsd0c76g0\\app\\resources\\codex.exe",
                    0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Proxy);
    // A different package does not match.
    EXPECT_TRUE(m->decideTcp(
                    L"C:\\Program Files\\WindowsApps\\SomethingElse_1.0.0.0_x64__hash\\app\\ChatGPT.exe",
                    0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Direct);
    // includeChildren=false: the child no longer inherits the rule (with
    // the GLOBAL cover-dir switch off; it defaults to ON).
    Config c2 = baseConfig();
    c2.rules[0].path =
        "C:\\Program Files\\WindowsApps\\OpenAI.Codex*\\app\\ChatGPT.exe";
    c2.rules[0].includeChildren = false;
    c2.routing.coverAppDirAlways = false;
    auto m2 = RuleMatcher::compile(c2, L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_TRUE(m2->decideTcp(
                    L"C:\\Program Files\\WindowsApps\\OpenAI.Codex_26.818.3698.0_x64__2p2nqsd0c76g0\\app\\Helper.exe",
                    0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Direct);
}

APS_TEST(rules, wildcard_matches_and_case_folding) {
    Config c = baseConfig();
    c.rules[0].path = "C:\\tools\\prox*";
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    // '*' crosses separators; matching is case-insensitive.
    EXPECT_TRUE(m->decideTcp(L"C:\\TOOLS\\ProxySuite\\bin\\tool.exe", 0x08080808,
                             443).action == RuleMatcher::Decision::Action::Proxy);
}

APS_TEST(rules, wildcard_rule_never_captures_excluded) {
    Config c = baseConfig();
    c.rules[0].path = "C:\\Tools\\*";
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    // Loop protection beats wildcard matching.
    EXPECT_TRUE(m->decideTcp(L"C:\\Tools\\clash.exe", 0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Direct);
}

APS_TEST(rules, global_cover_dir_switch_forces_children) {
    // The global master switch (routing.cover_app_dir_always, default ON)
    // makes a per-rule checkbox left off harmless: children are always
    // covered until the user deliberately turns the GLOBAL switch off.
    Config c = baseConfig();
    c.rules[0].includeChildren = false;  // per-rule off
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\helper.exe", 0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Proxy);   // global ON wins
    c.routing.coverAppDirAlways = false;
    auto m2 = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    EXPECT_TRUE(m2->decideTcp(L"C:\\Apps\\App\\helper.exe", 0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Direct);  // global OFF: flag respected
}

APS_TEST(rules, exact_rule_overrides_earlier_dir_rule) {
    // Original precedence: a directory-wide rule sets the hit but a LATER
    // exact-path rule overrides it. (Regression: the tri-state refactor once
    // broke on ANY match, making the earlier dir rule win.)
    Config c = Config::makeDefault();
    c.rules.clear();
    Rule broad;
    broad.id = "broad";
    broad.name = "Broad";
    broad.path = "C:\\Apps\\App\\Main.exe";   // dir-cover (children) only
    broad.includeChildren = true;
    broad.action = "proxy";
    Rule exact;
    exact.id = "exact";
    exact.name = "Exact";
    exact.path = "C:\\Apps\\App\\App.exe";
    exact.includeChildren = false;
    exact.action = "block";
    c.rules.push_back(broad);
    c.rules.push_back(exact);
    // Test the original precedence semantics: the GLOBAL cover-dir switch
    // (default ON) would force the exact rule to cover children too.
    c.routing.coverAppDirAlways = false;
    auto m = RuleMatcher::compile(c, L"C:\\Self\\AppProxySwitch.exe");
    // A sibling under the broad dir: the broad rule applies.
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\helper.exe", 0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Proxy);
    // The exact path: the later exact rule wins over the dir rule.
    EXPECT_TRUE(m->decideTcp(L"C:\\Apps\\App\\App.exe", 0x08080808, 443).action ==
                RuleMatcher::Decision::Action::Block);
}

APS_TEST_MAIN();
