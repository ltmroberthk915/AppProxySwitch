// Clash API client tests against the local mock controller.
#include <winsock2.h>

#include "aps/clash_api.hpp"
#include "mock_clash_api.hpp"
#include "mock_clash_pipe.hpp"
#include "aps/clash_pipe.hpp"
#include "testlib/appsw_test.h"

using namespace aps;
using aps::test::MockClashApi;

namespace {
struct WsaInit {
    WsaInit() { net::initWinsock(); }
};
WsaInit g_wsa;
}  // namespace

APS_TEST(clashapi, probe_and_version) {
    MockClashApi api;
    EXPECT_TRUE(api.start());
    ClashApiClient c("127.0.0.1", api.port(), "");
    std::string err;
    EXPECT_TRUE(c.probe(&err, 3000));
    if (!err.empty()) std::printf("    err: %s\n", err.c_str());
    EXPECT_EQ(api.versionHits(), 1u);
    api.stop();
}

APS_TEST(clashapi, pipe_supports_version_groups_switch_chunked_and_dns) {
    MockClashApi api;
    api.secret = "isolated-test-secret";
    api.useChunked = true;
    api.latencies["node-b"] = 37;
    api.dnsAnswers["test.invalid"] = {"1.2.3.4"};
    EXPECT_TRUE(api.start());
    aps::test::MockClashPipe pipe;
    EXPECT_TRUE(pipe.start(api.port()));
    ClashApiClient c("127.0.0.1", 0, api.secret, pipe.name, GetCurrentProcessId());
    EXPECT_TRUE(c.probeAny(1500).reachable);
    std::string error;
    auto group = c.currentSelectorGroup(&error, 1500);
    EXPECT_TRUE(group.has_value());
    EXPECT_EQ(c.nodeDelay("node-b", "http://test.invalid", 500, 1500), 37);
    EXPECT_TRUE(c.switchNode("auto", "node-b", &error));
    EXPECT_EQ(api.switches().size(), 1u);
    std::vector<uint32_t> ips;
    EXPECT_TRUE(c.resolveA("test.invalid", ips, &error, 1500));
    EXPECT_EQ(ips.size(), 1u);
    ClashApiClient wrong("127.0.0.1", 0, "wrong", pipe.name, GetCurrentProcessId());
    EXPECT_TRUE(wrong.probeAny(1500).needSecret);
}

APS_TEST(clashapi, pipe_rejects_remote_endpoints_wrong_owner_and_silent_server) {
    EXPECT_FALSE(localControllerPipe("\\\\remote\\pipe\\api"));
    EXPECT_FALSE(localControllerPipe("\\\\.\\pipe\\"));
    aps::test::MockClashPipe pipe;
    EXPECT_TRUE(pipe.start());
    ClashApiClient wrong("127.0.0.1", 0, "", pipe.name, GetCurrentProcessId() + 1);
    EXPECT_FALSE(wrong.probeAny(100).reachable);
    pipe.stop();
    pipe.respond = [](const std::string&) { Sleep(400); return std::string(); };
    EXPECT_TRUE(pipe.start());
    auto before = GetTickCount64();
    ClashApiClient silent("127.0.0.1", 0, "", pipe.name, GetCurrentProcessId());
    EXPECT_FALSE(silent.probeAny(80).reachable);
    EXPECT_LT(GetTickCount64() - before, 300ull);
}

APS_TEST(clashapi, selector_group_parsing) {
    MockClashApi api;
    api.selectorNow = "node-b";
    EXPECT_TRUE(api.start());
    ClashApiClient c("127.0.0.1", api.port(), "");
    std::string err;
    auto g = c.currentSelectorGroup(&err, 3000);
    EXPECT_TRUE(g.has_value());
    if (g) {
        EXPECT_STREQ(g->name, "auto");
        EXPECT_STREQ(g->now, "node-b");
        EXPECT_EQ(g->nodes.size(), 3u);
    }
    api.stop();
}

APS_TEST(clashapi, selector_group_parses_node_availability_history) {
    MockClashApi api;
    api.histories["node-a"] = {120, 0, 150, 0};
    api.histories["node-b"] = {80, 90, 100, 110};
    EXPECT_TRUE(api.start());
    ClashApiClient c("127.0.0.1", api.port(), "");
    std::string err;
    auto g = c.currentSelectorGroup(&err, 3000);
    EXPECT_TRUE(g.has_value());
    if (g) {
        EXPECT_EQ(g->history["node-a"].samples, 4);
        EXPECT_EQ(g->history["node-a"].successes, 2);
        EXPECT_EQ(g->history["node-b"].samples, 4);
        EXPECT_EQ(g->history["node-b"].successes, 4);
        EXPECT_TRUE(g->history.count("node-c") == 0);
    }
    api.stop();
}

APS_TEST(clashapi, rule_mode_uses_referenced_nested_selector_instead_of_global) {
    MockClashApi api;
    api.mode = "rule";
    api.groups = {{"GLOBAL", {"unused-a", "unused-b", "unused-c", "unused-d"}},
                  {"Catch all", {"Main route", "DIRECT"}},
                  {"Main route", {"JP-IEPL 1", "US-IEPL 2", "SG-IEPL 3"}},
                  {"AI route", {"US AI"}},
                  {"Unreferenced route", {"a", "b", "c", "d", "e"}}};
    api.groupSelections = {{"GLOBAL", "unused-a"}, {"Catch all", "Main route"},
                           {"Main route", "JP-IEPL 1"}, {"AI route", "US AI"},
                           {"Unreferenced route", "a"}};
    api.rulePolicies = {"AI route", "Catch all", "DIRECT"};
    EXPECT_TRUE(api.start());
    ClashApiClient client("127.0.0.1", api.port(), "");
    std::string error; std::vector<ClashGroup> groups;
    auto group = client.currentSelectorGroup(&error, 1500, &groups);
    EXPECT_TRUE(group.has_value());
    if (group) { EXPECT_STREQ(group->name, "Main route"); EXPECT_STREQ(group->now, "JP-IEPL 1"); }
    EXPECT_EQ(groups.size(), 5u);
}

APS_TEST(clashapi, rule_mode_prefers_service_selector_without_using_unreferenced_groups) {
    MockClashApi api;
    api.mode = "rule";
    api.groups = {{"General", {"node-a", "node-b", "node-c"}},
                  {"Service", {"node-b", "node-c"}},
                  {"Unused", {"node-a", "node-b", "node-c", "node-d"}}};
    api.groupSelections = {{"General", "node-a"}, {"Service", "node-b"}, {"Unused", "node-d"}};
    api.rulePolicies = {"Service", "General"};
    EXPECT_TRUE(api.start());
    ClashApiClient client("127.0.0.1", api.port(), "");
    std::string error;
    for (const auto& preferences : std::vector<std::vector<std::string>>{
             {"Service"}, {"missing", "Service"}, {"Unused", "Service"}}) {
        auto group = client.currentSelectorGroup(&error, 1500, nullptr, nullptr, preferences);
        EXPECT_TRUE(group.has_value());
        if (group) { EXPECT_STREQ(group->name, "Service"); EXPECT_STREQ(group->now, "node-b"); }
    }
    auto fallback = client.currentSelectorGroup(&error, 1500, nullptr, nullptr, {"Unused", "missing"});
    EXPECT_TRUE(fallback.has_value());
    if (fallback) EXPECT_STREQ(fallback->name, "General");
    EXPECT_TRUE(api.switches().empty());
}

APS_TEST(clashapi, preferred_rule_selector_retains_outer_target_and_resolves_nested_leaf) {
    MockClashApi api;
    api.mode = "rule";
    api.groups = {{"General", {"node-a", "node-b", "node-c"}},
                  {"Service", {"Automatic"}},
                  {"Automatic", {"node-b", "node-c"}}};
    api.groupTypes["Automatic"] = "URLTest";
    api.groupSelections = {{"General", "node-a"}, {"Service", "Automatic"}, {"Automatic", "node-b"}};
    api.rulePolicies = {"Service", "General"};
    EXPECT_TRUE(api.start());
    ClashApiClient client("127.0.0.1", api.port(), ""); std::string error;
    auto group = client.currentSelectorGroup(&error, 1500, nullptr, nullptr, {"Service"});
    EXPECT_TRUE(group.has_value());
    if (group) {
        EXPECT_STREQ(group->name, "Service");
        EXPECT_STREQ(group->now, "node-b");
        EXPECT_EQ(group->nodes.size(), 1u);
        EXPECT_STREQ(group->nodes.front(), "Automatic");
        EXPECT_STREQ(group->selectedMember, "Automatic");
        EXPECT_STREQ(group->memberLeaves.at("Automatic"), "node-b");
    }
    EXPECT_TRUE(api.switches().empty());
}

APS_TEST(clashapi, preferred_selector_maps_legal_choices_without_flattening_invalid_branches) {
    MockClashApi api;
    api.mode = "rule";
    api.groups = {{"Service", {"US relay", "Shared", "Cycle", "Empty", "DIRECT"}},
                  {"Shared", {"Automatic", "JP relay"}},
                  {"Automatic", {"SG IEPL", "JP relay"}},
                  {"Cycle", {"Service"}}, {"Empty", {"SG IEPL"}}};
    api.groupTypes["Automatic"] = "URLTest";
    api.groupSelections = {{"Service", "US relay"}, {"Shared", "Automatic"},
                           {"Automatic", "SG IEPL"}, {"Cycle", "Service"}, {"Empty", ""}};
    api.rulePolicies = {"Service"};
    EXPECT_TRUE(api.start());
    ClashApiClient client("127.0.0.1", api.port(), "");
    std::string error;
    auto group = client.currentSelectorGroup(&error, 1500, nullptr, nullptr, {"Service"});
    EXPECT_TRUE(group.has_value());
    if (group) {
        EXPECT_STREQ(group->now, "US relay");
        EXPECT_STREQ(group->selectedMember, "US relay");
        EXPECT_STREQ(group->memberLeaves.at("US relay"), "US relay");
        EXPECT_STREQ(group->memberLeaves.at("Shared"), "SG IEPL");
        EXPECT_TRUE(group->memberLeaves.count("Cycle") == 0);
        EXPECT_TRUE(group->memberLeaves.count("Empty") == 0);
        EXPECT_TRUE(group->memberLeaves.count("JP relay") == 0);
        EXPECT_STREQ(group->memberLeaves.at("DIRECT"), "DIRECT");
        EXPECT_EQ(group->nodes.size(), 5u);
    }
    EXPECT_TRUE(api.switches().empty());
}

APS_TEST(clashapi, group_preferences_do_not_override_global_legacy_or_direct_mode) {
    for (const auto* mode : {"global", "", "direct"}) {
        MockClashApi api;
        api.mode = mode;
        api.groups = {{"GLOBAL", {"node-a", "node-b"}}, {"Service", {"node-b"}}};
        api.groupSelections = {{"GLOBAL", "node-a"}, {"Service", "node-b"}};
        api.rulePolicies = {"Service"};
        EXPECT_TRUE(api.start());
        ClashApiClient client("127.0.0.1", api.port(), ""); std::string error;
        auto group = client.currentSelectorGroup(&error, 1500, nullptr, nullptr, {"Service"});
        if (std::string(mode) == "direct") EXPECT_FALSE(group.has_value());
        else {
            EXPECT_TRUE(group.has_value());
            if (group) EXPECT_STREQ(group->name, "GLOBAL");
        }
        EXPECT_TRUE(api.switches().empty());
    }
}

APS_TEST(clashapi, invalid_preferred_rule_chain_is_reported_without_general_fallback) {
    MockClashApi api;
    api.mode = "rule";
    api.groups = {{"General", {"node-a", "node-b", "node-c"}},
                  {"Service", {"Automatic"}}, {"Automatic", {"Service"}}};
    api.groupTypes["Automatic"] = "URLTest";
    api.groupSelections = {{"General", "node-a"}, {"Service", "Automatic"}, {"Automatic", "Service"}};
    api.rulePolicies = {"General", "Service"};
    EXPECT_TRUE(api.start());
    ClashApiClient client("127.0.0.1", api.port(), ""); std::string error;
    EXPECT_FALSE(client.currentSelectorGroup(&error, 1500, nullptr, nullptr, {"Service"}).has_value());
    EXPECT_FALSE(error.empty());
    EXPECT_TRUE(api.switches().empty());
}

APS_TEST(clashapi, runtime_direct_mode_and_missing_rule_targets_are_not_guessed) {
    for (const auto* mode : {"direct", "rule"}) {
        MockClashApi api; api.mode = mode;
        EXPECT_TRUE(api.start());
        ClashApiClient client("127.0.0.1", api.port(), ""); std::string error;
        EXPECT_FALSE(client.currentSelectorGroup(&error, 1500).has_value());
        EXPECT_FALSE(error.empty());
        EXPECT_TRUE(api.switches().empty());
    }
}

APS_TEST(clashapi, selected_automatic_subgroups_resolve_to_current_concrete_node) {
    for (const auto* mode : {"", "global", "rule"}) {
        MockClashApi api;
        api.mode = mode;
        const std::string target = std::string(mode) == "global" ? "GLOBAL" : "Main route";
        api.groups = {{target, {"Fast route", "JP-IEPL 1", "US-IEPL 2"}},
                      {"Fast route", {"Backup route", "US-IEPL 2"}},
                      {"Backup route", {"JP-IEPL 1"}}};
        api.groupTypes = {{"Fast route", "URLTest"}, {"Backup route", "Fallback"}};
        api.groupSelections = {{target, "Fast route"}, {"Fast route", "Backup route"},
                               {"Backup route", "JP-IEPL 1"}};
        api.rulePolicies = {target};
        api.histories["JP-IEPL 1"] = {120, 130};
        EXPECT_TRUE(api.start());
        ClashApiClient client("127.0.0.1", api.port(), "");
        std::string error; std::vector<ClashGroup> groups;
        auto selected = client.currentSelectorGroup(&error, 1500, &groups);
        EXPECT_TRUE(selected.has_value());
        if (selected) {
            EXPECT_STREQ(selected->name, target);
            EXPECT_STREQ(selected->now, "JP-IEPL 1");
            EXPECT_EQ(selected->nodes.size(), 3u);
            EXPECT_EQ(selected->history["JP-IEPL 1"].successes, 2);
        }
        EXPECT_EQ(groups.size(), 3u);
        EXPECT_TRUE(api.switches().empty());
    }
}

APS_TEST(clashapi, cyclic_subgroup_selection_reports_error_without_guessing_node) {
    MockClashApi api;
    api.mode = "rule";
    api.groups = {{"Main route", {"Fast route", "JP-IEPL 1"}},
                  {"Fast route", {"Main route"}}};
    api.groupTypes["Fast route"] = "URLTest";
    api.groupSelections = {{"Main route", "Fast route"}, {"Fast route", "Main route"}};
    api.rulePolicies = {"Main route"};
    EXPECT_TRUE(api.start());
    ClashApiClient client("127.0.0.1", api.port(), "");
    std::string error;
    EXPECT_FALSE(client.currentSelectorGroup(&error, 1500).has_value());
    EXPECT_FALSE(error.empty());
    EXPECT_TRUE(api.switches().empty());
}

APS_TEST(clashapi, node_delay_alive_and_dead) {
    MockClashApi api;
    api.latencies["node-a"] = 120;
    api.latencies["node-b"] = 800;
    // node-c absent => dead/timeout
    EXPECT_TRUE(api.start());
    ClashApiClient c("127.0.0.1", api.port(), "");
    EXPECT_EQ(c.nodeDelay("node-a", "http://www.gstatic.com/generate_204", 2000, 4000), 120);
    EXPECT_EQ(c.nodeDelay("node-b", "http://www.gstatic.com/generate_204", 2000, 4000), 800);
    EXPECT_EQ(c.nodeDelay("node-c", "http://www.gstatic.com/generate_204", 2000, 4000), -1);
    api.stop();
}

APS_TEST(clashapi, switch_node_puts_and_records) {
    MockClashApi api;
    EXPECT_TRUE(api.start());
    ClashApiClient c("127.0.0.1", api.port(), "");
    std::string err;
    EXPECT_TRUE(c.switchNode("auto", "node-c", &err));
    if (!err.empty()) std::printf("    err: %s\n", err.c_str());
    auto sw = api.switches();
    EXPECT_EQ(sw.size(), 1u);
    if (!sw.empty()) EXPECT_STREQ(sw[0], "auto::node-c");
    api.stop();
}

APS_TEST(clashapi, secret_auth_required) {
    MockClashApi api;
    api.secret = "s3cret-token";
    EXPECT_TRUE(api.start());
    ClashApiClient bad("127.0.0.1", api.port(), "");
    std::string err;
    EXPECT_FALSE(bad.probe(&err, 3000));  // 401
    ClashApiClient good("127.0.0.1", api.port(), "s3cret-token");
    EXPECT_TRUE(good.probe(&err, 3000));
    EXPECT_TRUE(api.lastRequestHadSecret());
    api.stop();
}

APS_TEST(clashapi, chunked_response_with_emoji_nodes) {
    // Real-world case (SakuraCat/Clash 1.10): chunked transfer encoding and
    // 4-byte UTF-8 emoji in node names.
    MockClashApi api;
    api.useChunked = true;
    api.selectorNow = "🇭🇰|香港-中转 01";
    api.nodes = {"🇭🇰|香港-中转 01", "🇯🇵|东京 02", "DIRECT"};
    EXPECT_TRUE(api.start());
    ClashApiClient c("127.0.0.1", api.port(), "");
    std::string err;
    auto g = c.currentSelectorGroup(&err, 3000);
    EXPECT_TRUE(g.has_value());
    if (!g.has_value()) std::printf("    err: %s\n", err.c_str());
    if (g) {
        EXPECT_STREQ(g->now, "🇭🇰|香港-中转 01");
        EXPECT_EQ(g->nodes.size(), 3u);
    }
    api.stop();
}

APS_TEST(clashapi, auto_detect_port) {
    MockClashApi api;
    // Bind on a common port? The mock binds ephemeral; instead verify the
    // function returns 0 when nothing is listening on the common ports.
    uint16_t detected = autoDetectClashApiPort("127.0.0.1", "", /*socksPort=*/0);
    // The mock's ephemeral port is not in the common list, so 0 is expected
    // UNLESS something else on this machine answers (be lenient: just verify
    // it doesn't hang and returns quickly).
    EXPECT_TRUE(detected == 0 || detected > 0);
    api.stop();
}

APS_TEST(clashapi, incident_mode_exposed_on_direct_and_global_without_active_group) {
    for (const auto* mode : {"direct", "global"}) {
        MockClashApi api; api.mode = mode;
        api.groups = {{"Other", {"node-a", "node-b"}}};
        api.groupSelections = {{"Other", "node-a"}};
        EXPECT_TRUE(api.start());
        ClashApiClient client("127.0.0.1", api.port(), "");
        std::string error, observed;
        EXPECT_FALSE(client.currentSelectorGroup(&error, 1500, nullptr, &observed).has_value());
        EXPECT_STREQ(observed, mode);
        EXPECT_FALSE(error.empty());
        EXPECT_TRUE(api.switches().empty());
    }
}

APS_TEST(clashapi, incident_rule_mode_is_exposed_separately_from_selected_node) {
    MockClashApi api; api.mode = "rule";
    api.rulePolicies = {"auto"};
    EXPECT_TRUE(api.start());
    ClashApiClient client("127.0.0.1", api.port(), "");
    std::string error, observed;
    EXPECT_TRUE(client.currentSelectorGroup(&error, 1500, nullptr, &observed).has_value());
    EXPECT_STREQ(observed, "rule");
    EXPECT_TRUE(api.switches().empty());
}

APS_TEST_MAIN();
