#include <windows.h>
#include <shlobj.h>
#include <cstring>

#include "aps/config.hpp"
#include "aps/path_util.hpp"
#include "aps/string_util.hpp"
#include "testlib/appsw_test.h"

using namespace aps;

namespace {
// Isolated temp file helper.
struct TempConfig {
    std::wstring path;
    TempConfig() {
        wchar_t dir[MAX_PATH];
        GetTempPathW(MAX_PATH, dir);
        path = std::wstring(dir) + L"aps-test-config-" +
               utf8ToWide(std::to_string(GetCurrentProcessId())) + L"-" +
               utf8ToWide(newId()) + L".json";
    }
    ~TempConfig() { if (!path.empty()) DeleteFileW(path.c_str()); }
};
}  // namespace

APS_TEST(config, defaults_are_valid) {
    Config c = Config::makeDefault();
    std::string err;
    EXPECT_TRUE(c.validate(&err));
    if (!err.empty()) std::printf("    err: %s\n", err.c_str());
    EXPECT_EQ(c.version, 1);
    EXPECT_STREQ(c.proxy.host, "127.0.0.1");
    EXPECT_EQ(c.proxy.port, 7891);
    EXPECT_STREQ(c.failMode, "open");
    EXPECT_TRUE(c.routing.bypassPrivate);
    EXPECT_TRUE(c.routing.blockUdpForRules);
    EXPECT_TRUE(c.routing.tlsDomainAllowlist.empty());
}

APS_TEST(config, tls_domain_policy_roundtrips_and_rejects_broad_or_malformed_patterns) {
    Config c;
    c.routing.tlsDomainAllowlist = {"Example.Invalid", "*.example.invalid"};
    Config parsed;
    std::string error;
    EXPECT_TRUE(Config::fromJson(c.toJson(), parsed, &error, nullptr));
    EXPECT_TRUE(parsed.routing.tlsDomainAllowlist == c.routing.tlsDomainAllowlist);
    for (const std::string invalid : {"*", "com", "*.com", "127.0.0.1", "https://example.invalid", "x.*.invalid", "a..invalid", "-a.invalid", "a.invalid."}) {
        c.routing.tlsDomainAllowlist = {invalid};
        EXPECT_FALSE(c.validate(&error));
    }
    c.routing.tlsDomainAllowlist.assign(65, "example.invalid");
    EXPECT_FALSE(c.validate(&error));
    auto value = Config{}.toJson();
    auto routing = json::Value::makeObject();
    routing.set("tls_domain_allowlist", "example.invalid");
    value.set("routing", std::move(routing));
    EXPECT_FALSE(Config::fromJson(value, parsed, &error, nullptr));
}

APS_TEST(config, recognized_legacy_node_preferences_do_not_count_as_unknown_fields) {
    json::Value value;
    std::string error;
    std::vector<std::string> warnings;
    EXPECT_TRUE(json::Value::parse("{\"node_monitor\":{\"region\":\"US\",\"node_class\":\"RES\"}}", value, &error));
    Config config;
    EXPECT_TRUE(Config::fromJson(value, config, &error, &warnings));
    EXPECT_TRUE(warnings.empty());
    EXPECT_TRUE(config.nodeMonitor.regions == std::vector<std::string>{"US"});
    EXPECT_TRUE(config.nodeMonitor.nodeClasses == std::vector<std::string>{"RES"});
}

APS_TEST(config, tls_domain_policy_matches_labels_not_suffix_lookalikes) {
    const std::vector<std::string> names = {"apex.example.invalid", "*.service.example.invalid"};
    EXPECT_TRUE(tlsDomainAllowed("APEX.EXAMPLE.INVALID", names));
    EXPECT_TRUE(tlsDomainAllowed("api.service.example.invalid", names));
    EXPECT_TRUE(tlsDomainAllowed("a.b.service.example.invalid", names));
    for (const std::string name : {"service.example.invalid", "badservice.example.invalid", "api.service.example.invalid.attacker.invalid", "another.example.invalid", "cover.example.invalid", "127.0.0.1", "a..service.example.invalid"})
        EXPECT_FALSE(tlsDomainAllowed(name, names));
    EXPECT_FALSE(tlsDomainAllowed("api.example.invalid", {}));
}

APS_TEST(config, json_roundtrip) {
    Config c;
    Rule r;
    r.id = "abc-123";
    r.name = "Telegram";
    r.path = "C:\\Apps\\Telegram\\Telegram.exe";
    r.enabled = true;
    r.includeChildren = false;
    c.rules.push_back(r);
    c.proxy.port = 7890;
    c.proxy.username = "user";
    c.setPlainPassword("secret");
    c.failMode = "closed";

    json::Value j = c.toJson();
    Config back;
    std::string err;
    std::vector<std::string> warnings;
    EXPECT_TRUE(Config::fromJson(j, back, &err, &warnings));
    if (!err.empty()) std::printf("    err: %s\n", err.c_str());
    EXPECT_EQ(back.proxy.port, 7890);
    EXPECT_EQ(back.rules.size(), 1u);
    EXPECT_STREQ(back.rules[0].path, "C:\\Apps\\Telegram\\Telegram.exe");
    EXPECT_TRUE(back.rules[0].enabled);
    EXPECT_STREQ(back.failMode, "closed");
    // DPAPI round trip through the password field.
    EXPECT_STREQ(back.plainPassword(), "secret");
}

APS_TEST(config, rule_action_roundtrip) {
    Config c;
    Rule r;
    r.id = "abc-123";
    r.path = "C:\\Apps\\App\\App.exe";
    r.action = "block";
    c.rules.push_back(r);
    json::Value j = c.toJson();
    Config back;
    std::string err;
    std::vector<std::string> warnings;
    EXPECT_TRUE(Config::fromJson(j, back, &err, &warnings));
    EXPECT_EQ(back.rules.size(), 1u);
    EXPECT_STREQ(back.rules[0].action, "block");

    // Absent "action" key normalizes to "proxy" (legacy configs).
    json::Value v;
    if (!json::Value::parse(
            "{\"version\":1,\"rules\":[{\"id\":\"x\",\"path\":\"C:\\\\a.exe\"}]}", v, &err)) {
        EXPECT_TRUE(false);  // doc itself must be valid JSON
        return;
    }
    Config legacy;
    EXPECT_TRUE(Config::fromJson(v, legacy, &err, &warnings));
    EXPECT_EQ(legacy.rules.size(), 1u);
    EXPECT_STREQ(legacy.rules[0].action, "proxy");
}

APS_TEST(config, node_region_roundtrip) {
    Config c;
    c.nodeMonitor.regions = {"JP", "SG"};
    json::Value j = c.toJson();
    Config back;
    std::string err;
    std::vector<std::string> warnings;
    EXPECT_TRUE(Config::fromJson(j, back, &err, &warnings));
    EXPECT_EQ(back.nodeMonitor.regions.size(), 2u);
    EXPECT_TRUE(back.nodeMonitor.regions[0] == "JP" &&
                back.nodeMonitor.regions[1] == "SG");
    // Absent regions -> empty (不限).
    Config legacy;
    json::Value v;
    EXPECT_TRUE(json::Value::parse("{\"version\":1}", v, &err));
    EXPECT_TRUE(Config::fromJson(v, legacy, &err, &warnings));
    EXPECT_TRUE(legacy.nodeMonitor.regions.empty());
    // LEGACY single-value "region" migrates into the set.
    json::Value v2;
    EXPECT_TRUE(json::Value::parse(
        "{\"version\":1,\"node_monitor\":{\"region\":\"JP\"}}", v2, &err));
    Config migrated;
    EXPECT_TRUE(Config::fromJson(v2, migrated, &err, &warnings));
    EXPECT_EQ(migrated.nodeMonitor.regions.size(), 1u);
    EXPECT_TRUE(migrated.nodeMonitor.regions[0] == "JP");
    // Unknown region rejected by validate.
    Config bad;
    bad.nodeMonitor.regions = {"XX"};
    EXPECT_FALSE(bad.validate(&err));
    EXPECT_TRUE(err.find("regions") != std::string::npos);
}

APS_TEST(config, subscription_settings_roundtrip) {
    Config c;
    c.subscription.autoRefresh = false;
    c.subscription.intervalHours = 12;
    c.subscription.startDelayMin = 5;
    json::Value j = c.toJson();
    Config back;
    std::string err;
    std::vector<std::string> warnings;
    EXPECT_TRUE(Config::fromJson(j, back, &err, &warnings));
    EXPECT_FALSE(back.subscription.autoRefresh);
    EXPECT_EQ(back.subscription.intervalHours, 12);
    EXPECT_EQ(back.subscription.startDelayMin, 5);
    EXPECT_TRUE(warnings.empty());
    // Absent section must not opt the user into modifying a third-party
    // proxy's subscription. Explicit legacy values still round-trip.
    json::Value v;
    EXPECT_TRUE(json::Value::parse("{\"version\":1}", v, &err));
    Config d;
    EXPECT_TRUE(Config::fromJson(v, d, &err, &warnings));
    EXPECT_FALSE(d.subscription.autoRefresh);
    EXPECT_EQ(d.subscription.intervalHours, 24);
    c.subscription.autoRefresh = true;
    warnings.clear();
    EXPECT_TRUE(Config::fromJson(c.toJson(), back, &err, &warnings));
    EXPECT_TRUE(back.subscription.autoRefresh);
    EXPECT_TRUE(warnings.empty());
}

APS_TEST(config, empty_preference_entries_are_dropped_not_fatal) {
    // 2026-08-31 data-loss incident: an older GUI wrote "不限" as a literal
    // empty-string entry (["SG","JP","KR","TW",""]). The parser treated it
    // as an invalid entry and rejected the WHOLE file — the next GUI start
    // then wiped the user's config (rules gone). Empty entries are now
    // dropped with a warning.
    json::Value v;
    std::string err;
    std::vector<std::string> warnings;
    EXPECT_TRUE(json::Value::parse(
        "{\"version\":1,\"node_monitor\":{"
        "\"regions\":[\"SG\",\"JP\",\"\",\"KR\"],"
        "\"node_classes\":[\"\",\"IEPL\"]}}", v, &err));
    Config c;
    EXPECT_TRUE(Config::fromJson(v, c, &err, &warnings));
    EXPECT_EQ(c.nodeMonitor.regions.size(), 3u);
    EXPECT_EQ(c.nodeMonitor.nodeClasses.size(), 1u);
    EXPECT_TRUE(c.nodeMonitor.nodeClasses[0] == "IEPL");
    EXPECT_TRUE(c.validate(&err));
    bool warned = false;
    for (const auto& w : warnings) {
        if (w.find("empty entry") != std::string::npos) warned = true;
    }
    EXPECT_TRUE(warned);
}

APS_TEST(config, cover_app_dir_always_roundtrip) {
    Config c;
    EXPECT_TRUE(c.routing.coverAppDirAlways);   // default ON
    c.routing.coverAppDirAlways = false;
    json::Value j = c.toJson();
    Config back;
    std::string err;
    std::vector<std::string> warnings;
    EXPECT_TRUE(Config::fromJson(j, back, &err, &warnings));
    EXPECT_FALSE(back.routing.coverAppDirAlways);
    // Absent field -> default ON (legacy configs).
    Config legacy;
    json::Value v;
    EXPECT_TRUE(json::Value::parse("{\"version\":1}", v, &err));
    EXPECT_TRUE(Config::fromJson(v, legacy, &err, &warnings));
    EXPECT_TRUE(legacy.routing.coverAppDirAlways);
}

APS_TEST(config, node_class_roundtrip) {
    Config c;
    c.nodeMonitor.nodeClasses = {"RES", "IEPL"};
    json::Value j = c.toJson();
    Config back;
    std::string err;
    std::vector<std::string> warnings;
    EXPECT_TRUE(Config::fromJson(j, back, &err, &warnings));
    EXPECT_EQ(back.nodeMonitor.nodeClasses.size(), 2u);
    // Absent node_classes -> default {"IEPL"} (preserves the old hard-coded
    // IEPL priority for configs written by earlier versions).
    Config legacy;
    json::Value v;
    EXPECT_TRUE(json::Value::parse("{\"version\":1}", v, &err));
    EXPECT_TRUE(Config::fromJson(v, legacy, &err, &warnings));
    EXPECT_EQ(legacy.nodeMonitor.nodeClasses.size(), 1u);
    EXPECT_TRUE(legacy.nodeMonitor.nodeClasses[0] == "IEPL");
    // LEGACY single-value "node_class" migrates.
    json::Value v2;
    EXPECT_TRUE(json::Value::parse(
        "{\"version\":1,\"node_monitor\":{\"node_class\":\"RES\"}}", v2, &err));
    Config migrated;
    EXPECT_TRUE(Config::fromJson(v2, migrated, &err, &warnings));
    EXPECT_EQ(migrated.nodeMonitor.nodeClasses.size(), 1u);
    EXPECT_TRUE(migrated.nodeMonitor.nodeClasses[0] == "RES");
    // Unknown class rejected by validate.
    Config bad;
    bad.nodeMonitor.nodeClasses = {"XX"};
    EXPECT_FALSE(bad.validate(&err));
    EXPECT_TRUE(err.find("node_classes") != std::string::npos);
}

APS_TEST(config, rejects_bad_schema) {
    auto checkFails = [](const std::string& doc, const char* why) {
        json::Value v;
        std::string perr;
        if (!json::Value::parse(doc, v, &perr)) {
            EXPECT_TRUE(false);  // doc itself must be valid JSON
            return;
        }
        Config c;
        std::string err;
        std::vector<std::string> warnings;
        bool ok = Config::fromJson(v, c, &err, &warnings);
        if (ok) std::printf("    (should have failed: %s)\n", why);
        EXPECT_FALSE(ok);
    };
    checkFails("{\"version\":1,\"proxy\":{\"port\":\"7891\"}}", "port as string");
    checkFails("{\"version\":1,\"proxy\":{\"port\":99999}}", "port out of range");
    checkFails("{\"version\":1,\"proxy\":{\"host\":\"8.8.8.8\"}}", "proxy host not loopback");
    checkFails("{\"version\":1,\"proxy\":{\"host\":\"not-an-ip\"}}", "bad host");
    checkFails("{\"version\":2}", "future version");
    checkFails("{\"fail_mode\":\"maybe\"}", "bad fail mode");
    checkFails("{\"version\":1,\"rules\":[{\"path\":\"relative.exe\"}]}", "relative rule path");
    checkFails("{\"version\":1,\"relay\":{\"port\":7891}}", "relay == proxy port");
    checkFails("{\"version\":1,\"logging\":{\"level\":\"verbose\"}}", "bad level");
    checkFails("{\"version\":1,\"rules\":[{\"id\":\"x\",\"path\":\"C:\\\\a.exe\"},{\"id\":\"x\",\"path\":\"C:\\\\b.exe\"}]}",
               "duplicate ids");
    checkFails("{\"version\":1,\"rules\":[{\"id\":\"x\",\"path\":\"C:\\\\a.exe\",\"action\":\"ban\"}]}",
               "unknown rule action");
}

APS_TEST(config, outlets_enabled_roundtrip) {
    Config c;
    Outlet o;
    o.id = "cfw";
    o.name = "CFW";
    o.host = "127.0.0.1";
    o.port = 7890;
    o.enabled = false;   // deactivated outlet must survive the roundtrip
    o.clashApi.host = "127.0.0.1";
    o.clashApi.port = 0; // auto-detect
    c.outlets.push_back(o);

    json::Value j = c.toJson();
    Config back;
    std::string err;
    std::vector<std::string> warnings;
    EXPECT_TRUE(Config::fromJson(j, back, &err, &warnings));
    EXPECT_EQ(back.outlets.size(), 1u);
    EXPECT_STREQ(back.outlets[0].id, "cfw");
    EXPECT_FALSE(back.outlets[0].enabled);
    EXPECT_EQ(back.outlets[0].clashApi.port, 0);
}

APS_TEST(config, unknown_keys_warn_not_fail) {
    const char* doc = "{\"version\":1,\"future_field\":123}";
    json::Value v;
    std::string err;
    EXPECT_TRUE(json::Value::parse(doc, v, &err));
    Config c;
    std::vector<std::string> warnings;
    EXPECT_TRUE(Config::fromJson(v, c, &err, &warnings));
    EXPECT_EQ(warnings.size(), 1u);
}

APS_TEST(config, file_save_load_atomic_roundtrip) {
    TempConfig tmp;
    Config c;
    Rule r;
    r.id = newId();
    r.name = "TestApp";
    r.path = "C:\\Test\\TestApp.exe";
    c.rules.push_back(r);
    std::string err;
    EXPECT_TRUE(saveConfigFile(tmp.path, c, &err));
    if (!err.empty()) std::printf("    err: %s\n", err.c_str());
    // The temp file must be gone (moved, not left behind).
    EXPECT_TRUE(GetFileAttributesW((dirName(tmp.path) + L"\\config.json.tmp").c_str()) ==
                INVALID_FILE_ATTRIBUTES);

    Config back;
    std::vector<std::string> warnings;
    bool wasDefault = false;
    EXPECT_TRUE(loadConfigFile(tmp.path, back, &err, &warnings, &wasDefault));
    EXPECT_FALSE(wasDefault);
    EXPECT_EQ(back.rules.size(), 1u);
    EXPECT_STREQ(back.rules[0].name, "TestApp");
}

APS_TEST(config, missing_file_yields_defaults) {
    TempConfig tmp;
    tmp.path += L".does-not-exist";
    Config c;
    std::string err;
    std::vector<std::string> warnings;
    bool wasDefault = false;
    EXPECT_TRUE(loadConfigFile(tmp.path, c, &err, &warnings, &wasDefault));
    EXPECT_TRUE(wasDefault);
    EXPECT_TRUE(c.rules.empty());
}

APS_TEST(config, self_heals_from_backup_when_deleted) {
    TempConfig tmp;
    Config c;
    Rule r;
    r.id = newId();
    r.name = "PreciousRule";
    r.path = "C:\\Test\\Precious.exe";
    c.rules.push_back(r);
    c.proxy.port = 7897;
    std::string err;
    EXPECT_TRUE(saveConfigFile(tmp.path, c, &err));
    // saveConfigFile also writes the shadow copies; verify the sibling one.
    EXPECT_TRUE(GetFileAttributesW((tmp.path + L".bak").c_str()) !=
                INVALID_FILE_ATTRIBUTES);

    // Simulate an external deletion of the main file (the sibling .bak stays).
    EXPECT_TRUE(DeleteFileW(tmp.path.c_str()));

    Config back;
    std::vector<std::string> warnings;
    bool wasDefault = false;
    EXPECT_TRUE(loadConfigFile(tmp.path, back, &err, &warnings, &wasDefault));
    EXPECT_FALSE(wasDefault);
    EXPECT_EQ(back.rules.size(), 1u);
    EXPECT_STREQ(back.rules[0].name, "PreciousRule");
    EXPECT_EQ(back.proxy.port, 7897);
    // The main file must have been restored on disk.
    EXPECT_TRUE(GetFileAttributesW(tmp.path.c_str()) != INVALID_FILE_ATTRIBUTES);
    bool sawRestoreNote = false;
    for (const auto& w : warnings) {
        if (w.find("restored from the automatic backup") != std::string::npos) {
            sawRestoreNote = true;
        }
    }
    EXPECT_TRUE(sawRestoreNote);

    // Roaming shadow copy is only for the REAL config path: temp paths must
    // stay isolated (never write/read the per-user roaming backup).
    std::wstring roamingDir;
    {
        PWSTR roaming = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr,
                                           &roaming)) &&
            roaming) {
            roamingDir = roaming;
            CoTaskMemFree(roaming);
        }
    }
    if (!roamingDir.empty()) {
        std::wstring roamingBak = roamingDir + L"\\AppProxySwitch\\config.json.bak";
        // Remove any pre-existing file, save via the temp path, and verify
        // the roaming copy was NOT touched by this save.
        DeleteFileW(roamingBak.c_str());
        EXPECT_TRUE(saveConfigFile(tmp.path, c, &err));
        EXPECT_TRUE(GetFileAttributesW(roamingBak.c_str()) ==
                    INVALID_FILE_ATTRIBUTES);
        DeleteFileW(roamingBak.c_str());
    }
}

APS_TEST(config, corrupt_file_fails_cleanly) {
    TempConfig tmp;
    HANDLE f = CreateFileW(tmp.path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    const char* bad = "{ not json ]";
    DWORD written = 0;
    WriteFile(f, bad, static_cast<DWORD>(std::strlen(bad)), &written, nullptr);
    CloseHandle(f);
    Config c;
    std::string err;
    std::vector<std::string> warnings;
    bool wasDefault = false;
    EXPECT_FALSE(loadConfigFile(tmp.path, c, &err, &warnings, &wasDefault));
    EXPECT_TRUE(!err.empty());
}

APS_TEST(config, dns_scope_is_safe_by_default_and_roundtrips_legacy_opt_in) {
    auto c = Config::makeDefault();
    EXPECT_TRUE(c.routing.dnsCleanup);
    EXPECT_FALSE(c.routing.dnsCleanupGlobal);
    Config old;
    std::string err;
    std::vector<std::string> warnings;
    json::Value legacy;
    EXPECT_TRUE(json::Value::parse("{\"version\":1,\"routing\":{\"dns_cleanup\":true}}", legacy, &err));
    EXPECT_TRUE(Config::fromJson(legacy, old, &err, &warnings));
    EXPECT_FALSE(old.routing.dnsCleanupGlobal);
    c.routing.dnsCleanupGlobal = true;
    EXPECT_TRUE(Config::fromJson(c.toJson(), old, &err, &warnings));
    EXPECT_TRUE(old.routing.dnsCleanupGlobal);
    EXPECT_TRUE(warnings.empty());
}

APS_TEST_MAIN();
