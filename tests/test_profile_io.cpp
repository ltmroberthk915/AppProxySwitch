// Config profile export/import semantics (portable profiles, no secrets).
#include <windows.h>

#include "aps/config.hpp"
#include "aps/profile_io.hpp"
#include "testlib/appsw_test.h"

using namespace aps;

namespace {
Config baseConfig() {
    Config c = Config::makeDefault();
    Rule r;
    r.id = "r1";
    r.name = "App";
    r.path = "C:\\Apps\\App\\App.exe";
    r.action = "block";
    c.rules.push_back(r);
    Outlet o;
    o.id = "o1";
    o.name = "outlet1";
    o.host = "127.0.0.1";
    o.port = 7890;
    c.outlets.push_back(o);
    return c;
}
}  // namespace

APS_TEST(profile, export_omits_secrets) {
    Config c = baseConfig();
    c.setPlainPassword("topsecret");
    c.proxy.clashApi.secretEnc = "ENC-CLASH";
    c.outlets[0].passwordEnc = "ENC-OUTLET-PASS";
    c.outlets[0].clashApi.secretEnc = "ENC-OUTLET-SECRET";

    std::string text = exportProfileJson(c);
    EXPECT_TRUE(text.find("topsecret") == std::string::npos);
    EXPECT_TRUE(text.find("ENC-") == std::string::npos);
    EXPECT_TRUE(text.find("password_enc") == std::string::npos);
    EXPECT_TRUE(text.find("secret_enc") == std::string::npos);

    // The exported text is still a fully valid config (with empty secrets).
    json::Value v;
    std::string err;
    EXPECT_TRUE(json::Value::parse(text, v, &err));
    Config back;
    std::vector<std::string> warnings;
    EXPECT_TRUE(Config::fromJson(v, back, &err, &warnings));
    EXPECT_STREQ(back.rules[0].action, "block");
    EXPECT_STREQ(back.proxy.passwordEnc, "");
}

APS_TEST(profile, import_roundtrip_keeps_local_secrets) {
    Config current = baseConfig();
    current.setPlainPassword("local-pass");
    current.proxy.clashApi.secretEnc = "LOCAL-CLASH";
    current.outlets[0].passwordEnc = "LOCAL-OUTLET-PASS";
    current.outlets[0].clashApi.secretEnc = "LOCAL-OUTLET-SECRET";

    // The file (exported from another machine) has no secrets.
    Config other = baseConfig();
    other.proxy.port = 7899;
    other.rules[0].action = "proxy";
    std::string text = exportProfileJson(other);

    Config out;
    std::string err;
    EXPECT_TRUE(importProfileJson(text, current, out, &err));
    // File fields win...
    EXPECT_EQ(out.proxy.port, 7899);
    EXPECT_STREQ(out.rules[0].action, "proxy");
    // ...local secrets are kept (enc blobs compared verbatim).
    EXPECT_TRUE(out.proxy.passwordEnc == current.proxy.passwordEnc);
    EXPECT_TRUE(out.proxy.clashApi.secretEnc == current.proxy.clashApi.secretEnc);
    EXPECT_EQ(out.outlets.size(), 1u);
    EXPECT_TRUE(out.outlets[0].passwordEnc == current.outlets[0].passwordEnc);
    EXPECT_TRUE(out.outlets[0].clashApi.secretEnc == current.outlets[0].clashApi.secretEnc);
    // Activation is machine-local: never imported.
    EXPECT_STREQ(out.routing.autoOutletId, "");
}

APS_TEST(profile, import_file_secrets_take_priority) {
    Config current = baseConfig();
    current.setPlainPassword("local-pass");

    // A hand-written file carrying its own enc blob must be kept verbatim.
    std::string text =
        "{\"version\":1,\"proxy\":{\"password_enc\":\"FILE-ENC\"},"
        "\"rules\":[],\"outlets\":[]}";
    Config out;
    std::string err;
    EXPECT_TRUE(importProfileJson(text, current, out, &err));
    EXPECT_TRUE(out.proxy.passwordEnc == "FILE-ENC");
}

APS_TEST(profile, import_outlet_secret_merge_by_id) {
    Config current = baseConfig();
    current.outlets[0].passwordEnc = "LOCAL-O1";
    // A second outlet that does not exist in the file.
    Outlet extra;
    extra.id = "o2";
    extra.passwordEnc = "LOCAL-O2";
    current.outlets.push_back(extra);

    Config file = baseConfig();   // o1 present, no secrets
    std::string text = exportProfileJson(file);

    Config out;
    std::string err;
    EXPECT_TRUE(importProfileJson(text, current, out, &err));
    EXPECT_EQ(out.outlets.size(), 1u);  // overall replace: o2 is gone
    EXPECT_TRUE(out.outlets[0].passwordEnc == "LOCAL-O1");  // merged by id
}

APS_TEST(profile, import_rejects_invalid) {
    Config current = baseConfig();
    Config out;
    std::string err;
    // Invalid JSON.
    EXPECT_FALSE(importProfileJson("{not json", current, out, &err));
    // Valid JSON, invalid action (F2 interplay: validate() rejects it).
    std::string bad =
        "{\"version\":1,\"rules\":[{\"id\":\"x\",\"path\":\"C:\\\\a.exe\","
        "\"action\":\"ban\"}]}";
    EXPECT_FALSE(importProfileJson(bad, current, out, &err));
    // Unknown region value would also be rejected (added in the region
    // feature; covered by test_config).
}

APS_TEST(profile, save_profile_file_writes_text) {
    Config c = baseConfig();
    wchar_t dir[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    std::wstring path = std::wstring(dir) + L"aps-test-profile-" +
                        std::to_wstring(GetCurrentProcessId()) + L".json";
    std::string err;
    EXPECT_TRUE(saveProfileFile(path, c, &err));
    std::string text;
    EXPECT_TRUE(loadProfileFile(path, text, &err));
    EXPECT_TRUE(text.find("\"version\":1") != std::string::npos);
    EXPECT_TRUE(text.find("password_enc") == std::string::npos);
    DeleteFileW(path.c_str());

    // Missing file -> clean failure.
    EXPECT_FALSE(loadProfileFile(dir + std::wstring(L"\\no-such-file.json"),
                                 text, &err));
    EXPECT_TRUE(!err.empty());
}

APS_TEST_MAIN();
