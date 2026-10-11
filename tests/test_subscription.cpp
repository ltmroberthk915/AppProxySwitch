// Subscription refresh helpers: URL discovery from SakuraCat's .store.json
// and the mixed-port patch (pure line edit).
#include <windows.h>

#include <cstdio>

#include "aps/subscription.hpp"
#include "testlib/appsw_test.h"

using namespace aps;

APS_TEST(subscription, patch_mixed_port_cases) {
    std::string yaml =
        "mixed-port: 7890\n"
        "external-controller: '127.0.0.1:9090'\n"
        "proxies:\n"
        "  - name: A\n";
    std::string got = subscription::patchMixedPort(yaml, 7897);
    EXPECT_TRUE(got.find("mixed-port: 7897") != std::string::npos);
    EXPECT_TRUE(got.find("mixed-port: 7890") == std::string::npos);
    EXPECT_TRUE(got.find("external-controller") != std::string::npos);  // untouched
    EXPECT_TRUE(got.find("  - name: A") != std::string::npos);          // untouched
    // Indented variant ("  mixed-port: ...") also patches.
    std::string indented = "  mixed-port: 1234\n";
    EXPECT_TRUE(subscription::patchMixedPort(indented, 7897).find("mixed-port: 7897") !=
                std::string::npos);
    // Missing field: unchanged.
    std::string noPort = "proxies:\n";
    EXPECT_STREQ(subscription::patchMixedPort(noPort, 7897), noPort);
}

APS_TEST(subscription, parse_mixed_port_cases) {
    // The auto-detect port extractor (mixed-port > port > socks-port, quotes
    // and trailing comments stripped, no provider-specific numbers assumed).
    EXPECT_EQ(subscription::parseMixedPort("mixed-port: 7897\nproxies:\n"),
              static_cast<uint16_t>(7897));
    EXPECT_EQ(subscription::parseMixedPort("port: 1234\nproxies:\n"),
              static_cast<uint16_t>(1234));
    EXPECT_EQ(subscription::parseMixedPort("socks-port: 4321\nproxies:\n"),
              static_cast<uint16_t>(4321));
    // Preference order: mixed-port beats port beats socks-port.
    EXPECT_EQ(subscription::parseMixedPort(
                  "mixed-port: 1111\nport: 2222\nsocks-port: 3333\n"),
              static_cast<uint16_t>(1111));
    EXPECT_EQ(subscription::parseMixedPort("port: 2222\nsocks-port: 3333\n"),
              static_cast<uint16_t>(2222));
    // Quotes and trailing comments stripped.
    EXPECT_EQ(subscription::parseMixedPort("mixed-port: '7897'\n"),
              static_cast<uint16_t>(7897));
    EXPECT_EQ(subscription::parseMixedPort("mixed-port: 7897 # the listener\n"),
              static_cast<uint16_t>(7897));
    EXPECT_EQ(subscription::parseMixedPort("mixed-port: \"58347\"\n"),
              static_cast<uint16_t>(58347));
    // Indented line still matches (patchMixedPort accepts the same shape).
    EXPECT_EQ(subscription::parseMixedPort("  mixed-port: 7000\n"),
              static_cast<uint16_t>(7000));
    // Absent / unparseable / out of range -> 0.
    EXPECT_EQ(subscription::parseMixedPort("proxies:\n  - name: A\n"),
              static_cast<uint16_t>(0));
    EXPECT_EQ(subscription::parseMixedPort("mixed-port: abc\n"),
              static_cast<uint16_t>(0));
    EXPECT_EQ(subscription::parseMixedPort("mixed-port: 0\n"),
              static_cast<uint16_t>(0));
    EXPECT_EQ(subscription::parseMixedPort("mixed-port: 99999\n"),
              static_cast<uint16_t>(0));
    // Only the KEY is matched: "port-range:" must not parse as "port:".
    EXPECT_EQ(subscription::parseMixedPort("port-range: 5000\n"),
              static_cast<uint16_t>(0));
}

APS_TEST(subscription, merge_into_existing) {
    std::string sub =
        "mixed-port: 7890\n"
        "mode: rule\n"
        "external-controller: '127.0.0.1:9090'\n"
        "proxies:\n"
        "  - name: A\n"
        "proxy-groups:\n"
        "  - name: G\n"
        "    type: url-test\n"
        "rules:\n"
        "  - MATCH,G\n";
    std::string existing =
        "mixed-port: 7897\n"
        "mode: direct\n"
        "external-controller: 127.0.0.1:39797\n"
        "proxies:\n"
        "  - name: OLD\n"
        "proxy-groups:\n"
        "  - name: G\n"
        "    type: url-test\n"
        "rules:\n"
        "  - MATCH,G\n"
        "tun:\n"
        "  enable: true\n"
        "  stack: gvisor\n";
    std::string merged = subscription::mergeIntoExisting(sub, existing, 7897);
    EXPECT_TRUE(merged.find("mixed-port: 7897") != std::string::npos);
    EXPECT_TRUE(merged.find("mixed-port: 7890") == std::string::npos);
    // mode is FORCED to rule: the kernel's own traffic (its DoH upstreams)
    // must route through the node — mode: direct poisons the kernel's DNS
    // (youtube.com -> Twitter IPs, measured 2026-08-28).
    EXPECT_TRUE(merged.find("mode: rule") != std::string::npos);
    EXPECT_TRUE(merged.find("mode: direct") == std::string::npos);
    // external-controller takes the EXISTING config's value.
    EXPECT_TRUE(merged.find("external-controller: 127.0.0.1:39797") !=
                std::string::npos);
    EXPECT_TRUE(merged.find("127.0.0.1:9090") == std::string::npos);
    // The sub's proxies win over the existing ones.
    EXPECT_TRUE(merged.find("- name: A") != std::string::npos);
    EXPECT_TRUE(merged.find("- name: OLD") == std::string::npos);
    // The GUI's own tun: block is preserved verbatim.
    EXPECT_TRUE(merged.find("tun:") != std::string::npos);
    EXPECT_TRUE(merged.find("stack: gvisor") != std::string::npos);
}

APS_TEST(subscription, looks_like_clash_yaml) {
    EXPECT_TRUE(subscription::looksLikeClashYaml(
        "mixed-port: 7890\nproxies:\n  - name: A\n"));
    // HTML 403 page (the measured corruption source).
    EXPECT_FALSE(subscription::looksLikeClashYaml(
        "<html><head><title>403 Forbidden</title></head><body></body></html>"));
    // Missing the proxies section.
    EXPECT_FALSE(subscription::looksLikeClashYaml("mixed-port: 7890\nrules:\n"));
    EXPECT_FALSE(subscription::looksLikeClashYaml(""));
}

APS_TEST(subscription, merge_sub_without_external_controller) {
    // Regression: a sub WITHOUT an external-controller line (e.g. after the
    // fetch guard strips nothing but the provider changed shape) must append
    // the existing value ONCE — the old code produced
    // "external-controller: external-controller: ...".
    std::string sub = "mixed-port: 7890\nproxies:\n  - name: A\n";
    std::string existing =
        "mixed-port: 7897\nexternal-controller: 127.0.0.1:39797\n"
        "proxies:\n  - name: OLD\ntun:\n  enable: true\n";
    std::string merged = subscription::mergeIntoExisting(sub, existing, 7897);
    size_t pos = merged.find("external-controller");
    EXPECT_TRUE(pos != std::string::npos);
    EXPECT_TRUE(merged.find("external-controller:", pos + 1) ==
                std::string::npos);  // exactly one occurrence
    EXPECT_TRUE(merged.find("external-controller: 127.0.0.1:39797") !=
                std::string::npos);
}

APS_TEST(subscription, parse_dns_server_ips) {
    // The kernel's own dns section names the resolvers the engine must
    // query through the tunnel — no hard-coded servers anywhere.
    std::string yaml =
        "dns:\n"
        "  enable: true\n"
        "  default-nameserver: [223.5.5.5, 223.6.6.6, 119.29.29.29]\n"
        "  nameserver: ['https://dns.alidns.com/dns-query', "
        "'https://doh.pub/dns-query']\n"
        "proxies:\n";
    auto ips = subscription::parseDnsServerIps(yaml);
    EXPECT_EQ(ips.size(), 3u);
    if (ips.size() == 3) {
        EXPECT_EQ(ips[0], 0xDF050505u);  // 223.5.5.5
        EXPECT_EQ(ips[1], 0xDF060606u);
        EXPECT_EQ(ips[2], 0x771D1D1Du);
    }
    // Block list form + a plain IP nameserver entry.
    std::string block =
        "dns:\n"
        "  default-nameserver:\n"
        "    - 1.2.3.4\n"
        "    - '8.8.4.4'\n"
        "  nameserver:\n"
        "    - 9.9.9.9\n";
    auto ips2 = subscription::parseDnsServerIps(block);
    EXPECT_EQ(ips2.size(), 3u);
    if (ips2.size() == 3) {
        EXPECT_EQ(ips2[0], 0x01020304u);
        EXPECT_EQ(ips2[1], 0x08080404u);
        EXPECT_EQ(ips2[2], 0x09090909u);
    }
    // No dns section: empty (the caller falls back to the adapter DNS).
    EXPECT_TRUE(subscription::parseDnsServerIps("proxies:\n").empty());
}

APS_TEST(subscription, parse_http_url_cases) {
    // The 2026-08-27 incident in test form: the path must survive the split
    // together with the query string — the broken implementation requested
    // "GET /?token=..." and received the server's HTML page.
    std::string host, obj;
    bool https = false;
    EXPECT_TRUE(subscription::parseHttpUrl(
        "https://0b96e976-9ec3-44c0-aa2b-30bf8b0792ea.com/sabusuku?token=abc",
        &host, &obj, &https));
    EXPECT_TRUE(https);
    EXPECT_STREQ(host, "0b96e976-9ec3-44c0-aa2b-30bf8b0792ea.com");
    EXPECT_STREQ(obj, "/sabusuku?token=abc");
    // No path: "/" + query must still keep the query.
    EXPECT_TRUE(subscription::parseHttpUrl("https://h.example.com/?token=x", &host,
                                           &obj, &https));
    EXPECT_STREQ(obj, "/?token=x");
    // No path, no query.
    EXPECT_TRUE(subscription::parseHttpUrl("https://h.example.com", &host, &obj,
                                           &https));
    EXPECT_STREQ(obj, "/");
    // Non-http scheme rejected.
    EXPECT_FALSE(subscription::parseHttpUrl("ftp://h/p", &host, &obj, &https));
}

APS_TEST(subscription, find_cfw_active_profile) {
    wchar_t dir[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    std::wstring base = std::wstring(dir) + L"aps-cfw-test-" +
                        std::to_wstring(GetCurrentProcessId());
    std::wstring cfgDir = base + L"\\.config\\clash";
    std::wstring cmd = L"powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '" +
                       cfgDir + L"' | Out-Null\"";
    _wsystem(cmd.c_str());
    std::string list =
        "files:\n"
        "  - time: 111.yml\n"
        "    url: https://old.example.com/sub\n"
        "  - time: 222.yml\n"
        "    url: https://new.example.com/sub?token=abc\n"
        "index: 1\n";
    HANDLE f = CreateFileW((cfgDir + L"\\list.yml").c_str(), GENERIC_WRITE, 0,
                           nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    EXPECT_TRUE(f != INVALID_HANDLE_VALUE);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(f, list.data(), static_cast<DWORD>(list.size()), &written,
                  nullptr);
        CloseHandle(f);
    }
    auto p = subscription::findClashForWindowsActiveProfile(cfgDir);
    EXPECT_TRUE(p.has_value());
    if (p) {
        EXPECT_TRUE(p->path == cfgDir + L"\\profiles\\222.yml");
        EXPECT_TRUE(p->url == "https://new.example.com/sub?token=abc");
    }
    std::wstring rm = L"powershell -NoProfile -Command \"Remove-Item -Recurse -Force '" +
                      base + L"'\"";
    _wsystem(rm.c_str());
}

APS_TEST(subscription, find_cfw_active_profile_in_profiles_dir) {
    // CFW 0.20+ keeps list.yml under profiles\ (the root copy is absent on
    // this machine) — the finder must fall back to profiles\list.yml.
    wchar_t dir[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    std::wstring base = std::wstring(dir) + L"aps-cfw2-test-" +
                        std::to_wstring(GetCurrentProcessId());
    std::wstring cfgDir = base + L"\\.config\\clash";
    std::wstring profDir = cfgDir + L"\\profiles";
    std::wstring cmd = L"powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '" +
                       profDir + L"' | Out-Null\"";
    _wsystem(cmd.c_str());
    std::string list =
        "files:\n"
        "  - time: 111.yml\n"
        "    url: https://old.example.com/sub\n"
        "  - time: 222.yml\n"
        "    url: https://new.example.com/sub?token=abc\n"
        "index: 1\n";
    HANDLE f = CreateFileW((profDir + L"\\list.yml").c_str(), GENERIC_WRITE, 0,
                           nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    EXPECT_TRUE(f != INVALID_HANDLE_VALUE);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(f, list.data(), static_cast<DWORD>(list.size()), &written, nullptr);
        CloseHandle(f);
    }
    auto p = subscription::findClashForWindowsActiveProfile(cfgDir);
    EXPECT_TRUE(p.has_value());
    if (p) {
        EXPECT_TRUE(p->path == cfgDir + L"\\profiles\\222.yml");
        EXPECT_TRUE(p->url == "https://new.example.com/sub?token=abc");
    }
    std::wstring rm = L"powershell -NoProfile -Command \"Remove-Item -Recurse -Force '" +
                      base + L"'\"";
    _wsystem(rm.c_str());
}

APS_TEST(subscription, merge_cfw_profile) {
    std::string sub =
        "mixed-port: 7890\n"
        "proxies:\n"
        "  - name: '香港-IEPL 01'\n"
        "  - name: '新加坡-IEPL 02'\n";
    std::string profile =
        "mixed-port: 58347\n"
        "proxies:\n"
        "  - name: 'OLD-NODE'\n"
        "proxy-groups:\n"
        "  - { name: 自动选择, type: url-test, proxies: ['剩余流量：43.2 GB', "
        "'OLD-NODE'], url: 'http://cp.cloudflare.com', interval: 7200 }\n"
        "rules:\n"
        "  - MATCH,自动选择\n";
    std::string merged = subscription::mergeCfwProfile(sub, profile);
    // Proxies replaced by the sub's.
    EXPECT_TRUE(merged.find("OLD-NODE") == std::string::npos);
    EXPECT_TRUE(merged.find("香港-IEPL 01") != std::string::npos);
    // The url-test group list regenerated: pseudo entry preserved, fresh
    // names present, stale name gone.
    EXPECT_TRUE(merged.find("剩余流量：43.2 GB") != std::string::npos);
    EXPECT_TRUE(merged.find("'新加坡-IEPL 02'") != std::string::npos);
    EXPECT_TRUE(merged.find("type: url-test") != std::string::npos);
}

APS_TEST(subscription, merge_cfw_profile_inline_json_names) {
    // xmrth-style subscriptions emit proxies as inline JSON flow entries —
    // the name extraction must handle - {"name":"X",...} as well as the
    // block style.
    std::string sub =
        "mixed-port: 7890\n"
        "proxies:\n"
        "  - {\"name\":\"香港800 专线 BGP\",\"type\":\"trojan\",\"port\":1}\n"
        "  - {\"name\":\"台湾611 中继\",\"type\":\"trojan\",\"port\":2}\n";
    std::string profile =
        "proxies:\n"
        "  - {\"name\":\"STALE\",\"type\":\"trojan\",\"port\":9}\n"
        "proxy-groups:\n"
        "  - { name: 自动选择, type: url-test, proxies: ['剩余流量：1.0 GB', "
        "'STALE'], url: 'http://cp.cloudflare.com', interval: 7200 }\n";
    std::string merged = subscription::mergeCfwProfile(sub, profile);
    EXPECT_TRUE(merged.find("STALE") == std::string::npos);
    EXPECT_TRUE(merged.find("香港800 专线 BGP") != std::string::npos);
    EXPECT_TRUE(merged.find("台湾611 中继") != std::string::npos);
    EXPECT_TRUE(merged.find("剩余流量：1.0 GB") != std::string::npos);
}

APS_TEST(subscription, find_sakuracat_url) {
    wchar_t dir[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    std::wstring base = std::wstring(dir) + L"aps-sub-test-" +
                        std::to_wstring(GetCurrentProcessId());
    std::wstring cfgDir = base + L"\\.config\\com.vortex.helper";
    // Missing dir: nullopt.
    EXPECT_FALSE(subscription::findSakuraCatUrl(cfgDir).has_value());
    // Create the dir + a .store.json with a SubscriptionUrl (contains a
    // & escape the JSON parser must decode).
    std::wstring cmd = L"powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '" +
                       cfgDir + L"' | Out-Null\"";
    _wsystem(cmd.c_str());
    std::wstring path = cfgDir + L"\\.store.json";
    std::string json =
        "{\"Id\":\"x\",\"Token\":\"t\",\"SubscriptionUrl\":"
        "\"https://example.com/sub?token=abc\\u0026flag=vortex\"}";
    HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    EXPECT_TRUE(f != INVALID_HANDLE_VALUE);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(f, json.data(), static_cast<DWORD>(json.size()), &written, nullptr);
        CloseHandle(f);
    }
    auto url = subscription::findSakuraCatUrl(cfgDir);
    EXPECT_TRUE(url.has_value());
    if (url) {
        EXPECT_TRUE(url->find("token=abc&flag=vortex") != std::string::npos);
    }
    // Cleanup.
    std::wstring rm = L"powershell -NoProfile -Command \"Remove-Item -Recurse -Force '" +
                      base + L"'\"";
    _wsystem(rm.c_str());
}

APS_TEST_MAIN();
