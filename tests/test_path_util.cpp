// IP classification helpers (never-proxy network-critical ranges).
#include "aps/path_util.hpp"
#include "testlib/appsw_test.h"

using namespace aps;

APS_TEST(path_util, never_proxy_ranges) {
    EXPECT_TRUE(isNeverProxyIpv4(0xE0000001u));   // 224.0.0.1 (multicast low)
    EXPECT_TRUE(isNeverProxyIpv4(0xEFFFFFFFu));   // 239.255.255.255 (multicast high)
    EXPECT_TRUE(isNeverProxyIpv4(0xEF000001u));   // 239.0.0.1 (admin-scoped)
    EXPECT_TRUE(isNeverProxyIpv4(0xFFFFFFFFu));   // 255.255.255.255 (limited broadcast)
    EXPECT_FALSE(isNeverProxyIpv4(0xDFFFFFFFu));  // 223.255.255.255 (just below multicast)
    EXPECT_FALSE(isNeverProxyIpv4(0xF0000001u));  // 240.0.0.1 (reserved, not multicast)
    EXPECT_FALSE(isNeverProxyIpv4(0x08080808u));  // 8.8.8.8
    EXPECT_FALSE(isNeverProxyIpv4(0x7F000001u));  // 127.0.0.1
    EXPECT_FALSE(isNeverProxyIpv4(0xC0A80001u));  // 192.168.0.1 (covered by isPrivateIpv4)
    EXPECT_FALSE(isNeverProxyIpv4(0xA9FE0001u));  // 169.254.0.1 (covered by isPrivateIpv4)
    EXPECT_FALSE(isNeverProxyIpv4(0x00000000u));  // 0.0.0.0 (covered by isPrivateIpv4)
}

APS_TEST(path_util, version_robust_path_store_app) {
    // The canonical case: Store apps embed the version in the install dir.
    std::wstring got = versionRobustPath(
        L"C:\\Program Files\\WindowsApps\\OpenAI.Codex_26.818.3698.0_x64__2p2nqsd0c76g0\\app\\ChatGPT.exe");
    std::wstring want =
        L"C:\\Program Files\\WindowsApps\\OpenAI.Codex*\\app\\ChatGPT.exe";
    EXPECT_TRUE(got == want);
    if (got != want) std::printf("    got: %ls\n", got.c_str());
}

APS_TEST(path_util, version_robust_path_variants) {
    auto check = [](const std::wstring& in, const std::wstring& want) {
        std::wstring got = versionRobustPath(in);
        if (got != want) std::printf("    %ls -> %ls (want %ls)\n", in.c_str(),
                                     got.c_str(), want.c_str());
        EXPECT_TRUE(got == want);
    };
    // app-name-version dirs
    check(L"C:\\Tools\\app-1.2.3\\bin\\app.exe", L"C:\\Tools\\app*\\bin\\app.exe");
    // v-prefixed version dir
    check(L"C:\\Tools\\v2.3.4\\app.exe", L"C:\\Tools\\*\\app.exe");
    // version token at the start of a segment
    check(L"C:\\Data\\26.1.9.0_x64\\app.exe", L"C:\\Data\\*\\app.exe");
    // NO version anywhere: untouched
    check(L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
          L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
    // Two numeric components only: NOT a version token, untouched
    check(L"C:\\Data\\2.0\\file.exe", L"C:\\Data\\2.0\\file.exe");
    // The FILENAME is never touched (versioned exe names stay exact)
    check(L"C:\\Apps\\dir\\app-1.2.3.exe", L"C:\\Apps\\dir\\app-1.2.3.exe");
    // Single-segment relative input: untouched
    check(L"app.exe", L"app.exe");
    // HEX-HASH dirs (Codex rotates bin\<sha>\ on every self-update,
    // measured 2026-09-01): wildcarded like versions.
    check(L"C:\\Users\\Ming\\AppData\\Local\\OpenAI\\Codex\\bin\\d0097be4feba73d0\\codex.exe",
          L"C:\\Users\\Ming\\AppData\\Local\\OpenAI\\Codex\\bin\\*\\codex.exe");
    check(L"C:\\Users\\Ming\\AppData\\Local\\OpenAI\\Codex\\bin\\b99306303521e97e\\codex.exe",
          L"C:\\Users\\Ming\\AppData\\Local\\OpenAI\\Codex\\bin\\*\\codex.exe");
    // Short hex like "abc1234" (<8) or mixed alnum: NOT a hash, untouched
    check(L"C:\\Data\\abc1234\\file.exe", L"C:\\Data\\abc1234\\file.exe");
    check(L"C:\\Data\\app2020\\file.exe", L"C:\\Data\\app2020\\file.exe");
}


APS_TEST_MAIN();
