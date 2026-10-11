// Node-name region detection: multi-signal corpus across naming styles
// (flags / Chinese simp+trad / English / ISO tokens / IATA codes) and the
// conservative conflict handling.
#include "aps/region_detect.hpp"
#include "testlib/appsw_test.h"

using namespace aps;

namespace {
void expectRegion(const char* name, const char* want) {
    std::string got = region::detectNodeRegion(name);
    if (got != want) {
        std::printf("    detectNodeRegion(\"%s\") = \"%s\", want \"%s\"\n", name,
                    got.c_str(), want);
    }
    EXPECT_STREQ(got, want);
}
}  // namespace

APS_TEST(region, emoji_flags) {
    expectRegion("🇭🇰 香港-原生-01", "HK");
    expectRegion("🇯🇵 Tokyo BGP", "JP");
    expectRegion("🇸🇬|新加坡", "SG");
    expectRegion("🇺🇸 US-LAX-01", "US");
    expectRegion("🇹🇼 台湾", "TW");
    expectRegion("🇰🇷 韩国首尔", "KR");
    // Two different flags: conservative unknown.
    EXPECT_STREQ(region::detectNodeRegion("🇭🇰 香港 | 🇯🇵 日本"), "");
}

APS_TEST(region, chinese_keywords_simp_and_trad) {
    expectRegion("香港-IEPL 01", "HK");
    expectRegion("台湾-IEPL 03", "TW");
    expectRegion("臺灣 02", "TW");
    expectRegion("台北 05", "TW");
    expectRegion("日本東京-02", "JP");
    expectRegion("日本-大阪-01", "JP");
    expectRegion("新加坡-中转-01", "SG");
    expectRegion("美國 05", "US");
    expectRegion("美国-洛杉矶", "US");
    expectRegion("韓國首爾-01", "KR");
    expectRegion("韩国-01", "KR");
    expectRegion("澳門 CTM", "MO");
    expectRegion("德国-法兰克福", "DE");
    expectRegion("英国-伦敦", "UK");
    // xmrth-provider vocabulary (the second airport the user added).
    expectRegion("香港800 专线 BGP", "HK");
    expectRegion("台湾611 中继", "TW");
    expectRegion("狮城502 中继 动态", "SG");      // 狮城 = Singapore
    expectRegion("马来753 中继", "MY");           // 马来 = Malaysia
    expectRegion("澳洲 IEPL 01", "AU");           // 澳洲 = Australia
    expectRegion("[IPLC·HK] 香港801|IPLC专线|1.5x", "HK");
}

APS_TEST(region, english_and_iso_tokens) {
    expectRegion("US-LAX-01", "US");
    expectRegion("JP_Tokyo_A", "JP");
    expectRegion("SG.中转.01", "SG");
    expectRegion("Taiwan VIP", "TW");
    expectRegion("Singapore 01", "SG");
    expectRegion("HongKong-02", "HK");
    expectRegion("KR-Seoul-05", "KR");
    expectRegion("TW|台湾-IEPL 03", "TW");
    // Whole-token equality prevents false hits inside longer words.
    expectRegion("status-01", "");
}

APS_TEST(region, iata_airport_codes) {
    expectRegion("NRT-01", "JP");
    expectRegion("HND-中转", "JP");
    expectRegion("SIN-02", "SG");
    expectRegion("ICN-01", "KR");
    expectRegion("FRA-03", "DE");
    expectRegion("LHR-01", "UK");
}

APS_TEST(region, single_char_and_ambiguity) {
    expectRegion("港-01", "HK");
    expectRegion("台-02", "TW");
    expectRegion("坡-03", "SG");
    expectRegion("美-01", "US");
    expectRegion("日-01", "JP");
    // "新北" is TW; "新加坡" is SG — never confused.
    expectRegion("新北-01", "TW");
    expectRegion("新加坡-01", "SG");
    // "新" alone is ambiguous and deliberately unmapped.
    expectRegion("新-01", "");
}

APS_TEST(region, unknown_and_conflicts) {
    expectRegion("IEPL 01", "");
    expectRegion("Node-A", "");
    expectRegion("01", "");
    expectRegion("", "");
    // Same-priority conflict (two cities of different regions).
    expectRegion("东京-洛杉矶-01", "");
}

APS_TEST(region, matches_semantics) {
    EXPECT_TRUE(region::matches("HK", "HK"));
    EXPECT_FALSE(region::matches("HK", "JP"));
    EXPECT_FALSE(region::matches("", "JP"));   // unknown never matches
    EXPECT_TRUE(region::matches("", ""));      // 不限
    EXPECT_TRUE(region::matches("JP", ""));    // 不限 matches everything
}

APS_TEST_MAIN();
