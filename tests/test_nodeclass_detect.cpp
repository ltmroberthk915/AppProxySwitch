// Node-class keyword matching (IEPL/家宽/原生/中转/直连/星链/进阶) with
// CN+EN keyword sets for provider-name redundancy.
#include "aps/nodeclass_detect.hpp"
#include "testlib/appsw_test.h"

using namespace aps;

namespace {
void expectMatch(const char* name, const char* cls, bool want) {
    bool got = nodeclass::matches(name, cls);
    if (got != want) {
        std::printf("    matches(\"%s\", \"%s\") = %d, want %d\n", name, cls,
                    got ? 1 : 0, want ? 1 : 0);
    }
    EXPECT_TRUE(got == want);
}
}  // namespace

APS_TEST(nodeclass, real_provider_vocabulary) {
    // Observed in the wild (SakuraCat/CFW airport): 地区[-家宽]-IEPL + 类词.
    expectMatch("香港-IEPL 01", "IEPL", true);
    expectMatch("韩国家宽-IEPL 01", "IEPL", true);
    expectMatch("韩国家宽-IEPL 01", "RES", true);
    expectMatch("香港家宽-IEPL 01", "RES", true);
    expectMatch("澳门-IEPL", "IEPL", true);
    expectMatch("美国-中转-01", "RELAY", true);
    expectMatch("美国-中转-01", "IEPL", false);
    expectMatch("新加坡-直连-01", "DIRECT", true);
    expectMatch("台湾-进阶-IEPL", "PREMIUM", true);
    expectMatch("台湾-进阶-IEPL", "IEPL", true);
    expectMatch("香港-原生-01", "NATIVE", true);
    expectMatch("星链家宽-IEPL", "STARLINK", true);
    expectMatch("星链家宽-IEPL", "RES", true);
}

APS_TEST(nodeclass, english_keywords) {
    // Future providers may name nodes in English.
    expectMatch("US-Residential-01", "RES", true);
    expectMatch("HK-Native-01", "NATIVE", true);
    expectMatch("SG-Direct-01", "DIRECT", true);
    expectMatch("JP-Relay-02", "RELAY", true);
    expectMatch("US-Starlink-01", "STARLINK", true);
    expectMatch("Premium-HK-01", "PREMIUM", true);
    expectMatch("US-LAX-01", "IEPL", false);
    expectMatch("US-Residential-01", "IEPL", false);
}

APS_TEST(nodeclass, xmrth_provider_vocabulary) {
    // The second airport (xmrth) names classes differently: 中继/IDC for
    // relays, 专线/IPLC/BGP for premium lines.
    expectMatch("香港800 专线 BGP", "PREMIUM", true);
    expectMatch("香港300 中继 BGP", "RELAY", true);
    expectMatch("香港301 中继", "RELAY", true);
    expectMatch("香港306 中继 IDC", "RELAY", true);
    expectMatch("[IPLC·HK] 香港801|IPLC专线|1.5x", "PREMIUM", true);
    expectMatch("香港800 专线 BGP", "RELAY", false);
    expectMatch("台湾611 中继", "IEPL", false);
    expectMatch("香港301 中继", "PREMIUM", false);
    // IPLC IS the leased-line class: providers name the same product either
    // way (2026-08-31: class=IEPL matched NOTHING on an all-IPLC profile —
    // the monitor re-selected every window, churning the kernel).
    expectMatch("[IPLC·JP] 日本811|IPLC专线|1.5x", "IEPL", true);
    expectMatch("[IPLC·US] 美国815|IPLC专线|1.5x", "IEPL", true);
    expectMatch("香港800 专线 BGP", "IEPL", false);  // 专线 alone = PREMIUM
}

APS_TEST(nodeclass, unknown_names_fail_open) {
    expectMatch("香港-IEPL 01", "RES", false);   // IEPL without 家宽 ≠ 家宽
    expectMatch("Node-A", "IEPL", false);
    expectMatch("Node-A", "RES", false);
    expectMatch("01", "PREMIUM", false);
    // 不限 matches everything; unknown class codes never match.
    expectMatch("anything", "", true);
    expectMatch("香港-IEPL 01", "WHATEVER", false);
}

APS_TEST_MAIN();
