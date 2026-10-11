// Node-class keyword matching. See nodeclass_detect.hpp.
//
// Vocabulary observed in the wild (SakuraCat/CFW airport subscription):
//   "香港-IEPL 01", "韩国家宽-IEPL 01", "香港家宽-IEPL 01",
//   "澳门-IEPL", "马来西亚-IEPL", plus 中转/直连/进阶/原生/星链 classes.
// Name layout: [地区][家宽][进阶][原生|中转|直连|星链][-IEPL][-序号].
// English keywords cover providers that name nodes in English.
#include "aps/nodeclass_detect.hpp"

#include <string>

namespace aps::nodeclass {

namespace {

// ASCII lowercase view of the name (non-ASCII passes through unchanged).
std::string fold(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        out.push_back(c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a')
                                           : static_cast<char>(c));
    }
    return out;
}

struct ClassDef {
    const char* code;
    const char* const* keywords;
};

// Ordered so the first matching class wins (IEPL checked last for the
// combo names like "家宽-IEPL" — but matches() only ever asks for ONE
// wanted class, so order is irrelevant here; it only matters for clarity).
// IEPL also matches "IPLC": providers name the same leased-line product
// either way (measured 2026-08-31: with class=IEPL selected, an xmrth
// profile whose nodes are all "[IPLC·JP] ...|IPLC专线|..." matched NOTHING
// — the monitor re-selected every stabilization window, churning the
// kernel and killing the browser's connections in a loop).
const char* const kIepl[] = {"iepl", "iplc"};
const char* const kRes[] = {"家宽", "residential", "家"};
const char* const kNative[] = {"原生", "native"};
// 中继/IDC are the xmrth-style relay vocabs (SakuraCat uses 中转).
const char* const kRelay[] = {"中转", "relay", "transit", "中继", "idc"};
const char* const kDirect[] = {"直连", "direct"};
const char* const kStarlink[] = {"星链", "starlink"};
// 专线/IPLC/BGP are the xmrth-style premium vocabs (SakuraCat uses 进阶).
const char* const kPremium[] = {"进阶", "premium", "vip", "elite", "专线",
                                "iplc", "bgp"};

bool containsAny(const std::string& name, const char* const* kws, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (name.find(kws[i]) != std::string::npos) return true;
    }
    return false;
}

}  // namespace

bool matches(std::string_view nodeName, std::string_view wanted) {
    if (wanted.empty()) return true;  // 不限
    const std::string name = fold(nodeName);
    if (wanted == "IEPL") {
        return containsAny(name, kIepl, 2);
    }
    if (wanted == "RES") {
        return containsAny(name, kRes, 3);
    }
    if (wanted == "NATIVE") {
        return containsAny(name, kNative, 2);
    }
    if (wanted == "RELAY") {
        return containsAny(name, kRelay, 5);
    }
    if (wanted == "DIRECT") {
        return containsAny(name, kDirect, 2);
    }
    if (wanted == "STARLINK") {
        return containsAny(name, kStarlink, 2);
    }
    if (wanted == "PREMIUM") {
        return containsAny(name, kPremium, 7);
    }
    return false;  // unknown class code: fail open (caller treats as no match)
}

bool matchesAny(std::string_view nodeName, const std::vector<std::string>& wanted) {
    if (wanted.empty()) return true;  // 不限
    for (const auto& w : wanted) {
        if (matches(nodeName, w)) return true;
    }
    return false;
}

}  // namespace aps::nodeclass
