#include "aps/rule_matcher.hpp"

#include "aps/path_util.hpp"
#include "aps/string_util.hpp"

namespace aps {

std::shared_ptr<const RuleMatcher> RuleMatcher::compile(const Config& cfg,
                                                        const std::wstring& selfPath) {
    auto m = std::make_shared<RuleMatcher>();
    m->cfg_ = cfg;
    m->selfPath_ = canonicalPathKey(selfPath);

    if (cfg.exclusions.builtin || !cfg.exclusions.extraNames.empty()) {
        if (cfg.exclusions.builtin) {
            for (const auto& n : cfg.exclusions.builtinNames) {
                m->exclusionNames_.insert(toLowerAsciiW(utf8ToWide(n)));
            }
        }
        for (const auto& n : cfg.exclusions.extraNames) {
            m->exclusionNames_.insert(toLowerAsciiW(utf8ToWide(n)));
        }
    }
    if (!selfPath.empty()) m->exclusionPaths_.insert(m->selfPath_);
    for (const auto& p : cfg.exclusions.extraPaths) {
        m->exclusionPaths_.insert(canonicalPathKey(utf8ToWide(p)));
    }

    for (const auto& r : cfg.rules) {
        CompiledRule cr;
        std::wstring w = utf8ToWide(r.path);
        cr.pathKey = canonicalPathKey(w);
        cr.hasWildcard = cr.pathKey.find(L'*') != std::wstring::npos;
        cr.dirKey = canonicalPathKey(dirName(w));
        if (!cr.dirKey.empty() && cr.dirKey.back() != L'\\') cr.dirKey.push_back(L'\\');
        cr.id = r.id;
        cr.outletId = r.outlet;
        cr.action = r.action;
        // Global master switch (routing.cover_app_dir_always, default ON)
        // forces whole-app-dir coverage: a per-rule checkbox left off used
        // to strand sub-process traffic (ChatGPT work mode = child exe) as
        // direct — the global switch makes that class of mistake impossible.
        cr.includeChildren = cfg.routing.coverAppDirAlways || r.includeChildren;
        m->rules_.push_back(std::move(cr));
    }
    return m;
}

namespace {
// Simple glob: '*' matches any sequence (including separators and none).
// Pattern and text are already case-folded canonical path keys. Used for
// rules whose path contains a wildcard — e.g. Store apps whose install dir
// embeds the version number (OpenAI.Codex_26.818.3698.0_x64__... changes on
// every auto-update; "OpenAI.Codex_*\app\ChatGPT.exe" survives them all).
bool globMatch(const std::wstring& pat, const std::wstring& text) {
    size_t t = 0, p = 0;
    size_t star = std::wstring::npos;
    size_t mark = 0;
    while (t < text.size()) {
        if (p < pat.size() && pat[p] == text[t]) {
            ++p;
            ++t;
        } else if (p < pat.size() && pat[p] == L'*') {
            star = p++;
            mark = t;
        } else if (star != std::wstring::npos) {
            p = star + 1;
            t = ++mark;
        } else {
            return false;
        }
    }
    while (p < pat.size() && pat[p] == L'*') ++p;
    return p == pat.size();
}
}  // namespace

bool RuleMatcher::isExcluded(const std::wstring& procPath) const {
    if (procPath.empty()) return false;
    if (canonicalPathKey(procPath) == selfPath_) return true;
    if (exclusionPaths_.count(canonicalPathKey(procPath))) return true;
    std::wstring name = toLowerAsciiW(baseName(procPath));
    return exclusionNames_.count(name) > 0;
}

bool RuleMatcher::isExcludedPath(const Config& cfg, const std::wstring& selfPath,
                                 const std::wstring& procPath) {
    // Static variant used by the GUI before an engine exists.
    auto m = compile(cfg, selfPath);
    return m->isExcluded(procPath);
}

RuleMatcher::Decision RuleMatcher::decideTcp(const std::wstring& procPath,
                                              uint32_t dstIpHost,
                                              uint16_t dstPortHost) const {
    (void)dstPortHost;  // reserved for future port-based rules
    Decision d;
    if (isExcluded(procPath)) return d;  // never proxy engine/clash/self

    const CompiledRule* hit = findEnabledRule(procPath);
    if (!hit) return d;

    // Network-critical destinations (multicast/broadcast) are never proxied
    // NOR blocked — they always pass through directly.
    if (isNeverProxyIpv4(dstIpHost)) return d;

    if (hit->action == "block") {
        d.action = Decision::Action::Block;
        d.ruleId = hit->id;
        d.outletId = hit->outletId;
        return d;
    }
    if (hit->action == "direct") {
        // Force direct: wins even when the bypass flags are off.
        d.action = Decision::Action::Direct;
        d.ruleId = hit->id;
        d.outletId = hit->outletId;
        return d;
    }

    if (cfg_.routing.bypassLoopback && isLoopbackIpv4(dstIpHost)) return d;
    if (cfg_.routing.bypassPrivate && isPrivateIpv4(dstIpHost)) return d;

    d.action = Decision::Action::Proxy;
    d.ruleId = hit->id;
    d.outletId = hit->outletId;
    return d;
}

RuleMatcher::Decision RuleMatcher::decideTcpDns(
    const std::wstring& procPath) const {
    Decision d;
    if (isExcluded(procPath)) return d;
    const CompiledRule* hit = findEnabledRule(procPath);
    if (!hit) return d;
    d.ruleId = hit->id;
    d.outletId = hit->outletId;
    if (hit->action == "block") {
        d.action = Decision::Action::Block;
    } else if (hit->action == "direct") {
        d.action = Decision::Action::Direct;
    } else {
        // Empty/legacy actions have always meant proxy.
        d.action = Decision::Action::Proxy;
    }
    return d;
}

bool RuleMatcher::shouldBlockUdp(const std::wstring& procPath, uint16_t dstPortHost) const {
    if (isExcluded(procPath)) return false;
    if (dstPortHost == 53) return false;  // let plain DNS through (all actions)
    const CompiledRule* hit = findEnabledRule(procPath);
    if (!hit) return false;
    if (hit->action == "block") return true;   // block rules drop UDP even
                                               // with the global flag off
    if (hit->action == "direct") return false; // direct rules never block UDP
    return cfg_.routing.blockUdpForRules;
}

bool RuleMatcher::isEnabledRuleProcess(const std::wstring& procPath) const {
    if (isExcluded(procPath)) return false;
    const CompiledRule* hit = findEnabledRule(procPath);
    if (!hit) return false;
    // proxy and block rules drop IPv6 SYNs (force IPv4 fallback); direct
    // rules let IPv6 through unhindered.
    return hit->action != "direct";
}

bool RuleMatcher::hasEnabledBlockRule(const Config& cfg) {
    for (const auto& r : cfg.rules) {
        if (r.enabled && r.action == "block") return true;
    }
    return false;
}

const RuleMatcher::CompiledRule* RuleMatcher::findEnabledRule(
    const std::wstring& procPath) const {
    const std::wstring key = canonicalPathKey(procPath);
    const CompiledRule* hit = nullptr;
    for (const auto& r : rules_) {
        // EXACT match (literal path or glob pattern): decisive — a later
        // exact rule overrides an earlier directory-wide rule (original
        // semantics: only the exact branch breaks).
        const bool exact = r.hasWildcard ? globMatch(r.pathKey, key)
                                         : r.pathKey == key;
        if (exact) {
            hit = &r;
            break;
        }
        // Directory-prefix match: sets the hit but does NOT break, so a
        // later exact rule can still override it. includeChildren applies
        // to wildcard rules too, as a SUBTREE glob: the pattern's directory
        // + "\*" covers every child under it (e.g. ChatGPT desktop's Codex
        // agent sub-process — work mode runs on a different process than
        // chat mode and must inherit the rule, or it goes direct and
        // "正在重新连接" forever).
        bool childMatch = false;
        if (r.includeChildren && !r.dirKey.empty()) {
            childMatch = r.hasWildcard
                             ? globMatch(r.dirKey + L"*", key)
                             : (key.size() > r.dirKey.size() &&
                                key.compare(0, r.dirKey.size(), r.dirKey) == 0);
        }
        if (childMatch) hit = &r;
    }
    if (!hit) return nullptr;
    // Enabled check must consult the live config (rule ids are stable).
    for (const auto& r : cfg_.rules) {
        if (r.id == hit->id && !r.enabled) return nullptr;
    }
    return hit;
}

}  // namespace aps
