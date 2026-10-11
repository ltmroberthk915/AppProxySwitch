// Immutable compiled view of the rules/exclusions; swapped atomically on
// config reload. Decisions for existing flows are frozen into NAT entries,
// so reloads only affect NEW connections.
#pragma once

#include <memory>
#include <set>
#include <string>
#include <vector>

#include "aps/config.hpp"

namespace aps {

class RuleMatcher {
public:
    struct Decision {
        enum class Action { Direct, Proxy, Block };
        Action action = Action::Direct;
        std::string ruleId;   // set when action != Direct (Block included,
                              // for stats + log attribution)
        std::string outletId; // frozen with the NAT entry ("" = default outlet)
    };

    static std::shared_ptr<const RuleMatcher> compile(const Config& cfg,
                                                      const std::wstring& selfPath);

    // Decision for a NEW TCP flow from `procPath` (full path) to dst.
    Decision decideTcp(const std::wstring& procPath, uint32_t dstIpHost,
                       uint16_t dstPortHost) const;

    // Decision for TCP DNS when the cleanup layer is enabled. A proxy rule
    // remains Proxy even when the configured resolver is private/loopback:
    // the engine redirects it to a local DNS bridge, not through SOCKS to
    // that private address. Direct/block rules keep their explicit action.
    Decision decideTcpDns(const std::wstring& procPath) const;

    // True when UDP from this process to a non-DNS destination should be
    // dropped (QUIC leak prevention). Only ever true for rule processes.
    bool shouldBlockUdp(const std::wstring& procPath, uint16_t dstPortHost) const;

    // True when `procPath` belongs to an ENABLED rule whose action blocks
    // IPv6 (proxy or block; direct rules let IPv6 through unhindered).
    // Used for the IPv6-TCP blocker: such processes have their IPv6 SYNs
    // dropped so happy-eyeballs falls back to the proxied IPv4 path.
    bool isEnabledRuleProcess(const std::wstring& procPath) const;

    // True when the config has any enabled rule with action == "block".
    // Used for pump gating: the UDP/TCP6 divert handles must be open even
    // when the global block flags are off, or block rules would leak.
    static bool hasEnabledBlockRule(const Config& cfg);

    // Loop protection: engine/self/clash cores, by exact path or image name.
    bool isExcluded(const std::wstring& procPath) const;

    // Used by the GUI to reject saving rules that would create loops.
    static bool isExcludedPath(const Config& cfg, const std::wstring& selfPath,
                               const std::wstring& procPath);

    const Config& config() const { return cfg_; }

private:
    Config cfg_;
    std::wstring selfPath_;
    std::set<std::wstring> exclusionPaths_;   // canonical (lower) keys
    std::set<std::wstring> exclusionNames_;   // lower image names
    struct CompiledRule {
        std::wstring pathKey;    // canonical path key (may contain '*')
        std::wstring dirKey;     // canonical dir key + sep (for children)
        std::string id;
        std::string outletId;
        std::string action;      // "proxy" | "direct" | "block"
        bool includeChildren;
        bool hasWildcard = false;  // glob-match the full path; includeChildren
                                   // then glob-matches the pattern's dir + "\*"
                                   // (subtree coverage for app children)
    };
    std::vector<CompiledRule> rules_;
    // Single precedence source: first path/dir match that is still enabled
    // in the live config (nullptr = none/excluded/disabled). Shared by
    // decideTcp/shouldBlockUdp/isEnabledRuleProcess so all three agree on
    // which rule (and action) wins.
    const CompiledRule* findEnabledRule(const std::wstring& procPath) const;
};

}  // namespace aps
