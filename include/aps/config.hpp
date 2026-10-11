// Application configuration: schema, defaults, validation, JSON mapping.
#pragma once

#include <string>
#include <vector>

#include "aps/dpapi.hpp"
#include "aps/json.hpp"

namespace aps {

constexpr int kConfigVersion = 1;

// One Clash-family controller API (for node health probing / auto-switch).
struct ClashApiConfig {
    std::string host = "127.0.0.1";
    int port = 0;                     // 0 = auto-detect on common ports
    std::string secretEnc;            // DPAPI-protected base64; empty = no auth
    std::string secretPlain;          // transient in-memory secret (auto-discovered
                                      // kernels); never serialized
    std::string plainSecret() const {
        if (!secretPlain.empty()) return secretPlain;
        if (secretEnc.empty()) return {};
        bool ok = false;
        std::string s = crypto::unprotectFromBase64(secretEnc, &ok);
        return ok ? s : std::string();
    }
    // Auto-discovered local controller transport; runtime-only, not user JSON.
    std::string pipe;
    uint32_t pipePid = 0;
};


struct ProxySettings {
    std::string host = "127.0.0.1";   // must be inside 127.0.0.0/8
    int port = 7891;                  // Clash/Mihomo SOCKS5 or mixed port
    std::string username;             // optional (RFC 1929)
    std::string passwordEnc;          // DPAPI-protected, base64; never plain
    int connectTimeoutMs = 5000;
    int ioTimeoutMs = 15000;
    int healthIntervalS = 10;
    int healthTimeoutMs = 3000;
    int healthFailThreshold = 2;
    // Node monitor for the default outlet. Defaults to auto-detect
    // (host set, port 0 = probe well-known ports then all local listening
    // ports) so it works out of the box with any Clash-family client.
    ClashApiConfig clashApi{"127.0.0.1", 0, ""};
};

struct RelaySettings {
    int port = 12753;                 // local transparent-relay listener
};

struct Rule {
    std::string id;                   // stable GUID-ish string
    std::string name;                 // display name
    std::string path;                 // absolute exe path (UTF-8)
    bool enabled = true;
    // Cover the WHOLE app directory (all exes under the selected exe's dir),
    // not just the one exe: apps update their main binary and spawn helper
    // sub-processes (ChatGPT desktop -> resources\codex.exe). Default ON for
    // newly added rules.
    bool includeChildren = true;
    std::string outlet;               // "" = default proxy; else an outlet id
    // Traffic disposition: "proxy" (bind to outlet, the default), "direct"
    // (force direct, no UDP/IPv6 blocking for this process), "block" (drop
    // new connections at SYN time; no NAT entry, no reinjection).
    // "" is normalized to "proxy" on load.
    std::string action = "proxy";
};

// One egress: a local SOCKS5 endpoint (another port/subscription/app).
struct Outlet {
    std::string id;
    std::string name;
    std::string host = "127.0.0.1";
    int port = 7890;
    std::string username;
    std::string passwordEnc;          // DPAPI-protected base64
    // Activated = this is THE egress in use. Deactivated outlets cost
    // nothing: no health checks, no traffic (helps avoid double-billing when
    // the user runs two subscriptions at once). Rules pointing at a
    // deactivated outlet transparently use the default outlet instead.
    bool enabled = true;
    ClashApiConfig clashApi;          // optional node monitor for this outlet
    // host 非空即认为配了监控器；port==0 表示"自动探测/追踪"（CFW 随机端口）。
    bool hasClashApi() const { return !clashApi.host.empty(); }
};

struct Exclusions {
    bool builtin = true;
    std::vector<std::string> builtinNames = {
        "clash.exe", "clash-win64.exe", "clash-meta.exe", "mihomo.exe",
        "mihomo-windows-amd64.exe", "verge-mihomo.exe", "MihomoParty.exe"};
    std::vector<std::string> extraPaths;
    std::vector<std::string> extraNames;
};

struct RoutingSettings {
    bool bypassLoopback = true;
    bool bypassPrivate = true;
    bool blockUdpForRules = true;     // drop non-DNS UDP from rules -> QUIC falls back to TCP
    bool blockIpv6ForRules = true;    // drop rule processes' IPv6 SYNs -> happy-eyeballs
                                      // falls back to IPv4, which we proxy
    // Anti-pollution DNS: rule processes' A queries are answered from the
    // Clash controller's /dns/query (remote resolution) so GFW-poisoned
    // answers never reach them.
    bool dnsCleanup = true;
    // Legacy machine-wide rewriting is opt-in. By default only queries
    // owned by proxy-rule processes are cleaned; shared system DNS and
    // unrelated applications retain their native answers.
    bool dnsCleanupGlobal = false;
    bool ipv6Enabled = false;         // reserved (v1 is IPv4-only)
    // The single "active" outlet id (manual or auto-discovered). When set,
    // it overrides the per-outlet enabled flags: only this outlet carries
    // traffic, everything else falls back to the default egress. "" = use
    // the outlets' enabled flags (legacy behavior).
    std::string autoOutletId;
    // GLOBAL master switch for rule children coverage (default ON): every
    // rule covers its WHOLE app directory regardless of its per-rule
    // checkbox. Store apps update their install dir and run agent modes on
    // sub-processes (measured: ChatGPT desktop's work mode =
    // app\resources\codex.exe — a per-rule checkbox left off made that
    // process go direct and the app loop on "Reconnecting" forever).
    // Turning this OFF restores exact per-rule checkbox semantics.
    bool coverAppDirAlways = true;
    // Preferred DNS servers for the anti-pollution resolver, tried BEFORE
    // the auto-detected ones (the kernel configs' nameserver lists). Plain
    // DNS from an overseas exit to a CHINA-hosted server (223.5.5.5 etc.)
    // crosses the GFW on the way back and comes back poisoned with
    // well-formed fake records (measured 2026-08-31); a FOREIGN server
    // (8.8.8.8 / 1.1.1.1) stays on the clean side of the border. Empty =
    // pure auto-detection (no assumptions in code — the value lives here,
    // in the user's own config). Entries are "ip" or "ip:port" (port
    // defaults to 53).
    std::vector<std::string> dnsServers;
};

struct LoggingSettings {
    std::string level = "info";       // debug|info|warn|error
    int maxFileMb = 10;
    int maxFiles = 5;
};

struct UiSettings {
    bool autostart = false;
    bool startMinimized = false;
    bool confirmStop = true;
};

struct AdvancedSettings {
    int natIdleTimeoutS = 86400;
    int synWaitS = 30;
    int maxSessions = 1024;
    int socketMapTtlS = 120;
};

// Node health monitoring (Clash controller API) settings.
struct NodeMonitorSettings {
    bool enabled = true;              // auto-switch master switch
    int intervalS = 60;               // poll interval
    int failThreshold = 2;            // consecutive failures before switching
    std::string delayUrl = "http://www.gstatic.com/generate_204";
    int delayTimeoutMs = 3000;
    // A node slower than this triggers re-selection and is excluded from the
    // candidate pool (fallback to the lowest-alive when everything exceeds
    // it). NOTE: the controller-measured delay includes the KERNEL's own
    // stack (DNS + implementation), so absolute values are NOT comparable
    // across kernels — measured on the same machine: controller delay
    // CFW=1254ms vs SakuraCat=298ms for the same node, while REAL SOCKS5
    // forwarding (IP CONNECT, no kernel DNS) measured CFW=332ms vs
    // SakuraCat=537ms — CFW is actually FASTER in real traffic. Within one
    // kernel the ranking is reliable. Default is therefore loose: it only
    // weeds out genuinely bad nodes (e.g. 1254ms), not kernel overhead.
    int maxLatencyMs = 800;
    // Stabilization window: non-dead re-selections (too slow / out of
    // region / out of class) do not fire more often than this many
    // seconds. Every node switch kills the kernel's existing connections —
    // an agent app's long-lived session reconnects on each churn (measured:
    // degraded nodes hovering near the latency budget caused a switch every
    // minute and a "reconnecting" loop). Dead nodes switch immediately;
    // manual rounds and preference changes bypass the window. 0 = off.
    int minSwitchIntervalS = 300;
    // Region preference, MULTI-SELECT ("HK"/"TW"/"SG"/"JP"/"US"/"KR"/"MO"/
    // "UK"/"DE"...; empty = 不限). Every checked region is part of the
    // acceptable set — a node matching ANY of them counts as in-region
    // (multi-select avoids "the one checked region's nodes all die" ->
    // fall off the preference entirely). Automatic recovery treats this as
    // a soft preference and falls back to alive nodes; explicit tests require
    // a matching node (detected from node names via region_detect; some airports
    // are transit-only and the entry IP is NOT the exit region, so IP
    // geolocation is deliberately NOT used).
    std::vector<std::string> regions;
    // Node-class preference, MULTI-SELECT ("IEPL"/"RES"(家宽)/"NATIVE"
    // (原生)/"RELAY"(中转)/"DIRECT"(直连)/"STARLINK"(星链)/"PREMIUM"(进阶);
    // empty = 不限). Default {"IEPL"} preserves the original hard-coded
    // IEPL priority. Automatic recovery has the same soft fallback as region;
    // explicit tests require a match (nodeclass_detect covers CN+EN).
    std::vector<std::string> nodeClasses = {"IEPL"};
    // REAL-TRAFFIC failure signal (first principles: the user's own flows
    // are the probe). When >= realFailThreshold connections through an
    // outlet fail inside realFailWindowS seconds AND the failure share is
    // >= realFailRatioPct%, the engine self-triggers a node re-selection —
    // even when the controller's /delay still reports the current node as
    // healthy (measured 2026-08-28: a node passed gstatic /delay at 305ms
    // while every real connection to blocked sites got TLS-reset). No
    // hard-coded target URL: the verification CONNECT after a switch dials
    // the exact destination the user's traffic just failed to reach.
    int realFailThreshold = 4;
    int realFailRatioPct = 40;
    int realFailWindowS = 60;
    // A node that FAILED the post-switch real-CONNECT verification is
    // excluded from candidate selection for this long (seconds) — the
    // retry loop then walks the candidate list instead of re-picking the
    // same broken node forever. 0 = off.
    int badNodeCooldownS = 600;
};

// Scheduled subscription refresh. Providers gate downloads behind IP
// whitelists whose entries ROTATE (dynamic home IPs + "长期未使用自动删
// 除"), while their own node IPs stay whitelisted unconditionally — so the
// reliable path is fetching THROUGH the kernel (already the retry) and
// keeping configs fresh enough that the kernel always has live nodes to
// ride (measured 2026-09-04: a config gone fully stale left the tunnel
// retry nothing to connect through). Refresh is opt-in. Client-owned
// lifecycle paths such as SakuraCat are also blocked in the engine, so
// a legacy auto_refresh=true cannot trigger config writes/core restarts.
struct SubscriptionSettings {
    bool autoRefresh = false;
    int intervalHours = 24;   // 0 = scheduled refresh off (start-delay one still runs)
    // Minutes after engine start for the first refresh (kernel adoption
    // grace; also catches "rebooted with a stale config").
    int startDelayMin = 10;
};

struct Config {
    int version = kConfigVersion;
    ProxySettings proxy;
    RelaySettings relay;
    std::vector<Rule> rules;
    std::vector<Outlet> outlets;
    Exclusions exclusions;
    RoutingSettings routing;
    std::string failMode = "open";    // "open" | "closed"
    NodeMonitorSettings nodeMonitor;
    SubscriptionSettings subscription;
    LoggingSettings logging;
    UiSettings ui;
    AdvancedSettings advanced;

    static Config makeDefault();

    // In-memory plaintext password (decrypted via DPAPI); empty when no auth.
    void setPlainPassword(const std::string& plain);
    std::string plainPassword() const;

    json::Value toJson() const;
    // Strict-typed parse. Returns false + human-readable error on violation.
    // Unknown keys are tolerated and reported via `warnings`.
    static bool fromJson(const json::Value& v, Config& out, std::string* error,
                         std::vector<std::string>* warnings);
    bool validate(std::string* error) const;
};

// --- persistence (atomic) ----------------------------------------------------
std::wstring defaultConfigPath();   // %LOCALAPPDATA%\AppProxySwitch\config.json

// Missing file -> returns true with defaults (first run). Corrupt file ->
// false + error; caller may back it up and continue with defaults.
bool loadConfigFile(const std::wstring& path, Config& out, std::string* error,
                    std::vector<std::string>* warnings, bool* wasDefault);

// Write via <path>.tmp + MoveFileEx(REPLACE_EXISTING|WRITE_THROUGH).
bool saveConfigFile(const std::wstring& path, const Config& cfg, std::string* error);

}  // namespace aps
