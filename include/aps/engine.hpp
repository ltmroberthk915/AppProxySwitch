// Engine orchestration: SOCKET-layer attribution, NETWORK-layer whole-flow
// NAT rewriting, relay + SOCKS5, health monitoring, stats and IPC push.
#pragma once

#include <atomic>
#include <condition_variable>
#include <deque>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <windivert.h>

#include "aps/config.hpp"
#include "aps/divert_device.hpp"
#include "aps/dns_rewrite.hpp"
#include "aps/health_monitor.hpp"
#include "aps/kernel_discovery.hpp"
#include "aps/nat_table.hpp"
#include "aps/rule_matcher.hpp"
#include "aps/relay_server.hpp"
#include "aps/socket_map.hpp"
#include "aps/stats.hpp"
#include "aps/subscription.hpp"
#include "aps/verge_subscription.hpp"
#include "aps/tcp_table.hpp"

namespace aps {

// The id of the built-in default egress (cfg.proxy).
inline constexpr const char* kDefaultOutletId = "__default__";

enum class EngineState { Starting, Running, Degraded, Draining, Stopping, Stopped };

const char* engineStateName(EngineState s);

struct EngineEvents {
    // Full JSON payload of an IPC message (without the trailing newline).
    std::function<void(const std::string&)> onStatus;
    std::function<void(const std::string&)> onStats;
    std::function<void(const std::string& level, const std::string& msg)> onLog;
    // Power saving: when set and returning false, the per-second STATS
    // build+push is skipped entirely (no GUI consumer — e.g. the GUI process
    // has exited). Empty = always push.
    std::function<bool()> wantsStats;
};

class Engine {
public:
    Engine(std::unique_ptr<IDivertDevice> device, EngineEvents events);
    ~Engine();

    bool start(const Config& cfg, std::string* err);
    void stop();

    // Atomic swap of rules/proxy settings. Affects NEW connections only.
    void reloadConfig(const Config& cfg);
    // Master switch: false stops intercepting new connections ("仅影响新连接").
    void setEnabled(bool on);
    // Tear down existing redirected connections (all, or one rule).
    void flushConnections(const std::optional<std::string>& ruleId);

    EngineState state() const { return state_.load(); }
    bool enabled() const { return enabled_.load(); }
    // Current STATUS message payload (used to answer HELLO).
    std::string statusJson() const { return buildStatusJson(); }
    // IPC: "测试并连接" — queue an immediate probe round. Fully async: the
    // caller only pushes an id into a deque and sets the wake event; the
    // node-monitor thread performs every network operation. Zero network
    // I/O and zero lock nesting on the pipe thread.
    // outletId: "" = full round; otherwise only that outlet is probed.
    void requestNodeSwitchRound(const std::string& outletId = "", bool manual = true,
                               const std::string& requestId = "");
    // Auto-discovery of running proxy kernels (Quick name-filtered scan by
    // default). Public so tests can drive adoption deterministically.
    void adoptDiscoveries(DiscoveryMode mode = DiscoveryMode::Quick);
    // Test seam: disable real machine scans inside the test harness (real
    // kernels running on a dev machine would leak into engine state).
    void setKernelDiscoveryEnabled(bool on) { kernelDiscoveryEnabled_.store(on); }
    // Test seam: replace the kernel-cache source (start() seeds remembered
    // kernels as offline rows). Empty = read the real kernel_cache.json.
    void setKernelCacheLoader(std::function<std::vector<DiscoveredKernel>()> fn) {
        kernelCacheLoader_ = std::move(fn);
    }
    // Test seam: shrink the fresh-DNS-cache TTL (default 5 min).
    void setDnsTtlMsForTest(int64_t v) { dnsTtlMs_.store(v); }
    // Test seam: redirect the health monitors' real-CONNECT probe to a
    // LOCAL endpoint (default 1.1.1.1:443 — harness tests must never dial
    // external hosts).
    void setHealthProbeDstForTest(const net::Endpoint4& dst) {
        healthProbeDst_ = dst;
    }
    // Test seam: redirect the DNS SOCKS resolver to a local TCP responder
    // (replaces the auto-detected per-kernel servers).
    void setDnsSocksDnsServerForTest(const net::Endpoint4& ep) {
        dnsServersOverride_ = {ep};
    }
    // Test seam: replace the DoH resolver (the real one does TLS via
    // WinHTTP — harness tests must never dial out).
    void setDohResolverForTest(
        std::function<bool(uint16_t proxyPort, uint32_t serverIp,
                           const std::string& name, std::vector<uint32_t>& ips,
                           int timeoutMs, std::string* err)> fn) {
        dohOverride_ = std::move(fn);
    }
    // "刷新订阅": supported profile-only refresh. SakuraCat is rejected
    // before reading/fetching/writing; its own client owns its lifecycle.
    void refreshSubscription(bool scheduled = false);
    // Test seam: replace the subscription fetcher (real one does HTTPS).
    void setSubscriptionFetcher(
        std::function<bool(const std::string&, std::string&, std::string*)> fn) {
        subFetcher_ = std::move(fn);
    }
    // Test seam: replace the final profile applier. Production refresh only
    // writes CFW's profile; SakuraCat must never reach this callback.
    void setSubApplier(
        std::function<void(const std::string& merged, const std::string& kind)>
            fn) {
        subApplier_ = std::move(fn);
    }
    // Test seams for the refresh flow's locations (real ones read the
    // machine's SakuraCat/CFW config dirs — hermetic tests redirect them).
    void setSakuraCatUrlFinder(
        std::function<std::optional<std::string>()> fn) {
        sakuraUrlFinder_ = std::move(fn);
    }
    void setSakuraCatConfigDir(std::wstring dir) {
        sakuraCatDirOverride_ = std::move(dir);
    }
    void setCfwProfileFinder(
        std::function<std::optional<subscription::ActiveProfile>()> fn) {
        cfwProfileFinder_ = std::move(fn);
    }
    // Test seam: inject live kernel discoveries without a real port scan
    // (a real scan would adopt the harness's own in-process mocks, which
    // makes multi-kernel states impossible to script).
    void seedDiscoveredKernelsForTest(
        const std::vector<DiscoveredKernel>& kernels) {
        std::lock_guard<std::mutex> lk(discMu_);
        for (const auto& k : kernels) {
            if (k.procName.empty()) continue;
            std::string id = k.id.empty() ? ("auto-" + k.procName) : k.id;
            discovered_[id] = KernelEntry{k, true, true};
        }
    }
    // Test seam: replace the machine scan inside adoptDiscoveries (the real
    // one probes the whole machine, so seeding + adoption race on real
    // kernels). Tests that script discovered_ use this to keep adoption
    // deterministic (typically: return {} — the pump's initial adoption
    // then can never mark seeded kernels offline).
    void setDiscoveryScanForTest(
        std::function<std::vector<DiscoveredKernel>(DiscoveryMode)> fn) {
        discoveryScan_ = std::move(fn);
    }

    // Test seams.
    SocketMap& socketMap() { return socketMap_; }
    void setTcpTable(std::unique_ptr<ITcpTableQuery> t) { tcpTable_ = std::move(t); }
    RelayServer& relay() { return relay_; }
    NatTable& nat() { return nat_; }
    StatsRegistry& stats() { return stats_; }
    // Read-only outlet introspection (tests; also useful to GUI tooling).
    RelayParams outletParams(const std::string& id) const;
    bool outletEnabled(const std::string& id) const;
    bool outletHealthy(const std::string& id) const;

private:
    struct Runtime {
        Config cfg;
        std::shared_ptr<const RuleMatcher> matcher;
    };
    std::shared_ptr<const Runtime> runtime() const;

    void socketPump();
    void tcpPump();
    void udpPump();
    void tcp6Pump();
    void dnsPump();
    void nodeMonitorPump();
    void timerPump();

    // --- node monitoring (Clash controller API) --------------------------------
    struct NodeStatus {
        std::string outletId;
        net::Endpoint4 checkedProxy{};  // endpoint this result actually measured
        std::string group;
        std::string node;
        int latencyMs = -1;
        bool alive = false;
        bool apiAvailable = false;
        std::string apiError;            // human-readable when apiAvailable=false
        std::string runtimeMode;        // controller mode, empty = unverified
        std::string routingWarning;     // node probes do not verify business routing
        uint16_t detectedPort = 0;       // discovered controller port (0 = unknown)
        int consecutiveFails = 0;
        int64_t lastSwitchAt = 0;
        std::string lastSwitchDetail;    // "node-b -> node-c (412ms)"
        // True while a re-selection round is measuring candidates for this
        // outlet: the GUI shows "切换中…" instead of the (stale) previous
        // node — the per-second STATS would otherwise keep repainting the
        // old node over the in-flight switch.
        bool switching = false;
        bool selectionSatisfied = true; // manual result met region/class filters
        std::string region;             // same detected/inferred region used for selection
        std::string testRequestId;      // correlates a GUI click with its own result
        // Region preference state: which region string the current node was
        // last evaluated against, and whether a re-select already proved the
        // region unavailable (prevents per-round flapping when the provider
        // simply has no node in the wanted region).
        std::string regionApplied;
        bool regionUnavailable = false;
        // Same anti-flap state for the node-class preference.
        std::string classApplied;
        bool classUnavailable = false;
        // True when classUnavailable was latched because a wanted
        // "GROUP:<name>" entry does not exist on THIS controller at all
        // (unsatisfiable — e.g. GROUP:AI服务 selected globally while the
        // SakuraCat controller has no such group). Unlike the veto latch,
        // this one re-arms automatically when the group appears (the user
        // switched the kernel's profile/provider).
        bool classGroupMissing = false;
        // Every selector group with its member list (refreshed each round):
        // backs the "GROUP:<name>" class entries (group membership, incl.
        // transitive sub-group references).
        std::map<std::string, std::vector<std::string>> groupNodes;
    };
    void nodeMonitorRound();                       // one probe/switch cycle
    void runNodeRoundFor(const std::string& outletId, bool manual = true,
                         const std::string& requestId = "");
    void monitorOneOutlet(const Config& cfg, const std::string& outletId,
                          const ClashApiConfig& api, NodeStatus& st,
                          bool manualRound = false);
    void seedNodeStatuses(const Config& cfg);
    std::map<std::string, NodeStatus> nodeStatusSnapshot() const;
    json::Value nodeStatusJson() const;
    json::Value effectiveProxyJson() const;
    json::Value kernelsJson() const;

    struct OwnerInfo {
        uint32_t pid = 0;
        std::wstring path;
    };
    std::optional<OwnerInfo> resolveOwner(uint32_t srcIp, uint16_t srcPort, uint32_t dstIp,
                                          uint16_t dstPort);
    void handleTcpPacket(uint8_t* buf, size_t len, const PacketMeta& meta);
    void handleUdpPacket(uint8_t* buf, size_t len);
    void handleTcp6Packet(uint8_t* buf, size_t len);
    void handleDnsPacket(uint8_t* buf, size_t len, const PacketMeta& meta);
    bool shouldCleanDns(uint8_t* buf, size_t len, const PacketMeta& meta);
    void dnsWorkerPump();
    void processDnsQuery(std::vector<uint8_t> packet, const PacketMeta& meta);
    // Shared A-resolution path for UDP DNS and the relay's TCP-DNS bridge.
    // Serialized because the chosen controller/kernel state is mutable.
    bool resolveCleanA(const std::string& name, std::vector<uint32_t>& ips,
                       std::string* source, std::string* err);
    bool resolveTcpDnsQuery(const uint8_t* query, size_t queryLen,
                            std::vector<uint8_t>& response);
    void injectDnsReply(const uint8_t* buf, size_t len, const PacketMeta& meta,
                        const uint8_t* dnsPayload, size_t dnsLen);
    // DNS fallback for kernels whose controller has no /dns/query (old
    // Clash cores like CFW's answer 404): resolve via TCP 53 THROUGH the
    // kernel's SOCKS tunnel — the nameserver sees the node's exit, so the
    // answer is unpoisoned. Called under dnsResolveMu_. `deadlineMs` is an
    // absolute nowMs() deadline shared with the controller fallback.
    bool resolveViaSocksTcpDns(const std::string& name,
                               std::vector<uint32_t>& ips,
                               int64_t deadlineMs = 0);
    // Auto-detected per-kernel DNS servers (kernel config.yaml dns section,
    // else the adapter's DNS) — no hard-coded servers.
    std::vector<net::Endpoint4> dnsServersForKernel(const std::string& id);
    void onProxyHealth(const std::string& outletId, bool healthy,
                       const std::string& detail);
    void sendTeardownRst(const std::shared_ptr<NatEntry>& e);

    // --- outlets (multi-egress) ----------------------------------------------
    struct OutletRuntime {
        // id -> RelayParams (egress endpoint + credentials); key kDefaultOutletId
        // always present.
        std::map<std::string, RelayParams> params;
        // display name per id ("" for the default outlet).
        std::map<std::string, std::string> names;
        // Disabled (deactivated) outlets: zero traffic, zero health checks,
        // rules bound to them fall back to the default outlet.
        std::set<std::string> disabled;
        // The default egress's EFFECTIVE SOCKS port after auto-resolution
        // (may differ from cfg.proxy.port when that port is dead and a live
        // kernel was auto-followed).
        uint16_t defaultSocksPort = 0;
    };
    std::shared_ptr<const OutletRuntime> outletsSnapshot() const {
        return outlets_.load();
    }
    void rebuildOutlets(const Config& cfg);
    // Auto-detect the default egress's SOCKS port: the configured port while
    // something still answers there (user intent is authoritative while it is
    // live); otherwise the activated kernel's port; otherwise the sole live
    // discovered kernel's port; otherwise STICKY — the port the default
    // egress already uses, when a live kernel still serves it (activating
    // the default row must not snap the egress back to a dead configured
    // port); otherwise the configured port unchanged (the node row then
    // reports the dead port explicitly).
    uint16_t resolveDefaultSocksPort(const Config& cfg);
    std::string resolveRuleOutlet(const std::string& ruleOutlet) const;
    net::Endpoint4 outletEndpoint(const std::string& id) const;
    std::string outletUsername(const std::string& id) const;
    std::string outletPassword(const std::string& id) const;
    void rebuildHealthMonitors(const Config& cfg);

    std::string buildStatusJson() const;
    std::string buildStatsJson() const;
    // Active-flow array for the STATS push ("活动连接" view): NAT snapshot
    // sorted by recency, capped, with process/host resolved on the fly.
    json::Value connectionsJson(int64_t nowMs) const;
    void pushStatus() { if (events_.onStatus) events_.onStatus(buildStatusJson()); }
    void pushStats() { if (events_.onStats) events_.onStats(buildStatsJson()); }

    std::unique_ptr<IDivertDevice> device_;
    EngineEvents events_;

    std::atomic<std::shared_ptr<const Runtime>> runtime_;
    SocketMap socketMap_;
    std::unique_ptr<ITcpTableQuery> tcpTable_ = std::make_unique<TcpTableQuery>();
    NatTable nat_;
    RelayServer relay_;
    // Per-egress reachability monitors (key = outlet id; kDefaultOutletId
    // always present). Rebuilt wholesale on config reload.
    std::mutex healthMu_;
    std::map<std::string, std::unique_ptr<HealthMonitor>> healthMonitors_;
    // Debounces automatic dead-tunnel recovery across wholesale health
    // monitor rebuilds. A rebuild creates fresh monitor objects whose first
    // callback is an announcement, not necessarily a new logical transition;
    // it must not bypass the node-switch stabilization policy every tick.
    std::mutex tunnelRecoveryMu_;
    std::string tunnelRecoveryOutlet_;
    bool tunnelRecoveryWasHealthy_ = true;
    // Where the health monitors' real-CONNECT probe dials (see
    // HealthMonitor::Params::dst). AUTO-DETECTED lazily: the delay_url
    // host resolved through the tunnel (no hard-coded IPs). {0,0} until
    // resolved — the probe degrades to greeting-only meanwhile. Tests
    // point it at a local listener via setHealthProbeDstForTest.
    net::Endpoint4 healthProbeDst_{0, 0};
    void maybeResolveHealthProbeDst(const Config& cfg);
    // Serializes health-monitor set rebuilds. Three threads can rebuild
    // concurrently (pipe RELOAD, the config-file watcher, and the node pump
    // adopting discoveries); without this, one rebuild overwrites another's
    // freshly started monitor while its thread is still running
    // (use-after-free -> silent engine death on "测试并连接").
    std::mutex rebuildMu_;
    std::atomic<std::shared_ptr<const OutletRuntime>> outlets_;
    StatsRegistry stats_;

    std::atomic<EngineState> state_{EngineState::Stopped};
    std::atomic<bool> enabled_{true};
    std::atomic<bool> stopping_{false};
    std::thread socketThread_, tcpThread_, udpThread_, tcp6Thread_, dnsThread_, dnsWorkerThread_,
        nodeThread_, timerThread_;
    // TCP-pump liveness heartbeat (see timerPump's stall watchdog).
    std::atomic<uint64_t> tcpPumpIters_{0};
    std::atomic<bool> tcpPumpExited_{false};
    // Next scheduled subscription refresh (see SubscriptionSettings);
    // consumed by the node pump. Set at pump start to now+startDelayMin.
    std::atomic<int64_t> nextAutoSubRefreshMs_{0};
    HANDLE nodeWakeEvent_ = nullptr;   // set by requestNodeSwitchRound()
    std::mutex nodeMu_;
    std::map<std::string, NodeStatus> nodeStatus_;
    // Async rapid-round queue (pipe thread pushes, node thread drains).
    std::mutex reqMu_;
    struct NodeRoundRequest { std::string outletId; bool manual; std::string requestId; };
    std::deque<NodeRoundRequest> pendingRounds_;
    // Auto-discovered proxy kernels: id ("auto-<proc>", extra same-named
    // instances get "auto-<proc>#2", "#3"...) -> entry. Two processes with
    // the same image name are DIFFERENT kernels and never overwrite each
    // other's ports (measured: a second com.vortex.helper.exe backend on
    // controller 39797 wiped the main instance's 7897/39798 pairing).
    struct KernelEntry {
        DiscoveredKernel kernel;
        bool alive = false;
        // True once a completed scan has observed this entry (found it, or
        // confirmed it missing). The GUI blocks clicks only on
        // CONFIRMED-dead rows — never during the brief "detecting" window
        // right after an engine start, where cached kernels are seeded
        // unverified (clicks then run a real probe instead of a dialog).
        bool verified = false;
    };
    std::mutex discMu_;
    std::map<std::string, KernelEntry> discovered_;
    std::atomic<bool> kernelDiscoveryEnabled_{true};
    std::function<std::vector<DiscoveredKernel>()> kernelCacheLoader_;  // test seam
    // Subscription-refresh state (reported in STATUS as "sub_refresh").
    std::mutex subRefreshMu_;
    std::string subRefreshMsg_;
    std::mutex subRefreshRunMu_;
    std::jthread subRefreshWorker_;
    std::atomic<bool> subRefreshWorkerActive_{false};
    std::optional<VergeSubscriptionTicket> pendingVergeRefresh_;
    std::function<bool(const std::string&, std::string&, std::string*)>
        subFetcher_;  // test seam
    std::function<void(const std::string& merged, const std::string& kind)>
        subApplier_;  // test seam
    std::function<std::optional<std::string>()> sakuraUrlFinder_;  // test seam
    std::wstring sakuraCatDirOverride_;                            // test seam
    std::function<std::optional<subscription::ActiveProfile>()>
        cfwProfileFinder_;  // test seam
    std::function<std::vector<DiscoveredKernel>(DiscoveryMode)>
        discoveryScan_;  // test seam
    int fullScanCountdown_ = 0;        // ticks until the next blind full scan
    std::atomic<uint64_t> unresolvedCount_{0};
    std::atomic<int64_t> degradedSinceMs_{0};
    std::atomic<bool> degradedDrained_{false};
    std::wstring selfPath_;
    uint16_t relayPort_ = 0;
    bool udpPumpRunning_ = false;
    bool tcp6PumpRunning_ = false;
    bool dnsPumpRunning_ = false;

    // DNS cleanup state
    std::atomic<uint16_t> dnsApiPort_{0};
    // Which kernel's controller answers DNS (re-picked when it dies) and
    // its secret. Guarded by dnsResolveMu_.
    std::string dnsApiKernelId_;
    std::string dnsApiSecret_;
    std::string dnsApiPipe_;  // protected by dnsResolveMu_, like secret/id
    uint32_t dnsApiPipePid_ = 0;
    // Kernel ids whose controller has NO /dns/query API (old Clash cores,
    // e.g. CFW's, answer 404): the controller path is skipped for them.
    std::set<std::string> dnsApiNoQuery_;
    // TCP DNS relay sessions can resolve concurrently with the UDP pump.
    // Keep selection/cooldown mutation single-threaded, preserving the old
    // dnsPump-only state machine exactly.
    std::mutex dnsResolveMu_;
    // Auto-detected DNS servers per kernel id (from the kernel's own
    // config.yaml dns section, else the adapter's DNS). NO hard-coded
    // servers. Tests override via setDnsSocksDnsServerForTest.
    std::map<std::string, std::vector<net::Endpoint4>> dnsServersCache_;
    std::mutex dnsServersMu_;                          // guards the cache
    std::vector<net::Endpoint4> dnsServersOverride_;  // test seam
    // DoH test seam (null = the real WinHTTP-based resolver).
    std::function<bool(uint16_t, uint32_t, const std::string&,
                       std::vector<uint32_t>&, int, std::string*)>
        dohOverride_;
    std::mutex dnsCacheMu_;
    dns::DnsCache dnsCache_;
    // Native answers only establish name/address associations. They must
    // NEVER enter the clean resolver cache or node-health trust decisions.
    dns::DnsCache observedDns_;
    struct PendingDns { std::string name; int64_t expires = 0; };
    std::map<std::string, PendingDns> pendingNativeDns_;
    std::mutex dnsQueueMu_;
    std::condition_variable dnsQueueCv_;
    struct DnsWork { std::vector<uint8_t> packet; PacketMeta meta; int64_t queuedAt = 0; };
    std::deque<DnsWork> dnsQueue_;
    // Outage cooldowns (while > now, further probes of THAT path are
    // skipped). SEPARATE per path: a controller outage must never gate the
    // healthy SOCKS tunnel path (measured 2026-08-28: a startup transient
    // set the controller cooldown, which gated the SOCKS path too, and
    // every query pass-through'd the poisoned system answer).
    std::atomic<int64_t> dnsControllerDownUntil_{0};
    std::atomic<int64_t> dnsSocksDownUntil_{0};
    // Fresh-cache TTL (test seam shrinks it; default 5 min).
    std::atomic<int64_t> dnsTtlMs_{5 * 60 * 1000};

    // Auto-tracked controller ports (CFW randomizes its API port per start):
    // first successful discovery is cached; a cached port that stops
    // answering is re-discovered automatically.
    std::mutex apiPortMu_;
    std::map<std::string, uint16_t> apiPortCache_;   // outletId -> port

    // REAL-TRAFFIC failure signal per outlet (first principles: the user's
    // own flows are the probe — no hard-coded target URL anywhere). The
    // relay thread reports every session outcome here; the node monitor
    // consumes it: enough failures inside the window self-trigger a node
    // re-selection, and the last failing destination becomes the
    // post-switch verification target (see monitorOneOutlet).
    struct FlowSignal {
        int64_t windowStartMs = 0;
        int32_t oks = 0;
        int32_t fails = 0;
        uint32_t lastFailIp = 0;
        uint16_t lastFailPort = 0;
        int64_t lastFailMs = 0;
        int64_t lastAutoRoundMs = 0;  // gates self-triggered rounds
        // Whether lastFailIp was in OUR injected-clean DNS cache at failure
        // time. Rewritten DNS answers are real IPs of unrelated services
        // (Facebook/Twitter): a CONNECT to them SUCCEEDS through any working
        // node, so an un-trusted target's success must never read as "node
        // confirmed" (measured 14:58:45: verification to 31.13.92.37 — a
        // Facebook IP — cleared the failure signal while the user's traffic
        // stayed broken). Captured at failure time because the switch
        // commits BEFORE the verification runs and flushes the cache.
        bool lastFailTrusted = false;
    };
    mutable std::mutex flowSignalMu_;  // mutable: flowFailsActive is const
    std::map<std::string, FlowSignal> flowSignals_;
    void onRelayResult(const std::string& outletId, uint32_t dstIp,
                       uint16_t dstPort, bool ok,
                       RelayFailureKind failureKind, const std::string& err);
    bool flowFailsActive(const std::string& outletId,
                         const NodeMonitorSettings& nm) const;
    void clearFlowSignal(const std::string& outletId);
    // Post-switch verification: dial the EXACT destination the user's
    // traffic just failed to reach, through the (new) current node.
    // Three outcomes: Cleared (trusted target reachable — clear the
    // signal), Failed (trusted target unreachable — cooldown the node and
    // re-select), NoVerdict (untrusted target — the app is holding a
    // stale/poisoned answer we never handed out; no node choice can fix
    // that, so neither clear nor punish. Recovery comes from the app
    // re-resolving, which our clean answers then serve).
    enum class VerifyOutcome { Cleared, Failed, NoVerdict };
    VerifyOutcome verifySwitchWithRealTarget(const Config& cfg,
                                             const std::string& outletId);
    // True when `ip` appears in any cached answer WE injected (leaf lock).
    bool dnsCacheContainsIp(uint32_t ip) const;
    // Per-outlet nodes that FAILED the post-switch real-CONNECT verify:
    // excluded from candidate selection until the cooldown expires (the
    // retry loop then walks the rest of the candidate list instead of
    // re-picking the same broken node forever).
    std::mutex badNodesMu_;
    std::map<std::string, std::map<std::string, int64_t>> badNodes_;
    bool nodeInBadCooldown(const std::string& outletId, const std::string& node,
                           int64_t nowMs);
    // Set by the relay when the connection to the outlet's SOCKS port itself
    // fails (kernel restarted / port randomized): the node pump runs an
    // immediate Quick discovery so the outlet re-pairs with the new port
    // instead of waiting for the next scheduled tick.
    std::atomic<bool> portHealRequested_{false};
    std::atomic<int64_t> lastPortHealMs_{0};  // anti-flap gate
};

}  // namespace aps
