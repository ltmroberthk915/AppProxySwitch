#include "aps/engine.hpp"

#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

#include "aps/clash_api.hpp"
#include "aps/kernel_config.hpp"
#include "aps/pump_watchdog.hpp"
#include "aps/verge_official.hpp"
#include "aps/dns_rewrite.hpp"
#include "aps/doh_resolver.hpp"
#include "aps/dpapi.hpp"
#include "aps/log.hpp"
#include "aps/nodeclass_detect.hpp"
#include "aps/packet_rewrite.hpp"
#include "aps/path_util.hpp"
#include "aps/policy.hpp"
#include "aps/region_detect.hpp"
#include "aps/socks5_client.hpp"
#include "aps/subscription.hpp"
#include "aps/string_util.hpp"
#include "aps/time_util.hpp"

namespace aps {

const char* engineStateName(EngineState s) {
    switch (s) {
        case EngineState::Starting: return "STARTING";
        case EngineState::Running: return "RUNNING";
        case EngineState::Degraded: return "DEGRADED";
        case EngineState::Draining: return "DRAINING";
        case EngineState::Stopping: return "STOPPING";
        case EngineState::Stopped: return "STOPPED";
    }
    return "?";
}

namespace {

std::string lowerAscii(const std::string& s) {
    std::string l;
    l.reserve(s.size());
    for (unsigned char c : s) {
        l.push_back(static_cast<char>(
            c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c));
    }
    return l;
}

bool nameHasToken(const std::string& name, const std::string& token) {
    return lowerAscii(name).find(token) != std::string::npos;
}

}  // namespace

Engine::Engine(std::unique_ptr<IDivertDevice> device, EngineEvents events)
    : device_(std::move(device)), events_(std::move(events)) {
    selfPath_ = currentModulePath();
}

Engine::~Engine() { stop(); }

std::shared_ptr<const Engine::Runtime> Engine::runtime() const {
    return runtime_.load();
}

// ---------------------------------------------------------------------------
// Outlets (multi-egress)
// ---------------------------------------------------------------------------

uint16_t Engine::resolveDefaultSocksPort(const Config& cfg) {
    const uint16_t configured = static_cast<uint16_t>(cfg.proxy.port);
    // The configured port is live: the user's explicit choice is authoritative.
    if (configured != 0 && hasLoopbackListener(configured)) return configured;
    // Manual mode (discovery disabled): never second-guess the config.
    if (!kernelDiscoveryEnabled_.load()) return configured;
    std::lock_guard<std::mutex> lk(discMu_);
    // The activated kernel is an explicit user choice: follow its live port
    // (kernels change ports — CFW randomizes them — a stale manual port must
    // not keep breaking unbound-rule traffic).
    if (!cfg.routing.autoOutletId.empty()) {
        auto it = discovered_.find(cfg.routing.autoOutletId);
        if (it != discovered_.end() && it->second.alive &&
            it->second.kernel.socksPort != 0) {
            return it->second.kernel.socksPort;
        }
    }
    // Exactly one live kernel: unambiguous — follow it. Two or more leave
    // the choice to the user (activation), and the node row reports the
    // dead configured port explicitly.
    uint16_t only = 0;
    int live = 0;
    for (const auto& kv : discovered_) {
        if (!kv.second.alive || kv.second.kernel.socksPort == 0) continue;
        ++live;
        only = kv.second.kernel.socksPort;
    }
    if (live == 1) return only;
    // Sticky: with several live kernels and no activation, keep the port the
    // default egress is ALREADY using when a live kernel still serves it.
    // Activating the default row (clears autoOutletId) must not snap the
    // egress back to a dead configured port — measured 2026-08-27: the
    // default row flipped 55128（自动）-> 7891 on click and the proxy died.
    auto prev = outlets_.load();
    if (prev && prev->defaultSocksPort != 0) {
        for (const auto& kv : discovered_) {
            if (kv.second.alive &&
                kv.second.kernel.socksPort == prev->defaultSocksPort) {
                return prev->defaultSocksPort;
            }
        }
    }
    return configured;
}

void Engine::rebuildOutlets(const Config& cfg) {
    auto rt = std::make_shared<OutletRuntime>();
    auto defaultIp = parseIpv4(cfg.proxy.host);
    const uint16_t defPort = resolveDefaultSocksPort(cfg);
    RelayParams def;
    def.proxy = net::Endpoint4{defaultIp.value_or(0x7F000001), defPort};
    def.username = cfg.proxy.username;
    def.password = cfg.plainPassword();
    def.connectTimeoutMs = cfg.proxy.connectTimeoutMs;
    rt->params[kDefaultOutletId] = def;
    rt->defaultSocksPort = defPort;
    if (defPort != static_cast<uint16_t>(cfg.proxy.port)) {
        // Auto-followed to a live kernel's port: say so once per change
        // (rebuilds also happen on every adoption tick — no log spam).
        auto prev = outlets_.load();
        if (!prev || prev->defaultSocksPort != defPort) {
            log::wf("default egress port auto-follows live kernel: {} -> {}",
                    cfg.proxy.port, defPort);
        }
        rt->names[kDefaultOutletId] =
            cfg.proxy.host + ":" + std::to_string(defPort) + "（自动）";
    } else {
        rt->names[kDefaultOutletId] =
            cfg.proxy.host + ":" + std::to_string(cfg.proxy.port);
    }
    for (const auto& o : cfg.outlets) {
        auto ip = parseIpv4(o.host);
        RelayParams p;
        p.proxy = net::Endpoint4{ip.value_or(0x7F000001),
                                 static_cast<uint16_t>(o.port)};
        p.username = o.username;
        p.password = [&o]() -> std::string {
            if (o.passwordEnc.empty()) return {};
            bool ok = false;
            std::string plain = crypto::unprotectFromBase64(o.passwordEnc, &ok);
            return ok ? plain : std::string();
        }();
        p.connectTimeoutMs = cfg.proxy.connectTimeoutMs;
        rt->params[o.id] = p;
        rt->names[o.id] = o.name.empty() ? (o.host + ":" + std::to_string(o.port))
                                         : o.name;
        if (!o.enabled) rt->disabled.insert(o.id);
    }
    // Auto-discovered kernels become egresses too (SOCKS port on loopback),
    // unless an existing egress already covers that port. A kernel is
    // enabled iff routing.autoOutletId names it (activation is a single
    // choice); manual outlets follow their own enabled flags.
    {
        std::lock_guard<std::mutex> lk(discMu_);
        for (const auto& kv : discovered_) {
            const auto& d = kv.second;
            if (!d.alive || d.kernel.socksPort == 0) {
                rt->disabled.insert(d.kernel.id);
                rt->names[d.kernel.id] = d.kernel.procName;
                continue;  // offline / SOCKS-less: default fallback, never routable
            }
            // Every alive kernel is an egress and a row of its own — the
            // pre-refactor "covered kernels get no row" rule made rows pop
            // in and out as the default egress auto-followed ports
            // (measured: activating the default row spawned a CFW row,
            // activating CFW deleted it again — read as "大乱套").
            RelayParams p;
            p.proxy = net::Endpoint4{0x7F000001, d.kernel.socksPort};
            p.connectTimeoutMs = cfg.proxy.connectTimeoutMs;
            rt->params[d.kernel.id] = p;
            rt->names[d.kernel.id] = d.kernel.procName;
            if (cfg.routing.autoOutletId != d.kernel.id) {
                rt->disabled.insert(d.kernel.id);
            }
        }
    }
    outlets_.store(rt);
}

// Rules without an explicit outlet binding follow the activated outlet
// (routing.autoOutletId) when one is set; otherwise the default egress.
// Explicit per-rule bindings are never redirected.
std::string Engine::resolveRuleOutlet(const std::string& ruleOutlet) const {
    if (!ruleOutlet.empty()) return ruleOutlet;
    auto rt = runtime();
    if (rt && !rt->cfg.routing.autoOutletId.empty()) {
        return rt->cfg.routing.autoOutletId;
    }
    return kDefaultOutletId;
}

bool Engine::outletEnabled(const std::string& id) const {
    auto rt = outlets_.load();
    if (!rt || id == kDefaultOutletId) return true;
    return rt->disabled.count(id) == 0;
}

RelayParams Engine::outletParams(const std::string& id) const {
    auto rt = outlets_.load();
    if (!rt) return RelayParams{};
    auto it = rt->params.find(id);
    if (it == rt->params.end() || rt->disabled.count(id)) {
        it = rt->params.find(kDefaultOutletId);  // disabled -> default fallback
    }
    return it->second;
}

bool Engine::outletHealthy(const std::string& id) const {
    std::string key = outletEnabled(id) ? id : std::string(kDefaultOutletId);
    std::lock_guard<std::mutex> lk(const_cast<Engine*>(this)->healthMu_);
    auto it = healthMonitors_.find(key);
    if (it == healthMonitors_.end()) {
        it = healthMonitors_.find(kDefaultOutletId);
    }
    return it == healthMonitors_.end() ? true : it->second->healthy();
}

void Engine::rebuildHealthMonitors(const Config& cfg) {
    if (stopping_.load()) return;  // shutdown owns the monitor set now
    std::lock_guard<std::mutex> rebuildLk(rebuildMu_);
    // Resolved once, before the discovery loop (resolveDefaultSocksPort takes
    // discMu_ — nesting it inside the loop below would deadlock).
    const uint16_t defPort = resolveDefaultSocksPort(cfg);
    std::vector<std::pair<std::string, HealthMonitor::Params>> plan;
    {
        auto ip = parseIpv4(cfg.proxy.host);
        HealthMonitor::Params hp;
        hp.proxy = net::Endpoint4{ip.value_or(0x7F000001), defPort};
        hp.username = cfg.proxy.username;
        hp.password = cfg.plainPassword();
        hp.dst = healthProbeDst_;
        hp.intervalS = cfg.proxy.healthIntervalS;
        hp.timeoutMs = cfg.proxy.healthTimeoutMs;
        hp.failThreshold = cfg.proxy.healthFailThreshold;
        plan.emplace_back(kDefaultOutletId, hp);
    }
    for (const auto& o : cfg.outlets) {
        auto ip = parseIpv4(o.host);
        HealthMonitor::Params hp;
        hp.proxy = net::Endpoint4{ip.value_or(0x7F000001),
                                  static_cast<uint16_t>(o.port)};
        hp.username = o.username;
        hp.password = [&o]() -> std::string {
            if (o.passwordEnc.empty()) return {};
            bool ok = false;
            std::string plain = crypto::unprotectFromBase64(o.passwordEnc, &ok);
            return ok ? plain : std::string();
        }();
        hp.dst = healthProbeDst_;
        hp.intervalS = cfg.proxy.healthIntervalS;
        hp.timeoutMs = cfg.proxy.healthTimeoutMs;
        hp.failThreshold = cfg.proxy.healthFailThreshold;
        plan.emplace_back(o.id, hp);
    }
    std::vector<DiscoveredKernel> aliveDiscovered;
    {
        std::lock_guard<std::mutex> lk(discMu_);
        for (const auto& kv : discovered_) {
            if (kv.second.alive && kv.second.kernel.socksPort != 0) {
                aliveDiscovered.push_back(kv.second.kernel);
            }
        }
    }
    for (const auto& d : aliveDiscovered) {
        HealthMonitor::Params hp;
        hp.proxy = net::Endpoint4{0x7F000001, d.socksPort};
        hp.dst = healthProbeDst_;
        hp.intervalS = cfg.proxy.healthIntervalS;
        hp.timeoutMs = cfg.proxy.healthTimeoutMs;
        hp.failThreshold = cfg.proxy.healthFailThreshold;
        plan.emplace_back(d.id, hp);
    }
    // Stop the old set first (joins their threads), then start the new set.
    std::map<std::string, std::unique_ptr<HealthMonitor>> fresh;
    {
        std::lock_guard<std::mutex> lk(healthMu_);
        healthMonitors_.swap(fresh);  // old monitors moved out
    }
    for (auto& kv : fresh) kv.second->stop();
    fresh.clear();
    {
        std::lock_guard<std::mutex> lk(healthMu_);
        for (auto& p : plan) {
            auto mon = std::make_unique<HealthMonitor>();
            mon->start(p.second, [this, id = p.first](bool healthy,
                                                      const std::string& detail) {
                onProxyHealth(id, healthy, detail);
            });
            healthMonitors_[p.first] = std::move(mon);
        }
    }
    log::ifmt("health monitors rebuilt for {} outlet(s)", plan.size());
}

bool Engine::start(const Config& cfg, std::string* err) {
    auto rt = std::make_shared<Runtime>();
    rt->cfg = cfg;
    rt->matcher = RuleMatcher::compile(cfg, selfPath_);
    runtime_.store(rt);

    state_.store(EngineState::Starting);
    pushStatus();

    // 1) Relay must listen before the first SYN gets redirected to it.
    rebuildOutlets(cfg);
    RelayParams rp = outletParams(kDefaultOutletId);
    rp.maxSessions = static_cast<size_t>(cfg.advanced.maxSessions);
    if (!relay_.start(rp, static_cast<uint16_t>(cfg.relay.port),
                      [this](uint32_t appIp, uint16_t appPort)
                          -> std::optional<RelayTarget> {
                          auto entry = nat_.findByRev(appIp, appPort);
                          // Loopback delivery of the rewritten SYN can report
                          // the source as 127.0.0.1 (kernels' TUN down) — the
                          // app port is unique among active flows, so a
                          // port-only fallback is safe and makes proxying
                          // immune to that delivery quirk.
                          if (!entry) entry = nat_.findByPort(appPort);
                          if (!entry) return std::nullopt;
                          if (static_cast<NatState>(entry->state.load()) ==
                              NatState::SynSent) {
                              entry->state.store(static_cast<int32_t>(NatState::Established));
                          }
                           RelayTarget t;
                           t.origDst = net::Endpoint4{entry->origDstIp, entry->origDstPort};
                           t.origSource = net::Endpoint4{entry->appIp, entry->appPort};
                           t.originalPid = entry->pid;
                           // A discovery/config reload may publish another
                           // outlet table between individual field reads.
                           const auto outlet = outletParams(entry->outletId);
                           t.proxy = outlet.proxy;
                           t.username = outlet.username;
                           t.password = outlet.password;
                            t.ruleId = entry->ruleId;
                            t.outletId = entry->outletId;
                            t.sink = entry;
                            if (entry->dnsBridge) {
                                t.resolveDns =
                                    [this](const uint8_t* query, size_t queryLen,
                                           std::vector<uint8_t>& response) {
                                        return resolveTcpDnsQuery(
                                            query, queryLen, response);
                                    };
                                // A local DNS bridge is not evidence about the
                                // selected node. Do not feed its direct fallback
                                // outcome into real-traffic health scoring.
                            } else {
                                const auto current = runtime();
                                if (current) {
                                    t.tlsDomainAllowlist = current->cfg.routing.tlsDomainAllowlist;
                                    t.allowTlsDomain = [this, ip = entry->origDstIp](const std::string& name) {
                                        std::lock_guard<std::mutex> lk(dnsCacheMu_);
                                        return dns::nameHasAddress(dnsCache_, name, ip, nowMs()) ||
                                               dns::nameHasAddress(observedDns_, name, ip, nowMs());
                                    };
                                }
                                t.onResult = [this](const std::string& oid,
                                                    uint32_t dip,
                                                    uint16_t dport, bool ok,
                                                    RelayFailureKind failureKind,
                                                    const std::string& err,
                                                    const std::string& domain) {
                                    onRelayResult(oid, dip, dport, ok,
                                                  failureKind, err, domain);
                                };
                            }
                            return t;
                      },
                      err)) {
        state_.store(EngineState::Stopped);
        pushStatus();
        return false;
    }
    relayPort_ = relay_.listenPort();

    // 2) Packet filters. The UDP/TCP6 divert handles must also be open when
    // any enabled "block"-action rule exists, or block rules would leak
    // non-DNS UDP and IPv6 SYNs while the global flags are off.
    const bool needUdp = cfg.routing.blockUdpForRules ||
                         RuleMatcher::hasEnabledBlockRule(cfg);
    const bool needTcp6 = cfg.routing.blockIpv6ForRules ||
                          RuleMatcher::hasEnabledBlockRule(cfg);
    if (!device_->start(relayPort_, needUdp, needTcp6, true, err)) {
        relay_.stop();
        state_.store(EngineState::Stopped);
        pushStatus();
        return false;
    }

    // 3) Health monitors (per outlet).
    rebuildHealthMonitors(cfg);

    // 4) Pumps.
    stopping_.store(false);
    tcpPumpIters_.store(0);
    tcpPumpExited_.store(false);
    enabled_.store(true);
    degradedDrained_.store(false);
    socketThread_ = std::thread([this] { socketPump(); });
    tcpThread_ = std::thread([this] { tcpPump(); });
    if (needUdp) {
        udpPumpRunning_ = true;
        udpThread_ = std::thread([this] { udpPump(); });
    }
    if (needTcp6) {
        tcp6PumpRunning_ = true;
        tcp6Thread_ = std::thread([this] { tcp6Pump(); });
    }
    dnsPumpRunning_ = true;
    dnsThread_ = std::thread([this] { dnsPump(); });
    dnsWorkerThread_ = std::thread([this] { dnsWorkerPump(); });
    nodeWakeEvent_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    seedNodeStatuses(cfg);
    // Seed REMEMBERED kernels from kernel_cache.json as UNVERIFIED rows: the
    // user's kernels are fixed machines, so their rows appear immediately.
    // Unverified means "no completed scan yet" — the row says 检测中…, and
    // clicks run a real probe instead of a "not started" dialog (the
    // pre-refactor build flashed every cached kernel as 内核未启动 for the
    // first second after each engine start; a click in that window got a
    // blocking dialog even though the kernel was running). The first Quick
    // scan flips them alive and refreshes their (possibly randomized)
    // ports. Guarded by kernelDiscoveryEnabled_ so tests that disable
    // discovery stay isolated from the dev machine's real cache.
    if (kernelDiscoveryEnabled_.load()) {
        try {
            std::vector<DiscoveredKernel> cached =
                kernelCacheLoader_ ? kernelCacheLoader_() : loadKernelCache();
            // Deterministic id assignment per image name: the instance that
            // loaded the config file (-f in its command line) keeps the base
            // id, further instances get "#2"/"#3" (same convention as
            // adoption). v3 persists IDs so removing historical ports does
            // not renumber activated or explicitly bound outlets.
            std::stable_sort(cached.begin(), cached.end(),
                      [](const DiscoveredKernel& a, const DiscoveredKernel& b) {
                          std::string na = lowerAscii(a.procName);
                          std::string nb = lowerAscii(b.procName);
                          if (na != nb) return na < nb;
                          bool af = a.cmdline.find("-f ") != std::string::npos;
                          bool bf = b.cmdline.find("-f ") != std::string::npos;
                          if (af != bf) return af;
                          return a.apiPort < b.apiPort;
                      });
            std::lock_guard<std::mutex> lk(discMu_);
            std::vector<std::string> seededIds;
            std::set<std::string> cachedIds, reservedIds;
            for (const auto& k : cached) {
                if (!k.id.empty()) reservedIds.insert(k.id);
            }
            std::string lastName;
            int perName = 0;
            for (auto& k : cached) {
                std::string nm = lowerAscii(k.procName);
                if (nm != lastName) {
                    lastName = nm;
                    perName = 0;
                }
                ++perName;
                if (k.id.empty() || cachedIds.count(k.id)) {
                    // Older/injected caches may repeat the base ID. Repair
                    // only those rows, leaving every unique stored ID intact.
                    int n = perName;
                    do {
                        k.id = "auto-" + nm + (n == 1 ? "" : "#" + std::to_string(n));
                        ++n;
                    } while (cachedIds.count(k.id) || reservedIds.count(k.id));
                }
                cachedIds.insert(k.id);
                // Copy the key BEFORE the move: in `discovered_[k.id] =
                // KernelEntry{std::move(k), ...}` the RHS is sequenced
                // FIRST (C++17) — std::move empties k.id and the entry is
                // inserted under the EMPTY key. That planted a dead
                // duplicate row next to every live kernel since the
                // seeding feature shipped (the original "two identical
                // com.vortex.helper.exe rows" report was this bug).
                const std::string key = k.id;
                if (discovered_.count(key) == 0) {
                    seededIds.push_back(key);
                    discovered_[key] = KernelEntry{std::move(k), false, false};
                }
            }
            // The very first STATUS push says 检测中… (unverified), NOT
            // 内核未启动: only a completed scan may confirm a kernel dead.
            {
                std::lock_guard<std::mutex> nlk(nodeMu_);
                for (const auto& id : seededIds) {
                    NodeStatus st;
                    st.outletId = id;
                    st.apiAvailable = false;
                    st.apiError = "检测中…";
                    nodeStatus_[id] = std::move(st);
                }
            }
        } catch (const std::exception& e) {
            log::wf("kernel cache seed failed: {}", e.what());
        } catch (...) {
            log::wf("kernel cache seed failed: unknown exception");
        }
    }
    nodeThread_ = std::thread([this] { nodeMonitorPump(); });
    timerThread_ = std::thread([this] { timerPump(); });

    state_.store(EngineState::Running);
    pushStatus();
    log::ifmt("engine started: relay=127.0.0.1:{} proxy={}:{} rules={}",
              relayPort_, cfg.proxy.host, cfg.proxy.port, cfg.rules.size());
    return true;
}

void Engine::stop() {
    if (state_.load() == EngineState::Stopping || state_.load() == EngineState::Stopped) {
        return;
    }
    state_.store(EngineState::Stopping);
    pushStatus();

    // Tear down redirected flows with RSTs while the inject handle is ALIVE,
    // so applications fail fast and reconnect (direct, since we're gone).
    for (const auto& e : nat_.snapshot()) sendTeardownRst(e);
    nat_.clear();

    stopping_.store(true);
    {
        std::lock_guard<std::mutex> lk(subRefreshRunMu_);
        subRefreshWorker_.request_stop();
        if (subRefreshWorker_.joinable()) subRefreshWorker_.join();
    }
    // Swap monitors out under the lock but join OUTSIDE it: a monitor's
    // state callback (onProxyHealth -> pushStatus -> outletHealthy) takes
    // healthMu_ itself, so joining while holding it deadlocks whenever the
    // callback is in flight at stop time (the rare "engine stop hangs"
    // freeze). rebuildMu_ serializes against concurrent rebuilds (pipe
    // RELOAD / file watcher / discovery adoption) so no rebuild can
    // overwrite monitors while their threads run.
    std::map<std::string, std::unique_ptr<HealthMonitor>> oldMonitors;
    {
        std::lock_guard<std::mutex> rebuildLk(rebuildMu_);
        std::lock_guard<std::mutex> lk(healthMu_);
        healthMonitors_.swap(oldMonitors);
    }
    for (auto& kv : oldMonitors) kv.second->stop();
    oldMonitors.clear();
    dnsQueueCv_.notify_all();
    if (dnsWorkerThread_.joinable()) dnsWorkerThread_.join();
    device_->requestStop();

    if (socketThread_.joinable()) socketThread_.join();
    if (tcpThread_.joinable()) tcpThread_.join();
    if (udpThread_.joinable()) udpThread_.join();
    if (tcp6Thread_.joinable()) tcp6Thread_.join();
    if (dnsThread_.joinable()) dnsThread_.join();
    // TCP-DNS relay callbacks share the pooled DoH sessions with dnsPump.
    // Stop and join them before releasing those sessions.
    relay_.stop();
    // No DNS request can still be using a pooled WinHTTP handle now. Release
    // every per-kernel session so an engine restart cannot inherit stale
    // CONNECT/TLS state from the old ports.
    doh::closeHttpProxySessions();
    {
        std::lock_guard<std::mutex> lk(reqMu_);
        pendingRounds_.clear();  // stale requests die with the old run
    }
    if (nodeWakeEvent_) SetEvent(nodeWakeEvent_);
    if (nodeThread_.joinable()) nodeThread_.join();
    if (timerThread_.joinable()) timerThread_.join();
    if (nodeWakeEvent_) {
        CloseHandle(nodeWakeEvent_);
        nodeWakeEvent_ = nullptr;
    }
    state_.store(EngineState::Stopped);
    pushStatus();
    log::i("engine stopped; system networking fully restored");
}

void Engine::reloadConfig(const Config& cfg) {
    auto rt = std::make_shared<Runtime>();
    rt->cfg = cfg;
    rt->matcher = RuleMatcher::compile(cfg, selfPath_);
    runtime_.store(rt);

    rebuildOutlets(cfg);
    RelayParams rp = outletParams(kDefaultOutletId);
    rp.maxSessions = static_cast<size_t>(cfg.advanced.maxSessions);
    relay_.updateParams(rp);
    rebuildHealthMonitors(cfg);

    if (static_cast<uint16_t>(cfg.relay.port) != relayPort_) {
        log::w("relay port change requires engine restart; keeping current port");
    }
    // The UDP/TCP6 divert handles are opened at start() only; a reload that
    // changes the effective gating (global flags or block rules appearing/
    // disappearing) cannot open/close them mid-flight.
    const bool needUdpNow = cfg.routing.blockUdpForRules ||
                            RuleMatcher::hasEnabledBlockRule(cfg);
    const bool needTcp6Now = cfg.routing.blockIpv6ForRules ||
                             RuleMatcher::hasEnabledBlockRule(cfg);
    if (needUdpNow != udpPumpRunning_ || needTcp6Now != tcp6PumpRunning_) {
        log::w("UDP/TCP6 blocking mode changed by reload; restart the engine to apply");
    }
    // The DNS pump is always present for passive name correlation. Both
    // families consult the current policy per query, so toggles apply now.
    dnsQueueCv_.notify_all();
    log::ifmt("config reloaded: rules={} enabled_rules={} outlets={}", cfg.rules.size(),
              [&] {
                  size_t n = 0;
                  for (const auto& r : cfg.rules) n += r.enabled ? 1 : 0;
                  return n;
              }(),
              cfg.outlets.size());
    pushStatus();
}

void Engine::setEnabled(bool on) {
    enabled_.store(on);
    log::ifmt("interception {} for NEW connections", on ? "enabled" : "disabled");
    pushStatus();
}

void Engine::flushConnections(const std::optional<std::string>& ruleId) {
    int torn = 0;
    for (const auto& e : nat_.snapshot()) {
        if (ruleId && e->ruleId != *ruleId) continue;
        sendTeardownRst(e);
        nat_.remove(e->appIp, e->appPort);
        stats_.connClosed(e->ruleId);
        ++torn;
    }
    log::ifmt("flushed {} redirected connection(s)", torn);
}

void Engine::sendTeardownRst(const std::shared_ptr<NatEntry>& e) {
    relay_.abortByPeer(e->appIp, e->appPort);
    uint8_t rst[64];
    uint32_t seq = e->seqValid.load() ? e->nextSeqRelayToApp.load() : 0;
    size_t n = pkt::buildRst(e->origDstIp, e->origDstPort, e->appIp, e->appPort, seq,
                             /*withAck=*/true, 0, rst, sizeof(rst));
    if (n > 0 && !device_->sendSyntheticTcp(rst, n, /*loopback=*/true)) {
        log::wf("failed to inject teardown RST for {}:{}",
                formatIpv4(e->appIp), e->appPort);
    }
}

// ---------------------------------------------------------------------------
// Pumps
// ---------------------------------------------------------------------------

void Engine::socketPump() {
    SocketEventInfo ev;
    while (!stopping_.load()) {
        if (!device_->recvSocket(ev)) break;
        switch (ev.kind) {
            case SocketEventInfo::Kind::Connect:
                log::df("sockevent CONNECT pid={} {}:{} -> {}:{} proto={}", ev.pid,
                        formatIpv4(ev.localIp), ev.localPort, formatIpv4(ev.remoteIp),
                        ev.remotePort, (int)ev.protocol);
                socketMap_.onConnect(ev.localIp, ev.localPort, ev.remoteIp, ev.remotePort,
                                     ev.pid, ev.protocol);
                break;
            case SocketEventInfo::Kind::Close:
                socketMap_.onClose(ev.localIp, ev.localPort);
                break;
            default:
                break;  // bind/listen/accept are not needed
        }
    }
}

void Engine::tcpPump() {
    std::vector<uint8_t> buf(kMaxPacketSize);
    while (!stopping_.load()) {
        // Packet work and the device's timed idle wait both prove liveness.
        tcpPumpIters_.fetch_add(1);
        size_t len = 0;
        PacketMeta meta;
        if (!device_->recvNetworkTcp(buf.data(), buf.size(), len, meta)) break;
        handleTcpPacket(buf.data(), len, meta);
    }
    tcpPumpExited_.store(true);
}

void Engine::udpPump() {
    std::vector<uint8_t> buf(kMaxPacketSize);
    while (!stopping_.load()) {
        size_t len = 0;
        PacketMeta meta;
        if (!device_->recvNetworkUdp(buf.data(), buf.size(), len, meta)) break;
        handleUdpPacket(buf.data(), len);
    }
}

void Engine::tcp6Pump() {
    std::vector<uint8_t> buf(kMaxPacketSize);
    while (!stopping_.load()) {
        size_t len = 0;
        PacketMeta meta;
        if (!device_->recvNetworkTcp6(buf.data(), buf.size(), len, meta)) break;
        handleTcp6Packet(buf.data(), len);
    }
}

// ---------------------------------------------------------------------------
// Node monitoring (Clash controller API)
// ---------------------------------------------------------------------------

void Engine::requestNodeSwitchRound(const std::string& outletId, bool manual, const std::string& requestId) {
    // Async by design: this runs on the pipe thread and must never do
    // network I/O or take the node monitor's locks. Just queue and wake.
    {
        std::lock_guard<std::mutex> lk(reqMu_);
        // Coalesce click spam: a round already queued for the same target
        // makes this one redundant (three rapid clicks used to pile up
        // three full 30s+ measurement rounds on the pump).
        for (auto& r : pendingRounds_) {
            if (r.outletId != outletId) continue;
            if (manual) { r.manual = true; r.requestId = requestId; }
            return;
        }
        pendingRounds_.push_back({outletId, manual, requestId});
    }
    log::ifmt("node monitor: rapid round requested for '{}'", outletId);
    if (nodeWakeEvent_) SetEvent(nodeWakeEvent_);
}

void Engine::refreshSubscription(bool scheduled) {
    std::unique_lock<std::mutex> runLock(subRefreshRunMu_, std::try_to_lock);
    if (!runLock.owns_lock() || stopping_.load() || subRefreshWorkerActive_.load()) return;
    // Refresh only through a supported non-restarting path. SakuraCat's
    // subscription/config/lifecycle belongs to its own client: the old
    // merge+restart flow killed the communication core on 2026-09-14.
    // Both manual and scheduled calls must be guarded, including legacy
    // configs that already contain auto_refresh=true.
    auto rt = runtime();
    if (!rt) return;
    auto setMsg = [this](const std::string& m) {
        std::lock_guard<std::mutex> lk(subRefreshMu_);
        subRefreshMsg_ = m;
    };
    setMsg("running");
    pushStatus();
    try {

    // The refresh targets the SELECTED kernel — the activated row
    // (routing.autoOutletId), or the kernel the default egress is following
    // when the default row is active. The other kernel is NOT touched at
    // all (independence: 哪个圆点选中就更新哪家). Nothing selected ->
    // explicit error instead of guessing.
    std::string targetId;
    {
        auto ort = outlets_.load();
        const uint16_t defPort = ort ? ort->defaultSocksPort : 0;
        std::lock_guard<std::mutex> lk(discMu_);
        if (!rt->cfg.routing.autoOutletId.empty()) {
            auto it = discovered_.find(rt->cfg.routing.autoOutletId);
            if (it != discovered_.end() && it->second.alive) targetId = it->first;
        } else if (defPort != 0) {
            for (const auto& kv : discovered_) {
                if (kv.second.alive && kv.second.kernel.socksPort == defPort) {
                    targetId = kv.first;
                    break;
                }
            }
        }
    }
    if (targetId.empty()) {
        if (!rt->cfg.routing.autoOutletId.empty()) {
            log::wf("subscription refresh: selected kernel is unavailable (no changes made)");
            setMsg("error: 已选中的内核当前不可用；未刷新任何订阅，也未切换出口");
        } else {
            log::wf("subscription refresh: no kernel selected (no changes made)");
            setMsg("error: 当前默认出口没有对应的在线内核；请先确认要刷新哪个客户端的订阅（未作任何修改）");
        }
        pushStatus();
        return;
    }
    bool wantSakura = false, wantCfw = false, wantVerge = false;
    DiscoveredKernel selectedKernel;
    uint16_t tunnelPort = 0;   // the TARGET kernel's mixed port
    {
        std::lock_guard<std::mutex> lk(discMu_);
        auto it = discovered_.find(targetId);
        if (it != discovered_.end()) {
            selectedKernel = it->second.kernel;
            const std::string& n = it->second.kernel.procName;
            if (nameHasToken(n, "vortex") || nameHasToken(n, "sakura")) {
                wantSakura = true;
            } else if (nameHasToken(n, "verge")) {
                wantVerge = true;
            } else if (nameHasToken(n, "clash")) {
                wantCfw = true;
            }
            if (it->second.alive) tunnelPort = it->second.kernel.socksPort;
        }
    }
    if (wantSakura) {
        log::wf("subscription refresh: SakuraCat refresh disabled; "
                "client owns config and kernel lifecycle (no changes made)");
        setMsg("error: 请在 SakuraCat 客户端更新订阅；APS 不再改写其配置或重启内核（未作任何修改）");
        pushStatus();
        return;
    }
    if (wantVerge) {
        // Verge already owns its subscription timer. Do not unexpectedly
        // hot-reload an active communication outlet on APS's startup timer.
        if (scheduled) {
            setMsg("error: Clash Verge 自动订阅更新由其客户端负责；APS 定时任务不会触发热加载，请手动刷新（未作修改）");
            log::i("subscription refresh: Verge scheduled request left to client (no changes made)");
            pushStatus();
            return;
        }
        subRefreshWorkerActive_.store(true);
        subRefreshWorker_ = std::jthread([this, selectedKernel](std::stop_token stop) {
            auto done = [this](const std::string& message) {
                { std::lock_guard<std::mutex> lk(subRefreshMu_); subRefreshMsg_ = message; }
                pushStatus();
            };
            try {
                done(refreshOfficialVerge(selectedKernel,stop));
            } catch (...) {
                done("error: 官方 Verge 刷新结果未确认；请在客户端核对，不会自动重试或重启");
            }
            subRefreshWorkerActive_.store(false);
        });
        return;
    }
    if (!wantCfw) {
        log::wf("subscription refresh: selected kernel '{}' has no supported subscription updater (no changes made)", targetId);
        setMsg(wantVerge
            ? "error: 已选中 Clash Verge；APS 暂不支持刷新其客户端订阅，请在 Clash Verge 的“订阅”页更新（未改配置、未重启、未切出口）"
            : "error: 已选中内核，但 APS 暂不支持刷新该客户端的订阅；请在对应代理客户端更新（未作任何修改）");
        pushStatus();
        return;
    }
    // Direct first, then a single retry THROUGH the target kernel's tunnel:
    // airports with IP-whitelisted downloads 403 the home IP but accept
    // their own node IPs unconditionally (xmrth's documented policy,
    // measured 2026-09-02 — this retry is what keeps refreshes working
    // without ever visiting the provider's website).
    auto fetchSub = [&](const std::string& u, std::string& out,
                        std::string* e) -> bool {
        if (subFetcher_) return subFetcher_(u, out, e);
        if (subscription::fetchText(u, out, e)) return true;
        if (tunnelPort != 0 &&
            subscription::fetchTextViaProxy(u, tunnelPort, out, e)) {
            log::ifmt("subscription refresh: direct fetch rejected; fetched "
                      "through the selected kernel (127.0.0.1:{})",
                      tunnelPort);
            return true;
        }
        return false;
    };
    // Keep CFW's existing profile-only update. It hot-reloads itself;
    // APS never restarts its kernel. No other client's config is touched.
    std::string cfwStatus = "skipped";
    auto cfw = wantCfw
                   ? (cfwProfileFinder_
                          ? cfwProfileFinder_()
                          : subscription::findClashForWindowsActiveProfile())
                   : std::optional<subscription::ActiveProfile>();
    if (cfw) {
        std::string csub, cerr;
        bool cfetched = fetchSub(cfw->url, csub, &cerr);
        if (!cfetched) {
            cfwStatus = "CFW 拉取失败: " + cerr;
        } else {
            std::string cprof;
            if (!subscription::loadTextFile(cfw->path, cprof, &cerr)) {
                cfwStatus = "CFW profile 读取失败: " + cerr;
            } else {
                std::string cmerged = subscription::mergeCfwProfile(csub, cprof);
                if (subApplier_) {
                    subApplier_(cmerged, "cfw");  // test seam
                    cfwStatus = "ok";
                } else if (!subscription::saveTextFile(cfw->path, cmerged, &cerr)) {
                    cfwStatus = "CFW profile 写入失败: " + cerr;
                } else {
                    // CFW hot-reloads its active profile when the file
                    // changes — DO NOT kill the core. Killing is wrong for
                    // CFW: it has no service.xml to relaunch from, its
                    // listener ports randomize on every start (waiting for
                    // the old port can never succeed), and its GUI does not
                    // always respawn the core promptly — measured
                    // 2026-08-28: the kill left the user without a kernel
                    // for minutes and errored "cannot read service.xml".
                    log::ifmt("subscription refresh: CFW profile updated "
                              "(core hot-reloads on its own)");
                    cfwStatus = "ok";
                }
            }
        }
    }
    // Preserve the existing CFW result protocol.
    std::string notes;
    if (cfwStatus != "ok" && cfwStatus != "skipped") {
        notes += "CFW: " + cfwStatus;
    }
    if (notes.empty()) {
        setMsg("ok");
    } else {
        log::wf("subscription refresh: {}", notes);
        setMsg("ok（" + notes + "）");
    }
    pushStatus();
    } catch (const std::exception& e) {
        // A throw must never leave sub_refresh stuck at "running" — the GUI
        // button would spin at 刷新中 forever (measured 2026-08-27).
        subRefreshWorkerActive_.store(false);
        log::ef("subscription refresh crashed: {}", e.what());
        setMsg("error: 订阅刷新异常: " + std::string(e.what()));
        pushStatus();
    } catch (...) {
        subRefreshWorkerActive_.store(false);
        log::ef("subscription refresh crashed: unknown exception");
        setMsg("error: 订阅刷新异常");
        pushStatus();
    }
}

namespace {
// Anti-flap gap between port-heal re-scans: a dead kernel makes EVERY new
// flow fail connection-level; re-scanning more often than this burns the
// Quick scan (~0.4 s of listener probing) for zero new information.
constexpr int64_t kPortHealMinGapMs = 30000;
// A failed destination stays valid as the post-switch verification target
// for this long (then the signal is considered stale and skipped).
constexpr int64_t kVerifyTargetMaxAgeMs = 10 * 60 * 1000;
// HARD BUDGET for one machine-wide DNS resolution. The cleanup path sits
// in front of EVERY process's lookups (Edge, agent apps, everything) —
// whatever happens to the kernels (hung node, DoH unreachable, transit
// timeouts), the whole attempt chain must surrender within this budget
// and fall through to the stale cache / the original query. The product
// promise is "never slower than without us" (2026-09-02: stacked DoH
// timeouts added 5-10s to every uncached domain for all browsers).
constexpr int64_t kDnsResolveBudgetMs = 2000;
// Clash built-in pseudo-proxies that appear as selector members: DIRECT
// measures ~50ms and wins every latency-based sweep, but selecting it
// "breaks" the tunnel for everything the user wants proxied — and the
// region preference immediately re-selects away from it, ping-ponging
// GLOBAL forever (measured 2026-08-31 16:45:16, DIRECT chosen then dropped
// 13 seconds later). They are routing targets, never nodes.
bool isPseudoNodeName(const std::string& n) {
    return n == "DIRECT" || n == "REJECT" || n == "REJECT-DROP" ||
           n == "PASS" || n == "COMPATIBLE" || n == "GLOBAL";
}

// "ip" or "ip:port" (port defaults to 53) -> endpoint, else nullopt.
std::optional<net::Endpoint4> parseDnsServerEntry(const std::string& s) {
    const size_t colon = s.find(':');
    const std::string ipPart =
        colon == std::string::npos ? s : s.substr(0, colon);
    auto ip = parseIpv4(ipPart);
    if (!ip) return std::nullopt;
    uint16_t port = 53;
    if (colon != std::string::npos) {
        char* endp = nullptr;
        const long p = std::strtol(s.c_str() + colon + 1, &endp, 10);
        if (endp == s.c_str() + colon + 1 || *endp != '\0' || p < 1 ||
            p > 65535) {
            return std::nullopt;
        }
        port = static_cast<uint16_t>(p);
    }
    return net::Endpoint4{*ip, port};
}
}  // namespace

void Engine::nodeMonitorPump() {
    // First round + first kernel scan run immediately: the GUI shows real
    // node data within seconds of start instead of an empty "...".
    requestNodeSwitchRound("", false);
    // First scheduled subscription refresh: start-delay grace after the
    // kernels are adopted (a rebooted machine with a stale config is the
    // classic case this catches).
    {
        auto rt0 = runtime();
        const int delayMin =
            rt0 ? rt0->cfg.subscription.startDelayMin : 10;
        nextAutoSubRefreshMs_.store(nowMs() +
                                    static_cast<int64_t>(delayMin) * 60000);
    }
    if (kernelDiscoveryEnabled_.load()) {
        try {
            adoptDiscoveries(DiscoveryMode::Full);
            fullScanCountdown_ = 10;
            pushStatus(); // discovery remains visible when automatic switching is disabled
        } catch (const std::exception& e) {
            log::ef("kernel discovery crashed: {}", e.what());
        } catch (...) {
            log::ef("kernel discovery crashed: unknown exception");
        }
    }
    while (!stopping_.load()) {
        auto rt = runtime();
        int intervalS = rt ? rt->cfg.nodeMonitor.intervalS : 60;
        // Scheduled subscription refresh (see SubscriptionSettings): keeps
        // configs fresh enough that the tunnel-retry path always has live
        // nodes to ride — the provider's own node IPs are whitelisted
        // unconditionally, so a fresh config makes the IP whitelist moot.
        // Runs on this pump (serial with monitor rounds; a refresh blocks
        // this thread for seconds at most once per interval).
        if (rt && rt->cfg.subscription.autoRefresh) {
            const int64_t now = nowMs();
            const int64_t intervalMs = rt->cfg.subscription.intervalHours > 0
                ? static_cast<int64_t>(rt->cfg.subscription.intervalHours) * 3600 * 1000
                : 0;
            if (now >= nextAutoSubRefreshMs_.load()) {
                log::ifmt("subscription refresh: scheduled auto-refresh firing");
                refreshSubscription(true);
                if (intervalMs > 0) {
                    nextAutoSubRefreshMs_.store(nowMs() + intervalMs);
                } else {
                    // interval 0: only the start-delayed refresh ever ran.
                    nextAutoSubRefreshMs_.store(
                        std::numeric_limits<int64_t>::max() / 2);
                }
            }
        }
        // Port self-heal: the relay saw a connection-level egress failure
        // (the kernel's SOCKS port itself unreachable — restarted with new
        // random ports, or stopped). Re-scan immediately instead of waiting
        // for the next discovery tick; the outlet re-pairs with whatever
        // port the kernel actually serves NOW. Consumed HERE because
        // adoptDiscoveries is single-threaded on this pump.
        if (portHealRequested_.exchange(false) &&
            kernelDiscoveryEnabled_.load() && rt) {
            const int64_t now = nowMs();
            if (now - lastPortHealMs_.load() >= kPortHealMinGapMs) {
                lastPortHealMs_.store(now);
                log::wf("port heal: kernel re-scan after connection-level "
                        "egress failure");
                try {
                    adoptDiscoveries(DiscoveryMode::Quick);
                } catch (const std::exception& e) {
                    log::ef("kernel discovery crashed: {}", e.what());
                } catch (...) {
                    log::ef("kernel discovery crashed: unknown exception");
                }
            }
        }
        // Wake event lets the GUI's "测试并连接" trigger an immediate round.
        DWORD wait = nodeWakeEvent_ ? WaitForSingleObject(nodeWakeEvent_, intervalS * 1000)
                                    : WaitForSingleObject(nullptr, intervalS * 1000);
        if (stopping_.load()) break;
        bool periodic = (wait == WAIT_TIMEOUT);
        rt = runtime(); // preferences/automatic switch may have changed while waiting

        // Drain requested rounds (queued by the pipe thread). Fully async:
        // every network operation happens here, never on the pipe thread.
        std::vector<NodeRoundRequest> reqs;
        {
            std::lock_guard<std::mutex> lk(reqMu_);
            while (!pendingRounds_.empty()) {
                reqs.push_back(pendingRounds_.front());
                pendingRounds_.pop_front();
            }
        }
        // Drain-side coalescing too: requests that arrived while the last
        // round was still running may duplicate each other.
        {
            std::vector<NodeRoundRequest> uniq;
            for (const auto& r : reqs) {
                bool dup = false;
                for (auto& u : uniq) {
                    if (u.outletId == r.outletId) {
                        if (r.manual) u = r;
                        dup = true; break;
                    }
                }
                if (!dup) uniq.push_back(r);
            }
            reqs = std::move(uniq);
        }
        if (rt && !rt->cfg.nodeMonitor.enabled) {
            std::erase_if(reqs, [](const NodeRoundRequest& request) { return !request.manual; });
        }
        // Startup/global automatic work must finish before explicit tests,
        // so it cannot replace their result before the next status publish.
        std::stable_sort(reqs.begin(), reqs.end(), [](const auto& a, const auto& b) {
            return !a.manual && b.manual;
        });
        bool didWork = !reqs.empty();
        if (rt && (rt->cfg.nodeMonitor.enabled || !reqs.empty())) {
            // Explicit tests work even when automatic switching is disabled.
            // Publish the start before discovery so the UI cannot complete a
            // new click using a stale successful status from an earlier round.
            if (!reqs.empty()) {
                {
                    std::lock_guard<std::mutex> lk(nodeMu_);
                    for (const auto& request : reqs) {
                        if (request.outletId.empty()) continue;
                        auto& st = nodeStatus_[request.outletId];
                        st.outletId = request.outletId;
                        st.switching = true;
                        st.testRequestId = request.manual ? request.requestId : std::string();
                    }
                }
                pushStatus();
            }
            // A click-driven round first re-scans for kernels (Quick,
            // ~0.4 s): a kernel the user JUST restarted is adopted
            // immediately instead of up to a full discovery tick later —
            // the pre-fix window made "测试并连接" on a restarted kernel
            // report 内核未启动 for up to 60 s (measured 2026-08-28).
            if (!reqs.empty() && kernelDiscoveryEnabled_.load()) {
                try {
                    adoptDiscoveries(DiscoveryMode::Quick);
                } catch (const std::exception& e) {
                    log::ef("kernel discovery crashed: {}", e.what());
                } catch (...) {
                    log::ef("kernel discovery crashed: unknown exception");
                }
            }
            for (const auto& request : reqs) {
                try {
                    if (request.outletId.empty()) {
                        nodeMonitorRound();
                    } else {
                        runNodeRoundFor(request.outletId, request.manual, request.requestId);
                    }
                } catch (const std::exception& e) {
                    log::ef("node monitor rapid round crashed: {}", e.what());
                } catch (...) {
                    log::ef("node monitor rapid round crashed: unknown exception");
                }
            }
            if (periodic && rt->cfg.nodeMonitor.enabled) {
                try {
                    nodeMonitorRound();
                } catch (const std::exception& e) {
                    log::ef("node monitor round crashed: {}", e.what());
                } catch (...) {
                    log::ef("node monitor round crashed: unknown exception");
                }
                didWork = true;
            }
        }
        if (periodic && kernelDiscoveryEnabled_.load()) {
            // Re-scan for kernels on the monitor tick: restarted kernels get
            // re-attached with their new random ports automatically. A blind
            // full scan runs every 10th tick as a fallback for kernels whose
            // process name no filter has ever seen.
            DiscoveryMode mode = DiscoveryMode::Quick;
            if (--fullScanCountdown_ <= 0) {
                mode = DiscoveryMode::Full;
                fullScanCountdown_ = 10;
            }
            try {
                adoptDiscoveries(mode);
                didWork = true;
            } catch (const std::exception& e) {
                log::ef("kernel discovery crashed: {}", e.what());
            } catch (...) {
                log::ef("kernel discovery crashed: unknown exception");
            }
        }
        if (didWork) pushStatus();
    }
}

void Engine::nodeMonitorRound() {
    auto rt = runtime();
    if (!rt) return;
    const Config& cfg = rt->cfg;

    // Carry the previous status over (like runNodeRoundFor does for manual
    // rounds): the failure streak for failThreshold>1 and the region
    // preference state must survive across timed rounds, or neither can ever
    // accumulate (fresh statuses reset them every round).
    auto carried = [this](const std::string& id) {
        NodeStatus st;
        st.outletId = id;
        std::lock_guard<std::mutex> lk(nodeMu_);
        auto it = nodeStatus_.find(id);
        if (it != nodeStatus_.end()) st = it->second;
        return st;
    };

    // Collect every outlet that gets probed this round: the default outlet
    // (when its controller is configured), enabled manual outlets, and the
    // auto-discovered kernels.
    std::vector<std::pair<std::string, ClashApiConfig>> jobs;

    // The default row often auto-follows the exact same discovered kernel
    // (same SOCKS + controller). Probing both ids concurrently is not just
    // duplicate work: both workers can PUT a different node to the same
    // selector. Measured 2026-09-04: __default__ and auto-clash-win64.exe
    // switched the same GLOBAL group 30ms apart, tearing down connections
    // twice. Monitor the active logical id once and mirror its status to the
    // alias row after the round.
    std::string defaultAliasKernelId;
    bool monitorDefault = true;
    bool skipAliasedKernelJob = false;
    if (!cfg.proxy.clashApi.host.empty()) {
        auto ort = outlets_.load();
        const uint16_t defaultSocksPort =
            ort ? ort->defaultSocksPort : static_cast<uint16_t>(cfg.proxy.port);
        const auto apiHost = parseIpv4(cfg.proxy.clashApi.host);
        const std::string configuredSecret = cfg.proxy.clashApi.plainSecret();
        // Discovered controller jobs always dial 127.0.0.1. Other 127/8
        // addresses can host a distinct listener on the same port, so only
        // the exact address proves these two logical rows share one API.
        if (apiHost && *apiHost == 0x7F000001) {
            std::lock_guard<std::mutex> lk(discMu_);
            for (const auto& kv : discovered_) {
                const auto& d = kv.second;
                if (!d.alive || d.kernel.socksPort != defaultSocksPort ||
                    !d.kernel.hasApi()) {
                    continue;
                }
                const bool apiMatches =
                    cfg.proxy.clashApi.port == 0 ||
                    static_cast<uint16_t>(cfg.proxy.clashApi.port) ==
                        d.kernel.apiPort;
                const bool secretMatches =
                    configuredSecret.empty() ||
                    configuredSecret == d.kernel.apiSecret;
                if (!apiMatches || !secretMatches) continue;

                defaultAliasKernelId = d.kernel.id.empty() ? kv.first
                                                            : d.kernel.id;
                // Empty autoOutletId means unbound traffic really belongs to
                // __default__; otherwise the discovered row is the stable
                // controller identity and the inactive default row is its
                // display alias.
                if (cfg.routing.autoOutletId.empty()) {
                    skipAliasedKernelJob = true;
                } else {
                    monitorDefault = false;
                }
                break;
            }
        }
    }
    if (!cfg.proxy.clashApi.host.empty() && monitorDefault) {
        jobs.emplace_back(kDefaultOutletId, cfg.proxy.clashApi);
    }
    for (const auto& o : cfg.outlets) {
        if (!o.hasClashApi()) continue;
        if (!o.enabled) continue;  // deactivated: no probing, zero cost
        jobs.emplace_back(o.id, o.clashApi);
    }
    // Auto-discovered kernels: probe via their controller API too, so node
    // rows / auto-switch work with zero manual configuration. Every alive
    // kernel is probed — it has its own row regardless of what port the
    // default egress is following.
    {
        std::lock_guard<std::mutex> lk(discMu_);
        for (const auto& kv : discovered_) {
            if (!kv.second.alive) continue;         // offline
            if (!kv.second.kernel.hasApi()) continue;  // no controller found
            const std::string id = kv.second.kernel.id.empty()
                                       ? kv.first
                                       : kv.second.kernel.id;
            if (skipAliasedKernelJob && id == defaultAliasKernelId) continue;
            ClashApiConfig a;
            a.host = "127.0.0.1";
            a.port = kv.second.kernel.apiPort;
            a.pipe = kv.second.kernel.apiPipe;
            a.pipePid = kv.second.kernel.pid;
            a.secretPlain = kv.second.kernel.apiSecret;
            jobs.emplace_back(id, std::move(a));
        }
    }

    // Run every outlet's round CONCURRENTLY. The user's trigger events
    // (region change, "测速并切换") mean "re-measure ALL kernels NOW" —
    // running them serially made the second kernel wait for the first one's
    // full candidate measurement (measured: 2 kernels × dead-heavy node
    // lists = 30-60s total, which reads as "nothing happened"). Each job
    // touches only its own controller + per-outlet caches.
    if (jobs.empty()) return;
    std::vector<std::thread> workers;
    workers.reserve(jobs.size());
    for (const auto& job : jobs) {
        workers.emplace_back([this, &cfg, &carried, job] {
            NodeStatus st = carried(job.first);
            st.testRequestId.clear(); // automatic metadata never completes a manual test
            // The final store must ALWAYS happen: a round that throws left
            // the mid-round "switching" bit set in nodeStatus_ forever (the
            // GUI row stuck on "切换中…" with no round running).
            try {
                monitorOneOutlet(cfg, job.first, job.second, st);
            } catch (const std::exception& e) {
                st.switching = false;
                st.apiAvailable = false;
                st.apiError = "监测轮次异常";
                log::ef("node monitor [{}] round crashed: {}", job.first, e.what());
            } catch (...) {
                st.switching = false;
                st.apiAvailable = false;
                st.apiError = "监测轮次异常";
                log::ef("node monitor [{}] round crashed: unknown", job.first);
            }
            std::lock_guard<std::mutex> lk(nodeMu_);
            nodeStatus_[job.first] = std::move(st);
        });
    }
    for (auto& t : workers) t.join();

    if (!defaultAliasKernelId.empty()) {
        const std::string sourceId =
            monitorDefault ? std::string(kDefaultOutletId)
                           : defaultAliasKernelId;
        const std::string targetId =
            monitorDefault ? defaultAliasKernelId
                           : std::string(kDefaultOutletId);
        std::lock_guard<std::mutex> lk(nodeMu_);
        auto source = nodeStatus_.find(sourceId);
        if (source != nodeStatus_.end()) {
            NodeStatus mirrored = source->second;
            mirrored.outletId = targetId;
            nodeStatus_[targetId] = std::move(mirrored);
        }
    }
}

void Engine::runNodeRoundFor(const std::string& outletId, bool manual, const std::string& requestId) {
    auto rt = runtime();
    if (!rt) return;
    const Config& cfg = rt->cfg;

    // Resolve the outlet's controller config (manual or discovered).
    ClashApiConfig api;
    bool found = false;
    if (outletId == kDefaultOutletId && !cfg.proxy.clashApi.host.empty()) {
        api = cfg.proxy.clashApi;
        found = true;
    }
    if (!found) {
        for (const auto& o : cfg.outlets) {
            if (o.id == outletId && o.hasClashApi()) {
                api = o.clashApi;
                found = true;
                break;
            }
        }
    }
    if (!found) {
        std::lock_guard<std::mutex> lk(discMu_);
        auto it = discovered_.find(outletId);
        if (it != discovered_.end() && it->second.alive &&
            it->second.kernel.hasApi()) {
            api.host = "127.0.0.1";
            api.port = it->second.kernel.apiPort;
            api.pipe = it->second.kernel.apiPipe;
            api.pipePid = it->second.kernel.pid;
            api.secretPlain = it->second.kernel.apiSecret;
            found = true;
        }
    }
    if (!found) {
        NodeStatus st;
        st.outletId = outletId;
        st.testRequestId = requestId;
        st.selectionSatisfied = false;
        if (const auto outlets = outlets_.load()) {
            // The candidate may be inactive. Routing fallback would test the
            // CURRENT outlet instead, falsely approving a different endpoint.
            if (const auto params = outlets->params.find(outletId); params != outlets->params.end()) {
                st.checkedProxy = params->second.proxy;
                std::string error;
                st.alive = Socks5Client::probe(params->second.proxy, cfg.proxy.healthTimeoutMs, nullptr, &error,
                                               params->second.username, params->second.password);
            }
        }
        st.apiError = st.alive ? "代理端口握手正常；节点控制器未识别，暂无法自动选线"
                              : "出口不可用；未切换连接";
        std::lock_guard<std::mutex> lk(nodeMu_);
        nodeStatus_[outletId] = std::move(st);
        return;
    }

    // Carry the previous status over: two manual "测试并连接" presses on a
    // dead node must trigger the switch path, exactly like the timed monitor
    // does.
    NodeStatus st;
    {
        std::lock_guard<std::mutex> lk(nodeMu_);
        auto it = nodeStatus_.find(outletId);
        if (it != nodeStatus_.end()) st = it->second;
    }
    st.outletId = outletId;
    if (!manual) st.testRequestId.clear();
    // Manual rounds evaluate and switch IMMEDIATELY on a dead/slow node —
    // the user clicked "测试并连接" and expects a result, not a fail
    // counter.
    try {
        monitorOneOutlet(cfg, outletId, api, st, manual);
    } catch (const std::exception& e) {
        st.switching = false;
        st.apiAvailable = false;
        st.apiError = "监测轮次异常";
        log::ef("node monitor [{}] round crashed: {}", outletId, e.what());
    } catch (...) {
        st.switching = false;
        st.apiAvailable = false;
        st.apiError = "监测轮次异常";
        log::ef("node monitor [{}] round crashed: unknown", outletId);
    }
    st.switching = false;
    if (manual) st.testRequestId = requestId;
    if (!st.apiAvailable || !st.alive) st.selectionSatisfied = false;
    {
        std::lock_guard<std::mutex> lk(nodeMu_);
        nodeStatus_[outletId] = std::move(st);
    }
}

void Engine::seedNodeStatuses(const Config& cfg) {
    std::lock_guard<std::mutex> lk(nodeMu_);
    if (!cfg.proxy.clashApi.host.empty()) {
        NodeStatus st;
        st.outletId = kDefaultOutletId;
        st.apiAvailable = false;
        st.apiError = "检测中…";
        nodeStatus_[kDefaultOutletId] = st;
    }
    for (const auto& o : cfg.outlets) {
        if (!o.hasClashApi() || !o.enabled) continue;
        NodeStatus st;
        st.outletId = o.id;
        st.apiAvailable = false;
        st.apiError = "检测中…";
        nodeStatus_[o.id] = st;
    }
}

void Engine::adoptDiscoveries(DiscoveryMode mode) {
    // Adoption rebuilds outlets + health monitors; racing a shutdown's
    // monitor teardown would leave orphan monitor threads behind (and the
    // stop path must never wait on adoption's network probes).
    if (stopping_.load()) return;
    std::vector<DiscoveredKernel> found;
    found = discoveryScan_ ? discoveryScan_(mode)
                           : discoverProxyKernels(500, mode);
    const auto currentRuntime = runtime();
    const std::string selectedId = currentRuntime ? currentRuntime->cfg.routing.autoOutletId : std::string();

    bool changed = false;
    {
        std::lock_guard<std::mutex> lk(discMu_);
        auto eqName = [](const std::string& a, const std::string& b) {
            return lowerAscii(a) == lowerAscii(b);
        };
        // Dir agreement for the port-based rules: an existing entry with an
        // UNKNOWN dir (v1 cache / unreadable command line) must still match
        // by name+port — two same-named kernels cannot share a SOCKS or API
        // port (binding conflicts), so name+port equality is a safe identity
        // even without dirs. Measured: a v1-cached vortex entry (no dir)
        // failed to match the live instance and split into a dead base row
        // plus a live #2 row — the "two com.vortex.helper.exe rows" mess.
        auto dirsAgree = [](const std::string& d, const std::string& k) {
            return d.empty() || lowerAscii(d) == lowerAscii(k);
        };
        std::set<std::string> seen;
        std::set<uint32_t> pidsInFound;
        for (const auto& k : found) pidsInFound.insert(k.pid);
        for (auto& k : found) {
            // Identity resolution (most specific first):
            // 1) same pid                     — same session instance
            // 2) same name+dir+api port       — restarted, pinned controller
            //                                  (SakuraCat's -ext-ctl)
            // 3) same name+dir+socks port     — restarted, controller churned
            // 4) same name+dir+cmdline        — restarted, ports randomized
            //                                  (CFW: launch line is stable)
            // 5) same name+dir, SOLE entry, its pid gone after this scan, and
            //    the cmdline cannot distinguish (v1 cache has none) — last
            //    resort restart match.
            // Otherwise: a NEW same-named instance — its own id and row, and
            // it NEVER overwrites the existing entry's ports (the 2026-08-27
            // incident: a second com.vortex.helper.exe wiped the main
            // instance's 7897/39798 pairing).
            const std::string base = "auto-" + lowerAscii(k.procName);
            std::string targetId;
            for (const auto& kv : discovered_) {
                if (!eqName(kv.second.kernel.procName, k.procName)) continue;
                if (kv.second.kernel.pid == k.pid) { targetId = kv.first; break; }
            }
            // Keep the user's activated identity ahead of historical cache
            // rows when a core moves between service and sidecar mode.
            // A verified pipe instance token survives prefix/path changes;
            // an exact directory+SOCKS match also recovers old SOCKS-only rows.
            if (targetId.empty() && !selectedId.empty()) {
                const auto selected = discovered_.find(selectedId);
                if (selected != discovered_.end()) {
                    const auto& d = selected->second.kernel;
                    const auto key = controllerPipeInstanceKey(k.apiPipe);
                    const bool samePipe = !k.apiPipe.empty() &&
                        (lowerAscii(d.apiPipe) == lowerAscii(k.apiPipe) ||
                         (!key.empty() && controllerPipeInstanceKey(d.apiPipe) == key));
                    const bool sameEndpoint = k.socksPort && d.socksPort == k.socksPort &&
                        !k.configDir.empty() && lowerAscii(d.configDir) == lowerAscii(k.configDir);
                    if (eqName(d.procName, k.procName) && !pidsInFound.count(d.pid) &&
                        (samePipe || sameEndpoint)) targetId = selectedId;
                }
            }
            // A pipe verified against this scan's server PID survives user
            // -> service transitions even when the config path becomes the
            // image-directory fallback. Directory equality must not split
            // this same controller into a new #2 row. Never steal a row
            // belonging to a different process also present in this scan.
            if (targetId.empty() && !k.apiPipe.empty()) {
                for (const auto& kv : discovered_) {
                    const auto& d = kv.second.kernel;
                    const auto key = controllerPipeInstanceKey(k.apiPipe);
                    if (!eqName(d.procName, k.procName) ||
                        (lowerAscii(d.apiPipe) != lowerAscii(k.apiPipe) &&
                         (key.empty() || controllerPipeInstanceKey(d.apiPipe) != key)) ||
                        pidsInFound.count(d.pid)) continue;
                    targetId = kv.first;
                    break;
                }
            }
            auto matchByDir = [&](const std::function<bool(const DiscoveredKernel&)>& pred,
                                  bool unique = false) {
                std::string hit;
                if (k.configDir.empty()) return hit;
                for (const auto& kv : discovered_) {
                    const auto& d = kv.second.kernel;
                    if (!eqName(d.procName, k.procName)) continue;
                    if (pidsInFound.count(d.pid)) continue; // another live instance
                    if (!dirsAgree(d.configDir, k.configDir)) continue;
                    if (pred(d)) {
                        if (!hit.empty()) return std::string();
                        hit = kv.first;
                        if (!unique) break;
                    }
                }
                return hit;
            };
            if (targetId.empty()) {
                targetId = matchByDir([&](const DiscoveredKernel& d) {
                    return (k.apiPort != 0 && d.apiPort == k.apiPort) ||
                           (!k.apiPipe.empty() && d.apiPipe == k.apiPipe);
                });
            }
            if (targetId.empty()) {
                targetId = matchByDir([&](const DiscoveredKernel& d) {
                    return k.socksPort != 0 && d.socksPort == k.socksPort;
                });
            }
            if (targetId.empty() && !k.cmdline.empty()) {
                const auto freshMatches = std::count_if(found.begin(), found.end(), [&](const auto& other) {
                    return eqName(other.procName, k.procName) && other.cmdline == k.cmdline &&
                           lowerAscii(other.configDir) == lowerAscii(k.configDir);
                });
                // Without historical endpoints, identical launch lines are
                // insufficient to reassign an old outlet to one of two cores.
                if (freshMatches == 1) {
                    targetId = matchByDir([&](const DiscoveredKernel& d) {
                        return !d.cmdline.empty() && d.cmdline == k.cmdline;
                    }, true);
                }
            }
            if (targetId.empty() && !k.configDir.empty()) {
                // Cached TCP ports are gone in v3; -ext-ctl and secrets can
                // also change at launch. An unambiguous config-file identity
                // survives those changes without merging concurrent cores.
                const auto launch = parseKernelLaunchConfig(k.cmdline);
                if (!launch.configFile.empty()) {
                    std::string candidate;
                    int matches = 0, freshMatches = 0;
                    for (const auto& other : found) {
                        if (eqName(other.procName, k.procName) &&
                            lowerAscii(other.configDir) == lowerAscii(k.configDir) &&
                            lowerAscii(parseKernelLaunchConfig(other.cmdline).configFile) == lowerAscii(launch.configFile))
                            ++freshMatches;
                    }
                    for (const auto& kv : discovered_) {
                        const auto& d = kv.second.kernel;
                        if (!eqName(d.procName, k.procName) || pidsInFound.count(d.pid) ||
                            lowerAscii(d.configDir) != lowerAscii(k.configDir) ||
                            lowerAscii(parseKernelLaunchConfig(d.cmdline).configFile) != lowerAscii(launch.configFile)) continue;
                        candidate = kv.first;
                        ++matches;
                    }
                    if (matches == 1 && freshMatches == 1) targetId = candidate;
                }
            }
            if (targetId.empty()) {
                int cnt = 0;
                std::string only;
                bool onlyGone = false, onlyCmdUnknown = false;
                for (const auto& kv : discovered_) {
                    const auto& d = kv.second.kernel;
                    if (!eqName(d.procName, k.procName)) continue;
                    if (!dirsAgree(d.configDir, k.configDir)) continue;
                    ++cnt;
                    only = kv.first;
                    onlyGone = pidsInFound.count(d.pid) == 0;
                    onlyCmdUnknown = d.cmdline.empty() || k.cmdline.empty();
                }
                if (cnt == 1 && onlyGone && onlyCmdUnknown) targetId = only;
            }
            if (targetId.empty()) {
                if (discovered_.find(base) == discovered_.end()) {
                    targetId = base;
                } else {
                    int n = 2;
                    while (discovered_.count(base + "#" + std::to_string(n))) ++n;
                    targetId = base + "#" + std::to_string(n);
                    log::wf("kernel: second instance of {} registered as {} "
                            "(pid {} socks {} api {})",
                            k.procName, targetId, k.pid, k.socksPort, k.apiPort);
                }
            }
            k.id = targetId;
            seen.insert(targetId);
            auto it = discovered_.find(targetId);
            if (it == discovered_.end()) {
                discovered_[targetId] = KernelEntry{k, k.socksPort != 0, true};
                changed = true;
                log::ifmt("kernel discovered: {} [pid {} dir '{}'] (socks {} api {})",
                          k.procName, k.pid, k.configDir, k.socksPort, k.apiPort);
                if (!k.apiPipe.empty())
                    log::ifmt("kernel {} [pid {} socks {}] controller pipe: {}",
                              k.procName, k.pid, k.socksPort, k.apiPipe);
            } else {
                auto& e = it->second;
                auto& old = e.kernel;
                // A transient scan miss on the controller must not wipe a
                // known API port: keep it when the same PID still serves
                // the same SOCKS port and only the API probe came up empty.
                if (old.pid == k.pid && old.socksPort == k.socksPort &&
                    !k.hasApi() && old.hasApi()) {
                    k.apiPort = old.apiPort;
                    k.apiPipe = old.apiPipe;
                    k.apiSecret = old.apiSecret;
                }
                if (e.alive != (k.socksPort != 0) || old.socksPort != k.socksPort ||
                    old.apiPort != k.apiPort || old.apiSecret != k.apiSecret ||
                    old.apiPipe != k.apiPipe || old.pid != k.pid ||
                    old.discoveryError != k.discoveryError) {
                    if (old.socksPort != k.socksPort || old.apiPort != k.apiPort) {
                        log::ifmt("kernel {} ports updated: socks {}->{} api {}->{}",
                                  k.procName, old.socksPort, k.socksPort,
                                  old.apiPort, k.apiPort);
                    }
                    if (old.apiPipe != k.apiPipe ||
                        (!k.apiPipe.empty() && old.pid != k.pid))
                        log::ifmt("kernel {} [pid {} socks {}] controller pipe: {}",
                                  k.procName, k.pid, k.socksPort,
                                  k.apiPipe.empty() ? "none" : k.apiPipe);
                    old = k;
                    e.alive = k.socksPort != 0;
                    changed = true;
                }
                e.verified = true;
            }
        }
        for (auto& kv : discovered_) {
            if (seen.count(kv.first) != 0) continue;
            if (!kv.second.kernel.discoveryError.empty()) {
                kv.second.kernel.discoveryError.clear();
                changed = true;
            }
            // A completed scan has now observed this entry. Unverified
            // (cache-seeded) entries become CONFIRMED dead here — the GUI
            // may then block clicks and show 内核未启动 definitively.
            if (!kv.second.verified) {
                kv.second.verified = true;
                changed = true;
            }
            if (kv.second.alive) {
                kv.second.alive = false;
                changed = true;
                log::ifmt("kernel went offline: {} (socks {})",
                          kv.second.kernel.procName, kv.second.kernel.socksPort);
            }
        }
    }

    // Persist the IDs assigned above; numeric ports only live in this engine.
    // An empty scan must also remove endpoints from the old cache format.
    mergeDiscoveredIntoCache(found);
    if (!changed) return;
    auto rt = runtime();
    if (!rt) return;
    const Config& cfg = rt->cfg;

    // Refresh egress + health sets so (a) new kernels are routable and
    // health-checked, (b) gone kernels fall back to the default egress.
    rebuildOutlets(cfg);
    rebuildHealthMonitors(cfg);

    // Keep the row set in sync: new kernels get a "检测中…" placeholder,
    // offline ones keep their row but read "已停止".
    {
        std::lock_guard<std::mutex> lk(nodeMu_);
        for (const auto& kv : discovered_) {
            auto it = nodeStatus_.find(kv.first);
            if (it == nodeStatus_.end()) {
                NodeStatus st;
                st.outletId = kv.first;
                st.apiAvailable = false;
                // Remembered-but-not-running kernels are known to be
                // offline immediately; genuinely new ones get probed by the
                // next monitor round.
                st.apiError = !kv.second.kernel.discoveryError.empty()
                                  ? kv.second.kernel.discoveryError
                                  : !kv.second.alive ? "内核未启动"
                                  : kv.second.kernel.hasApi() ? "检测中…"
                                  : "内核运行中，节点控制器尚未识别（不代表代理端口不可用）";
                nodeStatus_[kv.first] = std::move(st);
            } else if (!kv.second.alive) {
                it->second.apiAvailable = false;
                it->second.alive = false;
                it->second.latencyMs = -1;
                it->second.node.clear();
                it->second.apiError = kv.second.kernel.discoveryError.empty()
                                          ? "内核未启动" : kv.second.kernel.discoveryError;
            } else if (!kv.second.kernel.hasApi()) {
                it->second.apiAvailable = false;
                it->second.apiError = kv.second.kernel.discoveryError.empty()
                    ? "内核运行中，节点控制器尚未识别（不代表代理端口不可用）"
                    : kv.second.kernel.discoveryError;
            }
        }
    }
}

json::Value Engine::kernelsJson() const {
    json::Value arr = json::Value::makeArray();
    std::lock_guard<std::mutex> lk(const_cast<Engine*>(this)->discMu_);
    for (const auto& kv : discovered_) {
        // Every discovered kernel has a row of its own — always. Rows only
        // appear/disappear when the kernel itself starts/stops, never when
        // the default egress auto-follows a port.
        json::Value o = json::Value::makeObject();
        o.set("id", kv.second.kernel.id);
        o.set("name", kv.second.kernel.procName);
        o.set("pid", kv.second.kernel.pid);
        const bool current = kv.second.alive || !kv.second.kernel.discoveryError.empty();
        o.set("socks_port", static_cast<uint32_t>(current ? kv.second.kernel.socksPort : 0));
        o.set("api_port", static_cast<uint32_t>(current ? kv.second.kernel.apiPort : 0));
        o.set("has_api", kv.second.kernel.hasApi());
        o.set("controller", !kv.second.kernel.apiPipe.empty() ? "pipe" :
                            kv.second.kernel.apiPort ? "tcp" : "none");
        o.set("api_pipe", kv.second.kernel.apiPipe);
        o.set("discovery_error", kv.second.kernel.discoveryError);
        o.set("alive", kv.second.alive);
        // "seen" = a completed scan has observed this entry (found OR
        // confirmed missing). Unverified rows are the brief post-start
        // window: the GUI must not block clicks on them with a "not
        // started" dialog — a probe gives the real answer instead.
        o.set("seen", kv.second.verified);
        arr.append(std::move(o));
    }
    return arr;
}

void Engine::onRelayResult(const std::string& outletId, uint32_t dstIp,
                           uint16_t dstPort, bool ok,
                           RelayFailureKind failureKind,
                           const std::string& err, const std::string& domain) {
    // Engine-initiated aborts are not a verdict on the egress.
    if (!ok && failureKind == RelayFailureKind::Aborted) return;
    if (!ok) {
        log::df("relay: outcome={} outlet='{}' dst={}:{} error={}",
                relayFailureKindName(failureKind), outletId,
                formatIpv4(dstIp), dstPort, err);
        if (failureKind == RelayFailureKind::ProxyEndpoint) {
            // The configured local SOCKS listener itself disappeared (for
            // example, a restarted kernel picked new random ports). This is
            // the only relay outcome that calls for kernel discovery.
            portHealRequested_.store(true);
            if (nodeWakeEvent_) SetEvent(nodeWakeEvent_);
            return;
        }
        // Application resets and internal/configuration failures say nothing
        // about either the local listener or the selected node. Tunnel
        // failures alone may feed the trusted real-traffic signal below.
        if (failureKind != RelayFailureKind::Tunnel &&
            failureKind != RelayFailureKind::TlsNoResponse) return;
    }
    auto rt = runtime();
    if (!rt) return;
    const NodeMonitorSettings& nm = rt->cfg.nodeMonitor;
    const int64_t now = nowMs();
    bool fireRound = false;
    bool countedFailure = false;
    int fails = 0, total = 0;
    {
        std::lock_guard<std::mutex> lk(flowSignalMu_);
        FlowSignal& s = flowSignals_[outletId];
        if (s.windowStartMs == 0 ||
            now - s.windowStartMs >=
                static_cast<int64_t>(nm.realFailWindowS) * 1000) {
            s.windowStartMs = now;
            s.oks = 0;
            s.fails = 0;
        }
        if (ok) {
            s.oks++;
        } else {
            // Trust snapshot at failure time (the switch's cache flush
            // hasn't happened yet): only destinations WE resolved count.
            const bool trusted = dnsCacheContainsIp(dstIp) ||
                (failureKind == RelayFailureKind::TlsNoResponse && !domain.empty());
            if (trusted) {
                countedFailure = true;
                s.fails++;
                s.lastFailIp = dstIp;
                s.lastFailPort = dstPort;
                s.lastFailDomain = domain;
                s.lastFailMs = now;
                s.lastFailTrusted = true;
            }
            // UNTRUSTED failure (destination not from our clean answers and
            // the kernel port is alive): the app is holding a stale or
            // rewritten answer — poison IPs are REAL Facebook/Twitter
            // addresses, so their connect outcomes say nothing about node
            // quality. Counting them blamed healthy nodes and churned the
            // kernel in a loop (measured 2026-08-31). The actual fix — the
            // app re-resolving, which our clean answers serve — needs no
            // switch at all.
        }
        fails = s.fails;
        total = s.oks + s.fails;
        // Self-trigger a node re-selection when real traffic is failing at
        // the configured rate — even though the controller's /delay may
        // still report the current node healthy (measured 2026-08-28: a
        // node passed gstatic /delay at 305 ms while every real connection
        // to blocked sites got TLS-reset). Coalesce repeats at the independent
        // tunnel-health cadence: this prevents a burst from queueing duplicate
        // rounds, without trapping a newly selected bad node behind the
        // five-minute soft-preference stabilization window.
        if (countedFailure && total > 0 && fails >= nm.realFailThreshold &&
            fails * 100 >= total * nm.realFailRatioPct) {
            const int64_t gate =
                static_cast<int64_t>(std::max(1, rt->cfg.proxy.healthIntervalS)) *
                1000;
            if (s.lastAutoRoundMs == 0 || now - s.lastAutoRoundMs >= gate) {
                s.lastAutoRoundMs = now;
                fireRound = true;
            }
        }
    }
    if (fireRound) {
        log::wf("relay: real traffic failing through '{}' ({} of {} in window) "
                "— triggering node re-selection",
                outletId, fails, total);
        requestNodeSwitchRound(outletId, false);
    }
}

bool Engine::nodeInBadCooldown(const std::string& outletId,
                               const std::string& node, int64_t nowMs) {
    std::lock_guard<std::mutex> lk(badNodesMu_);
    auto oit = badNodes_.find(outletId);
    if (oit == badNodes_.end()) return false;
    auto nit = oit->second.find(node);
    return nit != oit->second.end() && nit->second > nowMs;
}

bool Engine::flowFailsActive(const std::string& outletId,
                             const NodeMonitorSettings& nm) const {
    const int64_t now = nowMs();
    std::lock_guard<std::mutex> lk(flowSignalMu_);
    auto it = flowSignals_.find(outletId);
    if (it == flowSignals_.end()) return false;
    const FlowSignal& s = it->second;
    if (s.windowStartMs == 0 ||
        now - s.windowStartMs >=
            static_cast<int64_t>(nm.realFailWindowS) * 1000) {
        return false;  // window expired (no fresh events)
    }
    const int total = s.oks + s.fails;
    return total > 0 && s.fails >= nm.realFailThreshold &&
           s.fails * 100 >= total * nm.realFailRatioPct;
}

void Engine::clearFlowSignal(const std::string& outletId) {
    std::lock_guard<std::mutex> lk(flowSignalMu_);
    auto it = flowSignals_.find(outletId);
    if (it == flowSignals_.end()) return;
    it->second.oks = 0;
    it->second.fails = 0;
    it->second.lastFailIp = 0;
    it->second.lastFailPort = 0;
    it->second.lastFailDomain.clear();
    it->second.lastFailMs = 0;
    it->second.lastFailTrusted = false;
    // windowStartMs / lastAutoRoundMs stay: they gate repeats, not verdicts.
}

bool Engine::dnsCacheContainsIp(uint32_t ip) const {
    std::lock_guard<std::mutex> lk(const_cast<Engine*>(this)->dnsCacheMu_);
    for (const auto& kv : dnsCache_) {
        for (uint32_t a : kv.second.first) {
            if (a == ip) return true;
        }
    }
    return false;
}

Engine::VerifyOutcome Engine::verifySwitchWithRealTarget(
    const Config& cfg, const std::string& outletId) {
    uint32_t ip = 0;
    uint16_t port = 0;
    bool trusted = false;
    std::string domain;
    {
        std::lock_guard<std::mutex> lk(flowSignalMu_);
        auto it = flowSignals_.find(outletId);
        if (it == flowSignals_.end()) return VerifyOutcome::Cleared;  // nothing to verify
        const FlowSignal& s = it->second;
        if (s.lastFailIp == 0 ||
            nowMs() - s.lastFailMs > kVerifyTargetMaxAgeMs) {
            return VerifyOutcome::Cleared;  // absent or stale: no verdict needed
        }
        ip = s.lastFailIp;
        port = s.lastFailPort;
        domain = s.lastFailDomain;
        trusted = s.lastFailTrusted;
    }
    if (!trusted) {
        // The app is holding an answer we never handed out (stale or
        // rewritten — those are real IPs of unrelated services, so a
        // successful CONNECT to them proves nothing). No node choice can
        // fix a bad destination: neither confirm nor punish. Recovery is
        // the app re-resolving; our clean answers then take over.
        log::wf("node monitor [{}]: verification target {}:{} was not "
                "resolved by us (stale/poisoned app-side answer); skipping "
                "the verdict", outletId, formatIpv4(ip), port);
        return VerifyOutcome::NoVerdict;
    }
    if (!domain.empty()) {
        // Mihomo acknowledges CONNECT before dialing. Neither that ACK nor
        // the app's original (possibly polluted) IP can confirm TLS recovery.
        // Keep the signal; subsequent real traffic supplies the verdict.
        log::ifmt("node monitor [{}]: awaiting real TLS traffic for {}; "
                  "SOCKS acceptance cannot confirm recovery", outletId, domain);
        return VerifyOutcome::NoVerdict;
    }
    const auto outlet = outletParams(outletId);
    if (outlet.proxy.port == 0) return VerifyOutcome::NoVerdict;
    std::string err;
    SOCKET s = INVALID_SOCKET;
    const int timeoutMs = std::min(cfg.nodeMonitor.delayTimeoutMs, 3000);
    if (!Socks5Client::connect(outlet.proxy, outlet.username, outlet.password,
                               net::Endpoint4{ip, port}, timeoutMs, s, &err)) {
        log::df("node monitor [{}]: verification CONNECT to {}:{} failed: {}",
                outletId, formatIpv4(ip), port, err);
        return VerifyOutcome::Failed;
    }
    net::closeSocket(s);
    log::ifmt("node monitor [{}]: verification CONNECT to {}:{} succeeded — "
              "node confirmed for the user's actual destination",
              outletId, formatIpv4(ip), port);
    return VerifyOutcome::Cleared;
}

void Engine::monitorOneOutlet(const Config& cfg, const std::string& outletId,
                              const ClashApiConfig& api, NodeStatus& st,
                              bool manualRound) {
    if (stopping_.load()) return;  // shutdown: don't start probe work
    // Monitoring measures this row even when it is not selected for routing.
    // outletParams() applies routing fallback and would stamp an inactive
    // kernel's result with a different kernel's address.
    net::Endpoint4 endpoint{};
    if (const auto monitored = outlets_.load()) {
        const auto params = monitored->params.find(outletId);
        if (params != monitored->params.end()) endpoint = params->second.proxy;
    }
    if (st.checkedProxy.port != 0 &&
        (st.checkedProxy.ip != endpoint.ip || st.checkedProxy.port != endpoint.port)) {
        st = NodeStatus{};
        st.outletId = outletId;
    }
    st.checkedProxy = endpoint;
    const NodeMonitorSettings& nm = cfg.nodeMonitor;
    // Statuses are carried across rounds now: every evaluation starts from a
    // clean "no API" state so a controller that died doesn't leave stale
    // "available" flags/errors on the GUI row. The switching bit is cleared
    // here too: ANY completed round for this outlet un-sticks a stale
    // "切换中…" (a crashed round used to leave it set forever).
    st.apiAvailable = false;
    st.apiError.clear();
    st.switching = false;
    // NOTE: there used to be a "real-tunnel gate" here that skipped the
    // whole round when the health monitor's CONNECT probe failed. Removed:
    // the probe dials through the CURRENT node, so a dead current node makes
    // the probe fail — and skipping the round is exactly the recovery the
    // round exists for. A dead-node kernel was stuck forever: the row showed
    // "出口不健康" while no candidate was ever tested (measured 2026-08-28:
    // SakuraCat stayed on a TLS-reset node for hours). The round's own
    // evidence is honest instead: a hung kernel fails the API probe below
    // ("API unavailable"), a dead node re-selects via the candidate sweep,
    // and an all-dead list reports "no alive node in group".
    std::string secret = api.plainSecret();
    uint16_t port = static_cast<uint16_t>(api.port);
    std::string pipe = api.pipe;
    uint32_t pipePid = api.pipePid;
    // Set when pairing fails because the remembered kernel on this SOCKS
    // port is simply not running (row message names the kernel).
    std::string offlineProc;
    bool liveWithoutController = false;
    if (port == 0 && pipe.empty()) {
        // Auto-tracked discovery: use the cached discovery first, only
        // re-scanning when it stops answering (CFW randomizes its API port
        // on every start, so the port may change underneath us).
        {
            std::lock_guard<std::mutex> lk(apiPortMu_);
            auto it = apiPortCache_.find(outletId);
            if (it != apiPortCache_.end()) {
                ClashApiClient cached(api.host, it->second, secret);
                std::string perr;
                if (cached.probe(&perr, 1000)) {
                    port = it->second;
                } else {
                    apiPortCache_.erase(it);  // stale; rediscover below
                }
            }
        }
        uint16_t socksPort = 0;
        {
            auto rt2 = outlets_.load();
            if (rt2) {
                auto it2 = rt2->params.find(outletId);
                if (it2 != rt2->params.end()) socksPort = it2->second.proxy.port;
            }
        }
        if (port == 0) {
            // Pair this outlet's SOCKS port with a discovered kernel's API
            // port (same-PID pairing from the fast Quick scan, ~0.4 s). Only
            // falls through to the slow full port scan when no kernel is
            // known — e.g. discovery disabled or the kernel uses a name the
            // scanner has never seen.
            offlineProc.clear();  // remembered kernel on this port, not running
            std::string pairWhy;  // diagnostics for the no-match log below
            if (socksPort != 0 && kernelDiscoveryEnabled_.load()) {
                std::lock_guard<std::mutex> lk(discMu_);
                for (const auto& kv : discovered_) {
                    const auto& d = kv.second;
                    if (d.kernel.socksPort != socksPort) continue;
                    if (!d.alive) {  // kernel known but not running
                        if (!liveWithoutController) {
                            offlineProc = d.kernel.procName;
                            pairWhy = "known kernel on this port is offline";
                        }
                        continue;  // a restarted instance may own the same port
                    }
                    if (!d.kernel.hasApi()) {
                        liveWithoutController = true;
                        offlineProc.clear();
                        pairWhy = "alive kernel on this port has no controller";
                        continue;  // another live record may have the controller
                    }
                    offlineProc.clear();
                    port = d.kernel.apiPort;
                    pipe = d.kernel.apiPipe;
                    pipePid = d.kernel.pid;
                    if (secret.empty() && !d.kernel.apiSecret.empty()) {
                        secret = d.kernel.apiSecret;
                    }
                    pairWhy = "paired with api port " + std::to_string(port);
                    break;
                }
            }
            if (port == 0 && pipe.empty()) {
                // Candidate-by-candidate diagnostics: every registry entry
                // with its ports and liveness. A pairing miss must explain
                // itself in the log (the 2026-08-27 incident left only the
                // bare miss line and took an hour to diagnose).
                std::string cands;
                {
                    std::lock_guard<std::mutex> lk(discMu_);
                    for (const auto& kv : discovered_) {
                        cands += kv.second.kernel.procName + "[" +
                                 std::to_string(kv.second.kernel.socksPort) + "/" +
                                 std::to_string(kv.second.kernel.apiPort) + "," +
                                 (kv.second.alive ? "alive" : "off") + "] ";
                    }
                }
                log::wf("node monitor [{}]: no kernel pairs with socks port "
                        "{}; registry:{} ; why: {}",
                        outletId, socksPort,
                        cands.empty() ? " <empty>" : cands,
                        pairWhy.empty() ? "no candidate matched the port" : pairWhy);
            }
        }
        if (port == 0 && pipe.empty()) {
            // With kernel discovery enabled, the pairing above is the truth:
            // a slow full-port scan must NOT run — it would latch onto the
            // FIRST controller that answers (measured: a stale manual CFW
            // outlet with a dead SOCKS port got paired with SakuraCat's
            // controller and displayed the wrong kernel's nodes).
            if (kernelDiscoveryEnabled_.load()) {
                st.apiAvailable = false;
                if (socksPort == 0) {
                    st.apiError = "端口未配置：请在管理出口填写 SOCKS 端口，或直接使用自动发现的内核";
                } else if (!offlineProc.empty()) {
                    // The user's actual question answered at the row itself:
                    // the proxy software for this port is simply not started.
                    st.apiError = "内核未启动：" + offlineProc +
                                  "（启动代理软件后自动恢复）";
                } else if (liveWithoutController) {
                    st.apiError = "内核运行中，节点控制器尚未识别（不代表代理端口不可用）";
                } else if (outletId == kDefaultOutletId) {
                    // Actionable: with several live kernels and no activation
                    // the default egress deliberately does not guess — tell
                    // the user exactly how to resolve it.
                    st.apiError = "默认端口 " + std::to_string(socksPort) +
                                  " 未匹配到节点控制器（可单独检测代理端口）";
                } else {
                    st.apiError = "未找到端口 " + std::to_string(socksPort) +
                                  " 对应的内核控制器（内核未启动或端口已变化）";
                }
                log::wf("node monitor [{}]: no kernel pairs with socks port {}; "
                        "not scanning blindly", outletId, socksPort);
                return;
            }
            bool needSecret = false;
            port = autoDetectClashApiPort(api.host, secret, socksPort, &needSecret);
            if (port == 0) {
                st.apiAvailable = false;
                st.apiError = "未找到 Clash 控制器（常见端口与本机监听端口均已探测）";
                log::df("node monitor [{}]: no controller API found", outletId);
                return;
            }
            if (needSecret && secret.empty()) {
                st.apiAvailable = false;
                st.apiError = "控制器需要密钥：请在界面的 API 密钥栏填写";
                log::wf("node monitor [{}]: controller on {}:{} needs a secret", outletId,
                        api.host, port);
                return;
            }
            {
                std::lock_guard<std::mutex> lk(apiPortMu_);
                apiPortCache_[outletId] = port;
            }
            log::ifmt("node monitor [{}]: discovered controller on {}:{}", outletId,
                      api.host, port);
        }
    }
    st.detectedPort = port;
    ClashApiClient client(api.host, port, secret, pipe, pipePid);
    const auto previousMode = st.runtimeMode;
    st.runtimeMode.clear();
    st.routingWarning.clear();
    std::string err;
    if (!client.probe(&err, 3000)) {
        st.apiAvailable = false;
        st.apiError = "节点控制器暂时不可用：" + err;
        st.switching = false;
        st.selectionSatisfied = false;
        // Secret-rotation self-heal: a 401/403 means the kernel changed its
        // controller secret (or the cached one is stale). Drop the cached
        // pairing and re-scan — the kernel's own config file is read again
        // and the fresh secret adopted. No secret is ever hard-coded.
        if (err.find("HTTP 401") != std::string::npos ||
            err.find("HTTP 403") != std::string::npos) {
            {
                std::lock_guard<std::mutex> lk(apiPortMu_);
                apiPortCache_.erase(outletId);
            }
            portHealRequested_.store(true);
            if (nodeWakeEvent_) SetEvent(nodeWakeEvent_);
            log::wf("node monitor [{}]: controller secret rejected — "
                    "scheduling re-scan for the fresh secret", outletId);
        }
        log::df("node monitor [{}]: API unavailable ({})", outletId, err);
        return;
    }
    st.groupNodes.clear();
    std::vector<ClashGroup> allGroups;
    std::vector<std::string> preferredGroups;
    for (const auto& wanted : nm.nodeClasses)
        if (wanted.rfind("GROUP:", 0) == 0 && wanted.size() > 6)
            preferredGroups.push_back(wanted.substr(6));
    auto group = client.currentSelectorGroup(&err, 3000, &allGroups, &st.runtimeMode,
                                            preferredGroups);
    if (st.runtimeMode != previousMode) {
        log::ifmt("outlet {} observed controller mode={}; origin=external-or-unknown "
                  "(APS does not change mode)", outletId,
                  st.runtimeMode.empty() ? "unknown" : st.runtimeMode);
    }
    st.routingWarning = st.runtimeMode == "rule"
        ? "规则模式按 APS 转发进程分流，目标服务的代理链待核对"
        : (st.runtimeMode.empty() ? "内核模式未核实；节点测速不代表目标服务可达"
                                  : "节点测速不代表目标服务可达");
    if (!group) {
        st.alive = false;
        st.latencyMs = -1;
        st.node.clear();
        st.group.clear();
        st.apiAvailable = false;
        st.apiError = "无法识别当前可切换策略组：" + err;
        st.switching = false;
        st.selectionSatisfied = false;
        log::df("node monitor [{}]: {}", outletId, err);
        return;
    }
    for (const auto& g : allGroups) st.groupNodes[g.name] = g.nodes;
    const bool allowNestedChoices = st.runtimeMode == "rule" &&
        std::find(preferredGroups.begin(), preferredGroups.end(), group->name) != preferredGroups.end();
    auto concreteChoice = [&](const std::string& member) -> std::optional<std::string> {
        if (isPseudoNodeName(member)) return std::nullopt;
        const bool nested = st.groupNodes.count(member) != 0;
        if (nested && !allowNestedChoices) return std::nullopt;
        const auto leaf = group->memberLeaves.find(member);
        const auto& node = leaf == group->memberLeaves.end() ? member : leaf->second;
        if (st.groupNodes.count(node) || isPseudoNodeName(node)) return std::nullopt;
        return node;
    };
    // AUTO-INFER region from group names: a group whose own name carries a
    // region signal (e.g. "香港节点") teaches that region to every member
    // node — including transitively referenced sub-groups. Opaque node
    // names then still get a region (no per-provider code changes).
    std::map<std::string, std::string> inferredRegion;
    for (const auto& [gname, members] : st.groupNodes) {
        std::string gr = region::detectNodeRegion(gname);
        if (gr.empty()) continue;
        std::set<std::string> visited;
        std::vector<std::string> stack = members;
        while (!stack.empty()) {
            std::string m = stack.back();
            stack.pop_back();
            if (!visited.insert(m).second) continue;
            if (st.groupNodes.count(m)) {
                auto it = st.groupNodes.find(m);
                for (const auto& sub : it->second) stack.push_back(sub);
                continue;
            }
            if (!inferredRegion.count(m)) inferredRegion[m] = gr;
        }
    }
    auto regionOfNode = [&](const std::string& node) {
        std::string r = region::detectNodeRegion(node);
        if (!r.empty()) return r;
        auto it = inferredRegion.find(node);
        return it != inferredRegion.end() ? it->second : std::string();
    };
    st.apiAvailable = true;
    st.apiError.clear();
    st.selectionSatisfied = true;
    const bool sameGroup = st.group == group->name;
    if (!sameGroup) {
        log::ifmt("node monitor [{}]: scope changed from '{}' to '{}' (mode={})",
                  outletId, st.group, group->name, st.runtimeMode);
        st.latencyMs = -1;
        st.consecutiveFails = 0;
        st.regionApplied.clear();
        st.regionUnavailable = false;
        st.classApplied.clear();
        st.classUnavailable = false;
        st.classGroupMissing = false;
        st.lastSwitchAt = 0;
        st.lastSwitchDetail.clear();
    }
    st.group = group->name;
    st.node = group->now;
    if (st.runtimeMode == "rule") {
        const bool configuredGroup = std::find(preferredGroups.begin(), preferredGroups.end(),
                                               st.group) != preferredGroups.end();
        st.routingWarning = std::string(configuredGroup ? "仅测速配置策略组「" : "仅测速通用策略组「") +
            st.group + "」；其他业务出口及 HTTP/WSS 流完整性未验证";
    }
    st.region = regionOfNode(st.node);
    const int controllerLatencyMs =
        client.nodeDelay(group->now, nm.delayUrl, nm.delayTimeoutMs,
                         nm.delayTimeoutMs + 3000);
    const bool controllerProbeAlive = controllerLatencyMs >= 0;
    const bool tunnelHealthy = outletHealthy(outletId);
    if (controllerProbeAlive) {
        st.latencyMs = controllerLatencyMs;
    } else {
        st.latencyMs = -1;
    }
    // /delay is controller metadata, while the health monitor performs a
    // real SOCKS CONNECT through the selected node. A timed round therefore
    // needs real-tunnel corroboration before declaring the node dead. A
    // targeted/manual round remains actionable on the first controller
    // failure, and a failed real tunnel is authoritative in either mode.
    st.alive = tunnelHealthy && (controllerProbeAlive || !manualRound);
    if (!controllerProbeAlive && tunnelHealthy && !manualRound) {
        st.selectionSatisfied = false;
        st.routingWarning += "；当前测速失败，业务可达性待确认";
        log::df("node monitor [{}]: controller delay failed for {}; "
                "local SOCKS accepts requests, TLS reachability unverified",
                outletId, group->now);
    } else if (controllerProbeAlive && !tunnelHealthy) {
        log::wf("node monitor [{}]: {} passes controller delay ({}ms), but "
                "the real tunnel is unhealthy",
                outletId, group->now, controllerLatencyMs);
    }
    // Current node unsatisfactory: dead, or alive but over the latency budget
    // (a slow-but-alive node would otherwise never be re-selected — e.g. an
    // old kernel stack measures 3-5x the latency of a modern one), or the
    // node's region no longer matches the preference.
    const std::vector<std::string>& wantRegions = nm.regions;
    const std::vector<std::string>& wantClasses = nm.nodeClasses;
    // Canonical applied-state keys: the SELECTED SET, sorted and joined —
    // multi-select means "any of these is acceptable".
    auto setKey = [](const std::vector<std::string>& v) {
        std::vector<std::string> s = v;
        std::sort(s.begin(), s.end());
        std::string key;
        for (size_t i = 0; i < s.size(); ++i) {
            if (i) key += ",";
            key += s[i];
        }
        return key;
    };
    // Preference resets run even when the current node is DEAD: otherwise a
    // dead-node round leaves the applied-state stale and every later round
    // misreads it as "preference changed" (bypassing the stabilization
    // window forever — measured: the window never engaged after a dead-node
    // switch, churning the kernel). A GENUINE change bypasses the window.
    const bool regionChanged = st.regionApplied != setKey(wantRegions);
    const bool classChanged = st.classApplied != setKey(wantClasses);
    const bool preferenceChanged = regionChanged || classChanged;
    if (regionChanged) {
        st.regionApplied = setKey(wantRegions);
        st.regionUnavailable = false;
    }
    if (classChanged) {
        st.classApplied = setKey(wantClasses);
        st.classUnavailable = false;
        st.classGroupMissing = false;
    }
    if (manualRound) {
        // "测试并连接" re-evaluates the current node's preferences too.
        st.regionUnavailable = false;
        st.classUnavailable = false;
    }
    bool outOfRegion = false;
    if (!wantRegions.empty() && st.alive) {
        // Region inert latch (mirror of the class one): when NO selectable
        // member carries a wanted region, the preference can't be satisfied
        // here — latch instead of re-selecting every window.
        if (!st.regionUnavailable &&
            !region::matchesAny(regionOfNode(st.node), wantRegions)) {
            bool anyInRegion = false;
            for (const auto& n : group->nodes) {
                const auto leaf = concreteChoice(n);
                if (!leaf) continue;
                if (region::matchesAny(regionOfNode(*leaf), wantRegions)) {
                    anyInRegion = true;
                    break;
                }
            }
            if (!anyInRegion) {
                st.regionUnavailable = true;
                log::ifmt("node monitor [{}]: no [{}] node in group {}; region "
                          "preference inert here", outletId,
                          setKey(wantRegions), group->name);
            }
        }
        outOfRegion = !st.regionUnavailable &&
                      !region::matchesAny(regionOfNode(st.node), wantRegions);
    }
    // Node-class preference (explicit form of the old hard-coded IEPL
    // priority): same soft semantics and anti-flap state as the region.
    // Matching: normal codes use the keyword tables; "GROUP:<name>" entries
    // use ACTUAL group membership (transitive over sub-group references) —
    // a provider's grouping can be selected as a "type" even when its nodes
    // carry no naming signal (measured: xmrth's 🤖AI服务 group holds
    // 美国63x 中继 nodes without "AI" in their names).
    auto nodeInGroup = [&](const std::string& node, const std::string& group) {
        std::set<std::string> visited;
        std::vector<std::string> stack = {group};
        while (!stack.empty()) {
            std::string g = stack.back();
            stack.pop_back();
            if (!visited.insert(g).second) continue;
            auto it = st.groupNodes.find(g);
            if (it == st.groupNodes.end()) continue;
            for (const auto& m : it->second) {
                if (m == node) return true;
                if (st.groupNodes.count(m)) stack.push_back(m);
            }
        }
        return false;
    };
    auto classMatches = [&](const std::string& node) {
        if (wantClasses.empty()) return true;  // 不限
        for (const auto& c : wantClasses) {
            if (c.rfind("GROUP:", 0) == 0) {
                if (nodeInGroup(node, c.substr(6))) return true;
            } else if (nodeclass::matches(node, c)) {
                return true;
            }
        }
        return false;
    };
    bool outOfClass = false;
    if (!wantClasses.empty() && st.alive) {
        // A wanted "GROUP:<name>" entry that this controller does not expose
        // at all is UNSATISFIABLE here (measured: GROUP:AI服务 picked
        // globally while the SakuraCat controller has no such group — the
        // old code re-triggered a re-select every round and flip-flopped
        // between the fastest nodes forever). When NO wanted class entry can
        // ever match on this controller, the class preference is INERT: no
        // trigger, latched — and it re-arms by itself when the group shows
        // up (the user switched the kernel's profile/provider).
        bool classSatisfiable = false;
        for (const auto& c : wantClasses) {
            if (c.rfind("GROUP:", 0) == 0) {
                if (st.groupNodes.count(c.substr(6))) {
                    classSatisfiable = true;
                    break;
                }
            } else {
                classSatisfiable = true;  // keyword classes can match anything
                break;
            }
        }
        if (!classSatisfiable) {
            if (!st.classGroupMissing) {
                st.classGroupMissing = true;
                st.classUnavailable = true;
                log::ifmt("node monitor [{}]: class [{}] has no group on this "
                          "controller; class preference inert here", outletId,
                          setKey(wantClasses));
            }
        } else if (st.classGroupMissing) {
            st.classGroupMissing = false;
            st.classUnavailable = false;  // the group appeared: re-arm
        }
        // Keyword classes can be UNSATISFIABLE too: no selectable member of
        // this group carries the vocabulary (measured 2026-08-31 16:45:
        // class [IEPL] on SakuraCat, whose nodes are all 中转/直连 names —
        // the monitor re-selected every window, ping-ponging GLOBAL between
        // nodes and DIRECT). Latch inert; re-arms on a class-change or a
        // manual round.
        if (!st.classUnavailable && !classMatches(st.node)) {
            bool anyInClass = false;
            for (const auto& n : group->nodes) {
                const auto leaf = concreteChoice(n);
                if (leaf && classMatches(*leaf)) { anyInClass = true; break; }
            }
            if (!anyInClass) {
                st.classUnavailable = true;
                log::ifmt("node monitor [{}]: no [{}] node in group {}; class "
                          "preference inert here", outletId,
                          setKey(wantClasses), group->name);
            }
        }
        outOfClass = !st.classUnavailable && !classMatches(st.node);
    }
    // Real-traffic failure signal: the user's own flows failing at the
    // configured rate overrides a healthy-looking /delay (measured
    // 2026-08-28: a node passed gstatic /delay at 305ms while every real
    // connection to blocked sites was TLS-reset).
    const bool realFail = flowFailsActive(outletId, nm);
    // A node that failed the post-switch verification is treated as dead
    // for selection purposes until its cooldown expires.
    const bool currentBad = nodeInBadCooldown(outletId, st.node, nowMs());
    const bool dead = !st.alive || currentBad;
    const bool tooSlow = st.alive && st.latencyMs > nm.maxLatencyMs;
    if (!manualRound && !dead && !tooSlow && !outOfRegion && !outOfClass && !realFail) {
        // Healthy: reset the failure streak and report.
        st.consecutiveFails = 0;
        log::df("node monitor [{}]: {} alive ({}ms)", outletId, group->now,
                st.latencyMs);
        return;
    }

    if (dead) {
        st.consecutiveFails++;
        if (currentBad) {
            log::wf("node monitor [{}]: node {} failed real verification; "
                    "re-selecting", outletId, group->now);
        } else {
            log::wf("node monitor [{}]: node {} unreachable (fail {}/{})",
                    outletId, group->now, st.consecutiveFails, nm.failThreshold);
        }
        // Manual rounds (GUI "测试并连接") evaluate immediately; timed rounds
        // require failThreshold consecutive failures first. Verification
        // failures ALWAYS re-select immediately — the retry loop depends on
        // it (each failed node is cooldowned and excluded next sweep).
        if (!manualRound && !currentBad &&
            st.consecutiveFails < nm.failThreshold) {
            return;
        }
    } else if (realFail) {
        // Trusted failures from the user's own resolved destinations are a
        // hard availability verdict, not a soft preference. Never hold them
        // behind minSwitchIntervalS: a just-selected broken node must be
        // replaceable immediately.
        log::wf("node monitor [{}]: node {} passes the delay test but real "
                "traffic is failing; re-selecting", outletId, group->now);
    } else {
        // Stabilization window: slow/region/class re-selections don't fire
        // more often than minSwitchIntervalS. Every switch kills the
        // kernel's existing connections — the agent's long-lived session
        // reconnects on each churn (measured: nodes hovering near the
        // latency budget caused a switch every minute and an endless
        // "reconnecting" loop). Dead nodes switch immediately; manual
        // rounds and preference changes bypass.
        if (!manualRound && !preferenceChanged && nm.minSwitchIntervalS > 0 &&
            st.lastSwitchAt > 0 &&
            nowMs() - st.lastSwitchAt <
                static_cast<int64_t>(nm.minSwitchIntervalS) * 1000) {
            log::df("node monitor [{}]: stabilization window (last switch "
                    "{}s ago); keeping {}",
                    outletId, (nowMs() - st.lastSwitchAt) / 1000, group->now);
            return;
        }
        if (tooSlow) {
            log::wf("node monitor [{}]: node {} too slow ({}ms > {}ms budget), "
                    "re-selecting", outletId, group->now, st.latencyMs,
                    nm.maxLatencyMs);
        } else if (outOfRegion) {
            log::wf("node monitor [{}]: node {} out of region [{}] (preferred), "
                    "re-selecting", outletId, group->now, setKey(wantRegions));
        } else if (outOfClass) {
            log::wf("node monitor [{}]: node {} out of class [{}] (preferred), "
                    "re-selecting", outletId, group->now, setKey(wantClasses));
        } else {
            log::ifmt("node monitor [{}]: explicit test compares current node with matching candidates", outletId);
        }
    }

    // Once real traffic, the independent tunnel probe, or an explicit test
    // has proved the CURRENT node bad, cool it too. Previously only a newly
    // switched candidate could enter cooldown, so the original broken node
    // was selected again as soon as the retry chain wrapped around.
    const bool currentProvenBad =
        realFail || !tunnelHealthy || (manualRound && !controllerProbeAlive);
    if (!currentBad && currentProvenBad && nm.badNodeCooldownS > 0) {
        {
            std::lock_guard<std::mutex> lk(badNodesMu_);
            badNodes_[outletId][group->now] =
                nowMs() + static_cast<int64_t>(nm.badNodeCooldownS) * 1000;
        }
        log::wf("node monitor [{}]: cooling proven-bad current node {} before "
                "candidate selection", outletId, group->now);
    }

    // The re-selection is committed: publish a live "switching" state so the
    // GUI keeps showing "切换中…" instead of repainting the stale previous
    // node from the per-second STATS (measured complaint: rows flipped back
    // to the old node during the measurement, looking like nothing happened).
    st.switching = true;
    {
        std::lock_guard<std::mutex> lk(nodeMu_);
        nodeStatus_[outletId] = st;
    }

    // Measure the other nodes (bounded concurrency: 16; strict, capped
    // timeout). Dead candidates burn one full timeout each — the +3000
    // read-deadline grace of the CURRENT-node probe would double that cost
    // here, so candidates use the strict timeout capped at 2s (measured: a
    // region re-select used to take 30-36s on a node list full of slow/dead
    // entries).
    const int probeTimeout = std::min(nm.delayTimeoutMs, 2000);
    struct ProbeResult {
        std::string selection; // legal immediate member used by PUT
        std::string node;
        int latency;
        std::string region;  // detected region ("" = unknown)
        bool inClass = false;  // matches the node-class preference
        int historySuccesses = 0;
        int historySamples = 0;
    };
    std::vector<ProbeResult> results;
    std::mutex resMu;
    std::vector<std::string> candidates;
    bool cooldownSkipped = false;
    auto collectCandidates = [&](bool ignoreCooldowns) {
        candidates.clear();
        cooldownSkipped = false;
        std::set<std::string> seen{group->now};
        for (const auto& n : group->nodes) {
            const auto leaf = concreteChoice(n);
            if (!leaf || !seen.insert(*leaf).second) continue;
            // Explicit rule-service selectors may legally select a child
            // branch at its existing leaf. General/global groups keep their
            // previous concrete-node policy; child selections stay untouched.
            // An explicit filtered test must not silently pick a node from
            // another region/type. Timed recovery keeps its soft fallback.
            if (manualRound && (!region::matchesAny(regionOfNode(*leaf), wantRegions) || !classMatches(*leaf))) continue;
            // A node that failed the post-switch real-CONNECT verification
            // is excluded for its cooldown (the retry loop then walks the
            // rest of the list instead of re-picking it).
            if (!ignoreCooldowns &&
                nodeInBadCooldown(outletId, *leaf, nowMs())) {
                cooldownSkipped = true;
                continue;
            }
            candidates.push_back(n);
        }
    };
    collectCandidates(false);
    const bool fellBackToCooldown = !manualRound && candidates.empty() && cooldownSkipped;
    if (fellBackToCooldown) {
        // Every candidate failed verification recently. Waiting out the
        // cooldown with broken traffic is worse than retrying the least-bad
        // node — fall back to the full list (the ranking sorts them; the
        // post-switch verify is skipped for this fallback, see below).
        collectCandidates(true);
        log::wf("node monitor [{}]: all candidates in verification cooldown; "
                "falling back to the full list", outletId);
    }
    std::atomic<size_t> next{0};
    std::vector<std::thread> workers;
    size_t workerCount = candidates.size() < 16 ? candidates.size() : 16;
    for (size_t w = 0; w < workerCount; ++w) {
        workers.emplace_back([&]() {
            while (true) {
                size_t i = next.fetch_add(1);
                if (i >= candidates.size()) break;
                const auto leaf = concreteChoice(candidates[i]);
                if (!leaf) continue;
                int lat = client.nodeDelay(*leaf, nm.delayUrl,
                                           probeTimeout, probeTimeout);
                ProbeResult pr;
                pr.selection = candidates[i];
                pr.node = *leaf;
                pr.latency = lat;
                pr.region = regionOfNode(pr.node);
                pr.inClass = classMatches(pr.node);
                auto history = group->history.find(pr.node);
                if (history != group->history.end()) {
                    pr.historySuccesses = history->second.successes;
                    pr.historySamples = history->second.samples;
                }
                std::lock_guard<std::mutex> lk(resMu);
                results.push_back(std::move(pr));
            }
        });
    }
    for (auto& t : workers) t.join();

    if (manualRound && !dead && !realFail && st.latencyMs >= 0 &&
        region::matchesAny(regionOfNode(st.node), wantRegions) && classMatches(st.node)) {
        ProbeResult current;
        current.selection = group->selectedMember;
        current.node = st.node;
        current.latency = st.latencyMs;
        current.region = regionOfNode(st.node);
        current.inClass = true;
        if (const auto history = group->history.find(st.node); history != group->history.end()) {
            current.historySuccesses = history->second.successes;
            current.historySamples = history->second.samples;
        }
        // Include the current node in ranking: keeping the best node must
        // never issue a redundant PUT that could disturb existing flows.
        results.insert(results.begin(), std::move(current));
    }

    // Selection policy: retained availability first, then the existing soft
    // preferences (region, latency budget, class), then fresh latency. The
    // controller's history costs no extra probes and catches the production
    // failure mode where an IEPL node passes ONE fresh /delay yet failed 4-7
    // of its last 10 checks. Unknown history stays neutral, preserving the
    // old ranking on controllers that do not expose it. Reuse the configured
    // real-traffic threshold/ratio rather than inventing provider-specific
    // constants.
    const ProbeResult* chosen = nullptr;
    int chosenRank = -1;
    for (const auto& r : results) {
        if (r.latency < 0) continue;  // dead
        const bool inRegion = region::matchesAny(r.region, wantRegions);
        const bool withinBudget = r.latency <= nm.maxLatencyMs;
        int reliabilityTier = 1;  // unknown = neutral
        if (r.historySamples > 0 &&
            r.historySamples >= nm.realFailThreshold) {
            const int failures = r.historySamples - r.historySuccesses;
            reliabilityTier =
                failures * 100 >= r.historySamples * nm.realFailRatioPct ? 0 : 2;
        }
        const int rank = reliabilityTier * 64 + (inRegion ? 16 : 0) +
                         (withinBudget ? 8 : 0) + (r.inClass ? 4 : 0);
        if (!chosen || rank > chosenRank ||
            (rank == chosenRank && r.latency < chosen->latency)) {
            chosen = &r;
            chosenRank = rank;
        }
    }
    if (!chosen) {
        st.switching = false;
        if (manualRound) {
            st.selectionSatisfied = false;
            st.lastSwitchDetail = "测试结果：没有符合地区/类型筛选的可用节点，保留当前选择";
        }
        log::wf("node monitor [{}]: no alive node in group {}", outletId,
                group->name);
        return;
    }
    if (manualRound && chosen->node == st.node) {
        st.switching = false;
        st.consecutiveFails = 0;
        st.lastSwitchDetail = "测试结果：当前节点已是符合筛选条件的最优线路（" +
                              std::to_string(st.latencyMs) + "ms）";
        return;
    }
    const bool fellBack = chosen->latency > nm.maxLatencyMs;
    if (fellBack) {
        log::wf("node monitor [{}]: all candidates exceed {}ms budget; "
                "falling back to lowest alive", outletId, nm.maxLatencyMs);
    }
    if (!wantRegions.empty()) {
        // Region preference beats speed: an in-region CURRENT node is never
        // swapped for a faster out-of-region one — but ONLY while it is
        // ALIVE. A dead node is never kept, even if its name matches the
        // region (measured: "keeping in-region node" used to pin a DEAD
        // node forever, killing the whole outlet).
        const bool curIn = region::matchesAny(regionOfNode(st.node), wantRegions);
        const bool chosenIn = region::matchesAny(chosen->region, wantRegions);
        // realFail bypasses the keep veto: a node whose real traffic is
        // failing is not "in region" in any useful sense.
        if (!dead && !realFail && curIn && !chosenIn) {
            st.switching = false;
            log::wf("node monitor [{}]: keeping in-region node {} (no "
                    "[{}] candidate)", outletId, st.node, setKey(wantRegions));
            // Both preference dimensions are "unavailable for improvement"
            // right now: suppress the OTHER trigger too, or the round
            // re-measures and re-vetoes forever (measured: a 7s
            // re-select -> veto loop on the CFW kernel).
            st.regionUnavailable = true;
            st.classUnavailable = true;
            return;
        }
        if (fellBack && tooSlow && chosen->latency >= st.latencyMs &&
            !(!curIn && chosenIn)) {
            st.switching = false;
            // A slow current node must not be replaced by something worse
            // (region upgrades are exempt).
            return;
        }
    } else if (fellBack && tooSlow && chosen->latency >= st.latencyMs) {
        st.switching = false;
        return;
    }
    if (!wantClasses.empty()) {
        // Class preference beats speed WITHIN the same region tier: an
        // in-class CURRENT node is never swapped for a faster out-of-class
        // one while both are in (or both out of) the wanted region — but a
        // REGION UPGRADE always wins (measured: region=SG kept re-picking
        // an alive Korean IEPL node because the class veto fired on every
        // out-of-region re-select, churning the kernel forever). A dead
        // current node is never kept.
        const bool curIn = classMatches(st.node);
        const bool chosenIn = classMatches(chosen->node);
        const bool curInRegion =
            region::matchesAny(regionOfNode(st.node), wantRegions);
        const bool chosenInRegion =
            region::matchesAny(chosen->region, wantRegions);
        if (!dead && !realFail && curIn && !chosenIn &&
            curInRegion == chosenInRegion) {
            st.switching = false;
            log::wf("node monitor [{}]: keeping in-class node {} (no "
                    "[{}] candidate)", outletId, st.node, setKey(wantClasses));
            st.classUnavailable = true;
            st.regionUnavailable = true;  // stop the re-measure loop
            return;
        }
    }
    st.switching = false;  // the round ends with this store
    std::string swErr;
    if (client.switchNode(group->name, chosen->selection, &swErr)) {
        if (chosen->selection != chosen->node) {
            std::string currentMode;
            const auto verified = client.currentSelectorGroup(&swErr, 3000, nullptr,
                                                              &currentMode, preferredGroups);
            if (!verified || verified->name != group->name || currentMode != "rule" ||
                verified->now != chosen->node) {
                st.selectionSatisfied = false;
                st.lastSwitchDetail = "嵌套策略选择在探测期间改变，实际出口待下一轮核对";
                log::wf("node monitor [{}]: nested member {} changed during selection verification",
                        outletId, chosen->selection);
                return;
            }
        }
        st.lastSwitchDetail = group->now + " -> " + chosen->node + " (" +
                              std::to_string(chosen->latency) + "ms)";
        if (outOfRegion && !dead && !tooSlow) {
            st.lastSwitchDetail = "地区切换: " + st.lastSwitchDetail;
        } else if (outOfClass && !dead && !tooSlow) {
            st.lastSwitchDetail = "类型切换: " + st.lastSwitchDetail;
        }
        st.lastSwitchAt = nowMs();
        st.consecutiveFails = 0;
        st.alive = true;
        st.node = chosen->node;
        st.region = chosen->region;
        st.latencyMs = chosen->latency;
        // The DNS resolution path changed with the node: cached answers may
        // have come back POISONED through the previous node's path (measured
        // 2026-08-31: a 中转 node's return path passes through network intermediaries, which
        // injects fake records into TCP-53 responses — the resolver cached
        // 69.171.235.22 for www.youtube.com). Flush so the next query
        // re-resolves through the NEW node immediately.
        {
            std::lock_guard<std::mutex> lk(dnsCacheMu_);
            dnsCache_.clear();
        }
        if (!wantRegions.empty()) {
            // Remember whether the region was satisfied so a provider without
            // the wanted regions doesn't trigger a re-select every round.
            st.regionUnavailable =
                !region::matchesAny(chosen->region, wantRegions);
        }
        if (!wantClasses.empty()) {
            st.classUnavailable = !classMatches(chosen->node);
        }
        log::ifmt("node monitor [{}]: auto-switched {}", outletId, st.lastSwitchDetail);
        // REAL verification: dial the EXACT destination the user's traffic
        // just failed to reach, through the new node (first principles —
        // no hard-coded probe URL anywhere). Only TRUSTED destinations
        // (resolved by us) carry a verdict: a successful CONNECT to a
        // poisoned answer (real Facebook/Twitter IPs) must never read as
        // "node confirmed". Failure cooldowns the node and re-triggers the
        // round, so the retry loop walks the candidate list until one
        // actually works.
        if (fellBackToCooldown) {
            log::wf("node monitor [{}]: keeping fallback node {} without "
                    "re-verifying (the whole list is in cooldown)", outletId,
                    chosen->node);
            // The walk exhausted the list: reset the cooldowns AND the
            // failure signal so the chain SETTLES here (otherwise every
            // periodic round re-switches to the cooldowned fallback,
            // churning the kernel forever). Fresh real failures re-arm a
            // new walk with a clean slate.
            {
                std::lock_guard<std::mutex> lk(badNodesMu_);
                badNodes_.erase(outletId);
            }
            clearFlowSignal(outletId);
        } else {
            const VerifyOutcome v = verifySwitchWithRealTarget(cfg, outletId);
            if (v == VerifyOutcome::Cleared) {
                clearFlowSignal(outletId);
            } else if (v == VerifyOutcome::Failed && nm.badNodeCooldownS > 0) {
                {
                    std::lock_guard<std::mutex> lk(badNodesMu_);
                    badNodes_[outletId][chosen->node] =
                        nowMs() +
                        static_cast<int64_t>(nm.badNodeCooldownS) * 1000;
                }
                log::wf("node monitor [{}]: node {} failed the real-CONNECT "
                        "verification; cooling it down and re-selecting",
                        outletId, chosen->node);
                requestNodeSwitchRound(outletId, false);
            }
            // NoVerdict: leave the signal — the destination was not ours
            // (stale/poisoned app-side answer); the app re-resolves and
            // our clean answers take over. Bounded by the switch gate.
        }
    } else {
        st.selectionSatisfied = false;
        st.lastSwitchDetail = "切换失败，保留当前选择：" + swErr;
        log::wf("node monitor [{}]: switch to {} failed: {}", outletId,
                chosen->node, swErr);
    }
}

std::map<std::string, Engine::NodeStatus> Engine::nodeStatusSnapshot() const {
    std::lock_guard<std::mutex> lk(const_cast<Engine*>(this)->nodeMu_);
    auto s = nodeStatus_;
    return s;
}

json::Value Engine::effectiveProxyJson() const {
    json::Value j = json::Value::makeObject();
    const std::string selected = resolveRuleOutlet("");
    const auto rt = outletsSnapshot();
    if (!rt) return j;
    std::string id = selected;
    auto it = rt->params.find(id);
    if (it == rt->params.end() || rt->disabled.count(id)) {
        id = kDefaultOutletId;
        it = rt->params.find(id);
    }
    if (it == rt->params.end()) return j;
    j.set("selected_id", selected);
    j.set("id", id);
    j.set("host", formatIpv4(it->second.proxy.ip));
    j.set("port", static_cast<uint32_t>(it->second.proxy.port));
    auto name = rt->names.find(id);
    j.set("name", name == rt->names.end() ? id : name->second);
    j.set("fallback", id != selected);
    return j;
}

json::Value Engine::nodeStatusJson() const {
    json::Value arr = json::Value::makeArray();
    auto snapshot = nodeStatusSnapshot();
    auto rt = outletsSnapshot();
    for (auto& kv : snapshot) {
        // A port can change between monitor rounds (or during a slow round).
        // Never combine the new runtime address with the old address's error.
        if (rt && kv.second.checkedProxy.port != 0) {
            const auto current = rt->params.find(kv.first);
            if (current != rt->params.end() &&
                (current->second.proxy.ip != kv.second.checkedProxy.ip ||
                 current->second.proxy.port != kv.second.checkedProxy.port)) {
                kv.second = NodeStatus{};
                kv.second.apiError = "实际出口已变化，等待节点检测";
            }
        }
        json::Value j = json::Value::makeObject();
        j.set("id", kv.first);
        std::string name = kv.first;
        if (rt) {
            auto it = rt->names.find(kv.first);
            if (it != rt->names.end()) name = it->second;
        }
        j.set("name", name);
        j.set("group", kv.second.group);
        j.set("node", kv.second.node);
        j.set("latency_ms", kv.second.latencyMs);
        j.set("alive", kv.second.alive);
        j.set("api", kv.second.apiAvailable);
        j.set("api_msg", kv.second.apiError);
        j.set("runtime_mode", kv.second.runtimeMode);
        j.set("routing_warning", kv.second.routingWarning);
        j.set("last_switch_at", kv.second.lastSwitchAt);
        j.set("last_switch_detail", kv.second.lastSwitchDetail);
        j.set("switching", kv.second.switching);
        j.set("selection_ok", kv.second.selectionSatisfied);
        j.set("test_request_id", kv.second.testRequestId);
        j.set("region", kv.second.region);
        json::Value classes = json::Value::makeArray();
        if (!kv.second.node.empty()) {
            for (const auto* code : {"IEPL", "RES", "NATIVE", "RELAY", "DIRECT", "STARLINK", "PREMIUM"})
                if (nodeclass::matches(kv.second.node, code)) classes.append(code);
        }
        j.set("node_classes", std::move(classes));
        {
            json::Value garr = json::Value::makeArray();
            for (const auto& g : kv.second.groupNodes) garr.append(g.first);
            j.set("groups", std::move(garr));
        }
        arr.append(std::move(j));
    }
    return arr;
}

void Engine::handleTcp6Packet(uint8_t* buf, size_t len) {
    // IPv6 TCP: packet layer carries no PID, so attribution is by source port
    // via the SOCKET layer (IPv6 events store localIp=0). Rule processes'
    // IPv6 handshakes are DROPPED so happy-eyeballs falls back to IPv4,
    // which the NAT pipeline proxies. Everything else passes through.
    PWINDIVERT_IPV6HDR ip6 = nullptr;
    PWINDIVERT_TCPHDR tcp = nullptr;
    UINT8 proto = 0;
    if (!WinDivertHelperParsePacket(buf, static_cast<UINT>(len), nullptr, &ip6, &proto,
                                    nullptr, nullptr, &tcp, nullptr, nullptr, nullptr,
                                    nullptr, nullptr)) {
        device_->sendLastTcp6(buf, len);
        return;
    }
    if (!ip6 || !tcp || proto != IPPROTO_TCP) {
        device_->sendLastTcp6(buf, len);
        return;
    }
    uint16_t srcPort = ntohs(tcp->SrcPort);
    uint16_t dstPort = ntohs(tcp->DstPort);
    auto m = socketMap_.find(0, srcPort);
    // The first SYN can beat its SOCKET-layer event. IPv4 already closes
    // this race through GetExtendedTcpTable; do the same for IPv6 before a
    // rule process gets one direct happy-eyeballs connection.
    if (!m && tcp->Syn && !tcp->Ack) {
        std::array<uint8_t, 16> srcIp{};
        std::memcpy(srcIp.data(), ip6->SrcAddr, srcIp.size());
        auto pid = tcpTable_->findOwnerByLocal6(srcIp, srcPort);
        if (pid && *pid != 0) {
            std::wstring path = socketMap_.resolvePathCached(*pid);
            if (!path.empty()) {
                socketMap_.insertResolved(0, srcPort, 0, dstPort, *pid, path,
                                          IPPROTO_TCP);
                m = socketMap_.find(0, srcPort);
                log::df("IPv6 SYN owner recovered from TCP table: :{} pid={} owner={}",
                        srcPort, *pid, wideToUtf8(path));
            }
        }
    }
    auto rt = runtime();
    if (rt && m && m->protocol == IPPROTO_TCP && !m->path.empty() &&
        rt->matcher->isEnabledRuleProcess(m->path)) {
        if (tcp->Syn) {
            log::df("blocked IPv6 SYN :{} -> :{} owner={} (force IPv4 fallback)",
                    srcPort, dstPort, wideToUtf8(m->path));
        }
        return;  // drop
    }
    device_->sendLastTcp6(buf, len);
}

void Engine::dnsPump() {
    std::vector<uint8_t> buf(kMaxPacketSize);
    while (!stopping_.load()) {
        size_t len = 0;
        PacketMeta meta;
        if (!device_->recvNetworkDns(buf.data(), buf.size(), len, meta)) break;
        handleDnsPacket(buf.data(), len, meta);
    }
}

// One A query over TCP 53 through the given SOCKS tunnel (2-byte length
// prefix framing). This is only the fallback behind DoH: the node exit sees
// the configured resolver, but plaintext replies can still be altered on a
// hostile return path.
bool dnsQueryOverSocks(const net::Endpoint4& proxy,
                       const net::Endpoint4& server, const std::string& name,
                       std::vector<uint32_t>& ips) {
    ips.clear();
    // Build a plain A query (id 0x1234, RD, one question).
    std::vector<uint8_t> q(12, 0);
    q[0] = 0x12;
    q[1] = 0x34;
    q[2] = 0x01;
    q[5] = 0x01;
    size_t start = 0;
    while (start <= name.size()) {
        size_t dot = name.find('.', start);
        std::string label = name.substr(
            start, dot == std::string::npos ? std::string::npos : dot - start);
        if (label.empty()) break;
        q.push_back(static_cast<uint8_t>(label.size()));
        q.insert(q.end(), label.begin(), label.end());
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    q.push_back(0);         // root terminator
    q.push_back(0);
    q.push_back(1);         // QTYPE A
    q.push_back(0);
    q.push_back(1);         // QCLASS IN

    SOCKET s = INVALID_SOCKET;
    std::string err;
    if (!Socks5Client::connect(proxy, "", "", server, 2500, s, &err)) {
        return false;
    }
    std::vector<uint8_t> wire;
    wire.push_back(static_cast<uint8_t>(q.size() >> 8));
    wire.push_back(static_cast<uint8_t>(q.size() & 0xFF));
    wire.insert(wire.end(), q.begin(), q.end());
    int to = 2500;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&to), sizeof(to));
    bool ok = send(s, reinterpret_cast<const char*>(wire.data()),
                   static_cast<int>(wire.size()), 0) ==
              static_cast<int>(wire.size());
    std::vector<uint8_t> resp;
    if (ok) {
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(3000);
        while (resp.size() < 2 ||
               (resp.size() >= 2 &&
                resp.size() < 2u + (resp[0] << 8 | resp[1]))) {
            char tmp[512];
            int n = recv(s, tmp, sizeof(tmp), 0);
            if (n <= 0) break;
            resp.insert(resp.end(), tmp, tmp + n);
            if (std::chrono::steady_clock::now() > deadline) break;
        }
    }
    net::closeSocket(s);
    if (resp.size() >= 14) {
        auto recs = dns::parseARecords(resp.data() + 2, resp.size() - 2);
        if (!recs.empty()) {
            ips = std::move(recs);
            return true;
        }
    }
    return false;
}

// The DNS servers the engine queries through the kernel's tunnel — fully
// auto-detected: the kernel's own config.yaml dns section (the resolvers IT
// trusts), else the adapter's DNS servers. No hard-coded servers anywhere.
std::vector<net::Endpoint4> Engine::dnsServersForKernel(const std::string& id) {
    if (!dnsServersOverride_.empty()) return dnsServersOverride_;
    {
        std::lock_guard<std::mutex> lk(dnsServersMu_);
        auto cit = dnsServersCache_.find(id);
        if (cit != dnsServersCache_.end()) return cit->second;
    }
    std::vector<net::Endpoint4> servers;
    {
        std::lock_guard<std::mutex> lk(discMu_);
        auto it = discovered_.find(id);
        if (it != discovered_.end() && !it->second.kernel.configDir.empty()) {
            std::wstring cfgPath =
                utf8ToWide(it->second.kernel.configDir) + L"\\config.yaml";
            std::string text, err;
            if (subscription::loadTextFile(cfgPath, text, &err)) {
                for (uint32_t ip : subscription::parseDnsServerIps(text)) {
                    servers.push_back(net::Endpoint4{ip, 53});
                }
            }
        }
    }
    if (servers.empty()) {
        // Adapter fallback: the system's configured DNS via GetNetworkParams
        // (SDK-version-proof). Public IPs only — a router address like
        // 192.168.x.1 is unreachable from the node's exit.
        FIXED_INFO fi{};
        ULONG fsz = sizeof(fi);
        if (GetNetworkParams(&fi, &fsz) == NO_ERROR) {
            for (auto* d = &fi.DnsServerList; d && servers.size() < 2;
                 d = d->Next) {
                uint32_t ip = parseIpv4(d->IpAddress.String).value_or(0);
                if (ip != 0 && (ip >> 24) != 127 &&
                    !((ip & 0xFF000000u) == 0x0A000000u) &&
                    !((ip & 0xFFF00000u) == 0xAC100000u) &&
                    !((ip & 0xFFFF0000u) == 0xC0A80000u)) {
                    servers.push_back(net::Endpoint4{ip, 53});
                }
            }
        }
    }
    {
        std::lock_guard<std::mutex> lk(dnsServersMu_);
        dnsServersCache_[id] = servers;
    }
    return servers;
}

void Engine::maybeResolveHealthProbeDst(const Config& cfg) {
    if (healthProbeDst_.ip != 0 || healthProbeDst_.port != 0) return;
    // The delay URL host (user-configurable) — no hard-coded IPs.
    std::string host = cfg.nodeMonitor.delayUrl;
    size_t p = host.find("://");
    if (p != std::string::npos) host = host.substr(p + 3);
    size_t sl = host.find('/');
    if (sl != std::string::npos) host = host.substr(0, sl);
    if (host.empty()) return;
    // The tunnel to resolve through: the default egress's SOCKS.
    auto ort = outlets_.load();
    if (!ort) return;
    auto it = ort->params.find(kDefaultOutletId);
    if (it == ort->params.end() || it->second.proxy.port == 0) return;
    const net::Endpoint4 proxy = it->second.proxy;
    // Servers from the kernel covering the default port, else the
    // DNS-chosen kernel, else any alive kernel.
    std::string kid;
    std::string pinnedDnsKernel;
    {
        std::lock_guard<std::mutex> lk(dnsResolveMu_);
        pinnedDnsKernel = dnsApiKernelId_;
    }
    {
        std::lock_guard<std::mutex> lk(discMu_);
        for (const auto& kv : discovered_) {
            if (!kv.second.alive || kv.second.kernel.socksPort == 0) continue;
            if (kv.second.kernel.socksPort == proxy.port) {
                kid = kv.first;
                break;
            }
        }
        if (kid.empty() && !pinnedDnsKernel.empty()) kid = pinnedDnsKernel;
        if (kid.empty()) {
            for (const auto& kv : discovered_) {
                if (kv.second.alive && kv.second.kernel.socksPort != 0) {
                    kid = kv.first;
                    break;
                }
            }
        }
    }
    if (kid.empty()) return;
    std::vector<uint32_t> ips;
    // Configured servers first (same poisoned-leg rationale as
    // resolveViaSocksTcpDns), then the auto-detected ones.
    for (const auto& s : cfg.routing.dnsServers) {
        if (auto ep = parseDnsServerEntry(s)) {
            if (dnsQueryOverSocks(proxy, *ep, host, ips) && !ips.empty()) {
                break;
            }
        }
    }
    if (ips.empty()) {
        for (const auto& server : dnsServersForKernel(kid)) {
            if (dnsQueryOverSocks(proxy, server, host, ips) && !ips.empty()) break;
        }
    }
    if (!ips.empty()) {
        healthProbeDst_ = net::Endpoint4{ips[0], 443};
        log::ifmt("health probe target auto-detected: {} -> {}", host,
                  ips[0]);
    }
}

bool Engine::resolveViaSocksTcpDns(const std::string& name,
                                   std::vector<uint32_t>& ips,
                                   int64_t deadlineMs) {
    ips.clear();
    // Budget start (see kDnsResolveBudgetMs): every attempt below is
    // deadline-checked; expiry aborts the chain with the cached/passthrough
    // fallback — the one hard rule of the machine-wide DNS layer is that it
    // must never add latency to any process's lookups.
    const int64_t deadline = deadlineMs > 0
                                 ? deadlineMs
                                 : nowMs() + kDnsResolveBudgetMs;
    // Candidate kernels: the DNS-pinned one first, then every other ALIVE
    // kernel with a SOCKS listener. A hung kernel that still accepts TCP
    // must not take DNS down with it (measured 2026-08-28: CFW's core hung —
    // its SOCKS listener aborted every handshake — while SakuraCat served
    // clean DNS; the pinned-kernel-only resolver then leaked every poisoned
    // answer straight through).
    std::vector<std::pair<std::string, uint16_t>> cands;
    {
        std::lock_guard<std::mutex> lk(discMu_);
        auto add = [&](const std::string& id) {
            auto it = discovered_.find(id);
            if (it != discovered_.end() && it->second.alive &&
                it->second.kernel.socksPort != 0) {
                cands.emplace_back(id, it->second.kernel.socksPort);
            }
        };
        add(dnsApiKernelId_);
        for (const auto& kv : discovered_) {
            if (kv.first != dnsApiKernelId_) add(kv.first);
        }
    }
    // User-configured servers first (data, not code): plain DNS to a
    // remote DNS resolver from an different network outlet passes through network intermediaries on the way
    // back and comes back with well-formed fake records (measured
    // 2026-08-31: 223.5.5.5 through an IPLC node still answered youtube
    // with Facebook IPs; 8.8.8.8 through the same node was clean). The
    // config value lives in the user's own config.json — empty = pure
    // auto-detection.
    std::vector<net::Endpoint4> preferred;
    if (auto rt2 = runtime()) {
        for (const auto& s : rt2->cfg.routing.dnsServers) {
            if (auto ep = parseDnsServerEntry(s)) preferred.push_back(*ep);
        }
    }
    for (const auto& [kid, socksPort] : cands) {
        // DoH FIRST, via this kernel's HTTP-CONNECT (mixed) port: plain
        // TCP-53 answers get swapped wherever the return path crosses the
        // network intermediaries — even from 8.8.8.8, through transit nodes (measured
        // 2026-08-31 17:33: youtube answered 69.171.235.22, a Facebook IP,
        // through the resolver's plain-53 path; the encrypted HTTPS body
        // cannot be injected). Only the USER-CONFIGURED servers are used as
        // DoH endpoints (data, not code — and tests never dial out).
        if (!preferred.empty()) {
            bool dohOk = false;
            for (const auto& server : preferred) {
                const int64_t remaining = deadline - nowMs();
                if (remaining < 200) return false;  // budget spent: fallback
                const int tmo = static_cast<int>(
                    remaining < 2500 ? remaining : 2500);
                std::string derr;
                const int64_t dohStarted = nowMs();
                bool r = dohOverride_
                             ? dohOverride_(socksPort, server.ip, name, ips,
                                            tmo, &derr)
                             : doh::resolveViaHttpProxy(socksPort, server.ip,
                                                        name, ips, tmo, &derr);
                const int64_t dohElapsed = nowMs() - dohStarted;
                if (r && !ips.empty()) {
                    dohOk = true;
                    log::df("dns cleanup: DoH {} via {} answered {} ip(s) in "
                            "{}ms",
                            formatIpv4(server.ip), kid, ips.size(), dohElapsed);
                    break;
                }
                log::df("dns cleanup: DoH {} via {} failed in {}ms: {}",
                        formatIpv4(server.ip), kid, dohElapsed,
                        derr.empty() ? "no answer" : derr);
            }
            if (dohOk) {
                if (kid != dnsApiKernelId_) {
                    std::lock_guard<std::mutex> lk(discMu_);
                    auto it = discovered_.find(kid);
                    if (it != discovered_.end()) {
                        dnsApiKernelId_ = kid;
                        dnsApiSecret_ = it->second.kernel.apiSecret;
                        dnsApiPort_.store(it->second.kernel.apiPort);
                        dnsApiPipe_ = it->second.kernel.apiPipe;
                        dnsApiPipePid_ = it->second.kernel.pid;
                    }
                }
                return true;
            }
            // DoH failed everywhere (no mixed-port, cert rejected, plain
            // servers): fall through to plain-53 below.
        }
        // Configured servers first, then every auto-detected server of
        // this kernel, until one answers.
        std::vector<net::Endpoint4> servers = preferred;
        for (const auto& s : dnsServersForKernel(kid)) {
            bool dup = false;
            for (const auto& x : servers) {
                if (x.ip == s.ip) dup = true;
            }
            if (!dup) servers.push_back(s);
        }
        for (const auto& server : servers) {
            if (nowMs() >= deadline) return false;  // budget spent
            if (dnsQueryOverSocks(net::Endpoint4{0x7F000001, socksPort}, server,
                                  name, ips) &&
                !ips.empty()) {
                // Adopt the kernel that actually answered: the next
                // resolution starts with it and the controller fallback
                // prefers it too. A later failure re-picks again.
                if (kid != dnsApiKernelId_) {
                    std::lock_guard<std::mutex> lk(discMu_);
                    auto it = discovered_.find(kid);
                    if (it != discovered_.end()) {
                        dnsApiKernelId_ = kid;
                        dnsApiSecret_ = it->second.kernel.apiSecret;
                        dnsApiPort_.store(it->second.kernel.apiPort);
                        dnsApiPipe_ = it->second.kernel.apiPipe;
                        dnsApiPipePid_ = it->second.kernel.pid;
                        log::ifmt("dns cleanup: kernel {} answered via SOCKS; "
                                  "adopting it for DNS", kid);
                    }
                }
                return true;
            }
        }
    }
    return false;
}

bool Engine::resolveCleanA(const std::string& name,
                           std::vector<uint32_t>& ips,
                           std::string* source, std::string* errOut) {
    ips.clear();
    if (source) source->clear();
    if (errOut) errOut->clear();
    std::lock_guard<std::mutex> serial(dnsResolveMu_);
    auto rt = runtime();
    if (!rt || !rt->cfg.routing.dnsCleanup) return false;

    // Robustness: a clean answer stays FRESH for 5 minutes (test seam may
    // shrink it); when resolution is unreachable, an answer up to 24h old
    // remains usable instead of leaking a possibly-polluted original query.
    const int64_t now = nowMs();
    const int64_t deadline = now + kDnsResolveBudgetMs;
    {
        std::lock_guard<std::mutex> lk(dnsCacheMu_);
        auto it = dnsCache_.find(name);
        if (it != dnsCache_.end() && now < it->second.second &&
            !it->second.first.empty()) {
            ips = it->second.first;
            if (source) *source = "cached";
            return true;
        }
    }

    // Pick a live controller independently of the active transport. This is
    // the same state machine previously owned solely by dnsPump; the serial
    // mutex now lets TCP-DNS relay sessions share it safely.
    {
        std::lock_guard<std::mutex> lk(discMu_);
        auto cur = discovered_.find(dnsApiKernelId_);
        if (cur == discovered_.end() || !cur->second.alive ||
            !cur->second.kernel.hasApi()) {
            dnsApiKernelId_.clear();
            dnsApiSecret_.clear();
            dnsApiPipe_.clear();
            dnsApiPipePid_ = 0;
            dnsApiPort_.store(0);
            for (const auto& kv : discovered_) {
                if (!kv.second.alive || !kv.second.kernel.hasApi()) continue;
                dnsApiKernelId_ = kv.first;
                dnsApiSecret_ = kv.second.kernel.apiSecret;
                break;
            }
            if (!rt->cfg.routing.autoOutletId.empty()) {
                auto act = discovered_.find(rt->cfg.routing.autoOutletId);
                if (act != discovered_.end() && act->second.alive &&
                    act->second.kernel.hasApi()) {
                    dnsApiKernelId_ = act->first;
                    dnsApiSecret_ = act->second.kernel.apiSecret;
                }
            }
        }
        auto chosen = discovered_.find(dnsApiKernelId_);
        if (chosen != discovered_.end()) {
            dnsApiPort_.store(chosen->second.kernel.apiPort);
            dnsApiPipe_ = chosen->second.kernel.apiPipe;
            dnsApiPipePid_ = chosen->second.kernel.pid;
            dnsApiSecret_ = chosen->second.kernel.apiSecret;
        }
    }
    if (dnsApiPort_.load() == 0 && dnsApiPipe_.empty()) {
        uint16_t port = static_cast<uint16_t>(rt->cfg.proxy.clashApi.port);
        if (port == 0) {
            bool needSecret = false;
            port = autoDetectClashApiPort(rt->cfg.proxy.clashApi.host,
                                          rt->cfg.proxy.clashApi.plainSecret(),
                                          static_cast<uint16_t>(rt->cfg.proxy.port),
                                          &needSecret);
        }
        dnsApiPort_.store(port);
        dnsApiSecret_ = rt->cfg.proxy.clashApi.plainSecret();
    }
    if (dnsApiPort_.load() == 0 && dnsApiPipe_.empty()) {
        if (errOut) *errOut = "no live DNS controller";
        return false;
    }

    std::string err;
    // PRIMARY: DoH (then TCP 53) through a live kernel's tunnel. This path
    // owns a short cooldown separate from the controller fallback.
    if (!dnsApiKernelId_.empty() && dnsSocksDownUntil_.load() <= now) {
        std::vector<uint32_t> tunnelIps;
        if (resolveViaSocksTcpDns(name, tunnelIps, deadline) &&
            !tunnelIps.empty()) {
            ips = std::move(tunnelIps);
            dnsSocksDownUntil_.store(0);
        } else {
            dnsSocksDownUntil_.store(now + 10000);
            err = "tunneled resolver unavailable";
        }
    }
    // SECONDARY: controller /dns/query, skipped for cores proven not to
    // implement it. Its cooldown never gates the primary tunnel path.
    if (ips.empty() && (dnsApiPort_.load() != 0 || !dnsApiPipe_.empty()) && nowMs() < deadline &&
        dnsControllerDownUntil_.load() <= now &&
        (dnsApiKernelId_.empty() ||
         dnsApiNoQuery_.count(dnsApiKernelId_) == 0)) {
        ClashApiClient client(rt->cfg.proxy.clashApi.host, dnsApiPort_.load(),
                              dnsApiSecret_, dnsApiPipe_, dnsApiPipePid_);
        const int64_t remaining = deadline - nowMs();
        const int timeoutMs = static_cast<int>(
            remaining < 2500 ? std::max<int64_t>(1, remaining) : 2500);
        if (client.resolveA(name, ips, &err, timeoutMs) && !ips.empty()) {
            dnsControllerDownUntil_.store(0);
        } else {
            if (!dnsApiKernelId_.empty() &&
                err.find("404") != std::string::npos) {
                dnsApiNoQuery_.insert(dnsApiKernelId_);
                log::wf("dns cleanup: kernel {} has no /dns/query; "
                        "using the SOCKS tunnel", dnsApiKernelId_);
            }
            if (err.find("HTTP 401") != std::string::npos ||
                err.find("HTTP 403") != std::string::npos) {
                portHealRequested_.store(true);
                if (nodeWakeEvent_) SetEvent(nodeWakeEvent_);
            }
            dnsControllerDownUntil_.store(now + 30000);
        }
    }
    if (ips.empty()) {
        std::lock_guard<std::mutex> lk(dnsCacheMu_);
        auto it = dnsCache_.find(name);
        if (it != dnsCache_.end() &&
            now - it->second.second <= dns::kStaleGraceMs &&
            !it->second.first.empty()) {
            ips = it->second.first;
            if (source) *source = "stale";
            if (errOut) *errOut = err;
            return true;
        }
        if (errOut) *errOut = err;
        return false;
    }
    {
        std::lock_guard<std::mutex> lk(dnsCacheMu_);
        if (dnsCache_.size() > 2048) dnsCache_.clear();
        dnsCache_[name] = {ips, now + dnsTtlMs_.load()};
    }
    if (source) *source = "resolved";
    if (errOut) *errOut = err;
    return true;
}

bool Engine::resolveTcpDnsQuery(const uint8_t* query, size_t queryLen,
                                std::vector<uint8_t>& response) {
    response.clear();
    const auto rt = runtime();
    if (!rt || !rt->cfg.routing.dnsCleanup || !enabled_.load()) return false;
    auto q = dns::parseQuery(query, queryLen);
    if (!q) return false;

    uint8_t out[1024];
    if (q->type == 28) {  // AAAA: successful empty answer forces IPv4.
        size_t n = dns::buildNoDataResponse(*q, out, sizeof(out));
        if (n == 0) return false;
        response.assign(out, out + n);
        log::df("dns cleanup {} AAAA -> NODATA (TCP)", q->name);
        return true;
    }
    if (q->type != 1) return false;  // preserve unsupported types exactly

    std::vector<uint32_t> ips;
    std::string source, err;
    if (!resolveCleanA(q->name, ips, &source, &err)) {
        log::df("dns cleanup resolve {} failed over TCP: {}", q->name, err);
        return false;
    }
    dns::AQuery aq{q->id, q->name};
    size_t n = dns::buildAResponse(aq, ips, out, sizeof(out));
    if (n == 0) return false;
    response.assign(out, out + n);
    if (source == "cached") {
        log::df("dns cleanup {} -> cached {} ip(s) (TCP)", q->name,
                ips.size());
    } else if (source == "stale") {
        log::wf("dns cleanup {} resolve failed ({}); serving stale cache "
                "({}) over TCP", q->name, err, ips.size());
    } else {
        log::ifmt("dns cleanup {} -> {} ip(s) (TCP)", q->name, ips.size());
    }
    return true;
}

namespace {
struct DnsPacketView {
    bool ipv6 = false;
    const uint8_t* src = nullptr;
    const uint8_t* dst = nullptr;
    const uint8_t* payload = nullptr;
    size_t payloadLen = 0;
    uint16_t srcPort = 0, dstPort = 0;
    size_t udpOffset = 0;
};
std::optional<DnsPacketView> dnsPacketView(const uint8_t* p, size_t len) {
    if (!p || len < 28) return std::nullopt;
    DnsPacketView v;
    const auto u16 = [&](size_t n) -> uint16_t {
        return static_cast<uint16_t>((p[n] << 8) | p[n + 1]);
    };
    if ((p[0] >> 4) == 4) {
        v.udpOffset = (p[0] & 15) * 4;
        if (v.udpOffset < 20 || v.udpOffset + 8 > len || p[9] != 17 ||
            (u16(6) & 0x3FFF) || u16(2) != len) return std::nullopt;
        v.src = p + 12; v.dst = p + 16;
    } else if ((p[0] >> 4) == 6) {
        // Extension/fragment headers pass through unchanged.
        if (len < 48 || p[6] != 17 || size_t(u16(4)) + 40 != len)
            return std::nullopt;
        v.ipv6 = true; v.udpOffset = 40;
        v.src = p + 8; v.dst = p + 24;
    } else return std::nullopt;
    const size_t off = v.udpOffset;
    const size_t udpLen = u16(off + 4);
    if (udpLen < 8 || off + udpLen != len) return std::nullopt;
    v.srcPort = u16(off); v.dstPort = u16(off + 2);
    v.payload = p + off + 8;
    v.payloadLen = udpLen - 8;
    return v;
}
std::string nativeDnsKey(const DnsPacketView& v, const PacketMeta& meta, uint16_t id) {
    const size_t n = v.ipv6 ? 16 : 4;
    std::string key(1, v.ipv6 ? '6' : '4');
    const uint8_t* local = meta.outbound ? v.src : v.dst;
    const uint8_t* remote = meta.outbound ? v.dst : v.src;
    key.append(reinterpret_cast<const char*>(local), n);
    key.append(reinterpret_cast<const char*>(remote), n);
    const uint16_t port = meta.outbound ? v.srcPort : v.dstPort;
    key.append(reinterpret_cast<const char*>(&port), sizeof(port));
    key.append(reinterpret_cast<const char*>(&id), sizeof(id));
    key.append(reinterpret_cast<const char*>(&meta.ifIdx), sizeof(meta.ifIdx));
    return key;
}
}

bool Engine::shouldCleanDns(uint8_t* buf, size_t len, const PacketMeta& meta) {
    const auto rt = runtime();
    if (!rt || !rt->cfg.routing.dnsCleanup || !enabled_.load() || stopping_.load())
        return false;
    if (rt->cfg.routing.dnsCleanupGlobal) return true;
    auto v = dnsPacketView(buf, len);
    if (!v) return false;
    uint32_t localIp = 0;
    if (!v->ipv6) {
        localIp = (uint32_t(v->src[0]) << 24) | (uint32_t(v->src[1]) << 16) |
                  (uint32_t(v->src[2]) << 8) | v->src[3];
    }
    auto owner = socketMap_.find(localIp, v->srcPort);
    if (!owner && localIp) owner = socketMap_.find(0, v->srcPort);
    std::wstring path;
    if (!v->ipv6 && owner && owner->protocol == 17 &&
        nowMs() - owner->lastSeenMs < rt->cfg.advanced.socketMapTtlS * 1000LL) {
        path = owner->path;
    } else if (tcpTable_) {
        std::optional<uint32_t> pid;
        if (v->ipv6) {
            std::array<uint8_t, 16> address{};
            std::memcpy(address.data(), v->src, 16);
            pid = tcpTable_->findUdpOwnerByLocal6(address, v->srcPort, meta.ifIdx);
        } else {
            pid = tcpTable_->findUdpOwnerByLocal(localIp, v->srcPort);
        }
        if (pid) path = socketMap_.resolvePathCached(*pid);
    }
    // Shared Windows DNS Client, unknown owners, explicit direct/block rules
    // and excluded kernels pass through. Never guess the original app PID.
    return !path.empty() && rt->matcher->decideTcpDns(path).action ==
                               RuleMatcher::Decision::Action::Proxy;
}

void Engine::handleDnsPacket(uint8_t* buf, size_t len, const PacketMeta& meta) {
    const auto v = dnsPacketView(buf, len);
    if (!v) { device_->sendLastDns(buf, len); return; }
    if (!meta.outbound) {
        // Do not wait for any resolver or application when forwarding replies.
        // Store only an association matched to a recently observed question.
        const auto answer = dns::parseAResponse(v->payload, v->payloadLen);
        if (answer && v->srcPort == 53) {
            const auto key = nativeDnsKey(*v, meta, answer->id);
            std::lock_guard<std::mutex> lk(dnsCacheMu_);
            const auto it = pendingNativeDns_.find(key);
            if (it != pendingNativeDns_.end() && it->second.expires >= nowMs() &&
                it->second.name == answer->name) {
                if (observedDns_.size() >= 2048) observedDns_.clear();
                observedDns_[answer->name] = {answer->ips, nowMs() + answer->ttl * 1000LL};
                pendingNativeDns_.erase(it);
            }
        }
        device_->sendLastDns(buf, len);
        return;
    }
    const auto q = dns::parseQuery(v->payload, v->payloadLen);
    if (!q || v->dstPort != 53 || (q->type != 1 && q->type != 28)) {
        device_->sendLastDns(buf, len); return;
    }
    if (q->type == 1) {
        // Register before forwarding, so a fast native reply can be matched.
        std::string lower = q->name;
        for (char& c : lower) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        std::lock_guard<std::mutex> lk(dnsCacheMu_);
        if (pendingNativeDns_.size() >= 2048) pendingNativeDns_.clear();
        pendingNativeDns_[nativeDnsKey(*v, meta, q->id)] = {lower, nowMs() + 30000};
    }
    if (!shouldCleanDns(buf, len, meta)) {
        device_->sendLastDns(buf, len); return;
    }
    if (q->type == 28) {
        uint8_t response[1024];
        const size_t size = dns::buildNoDataResponse(*q, response, sizeof(response));
        if (size) injectDnsReply(buf, len, meta, response, size);
        else device_->sendLastDns(buf, len);
        return;
    }
    {
        std::lock_guard<std::mutex> lk(dnsQueueMu_);
        if (!stopping_.load() && dnsQueue_.size() < 64) {
            dnsQueue_.push_back({std::vector<uint8_t>(buf, buf + len), meta, nowMs()});
            dnsQueueCv_.notify_one();
            return;
        }
    }
    // Bounded overload fallback: do not hold up unrelated applications.
    device_->sendLastDns(buf, len);
}

void Engine::dnsWorkerPump() {
    while (true) {
        DnsWork work;
        {
            std::unique_lock<std::mutex> lk(dnsQueueMu_);
            dnsQueueCv_.wait(lk, [&] { return stopping_.load() || !dnsQueue_.empty(); });
            if (dnsQueue_.empty()) {
                if (stopping_.load()) return;
                continue;
            }
            work = std::move(dnsQueue_.front());
            dnsQueue_.pop_front();
        }
        if (nowMs() - work.queuedAt > 2000) {
            WinDivertHelperCalcChecksums(work.packet.data(), static_cast<UINT>(work.packet.size()), nullptr, 0);
            device_->sendDnsPacket(work.packet.data(), work.packet.size(), work.meta);
        } else {
            processDnsQuery(std::move(work.packet), work.meta);
        }
    }
}

void Engine::processDnsQuery(std::vector<uint8_t> packet, const PacketMeta& meta) {
    const auto pass = [&] {
        WinDivertHelperCalcChecksums(packet.data(), static_cast<UINT>(packet.size()), nullptr, 0);
        device_->sendDnsPacket(packet.data(), packet.size(), meta);
    };
    if (!shouldCleanDns(packet.data(), packet.size(), meta)) { pass(); return; }
    const auto v = dnsPacketView(packet.data(), packet.size());
    const auto q = v ? dns::parseQuery(v->payload, v->payloadLen) : std::nullopt;
    if (!q) { pass(); return; }
    std::vector<uint32_t> ips;
    std::string source, err;
    if (!resolveCleanA(q->name, ips, &source, &err) ||
        !shouldCleanDns(packet.data(), packet.size(), meta)) {
        pass(); return;
    }
    uint8_t response[1024];
    const size_t size = dns::buildAResponse({q->id, q->name}, ips, response, sizeof(response));
    if (!size) { pass(); return; }
    injectDnsReply(packet.data(), packet.size(), meta, response, size);
    log::df("dns cleanup {} -> {} ip(s) ({}, rule-scoped={})", q->name,
            ips.size(), source, !runtime()->cfg.routing.dnsCleanupGlobal);
}

void Engine::injectDnsReply(const uint8_t* buf, size_t len, const PacketMeta& meta,
                            const uint8_t* dnsPayload, size_t dnsLen) {
    const auto v = dnsPacketView(buf, len);
    if (!v) return;
    const size_t header = v->ipv6 ? 40 : 20;
    std::vector<uint8_t> response(header + 8 + dnsLen, 0);
    std::memcpy(response.data(), buf, header);
    if (v->ipv6) {
        std::memcpy(response.data() + 8, v->dst, 16);
        std::memcpy(response.data() + 24, v->src, 16);
        const uint16_t payloadLen = htons(static_cast<uint16_t>(8 + dnsLen));
        std::memcpy(response.data() + 4, &payloadLen, 2);
    } else {
        response[0] = 0x45;
        std::memcpy(response.data() + 12, v->dst, 4);
        std::memcpy(response.data() + 16, v->src, 4);
        const uint16_t total = htons(static_cast<uint16_t>(response.size()));
        std::memcpy(response.data() + 2, &total, 2);
    }
    auto* udp = reinterpret_cast<PWINDIVERT_UDPHDR>(response.data() + header);
    udp->SrcPort = htons(v->dstPort);
    udp->DstPort = htons(v->srcPort);
    udp->Length = htons(static_cast<uint16_t>(8 + dnsLen));
    std::memcpy(response.data() + header + 8, dnsPayload, dnsLen);
    WinDivertHelperCalcChecksums(response.data(), static_cast<UINT>(response.size()), nullptr, 0);
    PacketMeta reply = meta;
    reply.outbound = false;
    reply.ipv6 = v->ipv6;
    device_->sendDnsPacket(response.data(), response.size(), reply);
}

void Engine::timerPump() {
    int64_t probeTick = 0;
    // No packets is normal. Only a receive thread that stops reporting idle
    // wait progress, blocked packet handling, or an exited pump warrants the
    // fail-safe. Degraded still intercepts traffic and needs this protection.
    PumpWatchdog watchdog(steadyMs());
    while (!stopping_.load()) {
        for (int i = 0; i < 10 && !stopping_.load(); ++i) Sleep(100);
        if (stopping_.load()) break;
        int64_t now = nowMs();
        auto rt = runtime();
        {
            const uint64_t iters = tcpPumpIters_.load();
            const uint64_t waits = device_->tcpReceiveWaitTicks();
            // Read exit before state: a pump exiting during normal stop must
            // not be combined with an older RUNNING snapshot.
            const bool exited = tcpPumpExited_.load();
            const auto state = state_.load();
            if (watchdog.stalled(steadyMs(), iters, waits,
                    state == EngineState::Running || state == EngineState::Degraded,
                    exited)) {
                log::ef("TCP pump stopped making progress — iterations={} idle_waits={} "
                        "exited={} state={}; fail-safe: engine exits "
                        "so network returns to the un-intercepted baseline. "
                        "Restart the engine when convenient.", iters, waits,
                        exited, engineStateName(state));
                fflush(nullptr);
                ExitProcess(1);
            }
        }
        // The health monitors' real-CONNECT target is AUTO-DETECTED: the
        // delay_url host (user-configurable, no hard-coded IPs) resolved
        // through the tunnel. Resolved lazily here (the timer thread is
        // allowed a one-off short network call) and reused by every
        // rebuild; the probe degrades to greeting-only until it resolves.
        if (rt && ++probeTick % 60 == 0) {
            maybeResolveHealthProbeDst(rt->cfg);
        }

        // NAT expiry / finished-flow cleanup.
        NatSweepConfig sc;
        sc.synTimeoutMs = rt->cfg.advanced.synWaitS * 1000;
        sc.idleTimeoutMs = rt->cfg.advanced.natIdleTimeoutS * 1000;
        for (const auto& e : nat_.sweep(now, sc)) {
            stats_.connClosed(e->ruleId);
            stats_.get(e->ruleId)->bytesUp.fetch_add(e->bytesUp.load());
            stats_.get(e->ruleId)->bytesDown.fetch_add(e->bytesDown.load());
        }

        socketMap_.sweep(now, rt->cfg.advanced.socketMapTtlS * 1000);

        // Degraded drain: after 10s of proxy-down, tear down remaining
        // redirected flows so applications reconnect (direct under
        // fail-open).
        if (state_.load() == EngineState::Degraded && !degradedDrained_.load() &&
            degradedSinceMs_.load() != 0 &&
            now - degradedSinceMs_.load() > 10000) {
            degradedDrained_.store(true);
            for (const auto& e : nat_.snapshot()) {
                sendTeardownRst(e);
                nat_.remove(e->appIp, e->appPort);
                stats_.connClosed(e->ruleId);
            }
            log::w("proxy still unreachable: remaining redirected flows torn down (fail-open)");
        }

        // Skip the per-second STATS build/push entirely when nobody is
        // listening (GUI process closed): parsing it would be pure waste.
        if (!events_.wantsStats || events_.wantsStats()) pushStats();
    }
}

// ---------------------------------------------------------------------------
// Packet handling
// ---------------------------------------------------------------------------

std::optional<Engine::OwnerInfo> Engine::resolveOwner(uint32_t srcIp, uint16_t srcPort,
                                                      uint32_t dstIp, uint16_t dstPort) {
    // Defense line 1: SOCKET-layer event arrived before the SYN.
    auto m = socketMap_.find(srcIp, srcPort);
    // Tolerate a zero local address in socket events (IPv4-mapped layout
    // differences): fall back to a port-only key match.
    if (!m && srcIp != 0) m = socketMap_.find(0, srcPort);
    if (m && m->protocol == IPPROTO_TCP && !m->path.empty() &&
        (m->remoteIp == 0 || (m->remoteIp == dstIp && m->remotePort == dstPort))) {
        return OwnerInfo{m->pid, m->path};
    }
    // Defense line 2: the TCB exists in SYN_SENT with the true owner PID.
    auto pid = tcpTable_->findOwnerByLocal(srcIp, srcPort);
    if (pid && *pid != 0) {
        std::wstring path = socketMap_.resolvePathCached(*pid);
        if (!path.empty()) {
            socketMap_.insertResolved(srcIp, srcPort, dstIp, dstPort, *pid, path,
                                      IPPROTO_TCP);
            return OwnerInfo{*pid, path};
        }
    }
    // Defense line 3: unresolved -> caller lets the SYN through (direct).
    return std::nullopt;
}

void Engine::handleTcpPacket(uint8_t* buf, size_t len, const PacketMeta& meta) {
    pkt::TcpPacket p;
    if (!pkt::parseTcpPacket(buf, len, p)) {
        // Not an IPv4/TCP packet we can reason about: pass through untouched.
        device_->sendLastTcp(buf, len, false);
        return;
    }
    // Data/ACK packets can arrive faster than the rotating log can retain
    // critical flow outcomes. Keep control transitions, while byte counters
    // cover ordinary traffic without synchronously logging every packet.
    if (p.syn || p.fin || p.rst) {
        log::df("pkt {}:{} -> {}:{} syn={} ack={} fin={} rst={} len={} lb={} if={}",
                formatIpv4(p.srcIp), p.srcPort, formatIpv4(p.dstIp), p.dstPort, p.syn ? 1 : 0,
                p.ackFlag ? 1 : 0, p.fin ? 1 : 0, p.rst ? 1 : 0, p.payloadLen,
                meta.loopback ? 1 : 0, meta.ifIdx);
    }
    int64_t now = nowMs();

    // Defensive 127/8 exclusion: the kernel filter only excludes the exact
    // address 127.0.0.1 (WinDivert 2.2.2 has no subnet syntax), so any other
    // loopback destination (rare) is passed through untouched here.
    if (isLoopbackIpv4(p.dstIp)) {
        device_->sendLastTcp(buf, len, false);
        return;
    }

    // ---- reverse path: relay listener -> application -------------------------
    // Forward NAT targets the originating flow's own local address. Its
    // native loopback reply therefore has equal source/destination IPs.
    // Keep the measured 127.0.0.1 reply variant too, but never identify an
    // unrelated sender as the relay just because it uses the same port.
    if (p.srcPort == relayPort_ &&
        (p.srcIp == p.dstIp || p.srcIp == 0x7F000001)) {
        auto entry = nat_.findByRev(p.dstIp, p.dstPort);
        if (entry) {
            entry->tLastActivityMs.store(now);
            entry->nextSeqRelayToApp.store(pkt::nextSeq(p));
            entry->seqValid.store(true);
            if (p.rst) entry->rstSeen.store(true);
            if (p.fin) {
                entry->relayFin.store(true);
                entry->state.store(static_cast<int32_t>(NatState::Closing));
            }
            pkt::rewriteSrc(p, entry->origDstIp, entry->origDstPort);
            pkt::recalcChecksums(buf, len);
            device_->sendLastTcp(buf, len, /*forceLoopback=*/true);
        } else {
            device_->sendLastTcp(buf, len, false);
        }
        return;
    }

    // ---- forward path: already-redirected flow -------------------------------
    auto entry = nat_.findByFwd(p.srcIp, p.srcPort, p.dstIp, p.dstPort);
    if (entry) {
        entry->tLastActivityMs.store(now);
        if (p.rst) entry->rstSeen.store(true);
        if (p.fin) {
            entry->appFin.store(true);
            entry->state.store(static_cast<int32_t>(NatState::Closing));
        } else if (!p.syn &&
                   static_cast<NatState>(entry->state.load()) == NatState::SynSent) {
            entry->state.store(static_cast<int32_t>(NatState::Established));
        }
        pkt::rewriteDst(p, entry->appIp, relayPort_);
        pkt::recalcChecksums(buf, len);
        device_->sendLastTcp(buf, len, /*forceLoopback=*/true);
        return;
    }

    // ---- new flow -------------------------------------------------------------
    if (p.syn && !p.ackFlag) {
        auto rt = runtime();
        auto owner = resolveOwner(p.srcIp, p.srcPort, p.dstIp, p.dstPort);
        if (!owner) {
            unresolvedCount_.fetch_add(1);
            log::df("unresolved SYN {}:{} -> {}:{} passed through", formatIpv4(p.srcIp),
                    p.srcPort, formatIpv4(p.dstIp), p.dstPort);
            device_->sendLastTcp(buf, len, false);
            return;
        }
        auto decision = rt->matcher->decideTcp(owner->path, p.dstIp, p.dstPort);
        bool dnsBridge = false;
        // TCP DNS was previously classified by the ordinary private-address
        // bypass, so rule apps could send every query straight to the LAN
        // resolver while UDP DNS was cleaned. Route proxy-rule TCP/53 into
        // the local framed-DNS bridge instead. Explicit direct/block rules
        // and network-critical multicast/broadcast keep their old semantics.
        if (rt->cfg.routing.dnsCleanup && p.dstPort == 53 &&
            !isNeverProxyIpv4(p.dstIp)) {
            auto dnsDecision = rt->matcher->decideTcpDns(owner->path);
            if (dnsDecision.action == RuleMatcher::Decision::Action::Proxy) {
                decision = std::move(dnsDecision);
                dnsBridge = true;
            }
        }
        if (decision.action == RuleMatcher::Decision::Action::Block) {
            // Explicit user rule: blackhole the SYN (no NAT entry, no
            // reinjection — same pattern as fail-closed and the IPv6 blocker).
            stats_.connBlocked(decision.ruleId);
            log::df("blocked SYN {}:{} -> {}:{} rule={} owner={}",
                    formatIpv4(p.srcIp), p.srcPort, formatIpv4(p.dstIp), p.dstPort,
                    decision.ruleId, wideToUtf8(baseName(owner->path)));
            return;
        }
        if (decision.action == RuleMatcher::Decision::Action::Direct) {
            log::df("syn-direct {}:{} -> {}:{} owner={}", formatIpv4(p.srcIp),
                    p.srcPort, formatIpv4(p.dstIp), p.dstPort, wideToUtf8(owner->path));
        }
        if (decision.action == RuleMatcher::Decision::Action::Proxy) {
            // Rules without an explicit outlet binding follow the activated
            // outlet (routing.autoOutletId); explicit bindings stay as-is.
            std::string outletId = resolveRuleOutlet(decision.outletId);
            // The DNS bridge is local and has its own exact-destination
            // fail-open fallback; outlet health must not bypass cleanup.
            NewFlowDecision d =
                dnsBridge
                    ? (enabled_.load() ? NewFlowDecision::Proxy
                                       : NewFlowDecision::Direct)
                    : decideNewFlow(enabled_.load(), outletHealthy(outletId),
                                    rt->cfg.failMode);
            if (d == NewFlowDecision::Drop) {
                log::df("fail-closed: dropped SYN {}:{} -> {}:{} ({})", formatIpv4(p.srcIp),
                        p.srcPort, formatIpv4(p.dstIp), p.dstPort,
                        wideToUtf8(baseName(owner->path)));
                return;  // blackhole
            }
            if (d == NewFlowDecision::Direct) {
                device_->sendLastTcp(buf, len, false);
                return;
            }
            if (relay_.activeSessions() >= rt->cfg.advanced.maxSessions) {
                log::wf("session cap reached ({}); new connection goes direct",
                        rt->cfg.advanced.maxSessions);
                device_->sendLastTcp(buf, len, false);
                return;
            }
            nat_.create(p.srcIp, p.srcPort, p.dstIp, p.dstPort, decision.ruleId,
                        outletId, owner->pid, now, dnsBridge);
            stats_.connOpened(decision.ruleId, owner->pid);
            if (dnsBridge) {
                log::df("TCP DNS bridge {}:{} -> {}:{} rule={}",
                        wideToUtf8(owner->path), p.srcPort,
                        formatIpv4(p.dstIp), p.dstPort, decision.ruleId);
            } else {
                log::ifmt("proxy {}:{} -> {}:{} rule={}",
                          wideToUtf8(owner->path), p.srcPort,
                          formatIpv4(p.dstIp), p.dstPort, decision.ruleId);
            }
            // The outbound SYN already contains the local address chosen
            // by Windows for this connection. The wildcard relay listener
            // accepts it through the machine's native route to itself.
            // Derive this per flow: a startup gateway/IP snapshot becomes
            // stale after DHCP/Wi-Fi changes and cannot cover multiple NICs.
            log::df("relay route {}:{} -> {}:{}", formatIpv4(p.srcIp),
                    p.srcPort, formatIpv4(p.srcIp), relayPort_);
            pkt::rewriteDst(p, p.srcIp, relayPort_);
            pkt::recalcChecksums(buf, len);
            device_->sendLastTcp(buf, len, /*forceLoopback=*/true);
            return;
        }
        device_->sendLastTcp(buf, len, false);
        return;
    }

    // ---- everything else: pass through (we MUST re-inject what we captured) --
    device_->sendLastTcp(buf, len, false);
}

void Engine::handleUdpPacket(uint8_t* buf, size_t len) {
    PWINDIVERT_IPHDR ip = nullptr;
    PWINDIVERT_UDPHDR udp = nullptr;
    uint32_t srcIp = 0, dstIp = 0;
    uint16_t srcPort = 0, dstPort = 0;
    if (!pkt::parseUdpPacket(buf, len, ip, udp, srcIp, srcPort, dstIp, dstPort)) {
        device_->sendLastUdp(buf, len);
        return;
    }
    if (isLoopbackIpv4(dstIp)) {
        device_->sendLastUdp(buf, len);
        return;
    }
    // Network-critical traffic is never proxied or blocked (fail-open
    // defense even if the divert filter were ever relaxed): multicast/
    // broadcast destinations and DHCP (67/68) always pass through.
    if (isNeverProxyIpv4(dstIp) || srcPort == 67 || srcPort == 68 ||
        dstPort == 67 || dstPort == 68) {
        device_->sendLastUdp(buf, len);
        return;
    }
    auto rt = runtime();
    auto m = socketMap_.find(srcIp, srcPort);
    if (m && m->protocol == IPPROTO_UDP && !m->path.empty() &&
        rt->matcher->shouldBlockUdp(m->path, dstPort) && !isLoopbackIpv4(dstIp)) {
        log::df("blocked UDP {}:{} -> {}:{} ({} QUIC/UDP leak prevention)",
                formatIpv4(srcIp), srcPort, formatIpv4(dstIp), dstPort,
                wideToUtf8(baseName(m->path)));
        return;  // drop: pushes apps back onto TCP (which we proxy)
    }
    device_->sendLastUdp(buf, len);
}

// ---------------------------------------------------------------------------
// Health / status
// ---------------------------------------------------------------------------

void Engine::onProxyHealth(const std::string& outletId, bool healthy,
                           const std::string& detail) {
    if (stopping_.load()) return;
    bool triggerTunnelRecovery = false;
    auto rt = runtime();
    if (rt) {
        const std::string activeOutlet =
            rt->cfg.routing.autoOutletId.empty()
                ? std::string(kDefaultOutletId)
                : rt->cfg.routing.autoOutletId;
        const bool tunnelDown =
            !healthy && detail.rfind("tunnel CONNECT failed:", 0) == 0;
        std::lock_guard<std::mutex> lk(tunnelRecoveryMu_);
        if (!rt->cfg.nodeMonitor.enabled) {
            // Re-arm if automatic switching is enabled later. The fresh
            // monitor built by RELOAD will then make the dead state actionable.
            tunnelRecoveryOutlet_.clear();
            tunnelRecoveryWasHealthy_ = true;
        } else if (outletId == activeOutlet) {
            if (tunnelRecoveryOutlet_ != activeOutlet) {
                tunnelRecoveryOutlet_ = activeOutlet;
                tunnelRecoveryWasHealthy_ = true;
            }
            if (healthy) {
                tunnelRecoveryWasHealthy_ = true;
            } else if (tunnelDown && tunnelRecoveryWasHealthy_) {
                tunnelRecoveryWasHealthy_ = false;
                triggerTunnelRecovery = true;
            }
        }
    }
    if (outletId != kDefaultOutletId) {
        // Secondary outlets only feed per-rule fail-open decisions; the
        // engine-level RUNNING/DEGRADED state follows the default outlet.
        log::ifmt("outlet {} {} ({})", outletId, healthy ? "up" : "DOWN", detail);
    } else {
        if (healthy) {
            degradedSinceMs_.store(0);
            degradedDrained_.store(false);
            if (state_.load() != EngineState::Running) {
                state_.store(EngineState::Running);
                log::ifmt("proxy reachable again ({}); interception resumed", detail);
            }
        } else {
            if (state_.load() == EngineState::Running) {
                state_.store(EngineState::Degraded);
                degradedSinceMs_.store(nowMs());
                degradedDrained_.store(false);
                log::wf("proxy unreachable ({}); new connections go direct (fail-open)", detail);
            }
        }
    }
    pushStatus();
    if (triggerTunnelRecovery) {
        log::wf("outlet {} tunnel became unhealthy; requesting immediate "
                "node re-selection", outletId);
        requestNodeSwitchRound(outletId, false);
    }
}

std::string Engine::buildStatusJson() const {
    json::Value j = json::Value::makeObject();
    j.set("type", "STATUS");
    j.set("state", engineStateName(state_.load()));
    j.set("enabled", enabled_.load());
    j.set("effective_proxy", effectiveProxyJson());
    j.set("proxy_reachable", outletHealthy(kDefaultOutletId));
    {
        std::lock_guard<std::mutex> lk(const_cast<Engine*>(this)->healthMu_);
        auto it = healthMonitors_.find(kDefaultOutletId);
        j.set("detail",
              "latency " + std::to_string(it == healthMonitors_.end()
                                              ? -1
                                              : it->second->lastLatencyMs()) +
                  "ms");
    }
    j.set("nat_entries", nat_.size());
    j.set("sessions", relay_.activeSessions());
    j.set("unresolved", unresolvedCount_.load());
    auto rt = runtime();
    j.set("auto_switch", rt ? rt->cfg.nodeMonitor.enabled : true);
    j.set("outlets", nodeStatusJson());
    j.set("kernels", kernelsJson());
    {
        std::lock_guard<std::mutex> lk(const_cast<Engine*>(this)->subRefreshMu_);
        j.set("sub_refresh", subRefreshMsg_);
    }
    return j.dump();
}

// Trim to at most `cap` bytes WITHOUT splitting a UTF-8 sequence (proc
// paths/hostnames may contain non-ASCII).
std::string utf8Trim(const std::string& s, size_t cap) {
    if (s.size() <= cap) return s;
    size_t n = cap;
    while (n > 0 && (static_cast<uint8_t>(s[n]) & 0xC0) == 0x80) --n;
    return s.substr(0, n);
}

json::Value Engine::connectionsJson(int64_t nowMs) const {
    // Most-recent-first, capped: the whole STATS line must stay under the
    // pipe's 64 KiB limit, so the array is trimmed defensively below.
    constexpr size_t kMaxConns = 64;
    constexpr size_t kMaxBytes = 40 * 1024;

    auto entries = nat_.snapshot();
    std::sort(entries.begin(), entries.end(),
              [](const auto& a, const auto& b) {
                  return a->tLastActivityMs.load() > b->tLastActivityMs.load();
              });
    if (entries.size() > kMaxConns) entries.resize(kMaxConns);

    auto build = [&](size_t n) {
        json::Value arr = json::Value::makeArray();
        for (size_t i = 0; i < n; ++i) {
            const auto& e = entries[i];
            json::Value o = json::Value::makeObject();
            // resolvePathCached mutates its pid->path cache; same const_cast
            // idiom as buildStatusJson's healthMu_ access below.
            auto* self = const_cast<Engine*>(this);
            o.set("proc", utf8Trim(wideToUtf8(self->socketMap_.resolvePathCached(e->pid)), 96));
            o.set("pid", e->pid);
            o.set("app_ip", formatIpv4(e->appIp));
            o.set("app_port", e->appPort);
            o.set("dst_ip", formatIpv4(e->origDstIp));
            o.set("dst_port", e->origDstPort);
            std::string stateName;
            switch (static_cast<NatState>(e->state.load())) {
                case NatState::SynSent: stateName = "syn"; break;
                case NatState::Established: stateName = "established"; break;
                case NatState::Closing: stateName = "closing"; break;
            }
            o.set("state", stateName);
            o.set("bytes_up", e->bytesUp.load());
            o.set("bytes_down", e->bytesDown.load());
            o.set("duration_ms", nowMs - e->tCreateMs.load());
            o.set("rule_id", e->ruleId);
            o.set("outlet_id", e->outletId);
            std::string host;
            {
                std::lock_guard<std::mutex> lk(self->dnsCacheMu_);
                auto h = dns::reverseLookup(self->dnsCache_, e->origDstIp, nowMs);
                if (h) host = utf8Trim(*h, 96);
            }
            o.set("host", host);
            arr.append(std::move(o));
        }
        return arr;
    };

    size_t n = entries.size();
    while (n > 1 && build(n).dump().size() > kMaxBytes) n /= 2;
    return build(n);
}

std::string Engine::buildStatsJson() const {
    json::Value j = json::Value::makeObject();
    j.set("type", "STATS");
    j.set("effective_proxy", effectiveProxyJson());
    j.set("nat_entries", nat_.size());
    j.set("sessions", relay_.activeSessions());
    j.set("rules", stats_.rulesJson());
    // Node status goes along with the 1s stats tick so the GUI's per-outlet
    // rows appear immediately (STATUS only fires every monitor interval).
    j.set("outlets", nodeStatusJson());
    j.set("kernels", kernelsJson());
    j.set("connections", connectionsJson(nowMs()));
    return j.dump();
}

}  // namespace aps
