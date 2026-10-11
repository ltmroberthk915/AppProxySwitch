#include "aps/config.hpp"

#include <windows.h>
#include <shlobj.h>

#include <iterator>

#include "aps/dpapi.hpp"
#include "aps/path_util.hpp"
#include "aps/string_util.hpp"

namespace aps {

namespace {

// Typed field readers: a wrong JSON type is a hard error (strict schema).
bool getStr(const json::Value& obj, const char* key, std::string& out, std::string* error) {
    const json::Value* v = obj.find(key);
    if (!v) return true;  // absent -> keep default
    if (!v->isString()) {
        if (error) *error = std::string("field '") + key + "' must be a string";
        return false;
    }
    out = v->asString();
    return true;
}

bool getInt(const json::Value& obj, const char* key, int& out, int lo, int hi,
            std::string* error) {
    const json::Value* v = obj.find(key);
    if (!v) return true;
    if (!v->isNumber()) {
        if (error) *error = std::string("field '") + key + "' must be a number";
        return false;
    }
    int64_t n = v->asInt();
    if (n < lo || n > hi) {
        if (error) *error = std::string("field '") + key + "' out of range";
        return false;
    }
    out = static_cast<int>(n);
    return true;
}

bool getBool(const json::Value& obj, const char* key, bool& out, std::string* error) {
    const json::Value* v = obj.find(key);
    if (!v) return true;
    if (!v->isBoolean()) {
        if (error) *error = std::string("field '") + key + "' must be a boolean";
        return false;
    }
    out = v->asBool();
    return true;
}

bool getStrArray(const json::Value& obj, const char* key, std::vector<std::string>& out,
                 std::string* error) {
    const json::Value* v = obj.find(key);
    if (!v) return true;
    if (!v->isArray()) {
        if (error) *error = std::string("field '") + key + "' must be an array";
        return false;
    }
    std::vector<std::string> res;
    for (size_t i = 0; i < v->size(); ++i) {
        if (!v->at(i).isString()) {
            if (error) *error = std::string("field '") + key + "' must contain only strings";
            return false;
        }
        res.push_back(v->at(i).asString());
    }
    out = std::move(res);
    return true;
}

void noteUnknownKeys(const json::Value& obj, const char* ctx,
                     const char* const* known, size_t knownCount,
                     std::vector<std::string>* warnings) {
    for (const auto& kv : obj.object()) {
        bool found = false;
        for (size_t i = 0; i < knownCount; ++i) {
            if (kv.first == known[i]) { found = true; break; }
        }
        if (!found && warnings) {
            warnings->push_back(std::string("unknown key ignored: ") + ctx + "." + kv.first);
        }
    }
}

}  // namespace

Config Config::makeDefault() {
    return Config{};
}

void Config::setPlainPassword(const std::string& plain) {
    proxy.passwordEnc = crypto::protectToBase64(plain);
}

std::string Config::plainPassword() const {
    if (proxy.passwordEnc.empty()) return {};
    bool ok = false;
    std::string plain = crypto::unprotectFromBase64(proxy.passwordEnc, &ok);
    return ok ? plain : std::string();
}

json::Value Config::toJson() const {
    json::Value root = json::Value::makeObject();
    root.set("version", version);

    json::Value p = json::Value::makeObject();
    p.set("host", proxy.host);
    p.set("port", proxy.port);
    p.set("protocol", "socks5");
    p.set("username", proxy.username);
    p.set("password_enc", proxy.passwordEnc);
    p.set("connect_timeout_ms", proxy.connectTimeoutMs);
    p.set("io_timeout_ms", proxy.ioTimeoutMs);
    p.set("health_check_interval_s", proxy.healthIntervalS);
    p.set("health_check_timeout_ms", proxy.healthTimeoutMs);
    p.set("health_fail_threshold", proxy.healthFailThreshold);
    json::Value papi = json::Value::makeObject();
    papi.set("host", proxy.clashApi.host);
    papi.set("port", proxy.clashApi.port);
    papi.set("secret_enc", proxy.clashApi.secretEnc);
    p.set("clash_api", std::move(papi));
    root.set("proxy", std::move(p));

    json::Value r = json::Value::makeObject();
    r.set("listen", "127.0.0.1");
    r.set("port", relay.port);
    root.set("relay", std::move(r));

    json::Value rulesJ = json::Value::makeArray();
    for (const auto& rule : rules) {
        json::Value j = json::Value::makeObject();
        j.set("id", rule.id);
        j.set("name", rule.name);
        j.set("path", rule.path);
        j.set("enabled", rule.enabled);
        j.set("include_children", rule.includeChildren);
        j.set("outlet", rule.outlet);
        j.set("action", rule.action);
        rulesJ.append(std::move(j));
    }
    root.set("rules", std::move(rulesJ));

    json::Value outletsJ = json::Value::makeArray();
    for (const auto& o : outlets) {
        json::Value j = json::Value::makeObject();
        j.set("id", o.id);
        j.set("name", o.name);
        j.set("host", o.host);
        j.set("port", o.port);
        j.set("username", o.username);
        j.set("password_enc", o.passwordEnc);
        j.set("enabled", o.enabled);
        json::Value api = json::Value::makeObject();
        api.set("host", o.clashApi.host);
        api.set("port", o.clashApi.port);
        api.set("secret_enc", o.clashApi.secretEnc);
        j.set("clash_api", std::move(api));
        outletsJ.append(std::move(j));
    }
    root.set("outlets", std::move(outletsJ));

    json::Value nm = json::Value::makeObject();
    nm.set("enabled", nodeMonitor.enabled);
    nm.set("interval_s", nodeMonitor.intervalS);
    nm.set("fail_threshold", nodeMonitor.failThreshold);
    nm.set("delay_url", nodeMonitor.delayUrl);
    nm.set("delay_timeout_ms", nodeMonitor.delayTimeoutMs);
    nm.set("max_latency_ms", nodeMonitor.maxLatencyMs);
    json::Value regs = json::Value::makeArray();
    for (const auto& r : nodeMonitor.regions) regs.append(r);
    nm.set("regions", std::move(regs));
    json::Value cls = json::Value::makeArray();
    for (const auto& c : nodeMonitor.nodeClasses) cls.append(c);
    nm.set("node_classes", std::move(cls));
    nm.set("min_switch_interval_s", nodeMonitor.minSwitchIntervalS);
    nm.set("real_fail_threshold", nodeMonitor.realFailThreshold);
    nm.set("real_fail_ratio_pct", nodeMonitor.realFailRatioPct);
    nm.set("real_fail_window_s", nodeMonitor.realFailWindowS);
    nm.set("bad_node_cooldown_s", nodeMonitor.badNodeCooldownS);
    root.set("node_monitor", std::move(nm));

    json::Value sub = json::Value::makeObject();
    sub.set("auto_refresh", subscription.autoRefresh);
    sub.set("interval_hours", subscription.intervalHours);
    sub.set("start_delay_min", subscription.startDelayMin);
    root.set("subscription", std::move(sub));

    json::Value ex = json::Value::makeObject();
    ex.set("builtin", exclusions.builtin);
    json::Value bn = json::Value::makeArray();
    for (const auto& n : exclusions.builtinNames) bn.append(n);
    ex.set("builtin_names", std::move(bn));
    json::Value xp = json::Value::makeArray();
    for (const auto& n : exclusions.extraPaths) xp.append(n);
    ex.set("extra_paths", std::move(xp));
    json::Value xn = json::Value::makeArray();
    for (const auto& n : exclusions.extraNames) xn.append(n);
    ex.set("extra_names", std::move(xn));
    root.set("exclusions", std::move(ex));

    json::Value ro = json::Value::makeObject();
    ro.set("bypass_loopback", routing.bypassLoopback);
    ro.set("bypass_private", routing.bypassPrivate);
    ro.set("block_udp_for_rules", routing.blockUdpForRules);
    ro.set("block_ipv6_for_rules", routing.blockIpv6ForRules);
    ro.set("dns_cleanup", routing.dnsCleanup);
    ro.set("dns_cleanup_global", routing.dnsCleanupGlobal);
    ro.set("ipv6_enabled", routing.ipv6Enabled);
    ro.set("auto_outlet_id", routing.autoOutletId);
    ro.set("cover_app_dir_always", routing.coverAppDirAlways);
    json::Value dnsArr = json::Value::makeArray();
    for (const auto& s : routing.dnsServers) dnsArr.append(s);
    ro.set("dns_servers", std::move(dnsArr));
    root.set("routing", std::move(ro));

    root.set("fail_mode", failMode);

    json::Value lg = json::Value::makeObject();
    lg.set("level", logging.level);
    lg.set("max_file_mb", logging.maxFileMb);
    lg.set("max_files", logging.maxFiles);
    root.set("logging", std::move(lg));

    json::Value uiJ = json::Value::makeObject();
    uiJ.set("autostart", ui.autostart);
    uiJ.set("start_minimized", ui.startMinimized);
    uiJ.set("confirm_stop", ui.confirmStop);
    root.set("ui", std::move(uiJ));

    json::Value adv = json::Value::makeObject();
    adv.set("nat_idle_timeout_s", advanced.natIdleTimeoutS);
    adv.set("syn_wait_s", advanced.synWaitS);
    adv.set("max_sessions", advanced.maxSessions);
    adv.set("socket_map_ttl_s", advanced.socketMapTtlS);
    root.set("advanced", std::move(adv));

    return root;
}

bool Config::fromJson(const json::Value& v, Config& out, std::string* error,
                      std::vector<std::string>* warnings) {
    if (!v.isObject()) {
        if (error) *error = "root must be an object";
        return false;
    }
    static const char* kRoot[] = {"version", "proxy", "relay", "rules", "outlets",
                                  "exclusions", "routing", "fail_mode", "node_monitor",
                                  "logging", "ui", "advanced", "subscription"};
    noteUnknownKeys(v, "", kRoot, std::size(kRoot), warnings);

    if (!getInt(v, "version", out.version, 1, 0xFFFF, error)) return false;
    if (out.version > kConfigVersion) {
        if (error) *error = "config version is newer than this build supports";
        return false;
    }

    const json::Value* p = v.find("proxy");
    if (p) {
        if (!p->isObject()) { if (error) *error = "'proxy' must be an object"; return false; }
        static const char* kP[] = {"host", "port", "protocol", "username", "password_enc",
                                   "connect_timeout_ms", "io_timeout_ms",
                                   "health_check_interval_s", "health_check_timeout_ms",
                                   "health_fail_threshold", "clash_api"};
        noteUnknownKeys(*p, "proxy", kP, std::size(kP), warnings);
        std::string proto;
        if (!getStr(*p, "protocol", proto, error)) return false;
        if (!proto.empty() && proto != "socks5") {
            if (error) *error = "only protocol 'socks5' is supported (Clash mixed port is compatible)";
            return false;
        }
        if (!getStr(*p, "host", out.proxy.host, error)) return false;
        if (!getInt(*p, "port", out.proxy.port, 1, 65535, error)) return false;
        if (!getStr(*p, "username", out.proxy.username, error)) return false;
        if (!getStr(*p, "password_enc", out.proxy.passwordEnc, error)) return false;
        if (!getInt(*p, "connect_timeout_ms", out.proxy.connectTimeoutMs, 100, 600000, error)) return false;
        if (!getInt(*p, "io_timeout_ms", out.proxy.ioTimeoutMs, 100, 600000, error)) return false;
        if (!getInt(*p, "health_check_interval_s", out.proxy.healthIntervalS, 1, 3600, error)) return false;
        if (!getInt(*p, "health_check_timeout_ms", out.proxy.healthTimeoutMs, 100, 60000, error)) return false;
        if (!getInt(*p, "health_fail_threshold", out.proxy.healthFailThreshold, 1, 10, error)) return false;
        const json::Value* papi = p->find("clash_api");
        if (papi) {
            if (!papi->isObject()) { if (error) *error = "proxy.clash_api must be an object"; return false; }
            static const char* kPA[] = {"host", "port", "secret_enc"};
            noteUnknownKeys(*papi, "proxy.clash_api", kPA, std::size(kPA), warnings);
            if (!getStr(*papi, "host", out.proxy.clashApi.host, error)) return false;
            if (!getInt(*papi, "port", out.proxy.clashApi.port, 0, 65535, error)) return false;
            if (!getStr(*papi, "secret_enc", out.proxy.clashApi.secretEnc, error)) return false;
        }
    }

    const json::Value* r = v.find("relay");
    if (r) {
        if (!r->isObject()) { if (error) *error = "'relay' must be an object"; return false; }
        static const char* kR[] = {"listen", "port"};
        noteUnknownKeys(*r, "relay", kR, std::size(kR), warnings);
        std::string listen;
        if (!getStr(*r, "listen", listen, error)) return false;
        if (!listen.empty() && listen != "127.0.0.1") {
            if (error) *error = "relay.listen must be 127.0.0.1";
            return false;
        }
        if (!getInt(*r, "port", out.relay.port, 1024, 65535, error)) return false;
    }

    const json::Value* rules = v.find("rules");
    if (rules) {
        if (!rules->isArray()) { if (error) *error = "'rules' must be an array"; return false; }
        std::vector<Rule> parsed;
        for (size_t i = 0; i < rules->size(); ++i) {
            const json::Value& j = rules->at(i);
            if (!j.isObject()) { if (error) *error = "rules[] entries must be objects"; return false; }
            static const char* kRule[] = {"id", "name", "path", "enabled",
                                          "include_children", "outlet", "action"};
            noteUnknownKeys(j, "rules[]", kRule, std::size(kRule), warnings);
            Rule rule;
            if (!getStr(j, "id", rule.id, error)) return false;
            if (!getStr(j, "name", rule.name, error)) return false;
            if (!getStr(j, "path", rule.path, error)) return false;
            if (!getBool(j, "enabled", rule.enabled, error)) return false;
            if (!getBool(j, "include_children", rule.includeChildren, error)) return false;
            if (!getStr(j, "outlet", rule.outlet, error)) return false;
            if (!getStr(j, "action", rule.action, error)) return false;
            if (rule.action.empty()) rule.action = "proxy";  // absent/empty = legacy
            if (rule.id.empty()) rule.id = newId();
            if (rule.name.empty()) rule.name = rule.path;
            parsed.push_back(std::move(rule));
        }
        out.rules = std::move(parsed);
    }

    const json::Value* outlets = v.find("outlets");
    if (outlets) {
        if (!outlets->isArray()) { if (error) *error = "'outlets' must be an array"; return false; }
        std::vector<Outlet> parsed;
        for (size_t i = 0; i < outlets->size(); ++i) {
            const json::Value& j = outlets->at(i);
            if (!j.isObject()) { if (error) *error = "outlets[] entries must be objects"; return false; }
            static const char* kO[] = {"id", "name", "host", "port", "username",
                                       "password_enc", "enabled", "clash_api"};
            noteUnknownKeys(j, "outlets[]", kO, std::size(kO), warnings);
            Outlet o;
            if (!getStr(j, "id", o.id, error)) return false;
            if (!getStr(j, "name", o.name, error)) return false;
            if (!getStr(j, "host", o.host, error)) return false;
            if (!getInt(j, "port", o.port, 1, 65535, error)) return false;
            if (!getStr(j, "username", o.username, error)) return false;
            if (!getStr(j, "password_enc", o.passwordEnc, error)) return false;
            if (!getBool(j, "enabled", o.enabled, error)) return false;
            const json::Value* api = j.find("clash_api");
            if (api) {
                if (!api->isObject()) { if (error) *error = "outlets[].clash_api must be an object"; return false; }
                static const char* kA[] = {"host", "port", "secret_enc"};
                noteUnknownKeys(*api, "outlets[].clash_api", kA, std::size(kA), warnings);
                if (!getStr(*api, "host", o.clashApi.host, error)) return false;
                if (!getInt(*api, "port", o.clashApi.port, 0, 65535, error)) return false;
                if (!getStr(*api, "secret_enc", o.clashApi.secretEnc, error)) return false;
            }
            if (o.id.empty()) o.id = newId();
            if (o.name.empty()) o.name = o.host + ":" + std::to_string(o.port);
            parsed.push_back(std::move(o));
        }
        out.outlets = std::move(parsed);
    }

    const json::Value* nm = v.find("node_monitor");
    if (nm) {
        if (!nm->isObject()) { if (error) *error = "'node_monitor' must be an object"; return false; }
        static const char* kN[] = {"enabled", "interval_s", "fail_threshold",
                                   "delay_url", "delay_timeout_ms",
                                   "max_latency_ms", "regions", "node_classes",
                                   "min_switch_interval_s", "real_fail_threshold",
                                   "real_fail_ratio_pct", "real_fail_window_s",
                                   "bad_node_cooldown_s"};
        noteUnknownKeys(*nm, "node_monitor", kN, std::size(kN), warnings);
        if (!getBool(*nm, "enabled", out.nodeMonitor.enabled, error)) return false;
        if (!getInt(*nm, "interval_s", out.nodeMonitor.intervalS, 10, 3600, error)) return false;
        if (!getInt(*nm, "fail_threshold", out.nodeMonitor.failThreshold, 1, 10, error)) return false;
        if (!getStr(*nm, "delay_url", out.nodeMonitor.delayUrl, error)) return false;
        if (!getInt(*nm, "delay_timeout_ms", out.nodeMonitor.delayTimeoutMs, 500, 30000, error)) return false;
        if (!getInt(*nm, "max_latency_ms", out.nodeMonitor.maxLatencyMs, 50, 10000, error)) return false;
        if (!getInt(*nm, "real_fail_threshold", out.nodeMonitor.realFailThreshold, 1, 100, error)) return false;
        if (!getInt(*nm, "real_fail_ratio_pct", out.nodeMonitor.realFailRatioPct, 1, 100, error)) return false;
        if (!getInt(*nm, "real_fail_window_s", out.nodeMonitor.realFailWindowS, 10, 3600, error)) return false;
        if (!getInt(*nm, "bad_node_cooldown_s", out.nodeMonitor.badNodeCooldownS, 0, 86400, error)) return false;
        const json::Value* regArr = nm->find("regions");
        if (regArr) {
            out.nodeMonitor.regions.clear();  // explicit array replaces the default
            if (!regArr->isArray()) {
                if (error) *error = "'node_monitor.regions' must be an array";
                return false;
            }
            for (size_t i = 0; i < regArr->size(); ++i) {
                if (!regArr->at(i).isString()) {
                    if (error) *error = "'node_monitor.regions[]' must be strings";
                    return false;
                }
                // Empty entries ("不限" written by an older GUI build) are
                // DROPPED with a warning, not fatal: a hard reject here made
                // the next GUI start treat the whole file as corrupt and
                // wipe the user's config (measured 2026-08-31 16:44).
                if (regArr->at(i).asString().empty()) {
                    if (warnings) warnings->push_back(
                        "node_monitor.regions[]: ignored empty entry");
                    continue;
                }
                out.nodeMonitor.regions.push_back(regArr->at(i).asString());
            }
        }
        const json::Value* clsArr = nm->find("node_classes");
        if (clsArr) {
            out.nodeMonitor.nodeClasses.clear();  // explicit array replaces the default
            if (!clsArr->isArray()) {
                if (error) *error = "'node_monitor.node_classes' must be an array";
                return false;
            }
            for (size_t i = 0; i < clsArr->size(); ++i) {
                if (!clsArr->at(i).isString()) {
                    if (error) *error = "'node_monitor.node_classes[]' must be strings";
                    return false;
                }
                if (clsArr->at(i).asString().empty()) {
                    if (warnings) warnings->push_back(
                        "node_monitor.node_classes[]: ignored empty entry");
                    continue;
                }
                out.nodeMonitor.nodeClasses.push_back(clsArr->at(i).asString());
            }
        }
        // Legacy single-value keys (pre-multi-select configs): migrate. The
        // old field WAS the whole selection — it replaces the defaults when
        // no explicit array was present.
        const json::Value* regOld = nm->find("region");
        if (regOld && regOld->isString() && !regOld->asString().empty()) {
            if (!regArr) out.nodeMonitor.regions.clear();
            bool have = false;
            for (const auto& r : out.nodeMonitor.regions) {
                if (r == regOld->asString()) { have = true; break; }
            }
            if (!have) out.nodeMonitor.regions.push_back(regOld->asString());
        }
        const json::Value* clsOld = nm->find("node_class");
        if (clsOld && clsOld->isString() && !clsOld->asString().empty()) {
            if (!clsArr) out.nodeMonitor.nodeClasses.clear();
            bool have = false;
            for (const auto& c : out.nodeMonitor.nodeClasses) {
                if (c == clsOld->asString()) { have = true; break; }
            }
            if (!have) out.nodeMonitor.nodeClasses.push_back(clsOld->asString());
        }
        if (!getInt(*nm, "min_switch_interval_s", out.nodeMonitor.minSwitchIntervalS, 0, 3600, error)) return false;
    }

    const json::Value* sub = v.find("subscription");
    if (sub) {
        if (!sub->isObject()) { if (error) *error = "'subscription' must be an object"; return false; }
        static const char* kS[] = {"auto_refresh", "interval_hours", "start_delay_min"};
        noteUnknownKeys(*sub, "subscription", kS, std::size(kS), warnings);
        if (!getBool(*sub, "auto_refresh", out.subscription.autoRefresh, error)) return false;
        if (!getInt(*sub, "interval_hours", out.subscription.intervalHours, 0, 720, error)) return false;
        if (!getInt(*sub, "start_delay_min", out.subscription.startDelayMin, 1, 240, error)) return false;
    }

    const json::Value* ex = v.find("exclusions");
    if (ex) {
        if (!ex->isObject()) { if (error) *error = "'exclusions' must be an object"; return false; }
        static const char* kE[] = {"builtin", "builtin_names", "extra_paths", "extra_names"};
        noteUnknownKeys(*ex, "exclusions", kE, std::size(kE), warnings);
        if (!getBool(*ex, "builtin", out.exclusions.builtin, error)) return false;
        if (!getStrArray(*ex, "builtin_names", out.exclusions.builtinNames, error)) return false;
        if (!getStrArray(*ex, "extra_paths", out.exclusions.extraPaths, error)) return false;
        if (!getStrArray(*ex, "extra_names", out.exclusions.extraNames, error)) return false;
    }

    const json::Value* ro = v.find("routing");
    if (ro) {
        if (!ro->isObject()) { if (error) *error = "'routing' must be an object"; return false; }
        static const char* kRo[] = {"bypass_loopback", "bypass_private", "block_udp_for_rules",
                                    "block_ipv6_for_rules", "dns_cleanup", "dns_cleanup_global", "ipv6_enabled",
                                    "auto_outlet_id", "cover_app_dir_always", "dns_servers"};
        noteUnknownKeys(*ro, "routing", kRo, std::size(kRo), warnings);
        if (!getBool(*ro, "bypass_loopback", out.routing.bypassLoopback, error)) return false;
        if (!getBool(*ro, "bypass_private", out.routing.bypassPrivate, error)) return false;
        if (!getBool(*ro, "block_udp_for_rules", out.routing.blockUdpForRules, error)) return false;
        if (!getBool(*ro, "block_ipv6_for_rules", out.routing.blockIpv6ForRules, error)) return false;
        if (!getBool(*ro, "dns_cleanup", out.routing.dnsCleanup, error)) return false;
        if (!getBool(*ro, "dns_cleanup_global", out.routing.dnsCleanupGlobal, error)) return false;
        if (!getBool(*ro, "ipv6_enabled", out.routing.ipv6Enabled, error)) return false;
        if (!getStr(*ro, "auto_outlet_id", out.routing.autoOutletId, error)) return false;
        if (!getBool(*ro, "cover_app_dir_always", out.routing.coverAppDirAlways, error)) return false;
        const json::Value* dnsArr = ro->find("dns_servers");
        if (dnsArr) {
            out.routing.dnsServers.clear();  // explicit array replaces the default
            if (!dnsArr->isArray()) {
                if (error) *error = "'routing.dns_servers' must be an array";
                return false;
            }
            for (size_t i = 0; i < dnsArr->size(); ++i) {
                if (!dnsArr->at(i).isString()) {
                    if (error) *error = "'routing.dns_servers[]' must be strings";
                    return false;
                }
                const std::string s = dnsArr->at(i).asString();
                const size_t colon = s.find(':');
                const std::string ipPart = colon == std::string::npos
                                               ? s
                                               : s.substr(0, colon);
                if (!parseIpv4(ipPart)) {
                    if (error) *error = "'routing.dns_servers[]' must be 'ip' or 'ip:port'";
                    return false;
                }
                if (colon != std::string::npos) {
                    const std::string pPart = s.substr(colon + 1);
                    char* endp = nullptr;
                    const long p = std::strtol(pPart.c_str(), &endp, 10);
                    if (endp == pPart.c_str() || *endp != '\0' || p < 1 ||
                        p > 65535) {
                        if (error) *error = "'routing.dns_servers[]' port out of range";
                        return false;
                    }
                }
                out.routing.dnsServers.push_back(s);
            }
        }
    }

    if (!getStr(v, "fail_mode", out.failMode, error)) return false;
    if (!out.failMode.empty() && out.failMode != "open" && out.failMode != "closed") {
        if (error) *error = "fail_mode must be 'open' or 'closed'";
        return false;
    }

    const json::Value* lg = v.find("logging");
    if (lg) {
        if (!lg->isObject()) { if (error) *error = "'logging' must be an object"; return false; }
        static const char* kL[] = {"level", "max_file_mb", "max_files"};
        noteUnknownKeys(*lg, "logging", kL, std::size(kL), warnings);
        if (!getStr(*lg, "level", out.logging.level, error)) return false;
        if (!out.logging.level.empty()) {
            const std::string l = out.logging.level;
            if (l != "debug" && l != "info" && l != "warn" && l != "error") {
                if (error) *error = "logging.level must be debug|info|warn|error";
                return false;
            }
        }
        if (!getInt(*lg, "max_file_mb", out.logging.maxFileMb, 1, 1024, error)) return false;
        if (!getInt(*lg, "max_files", out.logging.maxFiles, 1, 32, error)) return false;
    }

    const json::Value* ui = v.find("ui");
    if (ui) {
        if (!ui->isObject()) { if (error) *error = "'ui' must be an object"; return false; }
        static const char* kU[] = {"autostart", "start_minimized", "confirm_stop"};
        noteUnknownKeys(*ui, "ui", kU, std::size(kU), warnings);
        if (!getBool(*ui, "autostart", out.ui.autostart, error)) return false;
        if (!getBool(*ui, "start_minimized", out.ui.startMinimized, error)) return false;
        if (!getBool(*ui, "confirm_stop", out.ui.confirmStop, error)) return false;
    }

    const json::Value* adv = v.find("advanced");
    if (adv) {
        if (!adv->isObject()) { if (error) *error = "'advanced' must be an object"; return false; }
        static const char* kA[] = {"nat_idle_timeout_s", "syn_wait_s", "max_sessions", "socket_map_ttl_s"};
        noteUnknownKeys(*adv, "advanced", kA, std::size(kA), warnings);
        if (!getInt(*adv, "nat_idle_timeout_s", out.advanced.natIdleTimeoutS, 60, 30 * 86400, error)) return false;
        if (!getInt(*adv, "syn_wait_s", out.advanced.synWaitS, 5, 300, error)) return false;
        if (!getInt(*adv, "max_sessions", out.advanced.maxSessions, 16, 65536, error)) return false;
        if (!getInt(*adv, "socket_map_ttl_s", out.advanced.socketMapTtlS, 10, 3600, error)) return false;
    }
    return out.validate(error);
}

bool Config::validate(std::string* error) const {
    auto ip = parseIpv4(proxy.host);
    if (!ip) {
        if (error) *error = "proxy.host is not a valid IPv4 address";
        return false;
    }
#ifndef APS_TEST_HOOKS
    if (!isLoopbackIpv4(*ip)) {
        if (error) *error = "proxy.host must be inside 127.0.0.0/8 (local Clash/Mihomo)";
        return false;
    }
#endif
    if (relay.port == proxy.port) {
        if (error) *error = "relay.port must differ from proxy.port";
        return false;
    }
    for (const auto& rule : rules) {
        const std::wstring w = utf8ToWide(rule.path);
        if (w.size() < 3 || w[1] != L':' || (w[2] != L'\\' && w[2] != L'/')) {
            if (error) *error = "rule path must be absolute (e.g. C:\\Apps\\App.exe): " + rule.path;
            return false;
        }
        if (rule.action != "proxy" && rule.action != "direct" && rule.action != "block") {
            if (error) *error = "rule action must be proxy|direct|block: " + rule.name;
            return false;
        }
    }
    for (size_t i = 0; i < rules.size(); ++i) {
        for (size_t j = i + 1; j < rules.size(); ++j) {
            if (rules[i].id == rules[j].id) {
                if (error) *error = "duplicate rule id: " + rules[i].id;
                return false;
            }
        }
    }
    // Outlet checks: unique ids, loopback hosts, valid rule references.
    for (size_t i = 0; i < outlets.size(); ++i) {
        for (size_t j = i + 1; j < outlets.size(); ++j) {
            if (outlets[i].id == outlets[j].id) {
                if (error) *error = "duplicate outlet id: " + outlets[i].id;
                return false;
            }
        }
        auto ip = parseIpv4(outlets[i].host);
        if (!ip) {
            if (error) *error = "outlet host is not a valid IPv4 address: " + outlets[i].name;
            return false;
        }
#ifndef APS_TEST_HOOKS
        if (!isLoopbackIpv4(*ip)) {
            if (error) *error = "outlet host must be inside 127.0.0.0/8 (local proxy): " +
                                 outlets[i].name;
            return false;
        }
#endif
        if (outlets[i].port == relay.port) {
            if (error) *error = "outlet port must differ from relay.port: " + outlets[i].name;
            return false;
        }
    }
    for (const auto& rule : rules) {
        if (rule.outlet.empty()) continue;
        bool found = false;
        for (const auto& o : outlets) {
            if (o.id == rule.outlet) { found = true; break; }
        }
        if (!found) {
            if (error) *error = "rule references unknown outlet: " + rule.outlet;
            return false;
        }
    }
    {
        static const char* kRegions[] = {
            "HK", "TW", "SG", "JP", "US", "KR", "MO", "UK", "DE",
            "AU", "CA", "FR", "RU", "IN", "TH", "MY",
        };
        for (const auto& r : nodeMonitor.regions) {
            bool known = false;
            for (const char* k : kRegions) {
                if (r == k) { known = true; break; }
            }
            if (!known) {
                if (error) *error = "unknown node_monitor.regions entry: " + r;
                return false;
            }
        }
    }
    {
        static const char* kClasses[] = {
            "IEPL", "RES", "NATIVE", "RELAY", "DIRECT", "STARLINK", "PREMIUM",
        };
        for (const auto& c : nodeMonitor.nodeClasses) {
            // "GROUP:<name>" entries select a provider GROUP as a class
            // (membership-based; the name is dynamic, not whitelisted).
            if (c.rfind("GROUP:", 0) == 0 && c.size() > 6) continue;
            bool known = false;
            for (const char* k : kClasses) {
                if (c == k) { known = true; break; }
            }
            if (!known) {
                if (error) *error = "unknown node_monitor.node_classes entry: " + c;
                return false;
            }
        }
    }
    return true;
}

}  // namespace aps
