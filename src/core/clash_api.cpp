#include "aps/clash_api.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <algorithm>
#include <set>
#include <cctype>
#include <cstdio>
#include <vector>

#include "aps/json.hpp"
#include "aps/clash_pipe.hpp"
#include "aps/path_util.hpp"
#include "aps/string_util.hpp"

namespace aps {

namespace {

std::string httpRequest(const std::string& host, uint16_t port,
                        const std::string& method, const std::string& path,
                        const std::string& secret, const std::string& body,
                        int timeoutMs, ClashApiResult& out,
                        const std::string& pipe, uint32_t pipePid) {
    if (secret.find_first_of("\r\n") != std::string::npos) {
        out.error = "invalid controller secret";
        return {};
    }
    std::string req = method + " " + path + " HTTP/1.1\r\n";
    req += "Host: " + host + ":" + std::to_string(port) + "\r\n";
    req += "User-Agent: AppProxySwitch/1.0\r\n";
    req += "Accept: application/json\r\n";
    if (!secret.empty()) req += "Authorization: Bearer " + secret + "\r\n";
    req += "Connection: close\r\n";
    if (!body.empty()) {
        req += "Content-Type: application/json\r\n";
        req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }
    req += "\r\n";
    req += body;
    std::string resp;
    if (!pipe.empty()) {
        if (!requestControllerPipe(pipe, pipePid, req, timeoutMs, resp, out.error))
            return {};
    } else {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        out.error = "socket() failed";
        return {};
    }
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, host.c_str(), &sa.sin_addr);
    sa.sin_port = htons(port);

    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    ::connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    fd_set w, e;
    FD_ZERO(&w); FD_ZERO(&e); FD_SET(s, &w); FD_SET(s, &e);
    timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
    int sel = select(0, nullptr, &w, &e, &tv);
    if (sel <= 0) {
        closesocket(s);
        out.error = sel == 0 ? "controller connect timed out" : "controller connect failed";
        return {};
    }
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);

    if (net::sendAll(s, req.data(), req.size(), timeoutMs) != 0) {
        closesocket(s);
        out.error = "controller send failed";
        return {};
    }

    char buf[4096];
    // Connection: close — read until the peer closes (chunked replies have
    // no Content-Length, so we must not stop early). Deadline is strict:
    // callers that expect slow replies (node latency tests) pass a large
    // timeoutMs themselves; discovery probes rely on the deadline being
    // exactly what they asked for.
    int64_t deadline = static_cast<int64_t>(GetTickCount64()) + timeoutMs;
    while (static_cast<int64_t>(GetTickCount64()) < deadline) {
        fd_set r;
        FD_ZERO(&r);
        FD_SET(s, &r);
        timeval t{0, 200000};
        if (select(0, &r, nullptr, nullptr, &t) <= 0) continue;
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;  // peer closed or error
        resp.append(buf, static_cast<size_t>(n));
    }
    closesocket(s);
    }

    size_t hdrEnd = resp.find("\r\n\r\n");
    if (hdrEnd == std::string::npos) {
        out.error = "controller reply truncated";
        return {};
    }
    std::string headers = resp.substr(0, hdrEnd);
    std::string statusLine = resp.substr(0, resp.find("\r\n"));
    out.httpStatus = statusLine.size() > 12 ? atoi(statusLine.c_str() + 9) : 0;
    out.body = resp.substr(hdrEnd + 4);

    // Decode Transfer-Encoding: chunked when present (Clash 1.10+ uses it).
    std::string lower;
    for (char c : headers) lower.push_back(static_cast<char>(tolower(c)));
    if (lower.find("transfer-encoding: chunked") != std::string::npos) {
        std::string decoded;
        size_t pos = 0;
        while (pos < out.body.size()) {
            size_t lineEnd = out.body.find("\r\n", pos);
            if (lineEnd == std::string::npos) break;
            size_t size = strtoul(out.body.c_str() + pos, nullptr, 16);
            pos = lineEnd + 2;
            if (size == 0) break;  // terminal chunk
            if (pos + size > out.body.size()) break;
            decoded.append(out.body, pos, size);
            pos += size + 2;  // data + CRLF
        }
        out.body = std::move(decoded);
    }
if (getenv("APS_DUMP_BODY")) {
        std::printf("[client] decoded %zu bytes: ", out.body.size());
        for (size_t i = 0; i < out.body.size() && i < 80; ++i) {
            std::printf("%02X ", static_cast<unsigned char>(out.body[i]));
        }
        std::printf("\n");
    }
    return out.body;
}

}  // namespace

ClashApiClient::ClashApiClient(std::string host, uint16_t port, std::string secret,
                               std::string pipe, uint32_t pipePid)
    : host_(std::move(host)), port_(port), secret_(std::move(secret)),
      pipe_(std::move(pipe)), pipePid_(pipePid) {}

ClashApiResult ClashApiClient::request(const std::string& method,
                                       const std::string& path,
                                       const std::string& body, int timeoutMs) {
    ClashApiResult r;
    std::string resp = httpRequest(host_, port_, method, path, secret_, body,
                                   timeoutMs, r, pipe_, pipePid_);
    if (r.error.empty() && r.httpStatus == 0) {
        r.error = "no HTTP status";
    }
    if (r.error.empty() && r.httpStatus >= 400) {
        r.error = "HTTP " + std::to_string(r.httpStatus);
    }
    // 204 No Content (PUT /proxies) legitimately has an empty body.
    r.ok = r.error.empty() && r.httpStatus >= 200 && r.httpStatus < 400;
    return r;
}

bool ClashApiClient::probe(std::string* err, int timeoutMs) {
    ClashApiResult r = request("GET", "/version", "", timeoutMs);
    if (!r.ok && err) *err = r.error;
    return r.ok;
}

namespace {
// Auto-DETECTION must be strict: any random HTTP server answers 200 — a
// real controller is identified by a Clash-style /version payload (JSON
// object with a "version" string). This rejects dev servers / local app
// services whose HTTP ports would otherwise be mistaken for controllers.
bool looksLikeClashVersion(const std::string& body) {
    json::Value v;
    std::string err;
    if (!json::Value::parse(body, v, &err)) return false;
    if (!v.isObject()) return false;
    const json::Value* ver = v.find("version");
    return ver && ver->isString() && !ver->asString().empty();
}
}  // namespace

ClashApiClient::ProbeResult ClashApiClient::probeAny(int timeoutMs) {
    ClashApiResult r = request("GET", "/version", "", timeoutMs);
    ProbeResult p;
    p.httpStatus = r.httpStatus;
    // 401/403 still count: something demanding the controller secret IS a
    // controller (the body check can't run without it).
    p.needSecret = r.httpStatus == 401 || r.httpStatus == 403;
    p.reachable = p.needSecret || (r.ok && looksLikeClashVersion(r.body));
    return p;
}

std::optional<ClashGroup> ClashApiClient::currentSelectorGroup(
    std::string* err, int timeoutMs, std::vector<ClashGroup>* allGroups,
    std::string* runtimeMode, const std::vector<std::string>& preferredGroups) {
    if (runtimeMode) runtimeMode->clear();
    ClashApiResult r = request("GET", "/proxies", "", timeoutMs);
    if (!r.ok) {
        if (err) *err = r.error;
        return std::nullopt;
    }
    json::Value v;
    std::string perr;
    if (!json::Value::parse(r.body, v, &perr)) {
        if (err) *err = "proxies JSON: " + perr;
        return std::nullopt;
    }
    if (!v.isObject() || !v.find("proxies")) {
        if (err) *err = "proxies payload has no 'proxies' field";
        return std::nullopt;
    }
    const json::Value& proxies = *v.find("proxies");
    // Clash/Mihomo keeps a short per-proxy delay history alongside selector
    // groups. Collect it first so the selected selector can use the same
    // availability evidence. Missing/unknown shapes stay neutral.
    std::map<std::string, ClashNodeHistory> nodeHistory;
    for (const auto& kv : proxies.object()) {
        const json::Value& p = kv.second;
        if (!p.isObject()) continue;
        const json::Value* history = p.find("history");
        if (!history || !history->isArray()) continue;
        ClashNodeHistory stats;
        for (size_t i = 0; i < history->size(); ++i) {
            const json::Value& sample = history->at(i);
            if (!sample.isObject()) continue;
            const json::Value* delay = sample.find("delay");
            if (!delay || !delay->isNumber()) continue;
            ++stats.samples;
            if (delay->asNumber() > 0) ++stats.successes;
        }
        nodeHistory.emplace(kv.first, stats);
    }

    ClashGroup fallback;
    std::map<std::string, ClashGroup> groups;
    for (const auto& kv : proxies.object()) {
        const json::Value& p = kv.second;
        if (!p.isObject()) continue;
        const json::Value* type = p.find("type");
        if (!type) continue;
        const json::Value* now = p.find("now");
        const json::Value* nodes = p.find("all");
        if (!nodes || !nodes->isArray()) continue;
        ClashGroup g;
        g.name = kv.first;
        g.type = type->asString();
        g.now = now && now->isString() ? now->asString() : "";
        if (nodes && nodes->isArray()) {
            for (size_t i = 0; i < nodes->size(); ++i) {
                if (nodes->at(i).isString()) {
                    g.nodes.push_back(nodes->at(i).asString());
                }
            }
        }
        if (allGroups) allGroups->push_back(g);  // every group, for membership
        groups.emplace(g.name, g);
        if (g.type == "Selector" && !g.now.empty() && fallback.name.empty()) {
            // Only the selected selector needs the global node evidence.
            // Membership-only groups stay small even on large providers.
            g.history = nodeHistory;
            fallback = std::move(g);
        }
    }
    auto resolveSelectedNode = [&](const ClashGroup& target) -> std::optional<ClashGroup> {
        auto selected = target;
        selected.history = nodeHistory;
        selected.selectedMember = target.now;
        auto selectedLeaf = [&](std::string node) -> std::optional<std::string> {
            std::set<std::string> visited{target.name};
            while (true) {
                const auto child = groups.find(node);
                if (child == groups.end()) return node.empty() ? std::nullopt : std::optional<std::string>(node);
                if (!visited.insert(node).second || child->second.now.empty()) return std::nullopt;
                node = child->second.now;
            }
        };
        // A Selector can currently route through URLTest/Fallback or another
        // group. Display/probe its actual selected leaf, while retaining the
        // Selector's name and legal members as the switching target.
        const auto current = selectedLeaf(selected.now);
        if (!current) {
            if (err) *err = "当前策略组选择为空或存在循环，暂无法核对实际节点";
            return std::nullopt;
        }
        selected.now = *current;
        for (const auto& member : selected.nodes)
            if (const auto leaf = selectedLeaf(member)) selected.memberLeaves.emplace(member, *leaf);
        return selected;
    };
    // Inspect mode even when no Selector exists, and expose it independently
    // of selection success. A live listener must not conceal direct mode.
    const auto configs = request("GET", "/configs", "", timeoutMs);
    json::Value config;
    std::string mode;
    if (configs.ok && json::Value::parse(configs.body, config, nullptr))
        if (const auto* value = config.find("mode"); value && value->isString())
            mode = toLowerAscii(value->asString());
    if (runtimeMode) *runtimeMode = mode;
    if (mode == "direct") {
        if (err) *err = "内核处于直连模式：代理端口可用也会直连目标，请在代理客户端核对模式";
        return std::nullopt;
    }
    if (!fallback.name.empty()) {
        if (mode == "global") {
            if (const auto global = groups.find("GLOBAL"); global != groups.end() &&
                global->second.type == "Selector" && !global->second.now.empty()) {
                return resolveSelectedNode(global->second);
            }
            if (err) *err = "全局模式缺少有效 GLOBAL 策略组，未采用其他策略组猜测";
            return std::nullopt;
        }
        if (mode == "rule") {
            const auto rules = request("GET", "/rules", "", timeoutMs);
            json::Value payload;
            const json::Value* list = nullptr;
            if (rules.ok && json::Value::parse(rules.body, payload, nullptr)) list = payload.find("rules");
            if (!list || !list->isArray()) {
                if (err) *err = "规则模式的策略组归属暂无法核对，未采用 GLOBAL 猜测";
                return std::nullopt;
            }
            const ClashGroup* chosen = nullptr;
            size_t breadth = 0;
            std::set<std::string> referencedSelectors;
            auto concreteMembers = [&](const ClashGroup& g) {
                size_t count = 0;
                for (const auto& node : g.nodes)
                    if (!groups.count(node) && node != "DIRECT" && node != "REJECT" &&
                        node != "REJECT-DROP" && node != "PASS" && node != "COMPATIBLE") ++count;
                return count;
            };
            for (size_t i = 0; i < list->size(); ++i) {
                const auto* proxy = list->at(i).find("proxy");
                if (!proxy || !proxy->isString()) continue;
                auto target = proxy->asString();
                std::set<std::string> visited;
                const ClashGroup* active = nullptr;
                while (visited.insert(target).second) {
                    const auto group = groups.find(target);
                    if (group == groups.end()) break;
                    if (group->second.type == "Selector" && !group->second.now.empty()) {
                        active = &group->second;
                        if (target != "GLOBAL") referencedSelectors.insert(target);
                    }
                    target = group->second.now;
                }
                if (!active || active->name == "GLOBAL") continue;
                const auto concrete = concreteMembers(*active);
                // Use the broadest selector referenced by the actual rules.
                // Service-specific groups keep their independent selections.
                if (concrete && (!chosen || concrete > breadth)) { chosen = active; breadth = concrete; }
            }
            const ClashGroup* preferred = nullptr;
            size_t preferredBreadth = 0;
            for (const auto& name : preferredGroups) {
                if (!referencedSelectors.count(name)) continue;
                const auto& candidate = groups.at(name);
                const auto concrete = concreteMembers(candidate);
                if (!preferred || concrete > preferredBreadth ||
                    (concrete == preferredBreadth && name < preferred->name)) {
                    preferred = &candidate;
                    preferredBreadth = concrete;
                }
            }
            // Preserve the exact service Selector as the switching target,
            // even when its current selection goes through another group.
            // Unreferenced membership-only groups never redirect monitoring.
            if (preferred) return resolveSelectedNode(*preferred);
            if (!chosen) {
                if (err) *err = "规则未指向包含具体节点的可切换策略组";
                return std::nullopt;
            }
            return resolveSelectedNode(*chosen);
        }
        // Legacy controllers without runtime metadata retain their existing
        // selector protocol. No version/provider group names are used.
        return resolveSelectedNode(fallback);
    }
    if (err) *err = "no Selector group found";
    return std::nullopt;
}

int ClashApiClient::nodeDelay(const std::string& node, const std::string& url,
                              int timeoutMs, int httpTimeoutMs) {
    std::string path = "/proxies/" + urlEncode(node) + "/delay?url=" +
                       urlEncode(url) + "&timeout=" + std::to_string(timeoutMs);
    ClashApiResult r = request("GET", path, "", httpTimeoutMs);
    if (!r.ok) return -1;
    json::Value v;
    std::string perr;
    if (!json::Value::parse(r.body, v, &perr) || !v.isObject()) return -1;
    const json::Value* d = v.find("delay");
    if (d && d->isNumber()) return static_cast<int>(d->asNumber());
    return -1;
}

bool ClashApiClient::switchNode(const std::string& group, const std::string& node,
                                std::string* err) {
    std::string path = "/proxies/" + urlEncode(group);
    json::Value body = json::Value::makeObject();
    body.set("name", node);
    ClashApiResult r = request("PUT", path, body.dump(), 5000);
    if (!r.ok && err) *err = r.error;
    return r.ok;
}

bool ClashApiClient::resolveA(const std::string& name, std::vector<uint32_t>& ipsHost,
                              std::string* err, int timeoutMs) {
    std::string path = "/dns/query?name=" + urlEncode(name) + "&type=A";
    ClashApiResult r = request("GET", path, "", timeoutMs);
    if (!r.ok) {
        if (err) *err = r.error;
        return false;
    }
    json::Value v;
    std::string perr;
    if (!json::Value::parse(r.body, v, &perr) || !v.isObject()) {
        if (err) *err = "dns query JSON: " + perr;
        return false;
    }
    const json::Value* answer = v.find("Answer");
    if (!answer || !answer->isArray()) {
        if (err) *err = "dns query has no Answer";
        return false;
    }
    for (size_t i = 0; i < answer->size(); ++i) {
        const json::Value& a = answer->at(i);
        const json::Value* data = a.find("data");
        const json::Value* type = a.find("type");
        if (!data || !data->isString()) continue;
        if (type && type->isNumber() && type->asInt() != 1) continue;  // A only
        auto ip = parseIpv4(data->asString());
        if (ip) ipsHost.push_back(*ip);
    }
    if (ipsHost.empty()) {
        if (err) *err = "dns query returned no A records";
        return false;
    }
    return true;
}

bool ClashApiClient::putConfigs(const std::string& yaml, std::string* err,
                                int timeoutMs) {
    ClashApiResult r = request("PUT", "/configs?force=true", yaml, timeoutMs);
    if (!r.ok && err) *err = r.error;
    return r.ok;
}

std::string ClashApiClient::urlEncode(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            char hex[4];
            snprintf(hex, sizeof(hex), "%%%02X", c);
            out += hex;
        }
    }
    return out;
}

uint16_t autoDetectClashApiPort(const std::string& host, const std::string& secret,
                                uint16_t socksPort, bool* needSecret) {
    if (needSecret) *needSecret = false;
    auto tryPort = [&](uint16_t port) -> int {
        auto p = ClashApiClient(host, port, secret).probeAny(600);
        if (p.reachable) {
            if (needSecret) *needSecret = p.needSecret;
            return 1;
        }
        return 0;
    };

    // Enumerate ALL local TCP listeners with their owning PID — 127.0.0.1
    // AND INADDR_ANY-bound (several kernels bind the controller on all
    // interfaces, e.g. SakuraCat's fork — a 127.0.0.1 connect still reaches
    // them). There is deliberately no hard-coded port list here: with the
    // full listener table in hand, a real controller is whatever answers a
    // Clash /version.
    ULONG size = 0;
    struct ListenRow {
        uint16_t port;
        uint32_t pid;
    };
    std::vector<ListenRow> rows;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL,
                            0) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<uint8_t> buf(size);
        if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET,
                                TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                const auto& row = table->table[i];
                if (row.dwState != MIB_TCP_STATE_LISTEN) continue;
                if (row.dwLocalAddr != 0x0100007Fu && row.dwLocalAddr != 0)
                    continue;  // 127.0.0.1 (network order) or INADDR_ANY
                rows.push_back({ntohs(static_cast<uint16_t>(row.dwLocalPort & 0xFFFF)),
                                row.dwOwningPid});
            }
        }
    }

    // Pass 1: same PID as the SOCKS port (CFW: socks + API in one process).
    if (socksPort != 0) {
        uint32_t socksPid = 0;
        for (const auto& r : rows) {
            if (r.port == socksPort) { socksPid = r.pid; break; }
        }
        if (socksPid != 0) {
            for (const auto& r : rows) {
                if (r.port == socksPort) continue;
                if (r.pid == socksPid && tryPort(r.port)) return r.port;
            }
        }
    }

    // Pass 2: every remaining local listener, ascending port (deterministic;
    // the slow fallback that needs no prior knowledge of any kernel).
    std::vector<uint16_t> rest;
    for (const auto& r : rows) {
        if (r.port == socksPort) continue;
        rest.push_back(r.port);
    }
    std::sort(rest.begin(), rest.end());
    rest.erase(std::unique(rest.begin(), rest.end()), rest.end());
    for (uint16_t port : rest) {
        if (tryPort(port)) return port;
    }
    return 0;
}

}  // namespace aps
