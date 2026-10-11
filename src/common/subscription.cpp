// Subscription refresh support. See subscription.hpp.
#include "aps/subscription.hpp"

#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <tcpmib.h>

#include <sstream>

#include <cstdio>
#include <set>
#include <vector>

#include "aps/json.hpp"
#include "aps/log.hpp"
#include "aps/path_util.hpp"
#include "aps/string_util.hpp"

namespace aps::subscription {

namespace {

constexpr size_t kMaxSubBytes = 2 * 1024 * 1024;  // generous cap

std::wstring defaultSakuraCatDir() {
    PWSTR profile = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_Profile, 0, nullptr, &profile)) ||
        !profile) {
        return {};
    }
    std::wstring dir = profile;
    CoTaskMemFree(profile);
    return dir + L"\\.config\\com.vortex.helper";
}

}  // namespace

std::wstring sakuraCatConfigDir() { return defaultSakuraCatDir(); }

std::optional<std::string> findSakuraCatUrl(const std::wstring& configDir) {
    std::wstring dir = configDir.empty() ? defaultSakuraCatDir() : configDir;
    if (dir.empty()) return std::nullopt;
    std::wstring path = dir + L"\\.store.json";
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return std::nullopt;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(f, &size) || size.QuadPart > (1 << 20)) {
        CloseHandle(f);
        return std::nullopt;
    }
    std::string text;
    text.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    BOOL ok = ReadFile(f, text.empty() ? nullptr : text.data(),
                       static_cast<DWORD>(text.size()), &read, nullptr);
    CloseHandle(f);
    if (!ok) return std::nullopt;
    text.resize(read);
    json::Value v;
    std::string err;
    if (!json::Value::parse(text, v, &err) || !v.isObject()) return std::nullopt;
    const json::Value* u = v.find("SubscriptionUrl");
    if (!u || !u->isString() || u->asString().empty()) return std::nullopt;
    return u->asString();
}

namespace {

// One fetch attempt. The content guard (looksLikeClashYaml) runs here: a
// rate-limited server answers 200 with an HTML page, which must never reach
// a caller (measured: such a page was once merged into config.yaml).
// proxyPort != 0 routes the request through a local HTTP CONNECT proxy
// (a Clash kernel's mixed port) — the egress becomes the provider's own
// node IP, which airports whitelist for subscription updates while
// rejecting the home IP (measured 2026-09-02: xmrth 403 AUTH_FAIL direct;
// their docs: "本站代理节点的 IP 已统一加入白名单…随时可以通过代理
// 更新订阅").
bool fetchTextOnce(const std::string& url, std::string& yaml, std::string* err,
                   uint16_t proxyPort = 0) {
    HINTERNET session = nullptr;
    if (proxyPort != 0) {
        std::wstring proxy = L"127.0.0.1:" + std::to_wstring(proxyPort);
        session = WinHttpOpen(L"AppProxySwitch/1.0",
                              WINHTTP_ACCESS_TYPE_NAMED_PROXY, proxy.c_str(),
                              L"127.0.0.1;<local>", 0);
    } else {
        session = WinHttpOpen(L"AppProxySwitch/1.0",
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    }
    if (!session) {
        if (err) *err = "WinHttpOpen failed";
        return false;
    }
    // Tight timeouts: a rate-limited or dead endpoint must fail within
    // seconds, not hang the "刷新中" button for a minute (measured: the
    // old 10s/20s timeouts made a single failed attempt take ~40 s).
    WinHttpSetTimeouts(session, 5000, 5000, 8000, 8000);
    std::string host;
    std::string pathAndQuery;
    bool isHttps = false;
    if (!parseHttpUrl(url, &host, &pathAndQuery, &isHttps)) {
        if (err) *err = "bad subscription URL";
        WinHttpCloseHandle(session);
        return false;
    }
    bool ok = false;
    HINTERNET conn = WinHttpConnect(session, utf8ToWide(host).c_str(),
                                    isHttps ? INTERNET_DEFAULT_HTTPS_PORT
                                            : INTERNET_DEFAULT_HTTP_PORT,
                                    0);
    if (!conn) {
        if (err) *err = "WinHttpConnect failed";
        WinHttpCloseHandle(session);
        return false;
    }
    HINTERNET req = WinHttpOpenRequest(
        conn, L"GET", utf8ToWide(pathAndQuery).c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        isHttps ? WINHTTP_FLAG_SECURE : 0);
    if (!req) {
        if (err) *err = "WinHttpOpenRequest failed";
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return false;
    }
    // Clash-client User-Agent: providers NEGOTIATE THE PAYLOAD FORMAT on it
    // (measured 2026-09-04: xmrth answered a Chrome UA with a base64
    // trojan:// preview list while the same URL served real Clash YAML to
    // ClashforWindows — CFW's own updater with that UA succeeded minutes
    // later). The old Chrome UA also masked this: it looked like success.
    // (The 2026-08-27 rate-limit incident was against the default library
    // UA, not clash clients; airport subs universally serve YAML to them.)
    WinHttpAddRequestHeaders(
        req, L"User-Agent: ClashforWindows/0.20.15\r\n",
        static_cast<DWORD>(-1), WINHTTP_ADDREQ_FLAG_ADD);
    DWORD status = 0;
    if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(req, nullptr)) {
        DWORD sz = sizeof(status);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz,
                            WINHTTP_NO_HEADER_INDEX);
        yaml.clear();
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(req, &avail) && avail > 0) {
            if (yaml.size() + avail > kMaxSubBytes) {
                if (err) *err = "subscription too large";
                break;
            }
            std::vector<char> buf(avail);
            DWORD got = 0;
            if (!WinHttpReadData(req, buf.data(), avail, &got) || got == 0) break;
            yaml.append(buf.data(), got);
            if (yaml.size() >= kMaxSubBytes) break;
        }
        ok = !yaml.empty();
        if (!ok && err && err->empty()) *err = "empty subscription";
    } else {
        if (err) *err = "subscription request failed (error " +
                        std::to_string(GetLastError()) + ")";
    }
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    if (!ok) return false;
    if (!looksLikeClashYaml(yaml)) {
        // Diagnostic: what the server REALLY sent (status + head bytes) —
        // distinguishes rate-limit pages from path bugs from captive portals
        // without another round of manual curl bisecting.
        std::string head = yaml.substr(0, 120);
        for (auto& c : head)
            if (c == '\r' || c == '\n' || c == '\t') c = ' ';
        log::wf("subscription fetch: HTTP {}, {} bytes, head: {}", status,
                yaml.size(), head);
        if (err) {
            *err = status == 403 || status == 429
                       ? "订阅接口返回 HTTP " + std::to_string(status) +
                             "（被限流，稍后再试）"
                       : "订阅内容不是有效的 Clash 配置（HTTP " +
                             std::to_string(status) + "）";
        }
        return false;
    }
    return true;
}

}  // namespace

// Splits "https://host[:port]/path?query" into its connection parts. The
// request object MUST include the query string ("/path?query") — a previous
// implementation shared one buffer between path and query (WinHttpCrackUrl
// overwrote the path with the query) and every fetch silently requested
// "GET /?token=...", receiving the server's HTML page (2026-08-27 incident).
bool parseHttpUrl(const std::string& url, std::string* host,
                  std::string* pathAndQuery, bool* isHttps) {
    if (url.rfind("https://", 0) != 0 && url.rfind("http://", 0) != 0) return false;
    *isHttps = url.rfind("https://", 0) == 0;
    size_t p = url.find('/', isHttps ? 8 : 7);
    if (p == std::string::npos) {
        *host = url.substr(isHttps ? 8 : 7);
        *pathAndQuery = "/";
    } else {
        *host = url.substr(isHttps ? 8 : 7, p - (isHttps ? 8 : 7));
        *pathAndQuery = url.substr(p);
    }
    return !host->empty();
}

std::vector<uint32_t> parseDnsServerIps(const std::string& yaml) {
    std::vector<uint32_t> out;
    // Collect the value text of the two server lists (inline or block).
    auto collect = [&](const std::string& key, std::string& value) {
        std::istringstream ss(yaml);
        std::string line;
        while (std::getline(ss, line)) {
            // Strip comments.
            size_t h = line.find('#');
            if (h != std::string::npos) line = line.substr(0, h);
            // Strip indentation (the dns section is nested).
            size_t lead = line.find_first_not_of(" \t");
            std::string kline = lead == std::string::npos ? "" : line.substr(lead);
            if (kline.rfind(key, 0) != 0) continue;
            size_t c = kline.find(':');
            if (c != key.size()) continue;  // the colon must follow the key
            value += kline.substr(c + 1);
            // Block form: subsequent "- item" lines belong to the list;
            // anything else (a new key, a blank line) ends it.
            while (std::getline(ss, line)) {
                size_t l2 = line.find_first_not_of(" \t");
                if (l2 == std::string::npos) break;
                std::string cont = line.substr(l2);
                if (cont.rfind("-", 0) != 0) break;
                size_t h2 = cont.find('#');
                if (h2 != std::string::npos) cont = cont.substr(0, h2);
                value += " " + cont;
            }
        }
    };
    std::string text;
    collect("default-nameserver", text);
    collect("nameserver", text);
    // Walk the text for dotted-quad tokens.
    std::string tok;
    auto flush = [&]() {
        if (tok.empty()) return;
        uint32_t ip = parseIpv4(tok).value_or(0);
        if (ip != 0 && ip != 0x7F000001) out.push_back(ip);
        tok.clear();
    };
    for (char ch : text) {
        if ((ch >= '0' && ch <= '9') || ch == '.') {
            tok.push_back(ch);
        } else {
            flush();
        }
    }
    flush();
    return out;
}

bool fetchText(const std::string& url, std::string& yaml, std::string* err) {
    // Subscription servers rate-limit aggressively (measured: several rapid
    // refreshes in a row got an HTML 403 page on an otherwise healthy
    // subscription — a later retry with the same UA succeeded). Transient
    // rejections retry with backoff; the content guard runs on every
    // attempt, so a bad payload still never leaks through.
    for (int attempt = 1; attempt <= 3; ++attempt) {
        // Rate-limited endpoints (airport subscriptions throttle by IP/UA)
        // usually recover within a slow handful of seconds — give them room
        // instead of hammering and finishing with a page.
        if (attempt > 1) Sleep(attempt * 4000);  // 4s, 8s backoff
        if (fetchTextOnce(url, yaml, err)) return true;
    }
    return false;
}

bool fetchTextViaProxy(const std::string& url, uint16_t proxyPort,
                       std::string& yaml, std::string* err) {
    // Single attempt through a local HTTP CONNECT proxy (kernel mixed
    // port): the egress IP is the provider's own node — whitelisted for
    // subscription updates by airports that IP-auth downloads (xmrth's
    // documented policy; the home-IP direct path gets 403 AUTH_FAIL).
    // Content guard identical to the direct path.
    return fetchTextOnce(url, yaml, err, proxyPort);
}

bool looksLikeClashYaml(const std::string& text) {
    if (text.find("proxies:") == std::string::npos) return false;
    // HTML rejection (case-insensitive "<html").
    for (size_t i = 0; i + 5 <= text.size(); ++i) {
        if ((text[i] == '<' || text[i] == 'h') && i + 5 <= text.size()) {
            std::string head = text.substr(i, 5);
            for (auto& c : head) c = tolower(static_cast<unsigned char>(c));
            if (head == "<html") return false;
        }
    }
    return true;
}

namespace {

std::string trimCopy(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// Extract the text block of a top-level YAML section ("proxies:" at column
// 0 through the next column-0 key or EOF). Returns false when absent.
bool extractTopSection(const std::string& text, const std::string& key,
                       std::string* out, size_t* startOut, size_t* endOut) {
    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        if (nl == std::string::npos) nl = text.size();
        if (pos < nl && text.compare(pos, key.size(), key) == 0 &&
            text[pos + key.size()] == ':') {
            size_t end = nl + 1;
            while (end < text.size()) {
                size_t n2 = text.find('\n', end);
                if (n2 == std::string::npos) n2 = text.size();
                if (end < n2 && text[end] != ' ' && text[end] != '#' &&
                    text[end] != '-' && text[end] != '\r') {
                    size_t c2 = text.find(':', end);
                    if (c2 != std::string::npos && c2 < n2) break;
                }
                end = n2 + 1;
            }
            if (out) *out = text.substr(pos, end - pos);
            if (startOut) *startOut = pos;
            if (endOut) *endOut = end;
            return true;
        }
        pos = nl + 1;
    }
    return false;
}

// Replace the FIRST line whose trimmed form starts with `key` ("key:" or
// "key: value") with `replacement` (without newline).
bool replaceTopLine(std::string& text, const std::string& key,
                    const std::string& replacement, bool* found = nullptr) {
    if (found) *found = false;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        if (nl == std::string::npos) nl = text.size();
        size_t first = text.find_first_not_of(" \t\r", pos);
        if (first != std::string::npos && first < nl &&
            text.compare(first, key.size(), key) == 0 &&
            (first + key.size() >= nl || text[first + key.size()] == ':')) {
            std::string line = replacement;
            if (nl < text.size()) line += '\n';
            text.replace(pos, nl - pos + (nl < text.size() ? 1 : 0), line);
            if (found) *found = true;
            return true;
        }
        pos = nl + 1;
    }
    return false;
}

std::set<std::string> topLevelKeys(const std::string& yaml) {
    std::set<std::string> keys;
    size_t pos = 0;
    while (pos < yaml.size()) {
        size_t nl = yaml.find('\n', pos);
        if (nl == std::string::npos) nl = yaml.size();
        // Top-level YAML keys sit at column 0; indented lines are content.
        if (pos < nl && yaml[pos] != '#' && yaml[pos] != '-' && yaml[pos] != ' ') {
            size_t colon = yaml.find(':', pos);
            if (colon != std::string::npos && colon < nl) {
                keys.insert(yaml.substr(pos, colon - pos));
            }
        }
        pos = nl + 1;
    }
    return keys;
}

std::string processNameOfPid(uint32_t pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return {};
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    std::string name;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                name = wideToUtf8(pe.szExeFile);
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return name;
}

bool nameLooksLikeKernel(const std::string& name) {
    std::string l;
    for (char c : name) l.push_back(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
    return l.find("vortex") != std::string::npos ||
           l.find("clash") != std::string::npos ||
           l.find("mihomo") != std::string::npos ||
           l.find("sakura") != std::string::npos;
}

}  // namespace

std::optional<ActiveProfile> findClashForWindowsActiveProfile(
    const std::wstring& configDir) {
    std::wstring dir = configDir;
    if (dir.empty()) {
        PWSTR profile = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_Profile, 0, nullptr, &profile)) ||
            !profile) {
            return std::nullopt;
        }
        dir = profile;
        CoTaskMemFree(profile);
        dir += L"\\.config\\clash";
    }
    // CFW 0.20+ keeps list.yml under profiles\ (measured on this machine:
    // the root copy is absent while the real index lives in
    // profiles\list.yml). Try both locations.
    std::wstring listPath = dir + L"\\list.yml";
    HANDLE f = CreateFileW(listPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        listPath = dir + L"\\profiles\\list.yml";
        f = CreateFileW(listPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    if (f == INVALID_HANDLE_VALUE) return std::nullopt;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(f, &size) || size.QuadPart > (1 << 20)) {
        CloseHandle(f);
        return std::nullopt;
    }
    std::string text;
    text.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    BOOL ok = ReadFile(f, text.empty() ? nullptr : text.data(),
                       static_cast<DWORD>(text.size()), &read, nullptr);
    CloseHandle(f);
    if (!ok) return std::nullopt;
    text.resize(read);

    struct Entry {
        std::string name;
        std::string url;
    };
    std::vector<Entry> entries;
    Entry* cur = nullptr;
    int index = -1;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        if (nl == std::string::npos) nl = text.size();
        std::string line = text.substr(pos, nl - pos);
        size_t first = line.find_first_not_of(" \t\r");
        if (first != std::string::npos) {
            std::string body = line.substr(first);
            if (body.rfind("- time:", 0) == 0) {
                entries.push_back(
                    Entry{trimCopy(body.substr(7)), std::string()});
                cur = &entries.back();
            } else if (cur && body.rfind("url:", 0) == 0) {
                cur->url = trimCopy(body.substr(4));
            } else if (body.rfind("index:", 0) == 0) {
                index = atoi(body.substr(6).c_str());
            }
        }
        pos = nl + 1;
    }
    if (index < 0 || static_cast<size_t>(index) >= entries.size() ||
        entries[index].url.empty() || entries[index].name.empty()) {
        return std::nullopt;
    }
    ActiveProfile p;
    p.path = dir + L"\\profiles\\" + utf8ToWide(entries[index].name);
    p.url = entries[index].url;
    p.configDir = dir;
    return p;
}

std::string mergeCfwProfile(const std::string& sub, const std::string& profile) {
    std::string out = profile;
    // 1) Replace the proxies: section with the sub's.
    std::string subProxies, oldProxies;
    size_t oldStart = 0, oldEnd = 0;
    if (extractTopSection(sub, "proxies", &subProxies, nullptr, nullptr) &&
        extractTopSection(profile, "proxies", &oldProxies, &oldStart, &oldEnd)) {
        out.replace(oldStart, oldEnd - oldStart, subProxies);
    }
    // 2) Regenerate the first inline url-test group's node list (CFW's
    // "自动选择" carries every proxy name; a stale list breaks the profile).
    {
        size_t nl = 0;
        while (nl < out.size()) {
            size_t end = out.find('\n', nl);
            if (end == std::string::npos) end = out.size();
            std::string line = out.substr(nl, end - nl);
            if (line.find("type: url-test") != std::string::npos &&
                line.find("proxies: [") != std::string::npos) {
                // Old list: entries inside the brackets. Offsets must be
                // GLOBAL (nl + local) — the line-local offsets are only
                // valid inside `line`, not in `out`.
                size_t localOpen = line.find("proxies: [");
                size_t localClose = line.find(']', localOpen);
                if (localClose == std::string::npos) localClose = line.size();
                size_t open = nl + localOpen;
                size_t close = nl + localClose;
                std::string oldList = line.substr(localOpen + 11,
                                                  localClose - localOpen - 11);
                // New names from the sub's proxies block. Two formats exist
                // across providers: block style ("- name: 'X'") and inline
                // JSON flow ("- {\"name\":\"X\",...}" — the xmrth style).
                std::vector<std::string> names;
                {
                    // Inline JSON flow names.
                    size_t sp = 0;
                    while (sp < subProxies.size()) {
                        size_t np = subProxies.find("\"name\":\"", sp);
                        if (np == std::string::npos) break;
                        size_t vs = np + 8;
                        size_t ve = subProxies.find('"', vs);
                        if (ve == std::string::npos) break;
                        names.push_back(subProxies.substr(vs, ve - vs));
                        sp = ve + 1;
                    }
                }
                {
                    // Block-style names (may coexist; dedupe below).
                    size_t sp = 0;
                    while (sp < subProxies.size()) {
                        size_t snl = subProxies.find('\n', sp);
                        if (snl == std::string::npos) snl = subProxies.size();
                        std::string sline = subProxies.substr(sp, snl - sp);
                        size_t np = sline.find("- name:");
                        if (np != std::string::npos) {
                            std::string nm =
                                trimCopy(sline.substr(np + 7));
                            if (nm.size() >= 2 && nm.front() == '\'' &&
                                nm.back() == '\'') {
                                nm = nm.substr(1, nm.size() - 2);
                            }
                            bool have = false;
                            for (const auto& n : names) {
                                if (n == nm) { have = true; break; }
                            }
                            if (!have && !nm.empty()) names.push_back(nm);
                        }
                        sp = snl + 1;
                    }
                }
                // Preserve non-proxy pseudo entries from the old list
                // (CFW appends 剩余流量/套餐到期 from the subscription info).
                std::vector<std::string> keep;
                size_t cp = 0;
                while (cp < oldList.size()) {
                    size_t comma = oldList.find(", ", cp);
                    if (comma == std::string::npos) comma = oldList.size();
                    std::string item = oldList.substr(cp, comma - cp);
                    std::string itemT = trimCopy(item);
                    if (itemT.size() >= 2 && itemT.front() == '\'' &&
                        itemT.back() == '\'') {
                        itemT = itemT.substr(1, itemT.size() - 2);
                    }
                    bool isProxy = false;
                    for (const auto& n : names) {
                        if (n == itemT) { isProxy = true; break; }
                    }
                    // Only keep genuinely non-proxy pseudo entries — CFW's
                    // 剩余流量/套餐到期 lines carry a fullwidth colon; a
                    // stale REAL node name must be dropped.
                    if (!isProxy && !itemT.empty() &&
                        itemT.find("：") != std::string::npos) {
                        keep.push_back(itemT);
                    }
                    cp = comma + 2;
                }
                std::string newList;
                for (const auto& k : keep) {
                    if (!newList.empty()) newList += ", ";
                    newList += "'" + k + "'";
                }
                for (const auto& n : names) {
                    if (!newList.empty()) newList += ", ";
                    newList += "'" + n + "'";
                }
                out.replace(open, close - open + 1,
                            "proxies: [" + newList + "]");
                break;  // first url-test group only
            }
            nl = end + 1;
        }
    }
    return out;
}

std::string mergeIntoExisting(const std::string& sub, const std::string& existing,
                              int mixedPort) {
    std::string out = sub;
    // Listener port -> the running kernel's.
    replaceTopLine(out, "mixed-port", "mixed-port: " + std::to_string(mixedPort));
    // The kernel MUST run in rule mode: the kernel's OWN traffic (its DoH
    // upstream queries to alidns/doh.pub) falls through the rules and goes
    // through the node. In direct mode those queries fly out from China
    // directly, get GFW-poisoned (youtube.com -> Twitter IPs measured
    // 2026-08-28), and the kernel then serves poisoned answers to our DNS
    // cleanup and to every app. (SakuraCat's own GUI writes direct — we do
    // not replicate that; it silently breaks DNS.)
    replaceTopLine(out, "mode", "mode: rule");
    // external-controller: keep the existing config's value (the real
    // controller port is pinned by the -ext-ctl launch flag anyway).
    {
        size_t pos = 0;
        std::string extLine;
        while (pos < existing.size()) {
            size_t nl = existing.find('\n', pos);
            if (nl == std::string::npos) nl = existing.size();
            size_t first = existing.find_first_not_of(" \t\r", pos);
            if (first != std::string::npos && first < nl &&
                existing.compare(first, 19, "external-controller") == 0) {
                extLine = existing.substr(first, nl - first);
                break;
            }
            pos = nl + 1;
        }
        if (!extLine.empty()) {
            bool found = false;
            replaceTopLine(out, "external-controller", extLine, &found);
            if (!found) {
                // extLine already carries the "external-controller:" prefix.
                out += extLine + "\n";
            }
        }
    }
    // Append the GUI's own sections that the sub does NOT carry (measured:
    // SakuraCat adds a tun: block — appended verbatim preserves it).
    std::set<std::string> subKeys = topLevelKeys(out);
    size_t pos = 0;
    while (pos < existing.size()) {
        size_t nl = existing.find('\n', pos);
        if (nl == std::string::npos) nl = existing.size();
        // Only column-0 keys are sections; indented content stays put.
        if (pos < nl && existing[pos] != '#' && existing[pos] != '-' &&
            existing[pos] != ' ') {
            size_t colon = existing.find(':', pos);
            if (colon != std::string::npos && colon < nl) {
                std::string key = existing.substr(pos, colon - pos);
                if (!subKeys.count(key)) {
                    // Section = this line through the next column-0 key/EOF.
                    size_t end = nl + 1;
                    while (end < existing.size()) {
                        size_t n2 = existing.find('\n', end);
                        if (n2 == std::string::npos) n2 = existing.size();
                        if (end < n2 && existing[end] != '#' &&
                            existing[end] != '-' && existing[end] != ' ') {
                            size_t c2 = existing.find(':', end);
                            if (c2 != std::string::npos && c2 < n2) break;
                        }
                        end = n2 + 1;
                    }
                    out += "\n" + existing.substr(pos, end - pos);
                    pos = end;
                    continue;
                }
            }
        }
        pos = nl + 1;
    }
    return out;
}

std::string patchMixedPort(const std::string& yaml, int port) {
    std::string out = yaml;
    size_t pos = 0;
    while (pos < out.size()) {
        size_t nl = out.find('\n', pos);
        if (nl == std::string::npos) nl = out.size();
        size_t len = nl - pos;
        std::string line = out.substr(pos, len);
        // Trim leading whitespace for the compare only.
        size_t first = line.find_first_not_of(" \t\r");
        if (first != std::string::npos &&
            line.compare(first, 11, "mixed-port:") == 0) {
            std::string repl = line.substr(0, first) + "mixed-port: " +
                               std::to_string(port);
            if (nl < out.size()) repl += '\n';
            out.replace(pos, len + (nl < out.size() ? 1 : 0), repl);
            return out;  // first occurrence only
        }
        pos = nl + 1;
    }
    return out;
}

uint16_t parseMixedPort(const std::string& yaml) {
    for (const std::string& key :
         {"mixed-port", "port", "socks-port"}) {  // preference order
        size_t pos = 0;
        while (pos < yaml.size()) {
            size_t nl = yaml.find('\n', pos);
            if (nl == std::string::npos) nl = yaml.size();
            size_t first = yaml.find_first_not_of(" \t\r", pos);
            if (first != std::string::npos && first < nl &&
                yaml.compare(first, key.size(), key) == 0 &&
                yaml[first + key.size()] == ':') {
                std::string v =
                    yaml.substr(first + key.size() + 1, nl - first - key.size() - 1);
                size_t hash = v.find('#');
                if (hash != std::string::npos) v = v.substr(0, hash);
                v = trimCopy(v);
                if (v.size() >= 2 && ((v.front() == '\'' && v.back() == '\'') ||
                                      (v.front() == '"' && v.back() == '"'))) {
                    v = v.substr(1, v.size() - 2);
                }
                int n = atoi(v.c_str());
                if (n >= 1 && n <= 65535) return static_cast<uint16_t>(n);
                break;  // key present but unparseable: stop scanning it
            }
            pos = nl + 1;
        }
    }
    return 0;
}

bool loadConfigFile(const std::wstring& dir, std::string& yaml, std::string* err) {
    if (dir.empty()) {
        if (err) *err = "empty config dir";
        return false;
    }
    HANDLE f = CreateFileW((dir + L"\\config.yaml").c_str(), GENERIC_READ,
                           FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        if (err) *err = "cannot open config.yaml (error " +
                        std::to_string(GetLastError()) + ")";
        return false;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(f, &size) || size.QuadPart > (4 << 20)) {
        CloseHandle(f);
        if (err) *err = "config.yaml too large";
        return false;
    }
    yaml.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    BOOL ok = ReadFile(f, yaml.empty() ? nullptr : yaml.data(),
                       static_cast<DWORD>(yaml.size()), &read, nullptr);
    CloseHandle(f);
    if (!ok) {
        if (err) *err = "read of config.yaml failed";
        return false;
    }
    yaml.resize(read);
    return true;
}

bool saveConfigFile(const std::wstring& dir, const std::string& yaml,
                    std::string* err) {
    std::wstring path = dir + L"\\config.yaml";
    std::wstring tmp = path + L".tmp";
    HANDLE f = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                           nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        if (err) *err = "cannot create config.yaml.tmp (error " +
                        std::to_string(GetLastError()) + ")";
        return false;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(f, yaml.data(), static_cast<DWORD>(yaml.size()), &written,
                        nullptr);
    BOOL flushed = FlushFileBuffers(f);
    CloseHandle(f);
    if (!ok || !flushed || written != yaml.size()) {
        DeleteFileW(tmp.c_str());
        if (err) *err = "write of config.yaml failed";
        return false;
    }
    // Keep the previous config recoverable: a bad merge must never be able
    // to destroy the only copy (measured: an HTML 403 page was merged in
    // and the original config was lost with it).
    CopyFileW(path.c_str(), (path + L".bak").c_str(), FALSE);
    if (!MoveFileExW(tmp.c_str(), path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DWORD e = GetLastError();
        DeleteFileW(tmp.c_str());
        if (err) *err = "config.yaml replace failed (error " +
                        std::to_string(e) + ")";
        return false;
    }
    return true;
}

namespace {

bool listenerExistsOnPort(uint16_t port, uint32_t* pidOut) {
    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) !=
        ERROR_INSUFFICIENT_BUFFER) {
        return false;
    }
    std::vector<uint8_t> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        return false;
    }
    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (row.dwState != MIB_TCP_STATE_LISTEN) continue;
        if (ntohs(static_cast<uint16_t>(row.dwLocalPort & 0xFFFF)) != port) continue;
        if (row.dwLocalAddr != 0x0100007Fu && row.dwLocalAddr != 0) continue;
        if (pidOut) *pidOut = row.dwOwningPid;
        return true;
    }
    return false;
}

// Start the kernel with the WinSW service.xml launch command line.
bool startKernelFromServiceXml(const std::wstring& configDir, std::string* err) {
    std::wstring xmlPath = configDir + L"\\service.xml";
    HANDLE f = CreateFileW(xmlPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        if (err) *err = "cannot read service.xml";
        return false;
    }
    LARGE_INTEGER size{};
    std::string xml;
    if (!GetFileSizeEx(f, &size) || size.QuadPart > (1 << 20)) {
        CloseHandle(f);
        if (err) *err = "service.xml too large";
        return false;
    }
    xml.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    BOOL ok = ReadFile(f, xml.empty() ? nullptr : xml.data(),
                       static_cast<DWORD>(xml.size()), &read, nullptr);
    CloseHandle(f);
    if (!ok) {
        if (err) *err = "read of service.xml failed";
        return false;
    }
    xml.resize(read);
    auto extractTag = [&](const char* tag) -> std::string {
        std::string open = std::string("<") + tag + ">";
        std::string close = std::string("</") + tag + ">";
        size_t a = xml.find(open);
        if (a == std::string::npos) return {};
        size_t b = xml.find(close, a);
        if (b == std::string::npos) return {};
        return xml.substr(a + open.size(), b - a - open.size());
    };
    std::string exe = extractTag("executable");
    std::string args = extractTag("arguments");
    if (exe.empty()) {
        if (err) *err = "service.xml has no executable";
        return false;
    }
    std::wstring wexe = utf8ToWide(exe);
    std::wstring wargs = utf8ToWide(args);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cmd(wexe.size() + wargs.size() + 8);
    swprintf_s(cmd.data(), cmd.size(), L"\"%s\" %s", wexe.c_str(), wargs.c_str());
    if (!CreateProcessW(wexe.c_str(), cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr,
                        configDir.empty() ? nullptr : configDir.c_str(), &si,
                        &pi)) {
        if (err) *err = "kernel launch failed (error " +
                        std::to_string(GetLastError()) + ")";
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

bool waitForListener(uint16_t port, int timeoutMs) {
    const int step = 500;
    for (int t = 0; t < timeoutMs; t += step) {
        if (listenerExistsOnPort(port, nullptr)) return true;
        Sleep(step);
    }
    return listenerExistsOnPort(port, nullptr);
}

}  // namespace

bool loadTextFile(const std::wstring& path, std::string& text, std::string* err) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        if (err) *err = "cannot open file (error " +
                        std::to_string(GetLastError()) + ")";
        return false;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(f, &size) || size.QuadPart > (4 << 20)) {
        CloseHandle(f);
        if (err) *err = "file too large";
        return false;
    }
    text.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    BOOL ok = ReadFile(f, text.empty() ? nullptr : text.data(),
                       static_cast<DWORD>(text.size()), &read, nullptr);
    CloseHandle(f);
    if (!ok) {
        if (err) *err = "read failed";
        return false;
    }
    text.resize(read);
    return true;
}

bool saveTextFile(const std::wstring& path, const std::string& text,
                  std::string* err) {
    std::wstring tmp = path + L".tmp";
    HANDLE f = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                           nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        if (err) *err = "cannot create temp file (error " +
                        std::to_string(GetLastError()) + ")";
        return false;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(f, text.data(), static_cast<DWORD>(text.size()), &written,
                        nullptr);
    BOOL flushed = FlushFileBuffers(f);
    CloseHandle(f);
    if (!ok || !flushed || written != text.size()) {
        DeleteFileW(tmp.c_str());
        if (err) *err = "write failed";
        return false;
    }
    CopyFileW(path.c_str(), (path + L".bak").c_str(), FALSE);
    if (!MoveFileExW(tmp.c_str(), path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DWORD e = GetLastError();
        DeleteFileW(tmp.c_str());
        if (err) *err = "replace failed (error " + std::to_string(e) + ")";
        return false;
    }
    return true;
}

bool restartKernelOnPort(uint16_t port, const std::wstring& configDir,
                         std::string* err) {
    // 1) Kill the current instance (guarded: kernel-like process names only).
    uint32_t pid = 0;
    if (listenerExistsOnPort(port, &pid)) {
        std::string name = processNameOfPid(pid);
        if (!nameLooksLikeKernel(name)) {
            if (err) *err = "port " + std::to_string(port) +
                            " is owned by a non-kernel process (" + name +
                            "); refusing to kill it";
            return false;
        }
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!h) {
            if (err) *err = "cannot open kernel process " +
                            std::to_string(pid) + " (error " +
                            std::to_string(GetLastError()) + ")";
            return false;
        }
        BOOL killed = TerminateProcess(h, 0);
        CloseHandle(h);
        if (!killed) {
            if (err) *err = "cannot terminate kernel process (error " +
                            std::to_string(GetLastError()) + ")";
            return false;
        }
    }
    // 2) Wait for the wrapping service (WinSW onfailure=restart) to respawn.
    if (waitForListener(port, 10000)) return true;
    // 3) Nothing respawned it (e.g. the kernel was started directly by the
    // GUI, not under the service): start it from the service.xml command.
    if (!startKernelFromServiceXml(configDir, err)) return false;
    if (!waitForListener(port, 15000)) {
        if (err) *err = "kernel did not come back after restart";
        return false;
    }
    return true;
}

}  // namespace aps::subscription
