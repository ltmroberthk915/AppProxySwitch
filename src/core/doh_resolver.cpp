#include "aps/doh_resolver.hpp"

#include <windows.h>
#include <winhttp.h>

#include <map>
#include <mutex>

#include "aps/json.hpp"
#include "aps/net.hpp"
#include "aps/path_util.hpp"

namespace aps::doh {

namespace {

std::wstring wideFromUtf8(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                                nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        &w[0], n);
    return w;
}

// WinHttpOpen creates a session context. Keeping one context per local proxy
// lets WinHTTP retain its keep-alive pool between DNS requests instead of
// rebuilding that context for every uncached hostname. The DNS pump is
// currently single-threaded; the mutex also makes the lifetime safe if that
// changes later and prevents closeHttpProxySessions from racing a request.
class HttpProxySessionCache {
public:
    ~HttpProxySessionCache() { closeAll(); }

    HINTERNET getOrOpen(uint16_t proxyPort, std::string* err) {
        auto it = sessions_.find(proxyPort);
        if (it != sessions_.end()) return it->second;

        const std::wstring proxy =
            L"127.0.0.1:" + std::to_wstring(proxyPort);
        HINTERNET session = WinHttpOpen(L"AppProxySwitch/1.0",
                                        WINHTTP_ACCESS_TYPE_NAMED_PROXY,
                                        proxy.c_str(),
                                        L"127.0.0.1;<local>", 0);
        if (!session) {
            if (err) {
                *err = "doh: WinHttpOpen failed " +
                       std::to_string(GetLastError());
            }
            return nullptr;
        }
        sessions_.emplace(proxyPort, session);
        return session;
    }

    void closeAll() {
        std::lock_guard<std::mutex> lk(mu_);
        for (const auto& entry : sessions_) {
            WinHttpCloseHandle(entry.second);
        }
        sessions_.clear();
    }

    size_t size() {
        std::lock_guard<std::mutex> lk(mu_);
        return sessions_.size();
    }

    std::mutex& mutex() { return mu_; }

private:
    std::mutex mu_;
    std::map<uint16_t, HINTERNET> sessions_;
};

HttpProxySessionCache& sessionCache() {
    static HttpProxySessionCache cache;
    return cache;
}

}  // namespace

bool resolveViaHttpProxy(uint16_t proxyPort, uint32_t serverIp,
                         const std::string& name, std::vector<uint32_t>& ips,
                         int timeoutMs, std::string* err) {
    ips.clear();
    if (proxyPort == 0 || serverIp == 0) {
        if (err) *err = "doh: no endpoint";
        return false;
    }
    const std::string server = formatIpv4(serverIp);

    // The session is routed through the kernel's HTTP CONNECT proxy:
    // WinHTTP issues CONNECT to 127.0.0.1:proxyPort, then TLS to the DoH
    // server. Hold the cache lock through this synchronous request so timeout
    // mutation and lifecycle cleanup cannot race it.
    auto& cache = sessionCache();
    std::lock_guard<std::mutex> sessionLock(cache.mutex());
    HINTERNET session = cache.getOrOpen(proxyPort, err);
    if (!session) return false;
    WinHttpSetTimeouts(session, 0, timeoutMs, timeoutMs, timeoutMs);

    bool ok = false;
    HINTERNET connect = nullptr, request = nullptr;
    do {
        connect = WinHttpConnect(session, wideFromUtf8(server).c_str(),
                                 INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!connect) {
            if (err) *err = "doh: WinHttpConnect failed";
            break;
        }
        std::wstring path = L"/resolve?name=" + wideFromUtf8(name) +
                            L"&type=A";
        request = WinHttpOpenRequest(connect, L"GET", path.c_str(), nullptr,
                                     WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES,
                                     WINHTTP_FLAG_SECURE);
        if (!request) {
            if (err) *err = "doh: WinHttpOpenRequest failed";
            break;
        }
        if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(request, nullptr)) {
            DWORD e = GetLastError();
            if (err) *err = "doh: request failed " + std::to_string(e);
            break;
        }
        DWORD status = 0, size = sizeof(status);
        WinHttpQueryHeaders(request,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &size,
                            WINHTTP_NO_HEADER_INDEX);
        if (status != 200) {
            if (err) *err = "doh: HTTP " + std::to_string(status);
            break;
        }
        std::string body;
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(request, &avail) && avail > 0) {
            std::vector<char> chunk(avail);
            DWORD read = 0;
            if (!WinHttpReadData(request, chunk.data(), avail, &read) ||
                read == 0) {
                break;
            }
            body.append(chunk.data(), read);
        }
        json::Value v;
        std::string perr;
        if (!json::Value::parse(body, v, &perr) || !v.isObject()) {
            if (err) *err = "doh: bad JSON (" + perr + ")";
            break;
        }
        const json::Value* st = v.find("Status");
        if (!st || !st->isNumber() || st->asNumber() != 0) {
            if (err) *err = "doh: DNS status non-zero";
            break;
        }
        const json::Value* answers = v.find("Answer");
        if (!answers || !answers->isArray()) {
            if (err) *err = "doh: no Answer array";
            break;
        }
        for (size_t i = 0; i < answers->size(); ++i) {
            const json::Value& a = answers->at(i);
            if (!a.isObject()) continue;
            const json::Value* type = a.find("type");
            const json::Value* data = a.find("data");
            if (!type || !type->isNumber() || type->asNumber() != 1) continue;
            if (!data || !data->isString()) continue;
            // Host order, like every other IP in the engine.
            uint32_t ip = 0, b[4];
            if (sscanf_s(data->asString().c_str(), "%u.%u.%u.%u", &b[0], &b[1],
                         &b[2], &b[3]) == 4 &&
                b[0] < 256 && b[1] < 256 && b[2] < 256 && b[3] < 256) {
                ip = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
                ips.push_back(ip);
            }
        }
        if (ips.empty()) {
            if (err) *err = "doh: no A records";
            break;
        }
        ok = true;
    } while (false);

    if (request) WinHttpCloseHandle(request);
    if (connect) WinHttpCloseHandle(connect);
    return ok;
}

void closeHttpProxySessions() { sessionCache().closeAll(); }

size_t cachedHttpProxySessionCountForTest() {
    return sessionCache().size();
}

}  // namespace aps::doh
