#include "aps/relay_server.hpp"

#include "aps/log.hpp"
#include "aps/config.hpp"
#include "aps/path_util.hpp"
#include "aps/socks5_client.hpp"
#include "aps/tls_client_hello.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <vector>

namespace aps {

namespace {
constexpr size_t kPumpBuf = 64 * 1024;
// Local socket shutdown does not always wake a backpressured Windows select.
// Recheck explicit cancellation within the stop budget; idle streams do not
// expire and the configured queued-byte send deadline remains unchanged.
constexpr int kAbortCheckMs = 250;
static_assert(tls::kMaxClientHelloBytes <= kPumpBuf);
}  // namespace

RelaySession::RelaySession(uint64_t id, SOCKET appSock, net::Endpoint4 appPeer,
                           RelayTarget target, const RelayParams& params)
    : id_(id), appSock_(appSock), appPeer_(appPeer), target_(std::move(target)),
      params_(params) {}

RelaySession::~RelaySession() {
    closeSockets();
}

void RelaySession::closeSockets() {
    std::lock_guard<std::mutex> lock(socketsMu_);
    net::closeSocket(appSock_);
    net::closeSocket(socksSock_);
}

void RelaySession::replaceProxySocket(SOCKET socket) {
    std::lock_guard<std::mutex> lock(socketsMu_);
    net::closeSocket(socksSock_);
    socksSock_ = socket;
    if (abortFlag_.load() && socksSock_ != INVALID_SOCKET) {
        shutdown(socksSock_, SD_BOTH);
    }
}

bool RelaySession::runDnsBridge(RelayFailureKind& failureKind,
                                std::string& err) {
    enum class ReadResult { Ok, Eof, Error, Aborted };
    auto recvExactAbortable = [&](SOCKET s, char* data, size_t size,
                                  int timeoutMs) -> ReadResult {
        size_t got = 0;
        int waitedMs = 0;
        while (got < size) {
            if (abortFlag_.load()) return ReadResult::Aborted;
            const int sliceMs = timeoutMs == 0
                                    ? 1000
                                    : std::min(1000,
                                               std::max(1, timeoutMs - waitedMs));
            int n = net::recvSome(s, data + got, size - got, sliceMs);
            if (n == -2) {
                waitedMs += sliceMs;
                // App-side DNS connections may stay idle indefinitely. Only
                // direct upstream replies use a finite overall deadline.
                if (timeoutMs != 0 && waitedMs >= timeoutMs) {
                    return ReadResult::Error;
                }
                continue;
            }
            if (n < 0) return abortFlag_.load() ? ReadResult::Aborted
                                                : ReadResult::Error;
            if (n == 0) return got == 0 ? ReadResult::Eof : ReadResult::Error;
            got += static_cast<size_t>(n);
        }
        return ReadResult::Ok;
    };

    auto queryOriginal = [&](const std::vector<uint8_t>& query,
                             std::vector<uint8_t>& response) -> bool {
        if (abortFlag_.load()) {
            err = "aborted";
            return false;
        }
        replaceProxySocket(net::makeTcpSocket());
        if (abortFlag_.load()) {
            err = "aborted";
            return false;
        }
        if (socksSock_ == INVALID_SOCKET) {
            err = "TCP DNS fallback socket: " + net::lastError();
            return false;
        }
        std::string connectErr;
        if (net::connectWithTimeout(socksSock_, target_.origDst,
                                    params_.connectTimeoutMs,
                                    &connectErr) != 0) {
            err = "TCP DNS fallback connect: " + connectErr;
            return false;
        }
        uint8_t qlen[2] = {
            static_cast<uint8_t>(query.size() >> 8),
            static_cast<uint8_t>(query.size() & 0xFF)};
        if (net::sendAll(socksSock_, reinterpret_cast<const char*>(qlen),
                         sizeof(qlen), params_.pumpTimeoutMs) != 0 ||
            net::sendAll(socksSock_,
                         reinterpret_cast<const char*>(query.data()),
                         query.size(), params_.pumpTimeoutMs) != 0) {
            err = "TCP DNS fallback send: " + net::lastError();
            return false;
        }
        uint8_t rlen[2] = {};
        ReadResult rr = recvExactAbortable(
            socksSock_, reinterpret_cast<char*>(rlen), sizeof(rlen),
            params_.pumpTimeoutMs);
        if (rr != ReadResult::Ok) {
            err = rr == ReadResult::Aborted ? "aborted"
                                            : "TCP DNS fallback header failed";
            return false;
        }
        const size_t responseLen =
            (static_cast<size_t>(rlen[0]) << 8) | rlen[1];
        if (responseLen == 0) {
            err = "TCP DNS fallback returned an empty frame";
            return false;
        }
        response.resize(responseLen);
        rr = recvExactAbortable(
            socksSock_, reinterpret_cast<char*>(response.data()),
            response.size(), params_.pumpTimeoutMs);
        if (rr != ReadResult::Ok) {
            err = rr == ReadResult::Aborted ? "aborted"
                                            : "TCP DNS fallback response failed";
            return false;
        }
        replaceProxySocket(INVALID_SOCKET);
        return true;
    };

    while (!abortFlag_.load()) {
        uint8_t qlen[2] = {};
        // A TCP DNS connection is allowed to stay idle; 1-second slices only
        // exist so abort() is observed promptly. shutdown() also wakes recv.
        ReadResult rr = recvExactAbortable(
            appSock_, reinterpret_cast<char*>(qlen), sizeof(qlen), 0);
        if (rr == ReadResult::Eof) return true;
        if (rr == ReadResult::Aborted) {
            failureKind = RelayFailureKind::Aborted;
            err = "aborted";
            return false;
        }
        if (rr != ReadResult::Ok) {
            failureKind = RelayFailureKind::Application;
            err = "TCP DNS app header failed";
            return false;
        }
        const size_t queryLen =
            (static_cast<size_t>(qlen[0]) << 8) | qlen[1];
        if (queryLen == 0) {
            failureKind = RelayFailureKind::Application;
            err = "TCP DNS app sent an empty frame";
            return false;
        }
        std::vector<uint8_t> query(queryLen);
        rr = recvExactAbortable(appSock_,
                                reinterpret_cast<char*>(query.data()),
                                query.size(), 0);
        if (rr == ReadResult::Aborted) {
            failureKind = RelayFailureKind::Aborted;
            err = "aborted";
            return false;
        }
        if (rr != ReadResult::Ok) {
            failureKind = RelayFailureKind::Application;
            err = "TCP DNS app query failed";
            return false;
        }

        std::vector<uint8_t> response;
        bool handled = false;
        try {
            handled = target_.resolveDns &&
                      target_.resolveDns(query.data(), query.size(), response);
        } catch (...) {
            handled = false;  // exact original-resolver fallback below
        }
        if (!handled || response.empty() || response.size() > 0xFFFF) {
            response.clear();
            if (!queryOriginal(query, response)) {
                failureKind = abortFlag_.load() ? RelayFailureKind::Aborted
                                                : RelayFailureKind::Internal;
                return false;
            }
        }

        uint8_t outLen[2] = {
            static_cast<uint8_t>(response.size() >> 8),
            static_cast<uint8_t>(response.size() & 0xFF)};
        if (net::sendAll(appSock_, reinterpret_cast<const char*>(outLen),
                         sizeof(outLen), params_.pumpTimeoutMs) != 0 ||
            net::sendAll(appSock_,
                         reinterpret_cast<const char*>(response.data()),
                         response.size(), params_.pumpTimeoutMs) != 0) {
            failureKind = abortFlag_.load() ? RelayFailureKind::Aborted
                                            : RelayFailureKind::Application;
            err = failureKind == RelayFailureKind::Aborted
                      ? "aborted"
                      : "TCP DNS app response failed: " + net::lastError();
            return false;
        }
        const uint64_t up = static_cast<uint64_t>(query.size() + 2);
        const uint64_t down = static_cast<uint64_t>(response.size() + 2);
        bytesUp_.fetch_add(up);
        bytesDown_.fetch_add(down);
        if (target_.sink) target_.sink->onBytes(up, down);
    }
    failureKind = RelayFailureKind::Aborted;
    err = "aborted";
    return false;
}

void RelaySession::abort() {
    abortFlag_.store(true);
    // Unblock select() immediately on both sockets.
    std::lock_guard<std::mutex> lock(socketsMu_);
    if (appSock_ != INVALID_SOCKET) shutdown(appSock_, SD_BOTH);
    if (socksSock_ != INVALID_SOCKET) shutdown(socksSock_, SD_BOTH);
}

void RelaySession::run(std::function<void(RelaySession&)> onDone) {
    const auto startedAt = std::chrono::steady_clock::now();
    auto elapsedMs = [&] {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startedAt).count();
    };
    const char* firstEof = "none";
    int64_t firstEofMs = -1;
    const net::Endpoint4 proxy = target_.proxy.port != 0 ? target_.proxy : params_.proxy;
    net::Endpoint4 proxySource{};
    std::string tlsDomain, tlsName;
    const char* domainPolicy = "disabled";
    const char* addressType = "unconnected";
    auto noteEof = [&](const char* side) {
        // shutdown() from abort() can wake recv as EOF too. Keep that
        // teardown distinct from a peer's observed orderly close.
        if (abortFlag_.load()) return;
        if (firstEofMs < 0) {
            firstEof = side;
            firstEofMs = elapsedMs();
        }
        log::ifmt("relay flow={} eof_side={} first_eof={} at_ms={} up={} down={} "
                  "engine_pid={} pid={} source={}:{} destination={}:{} outlet={} "
                  "proxy_source={}:{} address_type={} target={}; "
                  "peer EOF does not verify HTTP/WSS completion", id_, side,
                  firstEof, elapsedMs(), bytesUp_.load(), bytesDown_.load(), GetCurrentProcessId(),
                  target_.originalPid, formatIpv4(target_.origSource.ip), target_.origSource.port,
                  formatIpv4(target_.origDst.ip), target_.origDst.port, target_.outletId,
                  formatIpv4(proxySource.ip), proxySource.port, addressType,
                  tlsDomain.empty() ? formatIpv4(target_.origDst.ip) : tlsDomain);
    };
    log::ifmt("relay flow={} pid={} source={}:{} peer={}:{} destination={}:{} outlet={}",
              id_, target_.originalPid, formatIpv4(target_.origSource.ip), target_.origSource.port,
              formatIpv4(appPeer_.ip), appPeer_.port, formatIpv4(target_.origDst.ip),
              target_.origDst.port, target_.outletId);
    auto finish = [&](bool ok, RelayFailureKind failureKind,
                      const std::string& err) {
        // abort() shuts both sockets down from another thread. That wake-up
        // can surface as app/socks recv error before the loop checks its flag;
        // the explicit engine teardown remains authoritative over that race.
        if (abortFlag_.load()) {
            ok = false;
            failureKind = RelayFailureKind::Aborted;
        } else if (ok && !tlsDomain.empty() &&
                   std::string_view(firstEof) == "proxy" &&
                   bytesUp_.load() > 0 && bytesDown_.load() == 0) {
            ok = false;
            failureKind = RelayFailureKind::TlsNoResponse;
            error_ = "proxy closed before any TLS response";
        }
        effectiveDomain_ = tlsDomain;
        ok_.store(ok);
        failureKind_.store(failureKind);
        if (failureKind == RelayFailureKind::Aborted) {
            error_ = "aborted";
        } else if (!err.empty()) {
            error_ = err;
        }
        log::ifmt("relay flow={} tcp_completed={} application_completion=unverified "
                  "failure={} first_eof={} first_eof_ms={} duration_ms={} "
                  "up={} down={} detail={} engine_pid={} pid={} source={}:{} "
                  "destination={}:{} outlet={} proxy={}:{} proxy_source={}:{} "
                  "address_type={} target={} domain_policy={} tls_name={}",
                  id_, ok, relayFailureKindName(failureKind), firstEof, firstEofMs,
                  elapsedMs(), bytesUp_.load(), bytesDown_.load(), error_, GetCurrentProcessId(),
                  target_.originalPid, formatIpv4(target_.origSource.ip), target_.origSource.port,
                  formatIpv4(target_.origDst.ip), target_.origDst.port, target_.outletId,
                  formatIpv4(proxy.ip), proxy.port, formatIpv4(proxySource.ip), proxySource.port,
                  addressType, tlsDomain.empty() ? formatIpv4(target_.origDst.ip) : tlsDomain,
                  domainPolicy, tlsName.empty() ? "none" : tlsName);
        closeSockets();
        if (target_.sink) target_.sink->onClosed();
        if (onDone) onDone(*this);
    };

    net::enableKeepalive(appSock_);

    if (target_.resolveDns) {
        RelayFailureKind failureKind = RelayFailureKind::None;
        std::string dnsErr;
        const bool ok = runDnsBridge(failureKind, dnsErr);
        finish(ok, failureKind, dnsErr);
        return;
    }

    std::string err;
    SOCKET socks = INVALID_SOCKET;
    // The per-rule outlet overrides the server defaults (multi-egress).
    std::string user = target_.proxy.port != 0 ? target_.username : params_.username;
    std::string pass = target_.proxy.port != 0 ? target_.password : params_.password;
    std::vector<uint8_t> prefix;
    if (target_.allowTlsDomain || !target_.tlsDomainAllowlist.empty()) {
        domainPolicy = "incomplete-or-timeout";
        // TCP has already been accepted: TLS clients can send ClientHello
        // before the upstream tunnel is established. Buffer only its prefix
        // and replay it byte-for-byte after CONNECT. Never wait indefinitely
        // for server-first protocols, a fragmented hello or an idle client.
        const int budgetMs = std::clamp(params_.connectTimeoutMs, 1, 200);
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(budgetMs);
        std::array<char, 4096> chunk{};
        while (!abortFlag_.load() && prefix.size() < tls::kMaxClientHelloBytes) {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            if (left <= 0) break;
            const size_t room = std::min(chunk.size(), tls::kMaxClientHelloBytes - prefix.size());
            const int n = net::recvSome(appSock_, chunk.data(), room, static_cast<int>(left));
            if (n <= 0) break;  // pump retains original EOF/error semantics
            prefix.insert(prefix.end(), chunk.data(), chunk.data() + n);
            const auto hello = tls::inspectClientHello(prefix.data(), prefix.size());
            if (hello.state == tls::HelloState::NeedMore) continue;
            if (hello.state == tls::HelloState::Name) {
                tlsName = hello.name;
                domainPolicy = "name-not-authorized";
                try {
                    if (tlsDomainAllowed(hello.name, target_.tlsDomainAllowlist)) {
                        tlsDomain = hello.name;
                        domainPolicy = "configured-name";
                    } else if (target_.allowTlsDomain && target_.allowTlsDomain(hello.name)) {
                        tlsDomain = hello.name;
                        domainPolicy = "observed-dns";
                    }
                } catch (...) {
                    // A failed correlation must not terminate the session
                    // thread or change the original destination.
                    domainPolicy = "authorization-error";
                }
            } else {
                domainPolicy = "no-visible-name";
            }
            break;
        }
    }
    if (abortFlag_.load()) {
        finish(false, RelayFailureKind::Aborted, "aborted");
        return;
    }
    Socks5FailureKind socksFailure = Socks5FailureKind::None;
    log::ifmt("relay flow={} domain_policy={} tls_name={} original={}:{}; "
              "TLS/HTTP not checked", id_, domainPolicy,
              tlsName.empty() ? "none" : tlsName, formatIpv4(target_.origDst.ip), target_.origDst.port);
    const bool connected = tlsDomain.empty()
        ? Socks5Client::connect(proxy, user, pass, target_.origDst,
                                params_.connectTimeoutMs, socks, &err, &socksFailure)
        : Socks5Client::connectDomain(proxy, user, pass, tlsDomain, target_.origDst.port,
                                      params_.connectTimeoutMs, socks, &err, &socksFailure);
    if (!connected) {
        // Fail-open semantics: abortive close (RST) so the application sees a
        // hard error and retries (the engine will let the retry go direct
        // while the proxy is degraded).
        net::enableAbortiveClose(appSock_);
        RelayFailureKind failureKind = RelayFailureKind::Internal;
        switch (socksFailure) {
            case Socks5FailureKind::ProxyEndpoint:
                failureKind = RelayFailureKind::ProxyEndpoint;
                break;
            case Socks5FailureKind::Tunnel:
                failureKind = RelayFailureKind::Tunnel;
                break;
            case Socks5FailureKind::Configuration:
                failureKind = RelayFailureKind::Configuration;
                break;
            case Socks5FailureKind::None:
            case Socks5FailureKind::Internal:
                failureKind = RelayFailureKind::Internal;
                break;
        }
        finish(false, failureKind, err);
        return;
    }
    replaceProxySocket(socks);
    sockaddr_in local{};
    int localLen = sizeof(local);
    const bool hasLocal = getsockname(socksSock_, reinterpret_cast<sockaddr*>(&local), &localLen) == 0;
    if (hasLocal) proxySource = {ntohl(local.sin_addr.s_addr), ntohs(local.sin_port)};
    addressType = tlsDomain.empty() ? "IPv4" : "DOMAIN";
    log::ifmt("relay flow={} SOCKS5 CONNECT accepted proxy={}:{} source={}:{} "
              "address_type={} target={}:{} domain_policy={} tls_name={}; TLS/HTTP not checked", id_,
              formatIpv4(proxy.ip), proxy.port,
              hasLocal ? formatIpv4(ntohl(local.sin_addr.s_addr)) : "unknown",
              hasLocal ? ntohs(local.sin_port) : 0,
              tlsDomain.empty() ? "IPv4" : "DOMAIN",
              tlsDomain.empty() ? formatIpv4(target_.origDst.ip) : tlsDomain, target_.origDst.port,
              domainPolicy, tlsName.empty() ? "none" : tlsName);
    net::enableKeepalive(socksSock_);
    if (!tlsDomain.empty()) {
        log::ifmt("relay flow={}: TLS domain preserved via '{}' -> {}:{} (SOCKS5 DOMAIN)",
                  id_, target_.outletId, tlsDomain, target_.origDst.port);
    }
    // A slow reader in one direction must not block traffic in the other.
    // select() followed by a blocking sendAll() can still block inside send
    // after its socket buffer fills, starving the opposite side indefinitely.
    u_long nonblocking = 1;
    if (ioctlsocket(appSock_, FIONBIO, &nonblocking) != 0 ||
        ioctlsocket(socksSock_, FIONBIO, &nonblocking) != 0) {
        finish(false, RelayFailureKind::Internal, "nonblocking pump: " + net::lastError());
        return;
    }
    bool appEof = false;    // app finished sending
    bool socksEof = false;  // proxy finished sending
    struct Pending {
        std::vector<char> data = std::vector<char>(kPumpBuf);
        size_t begin = 0, end = 0;
        std::chrono::steady_clock::time_point progress{};
        bool empty() const { return begin == end; }
    } up, down;
    if (!prefix.empty()) {
        std::copy(prefix.begin(), prefix.end(), up.data.begin());
        up.end = prefix.size();
        up.progress = std::chrono::steady_clock::now();
    }
    std::vector<uint8_t>().swap(prefix);
    const auto sendBudget = std::chrono::milliseconds(std::max(1, params_.pumpTimeoutMs));

    auto readInto = [&](SOCKET socket, Pending& pending, bool& eof,
                        SOCKET opposite, const char* side, RelayFailureKind failure) {
        const int r = recv(socket, pending.data.data(), static_cast<int>(pending.data.size()), 0);
        if (r == 0) {
            eof = true;
            noteEof(side);
            // Reads are enabled only when this direction's buffer is empty,
            // so every queued byte has been forwarded before propagating FIN.
            shutdown(opposite, SD_SEND);
        } else if (r == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) return true;
            finish(false, failure, std::string(side) + " recv: " + net::lastError());
            return false;
        } else {
            pending.begin = 0;
            pending.end = static_cast<size_t>(r);
            pending.progress = std::chrono::steady_clock::now();
        }
        return true;
    };
    auto writeFrom = [&](SOCKET socket, Pending& pending, bool uploading,
                         const char* side, RelayFailureKind failure) {
        const int w = send(socket, pending.data.data() + pending.begin,
                           static_cast<int>(pending.end - pending.begin), 0);
        if (w == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) return true;
            finish(false, failure, std::string(side) + " send: " + net::lastError());
            return false;
        }
        if (w > 0) {
            pending.begin += static_cast<size_t>(w);
            pending.progress = std::chrono::steady_clock::now();
            if (uploading) bytesUp_.fetch_add(static_cast<uint64_t>(w));
            else bytesDown_.fetch_add(static_cast<uint64_t>(w));
            if (target_.sink) target_.sink->onBytes(uploading ? w : 0, uploading ? 0 : w);
        }
        return true;
    };

    while (!abortFlag_.load()) {
        if (appEof && socksEof) break;
        const auto now = std::chrono::steady_clock::now();
        if ((!up.empty() && now - up.progress >= sendBudget) ||
            (!down.empty() && now - down.progress >= sendBudget)) {
            const bool blockedUp = !up.empty() && now - up.progress >= sendBudget;
            finish(false, blockedUp ? RelayFailureKind::Tunnel : RelayFailureKind::Application,
                   blockedUp ? "socks send timed out" : "app send timed out");
            return;
        }
        int waitMs = kAbortCheckMs;
        for (const Pending* pending : {&up, &down}) {
            if (!pending->empty()) {
                const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                    sendBudget - (now - pending->progress)).count();
                waitMs = std::min(waitMs, static_cast<int>(std::max<int64_t>(1, remaining)));
            }
        }
        fd_set rset, wset;
        FD_ZERO(&rset);
        FD_ZERO(&wset);
        if (!appEof && up.empty()) FD_SET(appSock_, &rset);
        if (!socksEof && down.empty()) FD_SET(socksSock_, &rset);
        if (!up.empty()) FD_SET(socksSock_, &wset);
        if (!down.empty()) FD_SET(appSock_, &wset);
        timeval tv{waitMs / 1000, (waitMs % 1000) * 1000};
        int n = select(0, &rset, &wset, nullptr, &tv);
        if (n < 0) {
            finish(false, RelayFailureKind::Internal,
                   "select failed: " + net::lastError());
            return;
        }
        if (n == 0) continue;  // tick: re-check abort flag

        // Read and write each direction independently; each queue is bounded
        // to one chunk. Idle streams have no send deadline.
        if (!appEof && FD_ISSET(appSock_, &rset)) {
            if (!readInto(appSock_, up, appEof, socksSock_, "application", RelayFailureKind::Application)) return;
        }
        if (!socksEof && FD_ISSET(socksSock_, &rset)) {
            if (!readInto(socksSock_, down, socksEof, appSock_, "proxy", RelayFailureKind::Tunnel)) return;
        }
        if (!up.empty() && FD_ISSET(socksSock_, &wset) &&
            !writeFrom(socksSock_, up, true, "socks", RelayFailureKind::Tunnel)) return;
        if (!down.empty() && FD_ISSET(appSock_, &wset) &&
            !writeFrom(appSock_, down, false, "app", RelayFailureKind::Application)) return;
    }
    const bool aborted = abortFlag_.load();
    finish(!aborted, aborted ? RelayFailureKind::Aborted
                             : RelayFailureKind::None,
           aborted ? "aborted" : "");
}

}  // namespace aps
