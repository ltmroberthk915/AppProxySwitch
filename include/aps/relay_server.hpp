// Local transparent relay: accepts WinDivert-redirected connections, looks up
// the original destination, tunnels through SOCKS5, and pumps bytes both ways.
#pragma once

#include <winsock2.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "aps/net.hpp"

namespace aps {

// Machine-readable session outcome.  Recovery decisions must use this value,
// never substrings from the diagnostic error message.
enum class RelayFailureKind {
    None,
    ProxyEndpoint,  // local SOCKS listener/port is unavailable or invalid
    Tunnel,         // listener answered; CONNECT or proxy-side pump failed
    Application,    // intercepted application closed/reset its side
    Configuration,  // credentials/protocol configuration is unusable
    Internal,
    Aborted,        // engine-initiated teardown
};

inline const char* relayFailureKindName(RelayFailureKind kind) {
    switch (kind) {
        case RelayFailureKind::None: return "none";
        case RelayFailureKind::ProxyEndpoint: return "proxy-endpoint";
        case RelayFailureKind::Tunnel: return "tunnel";
        case RelayFailureKind::Application: return "application";
        case RelayFailureKind::Configuration: return "configuration";
        case RelayFailureKind::Internal: return "internal";
        case RelayFailureKind::Aborted: return "aborted";
    }
    return "unknown";
}

// Per-session hooks owned by the engine (NAT entry). May be null in tests.
struct IRelaySessionSink {
    virtual ~IRelaySessionSink() = default;
    virtual void onBytes(uint64_t up, uint64_t down) = 0;
    virtual void onClosed() = 0;
};

// Everything the relay needs to know about one redirected connection.
struct RelayTarget {
    net::Endpoint4 origDst;
    net::Endpoint4 origSource; // frozen NAT source, may differ from relay peer
    uint32_t originalPid = 0;
    net::Endpoint4 proxy;      // egress SOCKS5 endpoint (per-rule outlet)
    std::string username;      // optional egress credentials
    std::string password;
    std::string ruleId;
    std::string outletId;      // engine-side outlet key (failure signal)
    std::shared_ptr<IRelaySessionSink> sink;   // optional
    // Opt-in passive TLS SNI recovery. A nonempty callback enables bounded
    // inspection; it must confirm that the name belongs to this session's
    // original destination (e.g. the engine's observed DNS answer). Unknown
    // names, ECH cover names and non-TLS traffic keep the original IP.
    std::function<bool(const std::string&)> allowTlsDomain;
    // Optional TCP-DNS bridge. When set, the relay consumes RFC 7766
    // two-byte-length-prefixed DNS messages locally. The callback returns a
    // clean response for queries it handles; false makes the relay query the
    // exact original resolver directly (fail-open, without involving SOCKS).
    std::function<bool(const uint8_t* query, size_t queryLen,
                       std::vector<uint8_t>& response)>
        resolveDns;
    // Session outcome report (the engine's real-traffic failure signal).
    // Called on the session thread right before the session is reaped.
    std::function<void(const std::string& outletId, uint32_t dstIp,
                       uint16_t dstPort, bool ok, RelayFailureKind failureKind,
                       const std::string& err)>
        onResult;
};

struct RelayParams {
    net::Endpoint4 proxy;
    std::string username;
    std::string password;
    int connectTimeoutMs = 5000;
    int pumpTimeoutMs = 10000;      // per-send wait inside the pump loop
    size_t maxSessions = 1024;
};

struct RelayCounters {
    std::atomic<uint64_t> accepted{0};
    std::atomic<uint64_t> unresolved{0};      // accept with no NAT entry (closed)
    std::atomic<uint64_t> socksFail{0};
    std::atomic<uint64_t> completed{0};
    std::atomic<uint64_t> aborted{0};
};

class RelaySession {
public:
    RelaySession(uint64_t id, SOCKET appSock, net::Endpoint4 appPeer, RelayTarget target,
                 const RelayParams& params);
    ~RelaySession();

    // Runs the pump on the calling thread; invokes onDone (still on this
    // thread) when the session ends. The server owns the thread.
    void run(std::function<void(RelaySession&)> onDone);
    void abort();   // thread-safe: unblocks the pump and tears both sockets down

    uint64_t id() const { return id_; }
    uint64_t bytesUp() const { return bytesUp_.load(); }
    uint64_t bytesDown() const { return bytesDown_.load(); }
    bool ok() const { return ok_.load(); }
    RelayFailureKind failureKind() const { return failureKind_.load(); }
    const std::string& error() const { return error_; }
    const net::Endpoint4& appPeer() const { return appPeer_; }
    const RelayTarget& target() const { return target_; }

private:
    bool runDnsBridge(RelayFailureKind& failureKind, std::string& err);

    uint64_t id_;
    SOCKET appSock_ = INVALID_SOCKET;
    SOCKET socksSock_ = INVALID_SOCKET;
    net::Endpoint4 appPeer_;
    RelayTarget target_;
    RelayParams params_;
    std::atomic<bool> abortFlag_{false};
    std::atomic<bool> ok_{false};
    std::atomic<RelayFailureKind> failureKind_{RelayFailureKind::None};
    std::string error_;
    std::atomic<uint64_t> bytesUp_{0};
    std::atomic<uint64_t> bytesDown_{0};
};

class RelayServer {
public:
    // Resolver maps the accepted peer (app ip:port) to its NAT entry info.
    using Resolver = std::function<std::optional<RelayTarget>(uint32_t appIp, uint16_t appPort)>;

    // Binds 127.0.0.1:listenPort (0 = ephemeral; query with listenPort()).
    bool start(const RelayParams& params, uint16_t listenPort, Resolver resolver,
               std::string* err);
    void stop();  // aborts + joins all sessions, closes the listener

    uint16_t listenPort() const { return listenPort_.load(); }
    size_t activeSessions() const;
    RelayCounters counters;

    // Abort sessions whose app-side peer matches (engine-initiated teardown).
    void abortByPeer(uint32_t appIp, uint16_t appPort);
    // Update proxy credentials/timeouts for future sessions (config reload).
    void updateParams(const RelayParams& params);

private:
    void acceptLoop();
    void reapSession(uint64_t id);

    // Session + its thread, kept alive together (self-detaching pattern:
    // the thread erases its entry and detaches itself as its final act).
    struct RelayEntry {
        std::shared_ptr<RelaySession> session;
        std::shared_ptr<std::thread> thread;
    };

    RelayParams params_;
    Resolver resolver_;
    SOCKET listener_ = INVALID_SOCKET;
    std::atomic<uint16_t> listenPort_{0};
    std::thread acceptThread_;
    std::atomic<bool> stopping_{false};
    std::mutex sessionsMu_;
    std::map<uint64_t, std::shared_ptr<RelayEntry>> sessions_;
    uint64_t nextSessionId_ = 1;
};

}  // namespace aps
