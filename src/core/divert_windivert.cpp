// Real IDivertDevice backed by WinDivert 2.2.2.
//
// Filters (validated against WinDivert 2.2.2's compiler via
// WinDivertHelperCompileFilter; note that this version does NOT accept
// subnet masks like 127.0.0.0/8 or address range comparisons, so we exclude
// the (by far dominant) 127.0.0.1 here and guard the rest of 127/8 in the
// engine's packet handler):
//   TCP : outbound and !impostor and tcp and ip.DstAddr != 127.0.0.1
//   UDP : same with udp (only opened when UDP blocking is on)
//   SOCKET: "tcp or udp" with SNIFF|RECV_ONLY (RECV_ONLY is mandatory for
//           the SOCKET layer per the documentation).
//
// Loopback traffic is only ever seen on the outbound path, which is what
// makes a single outbound filter cover both the app->origDst and the
// relay->app directions. The 127.0.0.1 destination exclusion prevents
// proxy loops (relay -> Clash) and keeps ordinary local traffic untouched.
#include <windows.h>
#include <windivert.h>

#include <atomic>
#include <cstring>
#include <string>
#include <thread>

#include "aps/divert_device.hpp"
#include "aps/log.hpp"

namespace aps {

namespace {

// SOCKET-layer address layout (empirically confirmed on WinDivert 2.2.2 /
// Win11 26200): IPv4 is stored in element[0] in host byte order, with the
// 0x0000FFFF marker in element[1]. Alternative layouts are tolerated.
uint32_t extractIpv4FromMapped(const UINT32 addr[4]) {
    if (addr[1] == 0x0000FFFFu || addr[1] == 0xFFFF0000u) return addr[0];
    if (addr[2] == 0xFFFF0000u || addr[2] == 0x0000FFFFu) {
        uint8_t b[4];
        std::memcpy(b, &addr[3], 4);
        return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 |
               (uint32_t)b[3];
    }
    return 0;
}

const char* tcpFilter =
    "outbound and !impostor and tcp and ip.DstAddr != 127.0.0.1";
// DHCP (67/68) never enters the engine: network-critical traffic must not be
// proxied/blocked (the engine keeps a defensive check in handleUdpPacket too).
const char* udpFilter =
    "outbound and !impostor and udp and ip.DstAddr != 127.0.0.1 and "
    "udp.SrcPort != 67 and udp.DstPort != 67 and "
    "udp.SrcPort != 68 and udp.DstPort != 68";
// All outbound IPv6 TCP: no PID in the packet layer, so the engine passes
// everything through except rule processes' handshakes (socket-map lookup by
// port), which are dropped to force happy-eyeballs onto the proxied IPv4.
const char* tcp6Filter = "outbound and !impostor and tcp and ipv6";
// Receive native replies only to correlate TLS names, never rewrite them.
// All queries are classified by process before any blocking resolver work.
const char* dnsFilter =
    "!impostor and udp and ((outbound and udp.DstPort == 53) or "
    "(inbound and udp.SrcPort == 53))";
const char* socketFilter = "tcp or udp";

bool filterIsValid(const char* filter, WINDIVERT_LAYER layer) {
    const char* err = nullptr;
    UINT errPos = 0;
    BOOL ok = WinDivertHelperCompileFilter(filter, layer, nullptr, 0, &err, &errPos);
    if (!ok && err) {
        log::ef("WinDivert filter rejected: '{}' ({})", err, filter);
    }
    return ok != FALSE;
}

}  // namespace

class WinDivertDevice : public IDivertDevice {
public:
    ~WinDivertDevice() override { closeAll(); }

    bool start(uint16_t relayListenPort, bool blockUdp, bool blockIpv6Tcp,
               bool enableDns, std::string* err) override {
        (void)relayListenPort;  // loopback exclusion covers relay/proxy ports
        if (!filterIsValid(tcpFilter, WINDIVERT_LAYER_NETWORK) ||
            !filterIsValid(socketFilter, WINDIVERT_LAYER_SOCKET) ||
            (blockUdp && !filterIsValid(udpFilter, WINDIVERT_LAYER_NETWORK)) ||
            (blockIpv6Tcp && !filterIsValid(tcp6Filter, WINDIVERT_LAYER_NETWORK)) ||
            (enableDns && !filterIsValid(dnsFilter, WINDIVERT_LAYER_NETWORK))) {
            if (err) *err = "internal error: invalid WinDivert filter";
            return false;
        }
        tcpHandle_ = WinDivertOpen(tcpFilter, WINDIVERT_LAYER_NETWORK, 0, 0);
        if (tcpHandle_ == INVALID_HANDLE_VALUE) {
            if (err) *err = describeOpenError(GetLastError());
            closeAll();
            return false;
        }
        tcpRecvEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!tcpRecvEvent_) {
            if (err) *err = "TCP receive event creation failed: " + std::to_string(GetLastError());
            closeAll();
            return false;
        }
        tcpWaitTicks_.store(0);
        // Larger queues: every outbound TCP packet of the machine flows here.
        WinDivertSetParam(tcpHandle_, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
        WinDivertSetParam(tcpHandle_, WINDIVERT_PARAM_QUEUE_TIME, 2000);
        WinDivertSetParam(tcpHandle_, WINDIVERT_PARAM_QUEUE_SIZE, 16 * 1024 * 1024);

        if (blockUdp) {
            udpHandle_ = WinDivertOpen(udpFilter, WINDIVERT_LAYER_NETWORK, 1, 0);
            if (udpHandle_ == INVALID_HANDLE_VALUE) {
                if (err) *err = describeOpenError(GetLastError());
                closeAll();
                return false;
            }
        }

        if (blockIpv6Tcp) {
            tcp6Handle_ = WinDivertOpen(tcp6Filter, WINDIVERT_LAYER_NETWORK, 2, 0);
            if (tcp6Handle_ == INVALID_HANDLE_VALUE) {
                if (err) *err = describeOpenError(GetLastError());
                closeAll();
                return false;
            }
        }

        if (enableDns) {
            dnsHandle_ = WinDivertOpen(dnsFilter, WINDIVERT_LAYER_NETWORK, 3, 0);
            if (dnsHandle_ == INVALID_HANDLE_VALUE) {
                if (err) *err = describeOpenError(GetLastError());
                closeAll();
                return false;
            }

        }

        socketHandle_ = WinDivertOpen(socketFilter, WINDIVERT_LAYER_SOCKET, 0,
                                       WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
        if (socketHandle_ == INVALID_HANDLE_VALUE) {
            if (err) *err = describeOpenError(GetLastError());
            closeAll();
            return false;
        }
        return true;
    }

    void requestStop() override {
        HANDLE handles[5] = {tcpHandle_, udpHandle_, tcp6Handle_, dnsHandle_,
                             socketHandle_};
        for (HANDLE h : handles) {
            if (h != INVALID_HANDLE_VALUE) {
                WinDivertShutdown(h, WINDIVERT_SHUTDOWN_BOTH);
            }
        }
    }

    bool recvNetworkTcp(uint8_t* buf, size_t cap, size_t& len, PacketMeta& meta) override {
        WINDIVERT_ADDRESS addr{};
        UINT recvLen = 0;
        OVERLAPPED ov{};
        ov.hEvent = tcpRecvEvent_;
        ResetEvent(tcpRecvEvent_);
        if (!WinDivertRecvEx(tcpHandle_, buf, static_cast<UINT>(cap), &recvLen,
                             0, &addr, nullptr, &ov)) {
            const DWORD error = GetLastError();
            if (error != ERROR_IO_PENDING) {
                log::wf("TCP receive failed: error={}", error);
                return false;
            }
            // Keep the SAME receive pending across idle intervals. Cancelling
            // and resubmitting every second could lose a racing packet.
            while (true) {
                const DWORD wait = WaitForSingleObject(tcpRecvEvent_, 1000);
                if (wait == WAIT_TIMEOUT) {
                    tcpWaitTicks_.fetch_add(1);
                    continue;
                }
                if (wait != WAIT_OBJECT_0) {
                    log::ef("TCP receive wait failed: error={}", GetLastError());
                    CancelIoEx(tcpHandle_, &ov);
                    // ov/addr/buf must remain alive until cancellation finishes.
                    DWORD unused = 0;
                    GetOverlappedResult(tcpHandle_, &ov, &unused, TRUE);
                    return false;
                }
                DWORD completed = 0;
                if (!GetOverlappedResult(tcpHandle_, &ov, &completed, FALSE)) {
                    log::wf("TCP receive completion failed: error={}", GetLastError());
                    return false;
                }
                recvLen = completed;
                break;
            }
        }
        lastTcpAddr_ = addr;
        len = recvLen;
        fillMeta(addr, meta);
        return true;
    }
    uint64_t tcpReceiveWaitTicks() const override { return tcpWaitTicks_.load(); }
    bool recvNetworkUdp(uint8_t* buf, size_t cap, size_t& len, PacketMeta& meta) override {
        WINDIVERT_ADDRESS addr{};
        UINT recvLen = 0;
        if (!recv(udpHandle_, buf, cap, recvLen, addr)) return false;
        lastUdpAddr_ = addr;
        len = recvLen;
        fillMeta(addr, meta);
        return true;
    }
    bool recvNetworkTcp6(uint8_t* buf, size_t cap, size_t& len, PacketMeta& meta) override {
        WINDIVERT_ADDRESS addr{};
        UINT recvLen = 0;
        if (!recv(tcp6Handle_, buf, cap, recvLen, addr)) return false;
        lastTcp6Addr_ = addr;
        len = recvLen;
        fillMeta(addr, meta);
        return true;
    }
    bool recvNetworkDns(uint8_t* buf, size_t cap, size_t& len, PacketMeta& meta) override {
        WINDIVERT_ADDRESS addr{};
        UINT recvLen = 0;
        if (!recv(dnsHandle_, buf, cap, recvLen, addr)) return false;
        lastDnsAddr_ = addr;
        len = recvLen;
        fillMeta(addr, meta);
        return true;
    }

    static void fillMeta(const WINDIVERT_ADDRESS& addr, PacketMeta& meta) {
        meta.outbound = addr.Outbound != 0;
        meta.loopback = addr.Loopback != 0;
        meta.impostor = addr.Impostor != 0;
        meta.ipv6 = addr.IPv6 != 0;
        meta.ifIdx = addr.Network.IfIdx;
        meta.subIfIdx = addr.Network.SubIfIdx;
    }

    bool sendLastTcp(const uint8_t* buf, size_t len, bool forceLoopback) override {
        WINDIVERT_ADDRESS addr = lastTcpAddr_;
        if (forceLoopback) {
            // Only flag the loopback path; keep the original interface index,
            // which for self-addressed packets already is the loopback one.
            addr.Loopback = 1;
        }
        return send(tcpHandle_, buf, len, addr);
    }
    bool sendLastUdp(const uint8_t* buf, size_t len) override {
        return send(udpHandle_, buf, len, lastUdpAddr_);
    }
    bool sendLastTcp6(const uint8_t* buf, size_t len) override {
        return send(tcp6Handle_, buf, len, lastTcp6Addr_);
    }
    bool sendLastDns(const uint8_t* buf, size_t len) override {
        return send(dnsHandle_, buf, len, lastDnsAddr_);
    }

    bool sendDnsPacket(const uint8_t* buf, size_t len,
                       const PacketMeta& meta) override {
        WINDIVERT_ADDRESS addr{};
        addr.Layer = WINDIVERT_LAYER_NETWORK;
        addr.Event = WINDIVERT_EVENT_NETWORK_PACKET;
        addr.Outbound = meta.outbound;
        addr.Loopback = meta.loopback;
        addr.IPv6 = meta.ipv6;
        addr.IPChecksum = addr.UDPChecksum = 1;
        addr.Network.IfIdx = meta.ifIdx;
        addr.Network.SubIfIdx = meta.subIfIdx;
        return send(dnsHandle_, buf, len, addr);
    }

    bool sendSyntheticTcp(const uint8_t* buf, size_t len, bool loopback) override {
        WINDIVERT_ADDRESS addr = lastTcpAddr_;
        addr.Layer = WINDIVERT_LAYER_NETWORK;
        addr.Event = WINDIVERT_EVENT_NETWORK_PACKET;
        addr.Outbound = 1;
        addr.Loopback = loopback ? 1 : 0;
        // Reuse the last observed interface index (correct for loopback
        // delivery to local apps); zeroing it makes WinDivertSend fail with
        // ERROR_NO_DATA on some systems.
        addr.IPChecksum = 0;
        addr.TCPChecksum = 0;
        return send(tcpHandle_, buf, len, addr);
    }

    bool recvSocket(SocketEventInfo& ev) override {
        WINDIVERT_ADDRESS addr{};
        UINT unusedLen = 0;
        if (!recv(socketHandle_, nullptr, 0, unusedLen, addr)) return false;
        switch (addr.Event) {
            case WINDIVERT_EVENT_SOCKET_BIND: ev.kind = SocketEventInfo::Kind::Bind; break;
            case WINDIVERT_EVENT_SOCKET_CONNECT: ev.kind = SocketEventInfo::Kind::Connect; break;
            case WINDIVERT_EVENT_SOCKET_LISTEN: ev.kind = SocketEventInfo::Kind::Listen; break;
            case WINDIVERT_EVENT_SOCKET_ACCEPT: ev.kind = SocketEventInfo::Kind::Accept; break;
            case WINDIVERT_EVENT_SOCKET_CLOSE: ev.kind = SocketEventInfo::Kind::Close; break;
            default: return true;  // ignore unknown events, keep looping
        }
        ev.pid = addr.Socket.ProcessId;
        ev.protocol = addr.Socket.Protocol;
        ev.localIp = extractIpv4FromMapped(addr.Socket.LocalAddr);
        ev.remoteIp = extractIpv4FromMapped(addr.Socket.RemoteAddr);
        // WinDivert socket-layer ports are delivered in host byte order
        // (see the official socketdump example); verified in M4 smoke tests.
        ev.localPort = addr.Socket.LocalPort;
        ev.remotePort = addr.Socket.RemotePort;
        if (ev.localIp == 0 && (ev.localPort != 0 || ev.remotePort != 0)) {
            // Raw words for diagnosing the IPv4-mapped layout on this system.
            log::df("sockaddr raw L={:08x} {:08x} {:08x} {:08x} R={:08x} {:08x} {:08x} {:08x}",
                    addr.Socket.LocalAddr[0], addr.Socket.LocalAddr[1],
                    addr.Socket.LocalAddr[2], addr.Socket.LocalAddr[3],
                    addr.Socket.RemoteAddr[0], addr.Socket.RemoteAddr[1],
                    addr.Socket.RemoteAddr[2], addr.Socket.RemoteAddr[3]);
        }
        return true;
    }

private:
    static bool recv(HANDLE h, uint8_t* buf, size_t cap, UINT& outLen,
                     WINDIVERT_ADDRESS& outAddr) {
        return WinDivertRecv(h, buf, static_cast<UINT>(cap), &outLen, &outAddr) != FALSE;
    }

    static bool send(HANDLE h, const uint8_t* buf, size_t len, WINDIVERT_ADDRESS& addr) {
        UINT sendLen = 0;
        if (WinDivertSend(h, buf, static_cast<UINT>(len), &sendLen, &addr)) {
            return true;
        }
        DWORD e = GetLastError();
        if (e != ERROR_HOST_UNREACHABLE) {  // TTL-exhausted impostor: drop silently
            log::df("WinDivertSend failed: {}", e);
        }
        return false;
    }

    static std::string describeOpenError(DWORD e) {
        switch (e) {
            case ERROR_ACCESS_DENIED:
                return "需要管理员权限：引擎必须以管理员身份运行（拒绝访问 WinDivert 驱动）";
            case ERROR_INVALID_PARAMETER:
                return "WinDivert 过滤器无效（内部错误）";
            case ERROR_FILE_NOT_FOUND:
                return "找不到 WinDivert 驱动（WinDivert64.sys 需与程序同目录）";
            default:
                return "WinDivertOpen 失败，错误码 " + std::to_string(e);
        }
    }

    void closeAll() {
        HANDLE handles[5] = {tcpHandle_, udpHandle_, tcp6Handle_, dnsHandle_,
                             socketHandle_};
        tcpHandle_ = udpHandle_ = tcp6Handle_ = dnsHandle_ =
            socketHandle_ = INVALID_HANDLE_VALUE;
        for (HANDLE h : handles) {
            if (h != INVALID_HANDLE_VALUE) WinDivertClose(h);
        }
        if (tcpRecvEvent_) { CloseHandle(tcpRecvEvent_); tcpRecvEvent_ = nullptr; }
    }

    HANDLE tcpHandle_ = INVALID_HANDLE_VALUE;
    HANDLE tcpRecvEvent_ = nullptr;
    std::atomic<uint64_t> tcpWaitTicks_{0};
    HANDLE udpHandle_ = INVALID_HANDLE_VALUE;
    HANDLE tcp6Handle_ = INVALID_HANDLE_VALUE;
    HANDLE dnsHandle_ = INVALID_HANDLE_VALUE;
    HANDLE socketHandle_ = INVALID_HANDLE_VALUE;
    WINDIVERT_ADDRESS lastTcpAddr_{};
    WINDIVERT_ADDRESS lastUdpAddr_{};
    WINDIVERT_ADDRESS lastTcp6Addr_{};
    WINDIVERT_ADDRESS lastDnsAddr_{};
};

std::unique_ptr<IDivertDevice> makeWinDivertDevice() {
    return std::make_unique<WinDivertDevice>();
}

}  // namespace aps
