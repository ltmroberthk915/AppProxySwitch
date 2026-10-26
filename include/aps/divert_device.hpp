// Neutral packet-interception abstraction so the engine can be driven by a
// fake device in tests (no driver, no admin). The real implementation talks
// to WinDivert; see src/core/divert_windivert.cpp.
#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace aps {

// Neutral mirror of the WinDivert address flags the engine consumes.
struct PacketMeta {
    bool outbound = false;
    bool loopback = false;
    bool impostor = false;
    bool ipv6 = false;
    uint32_t ifIdx = 0;   // original interface index (loopback = loopback ifidx)
    uint32_t subIfIdx = 0;
};

// Neutral mirror of WINDIVERT_ADDRESS.Socket for SOCKET-layer events.
struct SocketEventInfo {
    enum class Kind { Bind, Connect, Listen, Accept, Close };
    Kind kind = Kind::Connect;
    uint32_t pid = 0;
    uint32_t localIp = 0;    // host byte order (0 when not applicable)
    uint16_t localPort = 0;  // host byte order
    uint32_t remoteIp = 0;
    uint16_t remotePort = 0;
    uint8_t protocol = 6;    // 6 = TCP, 17 = UDP
};

constexpr size_t kMaxPacketSize = 65535 + 64;  // WinDivert MTU_MAX-ish headroom

class IDivertDevice {
public:
    virtual ~IDivertDevice() = default;

    // relayListenPort is baked into the network filters (both to exclude
    // loopback destinations and to identify reverse-path traffic upstream).
    // blockUdp/blockIpv6Tcp open additional handles used to drop rule
    // processes' QUIC/UDP and IPv6-TCP handshakes so they fall back to the
    // proxied IPv4 path. dnsFilter opens the UDP:53 handle used by the
    // anti-pollution DNS rewriter.
    virtual bool start(uint16_t relayListenPort, bool blockUdp, bool blockIpv6Tcp,
                       bool dnsFilter, std::string* err) = 0;

    // Unblock pending recvNetworkTcp/recvNetworkUdp/recvSocket calls. Safe to
    // call from another thread. After requestStop, recvs return false.
    virtual void requestStop() = 0;

    // Blocking receive of one outbound TCP packet that passed the network
    // filter. Returns false on stop/error (device unusable afterwards).
    virtual bool recvNetworkTcp(uint8_t* buf, size_t cap, size_t& len, PacketMeta& meta) = 0;
    // Progress of the TCP receive thread while an asynchronous receive is
    // pending. Idle waits are live; a separate timer must never fabricate it.
    virtual uint64_t tcpReceiveWaitTicks() const { return 0; }
    // Blocking receive of one outbound UDP packet (only when blockUdp).
    virtual bool recvNetworkUdp(uint8_t* buf, size_t cap, size_t& len, PacketMeta& meta) = 0;
    // Blocking receive of one outbound IPv6 TCP packet (only when blockIpv6Tcp).
    virtual bool recvNetworkTcp6(uint8_t* buf, size_t cap, size_t& len, PacketMeta& meta) = 0;
    // Blocking receive of one outbound UDP DNS packet (only when dnsFilter).
    virtual bool recvNetworkDns(uint8_t* buf, size_t cap, size_t& len, PacketMeta& meta) = 0;
    // Re-inject the (possibly rewritten) DNS packet; the caller swaps the
    // UDP src/dst ports for locally-delivered replies.
    virtual bool sendLastDns(const uint8_t* buf, size_t len) = 0;
    // Explicit metadata makes deferred DNS replies independent of the
    // receive thread's next packet. Checksums must already be valid.
    virtual bool sendDnsPacket(const uint8_t* buf, size_t len,
                               const PacketMeta& meta) = 0;

    // Re-inject the packet last returned by recvNetworkTcp/Udp with its
    // original direction; forceLoopback describes the local forward rewrite.
    // WinDivert ignores that flag on send; translated external replies must
    // use sendTcpPacket with explicit inbound metadata instead.
    virtual bool sendLastTcp(const uint8_t* buf, size_t len, bool forceLoopback) = 0;
    // Explicit metadata for translated replies. WinDivert ignores Loopback
    // on injection: Outbound selects the path, and inbound needs the flow's
    // original interface rather than the last local relay packet's interface.
    // The caller must recalculate IP/TCP checksums before sending.
    virtual bool sendTcpPacket(const uint8_t* buf, size_t len,
                               const PacketMeta& meta) = 0;
    virtual bool sendLastUdp(const uint8_t* buf, size_t len) = 0;
    virtual bool sendLastTcp6(const uint8_t* buf, size_t len) = 0;

    // Inject a synthesized packet (e.g., a teardown RST) without borrowing
    // mutable receive-thread state. Checksums must already be valid.
    virtual bool sendSyntheticTcp(const uint8_t* buf, size_t len,
                                  const PacketMeta& meta) = 0;

    // Blocking receive of one SOCKET-layer event. Returns false on stop/error.
    virtual bool recvSocket(SocketEventInfo& ev) = 0;
};

// Real implementation (src/core/divert_windivert.cpp). Requires admin.
std::unique_ptr<IDivertDevice> makeWinDivertDevice();

}  // namespace aps
