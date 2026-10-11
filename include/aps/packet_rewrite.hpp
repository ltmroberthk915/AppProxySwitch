// IPv4/TCP packet parsing and rewriting. Thin layer over the WinDivert
// helper API (ParsePacket / CalcChecksums are pure user-mode calls, so this
// module works without admin rights and is unit-testable).
#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windivert.h>

#include <cstddef>
#include <cstdint>

namespace aps::pkt {

struct TcpPacket {
    PWINDIVERT_IPHDR ip = nullptr;
    PWINDIVERT_TCPHDR tcp = nullptr;
    const uint8_t* payload = nullptr;
    uint32_t payloadLen = 0;
    // Host-order convenience values.
    uint32_t srcIp = 0, dstIp = 0;
    uint16_t srcPort = 0, dstPort = 0;
    uint32_t seq = 0, ack = 0;
    bool syn = false, ackFlag = false, fin = false, rst = false;
};

// Parse an IPv4 TCP packet. Returns false for anything else (IPv6, UDP,
// fragments, truncated).
bool parseTcpPacket(const uint8_t* data, size_t len, TcpPacket& out);

// Minimal IPv4/UDP parse (engine's UDP block path).
bool parseUdpPacket(const uint8_t* data, size_t len, PWINDIVERT_IPHDR& ip,
                    PWINDIVERT_UDPHDR& udp, uint32_t& srcIpHost, uint16_t& srcPortHost,
                    uint32_t& dstIpHost, uint16_t& dstPortHost);

// Rewrite the destination (used for app -> origDst redirection).
void rewriteDst(TcpPacket& p, uint32_t newDstIpHost, uint16_t newDstPortHost);
// Rewrite the source (used for relay -> app return path).
void rewriteSrc(TcpPacket& p, uint32_t newSrcIpHost, uint16_t newSrcPortHost);

// Recalculate IPv4+TCP checksums for a modified packet.
void recalcChecksums(uint8_t* data, size_t len);

// The next sequence number the receiver will expect (SEQ accounting for
// payload/SYN/FIN), used to track nextSeqRelayToApp.
uint32_t nextSeq(const TcpPacket& p);

// Synthesize a 40-byte IPv4+TCP RST packet. Returns the length (0 on error).
size_t buildRst(uint32_t srcIpHost, uint16_t srcPortHost, uint32_t dstIpHost,
                uint16_t dstPortHost, uint32_t seqHost, bool withAck,
                uint32_t ackHost, uint8_t* out, size_t cap);

}  // namespace aps::pkt
