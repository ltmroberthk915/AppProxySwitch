// GetExtendedTcpTable fallback for the SOCKET-event vs SYN race: when a SYN
// arrives without a mapping (defense line 2), the TCB row in SYN_SENT state
// carries the true owning PID.
#pragma once

#include <array>
#include <cstdint>
#include <optional>

namespace aps {

class ITcpTableQuery {
public:
    virtual ~ITcpTableQuery() = default;
    virtual std::optional<uint32_t> findOwnerByLocal(uint32_t localIp, uint16_t localPort) = 0;
    virtual std::optional<uint32_t> findUdpOwnerByLocal(
        uint32_t, uint16_t) { return std::nullopt; }
    virtual std::optional<uint32_t> findUdpOwnerByLocal6(
        const std::array<uint8_t, 16>&, uint16_t,
        uint32_t) { return std::nullopt; }
    // IPv6 counterpart used when the NETWORK-layer SYN wins the race against
    // the SOCKET-layer connect event. The address is kept in wire byte order,
    // exactly as both WinDivert and MIB_TCP6ROW_OWNER_PID expose it.
    virtual std::optional<uint32_t> findOwnerByLocal6(
        const std::array<uint8_t, 16>& localIp, uint16_t localPort) {
        (void)localIp;
        (void)localPort;
        return std::nullopt;
    }
};

class TcpTableQuery : public ITcpTableQuery {
public:
    std::optional<uint32_t> findOwnerByLocal(uint32_t localIp, uint16_t localPort) override;
    std::optional<uint32_t> findUdpOwnerByLocal(uint32_t localIp, uint16_t localPort) override;
    std::optional<uint32_t> findUdpOwnerByLocal6(
        const std::array<uint8_t, 16>& localIp, uint16_t localPort,
        uint32_t scopeId) override;
    std::optional<uint32_t> findOwnerByLocal6(
        const std::array<uint8_t, 16>& localIp, uint16_t localPort) override;
};

}  // namespace aps
