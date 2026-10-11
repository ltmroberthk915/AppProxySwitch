#include "aps/tcp_table.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <cstring>
#include <vector>

namespace aps {

std::optional<uint32_t> TcpTableQuery::findUdpOwnerByLocal(
    uint32_t localIp, uint16_t localPort) {
    ULONG size = 0;
    if (GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER)
        return std::nullopt;
    std::vector<uint8_t> buf(size);
    if (GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0) != NO_ERROR) return std::nullopt;
    auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
    std::optional<uint32_t> owner;
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (ntohs(static_cast<uint16_t>(row.dwLocalPort)) != localPort ||
            (row.dwLocalAddr != 0 && ntohl(row.dwLocalAddr) != localIp)) continue;
        if (owner && *owner != row.dwOwningPid) return std::nullopt;
        owner = row.dwOwningPid;
    }
    return owner;
}

std::optional<uint32_t> TcpTableQuery::findUdpOwnerByLocal6(
    const std::array<uint8_t, 16>& localIp, uint16_t localPort, uint32_t scopeId) {
    ULONG size = 0;
    if (GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6,
                            UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER)
        return std::nullopt;
    std::vector<uint8_t> buf(size);
    if (GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET6,
                            UDP_TABLE_OWNER_PID, 0) != NO_ERROR) return std::nullopt;
    auto* table = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buf.data());
    std::optional<uint32_t> owner;
    const std::array<uint8_t, 16> any{};
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (ntohs(static_cast<uint16_t>(row.dwLocalPort)) != localPort ||
            (row.dwLocalScopeId != 0 && row.dwLocalScopeId != scopeId) ||
            (std::memcmp(row.ucLocalAddr, any.data(), 16) != 0 &&
             std::memcmp(row.ucLocalAddr, localIp.data(), 16) != 0)) continue;
        if (owner && *owner != row.dwOwningPid) return std::nullopt;
        owner = row.dwOwningPid;
    }
    return owner;
}

std::optional<uint32_t> TcpTableQuery::findOwnerByLocal(uint32_t localIp, uint16_t localPort) {
    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) !=
        ERROR_INSUFFICIENT_BUFFER) {
        return std::nullopt;
    }
    std::vector<uint8_t> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) !=
        NO_ERROR) {
        return std::nullopt;
    }
    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_TCPROW_OWNER_PID& row = table->table[i];
        // dwLocalAddr is in network byte order; dwLocalPort is in network
        // byte order in the low word of the DWORD.
        uint32_t rowIp = ntohl(row.dwLocalAddr);
        uint16_t rowPort = ntohs(static_cast<uint16_t>(row.dwLocalPort & 0xFFFF));
        if (rowIp == localIp && rowPort == localPort) {
            return row.dwOwningPid;
        }
    }
    return std::nullopt;
}

std::optional<uint32_t> TcpTableQuery::findOwnerByLocal6(
    const std::array<uint8_t, 16>& localIp, uint16_t localPort) {
    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6,
                            TCP_TABLE_OWNER_PID_ALL, 0) !=
        ERROR_INSUFFICIENT_BUFFER) {
        return std::nullopt;
    }
    std::vector<uint8_t> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET6,
                            TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        return std::nullopt;
    }
    auto* table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_TCP6ROW_OWNER_PID& row = table->table[i];
        const uint16_t rowPort =
            ntohs(static_cast<uint16_t>(row.dwLocalPort & 0xFFFF));
        if (rowPort == localPort &&
            std::memcmp(row.ucLocalAddr, localIp.data(), localIp.size()) == 0) {
            return row.dwOwningPid;
        }
    }
    return std::nullopt;
}

}  // namespace aps
