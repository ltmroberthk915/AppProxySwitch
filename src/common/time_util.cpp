#include "aps/time_util.hpp"

#include <chrono>
#include <cstdio>
#include <windows.h>

namespace aps {

int64_t nowMs() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    // 100ns ticks since 1601-01-01 -> ms since 1970-01-01
    return static_cast<int64_t>((u.QuadPart - 116444736000000000ULL) / 10000ULL);
}

int64_t steadyMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

std::string formatLocalTime(int64_t unixMs) {
    FILETIME ft;
    ULARGE_INTEGER u;
    u.QuadPart = static_cast<ULONGLONG>(unixMs * 10000 + 116444736000000000ULL);
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    SYSTEMTIME utc, local;
    FileTimeToSystemTime(&ft, &utc);
    SystemTimeToTzSpecificLocalTime(nullptr, &utc, &local);
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                  local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute,
                  local.wSecond, local.wMilliseconds);
    return buf;
}

std::string fileTimestamp() {
    SYSTEMTIME local;
    GetLocalTime(&local);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d%02d%02d-%02d%02d%02d", local.wYear,
                  local.wMonth, local.wDay, local.wHour, local.wMinute, local.wSecond);
    return buf;
}

}  // namespace aps
