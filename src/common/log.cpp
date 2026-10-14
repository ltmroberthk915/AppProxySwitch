#include "aps/log.hpp"

#include <windows.h>

#include <cstdio>
#include <atomic>
#include <mutex>

#include "aps/path_util.hpp"
#include "aps/time_util.hpp"

namespace aps::log {

namespace {

struct LogState {
    std::mutex mu;
    HANDLE file = INVALID_HANDLE_VALUE;
    std::atomic<Level> level{Level::Info};
    int maxFileMb = 10;
    int maxFiles = 5;
    std::wstring dir;
    std::wstring base = L"aps";
    bool inited = false;
};

LogState& state() {
    static LogState s;
    return s;
}

const char* levelTag(Level l) {
    switch (l) {
        case Level::Debug: return "DEBUG";
        case Level::Info: return "INFO ";
        case Level::Warn: return "WARN ";
        case Level::Error: return "ERROR";
    }
    return "?????";
}

void closeFile(LogState& s) {
    if (s.file != INVALID_HANDLE_VALUE) {
        CloseHandle(s.file);
        s.file = INVALID_HANDLE_VALUE;
    }
}

std::wstring logFilePath(const std::wstring& dir, const std::wstring& name) {
    return dir + L"\\" + name;
}

HANDLE openFile(const std::wstring& path) {
    // Permit live readers; GUI and engine use separate base names.
    return CreateFileW(path.c_str(), FILE_APPEND_DATA,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, nullptr);
}

void rotateIfNeeded(LogState& s) {
    // Caller holds the mutex.
    if (s.file == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(s.file, &size)) return;
    if (size.QuadPart < static_cast<LONGLONG>(s.maxFileMb) * 1024 * 1024) return;

    closeFile(s);
    // <base>.log.(N-1) <- <base>.log.N ... <base>.log.1 <- <base>.log
    for (int i = s.maxFiles - 1; i >= 1; --i) {
        std::wstring from = logFilePath(s.dir, s.base + L".log." + std::to_wstring(i));
        std::wstring to = logFilePath(s.dir, s.base + L".log." + std::to_wstring(i + 1));
        MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_REPLACE_EXISTING);
    }
    MoveFileExW(logFilePath(s.dir, s.base + L".log").c_str(),
                logFilePath(s.dir, s.base + L".log.1").c_str(), MOVEFILE_REPLACE_EXISTING);
    // Reopen the (now rotated-away) base file so logging continues.
    s.file = openFile(logFilePath(s.dir, s.base + L".log"));
}

}  // namespace

bool init(const std::wstring& dir, Level level, int maxFileMb, int maxFiles,
          const wchar_t* baseName) {
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mu);
    closeFile(s);
    if (!ensureDirectory(dir)) return false;
    s.dir = dir;
    s.base = baseName ? baseName : L"aps";
    s.level.store(level, std::memory_order_relaxed);
    s.maxFileMb = maxFileMb > 0 ? maxFileMb : 10;
    s.maxFiles = maxFiles > 0 ? maxFiles : 5;
    s.file = openFile(logFilePath(dir, s.base + L".log"));
    s.inited = s.file != INVALID_HANDLE_VALUE;
    return s.inited;
}

void shutdown() {
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mu);
    closeFile(s);
    s.inited = false;
}

void setLevel(Level level) {
    state().level.store(level, std::memory_order_relaxed);
}

Level level() {
    return state().level.load(std::memory_order_relaxed);
}

void write(Level level, std::string_view msg) {
    auto& s = state();
    if (level < s.level.load(std::memory_order_relaxed)) return;
    std::string utf8 = std::format("{} [{}] {}\r\n", formatLocalTime(nowMs()),
                                   levelTag(level), msg);
    std::lock_guard<std::mutex> lk(s.mu);
    if (!s.inited || s.file == INVALID_HANDLE_VALUE) return;
    rotateIfNeeded(s);
    DWORD written = 0;
    WriteFile(s.file, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
}

void clear() {
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mu);
    closeFile(s);
    if (s.dir.empty()) return;
    for (int i = 1; i <= s.maxFiles + 1; ++i) {
        DeleteFileW(logFilePath(s.dir, s.base + L".log." + std::to_wstring(i)).c_str());
    }
    DeleteFileW(logFilePath(s.dir, s.base + L".log").c_str());
    if (s.inited) s.file = openFile(logFilePath(s.dir, s.base + L".log"));
}

}  // namespace aps::log
