// Metadata-only rotating logger.
//
// PRIVACY INVARIANT: log lines may contain timestamps, process paths,
// destination IP:port, rule actions, error codes and byte counters. They must
// never contain packet payloads, credentials, cookies or any application-layer
// content. Callers are responsible for formatting within this contract.
#pragma once

#include <format>
#include <string>
#include <string_view>

namespace aps::log {

enum class Level { Debug = 0, Info = 1, Warn = 2, Error = 3 };

// Open <dir>\<baseName>.log (creating <dir> if needed). GUI and engine use
// separate base names so they never fight over one file. Returns false on
// failure; logging then becomes a no-op sink (never crashes the engine).
bool init(const std::wstring& dir, Level level, int maxFileMb, int maxFiles,
          const wchar_t* baseName = L"aps");
void shutdown();

// Re-read thresholds (config reload).
void setLevel(Level level);
Level level();

void write(Level level, std::string_view msg);

// Delete current + rotated files (GUI "清除日志").
void clear();

inline void d(std::string_view msg) { write(Level::Debug, msg); }
inline void i(std::string_view msg) { write(Level::Info, msg); }
inline void w(std::string_view msg) { write(Level::Warn, msg); }
inline void e(std::string_view msg) { write(Level::Error, msg); }

template <class... Args>
void df(std::format_string<Args...> fmt, Args&&... args) {
    if (level() <= Level::Debug) write(Level::Debug, std::format(fmt, std::forward<Args>(args)...));
}
template <class... Args>
void ifmt(std::format_string<Args...> fmt, Args&&... args) {
    if (level() <= Level::Info) write(Level::Info, std::format(fmt, std::forward<Args>(args)...));
}
template <class... Args>
void wf(std::format_string<Args...> fmt, Args&&... args) {
    if (level() <= Level::Warn) write(Level::Warn, std::format(fmt, std::forward<Args>(args)...));
}
template <class... Args>
void ef(std::format_string<Args...> fmt, Args&&... args) {
    if (level() <= Level::Error) write(Level::Error, std::format(fmt, std::forward<Args>(args)...));
}

}  // namespace aps::log
