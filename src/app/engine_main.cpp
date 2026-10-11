#include "aps/engine_main.hpp"

#include <windows.h>
#include <dbghelp.h>

#include <atomic>
#include <memory>
#include <mutex>

#include "aps/config.hpp"
#include "aps/dpapi.hpp"
#include "aps/engine.hpp"
#include "aps/log.hpp"
#include "aps/net.hpp"
#include "aps/path_util.hpp"
#include "aps/pipe.hpp"
#include "aps/protocol.hpp"
#include "aps/string_util.hpp"
#include "aps/time_util.hpp"

namespace aps {

namespace {

LONG WINAPI engineCrashHandler(EXCEPTION_POINTERS* ep) {
    // Last-resort diagnostics: write a minidump for offline symbol analysis.
    if (ep && ep->ExceptionRecord) {
        log::ef("ENGINE CRASH code=0x{:08X} addr={}",
                ep->ExceptionRecord->ExceptionCode,
                reinterpret_cast<void*>(ep->ExceptionRecord->ExceptionAddress));
        HMODULE dbg = LoadLibraryW(L"dbghelp.dll");
        if (dbg) {
            auto dumpFn = reinterpret_cast<BOOL(WINAPI*)(HANDLE, DWORD, HANDLE,
                                                         MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION,
                                                         PMINIDUMP_USER_STREAM_INFORMATION,
                                                         PMINIDUMP_CALLBACK_INFORMATION)>(
                reinterpret_cast<void*>(
                    GetProcAddress(dbg, "MiniDumpWriteDump")));
            if (dumpFn) {
                std::wstring dir = appDataDir();
                std::wstring path = (dir.empty() ? std::wstring(L"C:\\")
                                                 : dir) + L"\\crash.dmp";
                HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (h != INVALID_HANDLE_VALUE) {
                    MINIDUMP_EXCEPTION_INFORMATION info{};
                    info.ThreadId = GetCurrentThreadId();
                    info.ExceptionPointers = ep;
                    info.ClientPointers = TRUE;
                    dumpFn(GetCurrentProcess(), GetCurrentProcessId(), h,
                           static_cast<MINIDUMP_TYPE>(0x00000002),  // MiniDumpWithFullMemory
                           &info, nullptr, nullptr);
                    CloseHandle(h);
                    log::ef("crash dump written: {}", wideToUtf8(path));
                }
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

log::Level parseLogLevel(const std::string& s) {
    if (s == "debug") return log::Level::Debug;
    if (s == "warn") return log::Level::Warn;
    if (s == "error") return log::Level::Error;
    return log::Level::Info;
}

}  // namespace

int runEngineMode(const std::wstring& configPath) {
    net::initWinsock();
    const std::wstring cfgPath = configPath.empty() ? defaultConfigPath() : configPath;

    // Single engine instance. If a previous instance is mid-shutdown (its
    // mutex is still held while STOP tears down), WAIT for it instead of
    // dying instantly — the GUI may relaunch us immediately after "停止截流".
    HANDLE single = CreateMutexW(nullptr, TRUE, L"Local\\AppProxySwitchEngine");
    if (single == nullptr) return 2;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (WaitForSingleObject(single, 15000) != WAIT_OBJECT_0) {
            CloseHandle(single);
            return 2;  // a real second instance is running
        }
        CloseHandle(single);
        single = CreateMutexW(nullptr, TRUE, L"Local\\AppProxySwitchEngine");
        if (single == nullptr || GetLastError() == ERROR_ALREADY_EXISTS) {
            if (single) CloseHandle(single);
            return 2;
        }
    }

    Config cfg;
    std::string cfgErr;
    std::vector<std::string> warnings;
    bool wasDefault = false;
    if (!loadConfigFile(cfgPath, cfg, &cfgErr, &warnings, &wasDefault)) {
        // Corrupt config: back it up and run with defaults rather than dying.
        std::wstring bak = cfgPath + L"." + utf8ToWide(fileTimestamp()) + L".bak";
        MoveFileExW(cfgPath.c_str(), bak.c_str(), MOVEFILE_REPLACE_EXISTING);
        cfg = Config::makeDefault();
        cfgErr = "config invalid (" + cfgErr + "); backed up, using defaults";
    }
    std::wstring dataDir = appDataDir();
    if (!dataDir.empty()) {
        log::init(dataDir + L"\\logs", parseLogLevel(cfg.logging.level),
                  cfg.logging.maxFileMb, cfg.logging.maxFiles);
    }
    if (!cfgErr.empty()) log::wf("{}", cfgErr);
    for (const auto& w : warnings) log::wf("config: {}", w);

    if (!crypto::isProcessElevated()) {
        log::ef("engine requires administrator privileges (WinDivert driver)");
        return 5;
    }
    SetUnhandledExceptionFilter(engineCrashHandler);

    EngineEvents ev;
    auto pipe = std::make_shared<ipc::PipeServer>();
    ev.onStatus = [pipe](const std::string& s) { pipe->sendLine(s); };
    ev.onStats = [pipe](const std::string& s) { pipe->sendLine(s); };
    ev.onLog = [pipe](const std::string& level, const std::string& msg) {
        json::Value m = json::Value::makeObject();
        m.set("type", "LOG");
        m.set("level", level);
        m.set("msg", msg.substr(0, 512));
        pipe->sendLine(m.dump());
    };
    // No GUI connected (process closed) OR the window is hidden in the tray
    // => the engine skips the per-second STATS build entirely. The GUI flips
    // the visibility gate via SET_VISIBLE when the window shows/hides.
    std::atomic<bool> statsVisible{true};
    ev.wantsStats = [pipe, &statsVisible] {
        return pipe->hasClient() && statsVisible.load();
    };

    auto engine = std::make_shared<Engine>(makeWinDivertDevice(), std::move(ev));
    std::string startErr;
    if (!engine->start(cfg, &startErr)) {
        log::ef("engine failed to start: {}", startErr);
        return 3;
    }

    HANDLE stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::atomic<bool> requestedStop{false};

    // Watch the config file: any save (GUI, scripts, hand-editing) reloads
    // automatically. This removes the dependence on pipe RELOAD messages,
    // which is fragile because the pipe is single-client.
    auto configMtime = [&cfgPath]() -> int64_t {
        WIN32_FILE_ATTRIBUTE_DATA info{};
        if (GetFileAttributesExW(cfgPath.c_str(), GetFileExInfoStandard, &info)) {
            ULARGE_INTEGER u;
            u.LowPart = info.ftLastWriteTime.dwLowDateTime;
            u.HighPart = info.ftLastWriteTime.dwHighDateTime;
            return static_cast<int64_t>(u.QuadPart);
        }
        return 0;
    };
    // Shared between the pipe RELOAD handler and the watcher tick: a save
    // that is already applied via an explicit RELOAD must not be applied a
    // second time, and the two paths must never call reloadConfig
    // concurrently (concurrent health-monitor rebuilds used to destroy a
    // running monitor -> silent engine death on "测试并连接").
    std::mutex reloadMu;
    int64_t lastMtime = configMtime();

    pipe->start(controlPipeName(), [&](const json::Value& msg) {
        std::string type;
        try {
        type = msg.find("type") ? msg.find("type")->asString() : "";
        if (type == "HELLO") {
            pipe->sendLine(ipc::welcome(crypto::isProcessElevated(), APS_VERSION,
                                        engineStateName(engine->state())));
            pipe->sendLine(engine->statusJson());
        } else if (type == "RELOAD") {
            std::lock_guard<std::mutex> rlk(reloadMu);
            Config c2;
            std::string err2;
            std::vector<std::string> w2;
            bool def2 = false;
            if (loadConfigFile(cfgPath, c2, &err2, &w2, &def2) && c2.validate(&err2)) {
                engine->reloadConfig(c2);
                log::setLevel(parseLogLevel(c2.logging.level));
                lastMtime = configMtime();  // the watcher won't duplicate
            } else {
                log::wf("RELOAD rejected: {}", err2);
            }
        } else if (type == "STOP") {
            requestedStop.store(true);
            SetEvent(stopEvent);
        } else if (type == "FLUSH") {
            const json::Value* rid = msg.find("rule_id");
            if (rid && rid->isString() && !rid->asString().empty()) {
                engine->flushConnections(rid->asString());
            } else {
                engine->flushConnections(std::nullopt);
            }
        } else if (type == "SET_ENABLED") {
            const json::Value* en = msg.find("enabled");
            if (en && en->isBoolean()) engine->setEnabled(en->asBool());
        } else if (type == "NODESWITCH") {
            const json::Value* oval = msg.find("outlet");
            const json::Value* request = msg.find("request_id");
            engine->requestNodeSwitchRound(
                oval && oval->isString() ? oval->asString() : std::string(), true,
                request && request->isString() && request->asString().size()<=128
                    ? request->asString() : std::string());
        } else if (type == "SET_VISIBLE") {
            const json::Value* v = msg.find("visible");
            statsVisible.store(v && v->isBoolean() ? v->asBool() : true);
        } else if (type == "SUBREFRESH") {
            engine->refreshSubscription();
        } else if (type == "GETSTATUS" || type == "GETSTATS") {
            // Engine pushes STATUS/STATS every second anyway.
        }
        } catch (const std::exception& e) {
            log::ef("pipe message '{}' crashed: {}", type, e.what());
        } catch (...) {
            log::ef("pipe message crashed: unknown exception");
        }
    }, nullptr);

    log::ifmt("engine process ready (version {})", APS_VERSION);

    // Block until STOP (or the process is killed; handles close -> traffic
    // resumes through the normal path automatically). The 1s tick also
    // services the config-file watcher.
    while (WaitForSingleObject(stopEvent, 1000) == WAIT_TIMEOUT) {
        int64_t mtime = configMtime();
        if (mtime != lastMtime) {
            std::lock_guard<std::mutex> rlk(reloadMu);
            lastMtime = mtime;
            Config c2;
            std::string err2;
            std::vector<std::string> w2;
            bool def2 = false;
            if (loadConfigFile(cfgPath, c2, &err2, &w2, &def2) && c2.validate(&err2)) {
                engine->reloadConfig(c2);
                log::setLevel(parseLogLevel(c2.logging.level));
                log::ifmt("config file changed: auto-reloaded (rules={})", c2.rules.size());
            } else {
                log::wf("config change rejected: {}", err2);
                lastMtime = configMtime();  // don't hammer on a corrupt file
            }
        }
    }

    pipe->sendLine(ipc::bye("stopped"));
    engine->stop();
    pipe->stop();
    log::i("engine exiting cleanly");
    CloseHandle(stopEvent);
    ReleaseMutex(single);
    CloseHandle(single);
    return 0;
}

}  // namespace aps
