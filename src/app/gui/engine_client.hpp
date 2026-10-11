// GUI-side engine lifecycle: launch elevated engine, talk to it over the
// control pipe, surface status/stats to the UI.
#pragma once

#include <windows.h>

#include <atomic>
#include <functional>
#include <string>

#include "aps/pipe.hpp"

namespace aps::gui {

class EngineClient {
public:
    // Called on a background thread; marshal to the UI thread yourself.
    struct Callbacks {
        std::function<void(const std::string& statusJson)> onStatus;
        std::function<void(const std::string& statsJson)> onStats;
        std::function<void(bool connected)> onConnection;
    };

    explicit EngineClient(Callbacks cbs);

    // If a pipe already exists, just connects. Otherwise launches
    // AppProxySwitch.exe --engine elevated (UAC). Returns false when the
    // launch itself fails.
    bool ensureEngineRunning();

    void connectPipe();
    void disconnectPipe();
    bool connected() const { return client_.connected(); }

    bool sendStop();
    bool sendReload();
    bool sendFlush(const std::string& ruleId);
    bool sendSetEnabled(bool enabled);
    bool sendNodeSwitch(const std::string& outletId = "", const std::string& requestId = "");
    bool sendSetVisible(bool visible);   // gates the 1s STATS push
    bool sendSubRefresh();               // "刷新订阅" (kernel hot-reload)

private:
    static bool pipeExists();
    bool launchEngine();

    Callbacks cbs_;
    ipc::PipeClient client_;
    std::atomic<bool> launchAttempted_{false};
};

}  // namespace aps::gui
