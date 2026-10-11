#include "engine_client.hpp"

#include <shellapi.h>

#include "aps/engine_main.hpp"
#include "aps/path_util.hpp"
#include "aps/protocol.hpp"

namespace aps::gui {

EngineClient::EngineClient(Callbacks cbs) : cbs_(std::move(cbs)) {
    client_.start(controlPipeName(),
                  [this](const json::Value& msg) {
                      const json::Value* t = msg.find("type");
                      if (!t) return;
                      const std::string type = t->asString();
                      if (type == "STATUS" && cbs_.onStatus) cbs_.onStatus(msg.dump());
                      if (type == "STATS" && cbs_.onStats) cbs_.onStats(msg.dump());
                  },
                  [this](bool connected) {
                      // Send HELLO on (re)connect; the very first sendLine from
                      // the UI thread may have raced the connection and been
                      // dropped, which left the engine not knowing the GUI.
                      if (connected) {
                          client_.sendLine(ipc::hello(GetCurrentProcessId(), APS_VERSION));
                      }
                      if (cbs_.onConnection) cbs_.onConnection(connected);
                  });
}

bool EngineClient::pipeExists() {
    if (WaitNamedPipeW(controlPipeName().c_str(), 0)) return true;
    // WaitNamedPipe fails when no instance is waiting; check existence.
    HANDLE h = CreateFileW(controlPipeName().c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        return true;
    }
    return GetLastError() == ERROR_PIPE_BUSY;
}

bool EngineClient::launchEngine() {
    std::wstring exe = currentModulePath();
    if (exe.empty()) return false;
    std::wstring args = L"\"" + exe + L"\" --engine";
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = exe.c_str();
    sei.lpParameters = L"--engine";
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    if (!ShellExecuteExW(&sei)) {
        return false;  // UAC declined or launch failed
    }
    if (sei.hProcess) {
        // Give the engine a moment to create the pipe; do not block the UI
        // thread for the whole boot, just for basic failure detection.
        WaitForSingleObject(sei.hProcess, 1500);
        CloseHandle(sei.hProcess);
    }
    return true;
}

bool EngineClient::ensureEngineRunning() {
    if (!pipeExists()) {
        if (!launchEngine()) return false;
    }
    // Wait for a REAL connection, not just a pipe handle: a shutting-down
    // engine still holds its pipe for a few hundred ms, and the new engine
    // (launched above or by the user) needs a moment to boot.
    for (int i = 0; i < 200; ++i) {  // up to 10s
        if (client_.connected()) {
            connectPipe();
            return true;
        }
        Sleep(50);
    }
    // Still nothing: the pipe we saw may have been the dying engine's.
    // Launch once more (its mutex is released by now, so this succeeds).
    if (!pipeExists() && !launchEngine()) return false;
    for (int i = 0; i < 200; ++i) {
        if (client_.connected()) {
            connectPipe();
            return true;
        }
        Sleep(50);
    }
    return false;
}

void EngineClient::connectPipe() {
    // PipeClient auto-reconnects in the background; a no-op connect attempt
    // speeds up the first connection.
    (void)client_.sendLine(ipc::hello(GetCurrentProcessId(), APS_VERSION));
}

void EngineClient::disconnectPipe() {
    // Keep the client thread alive; just signal the engine to stop.
}

bool EngineClient::sendStop() { return client_.sendLine(ipc::stop()); }
bool EngineClient::sendReload() { return client_.sendLine(ipc::reload()); }
bool EngineClient::sendFlush(const std::string& ruleId) {
    return client_.sendLine(ipc::flush(ruleId));
}
bool EngineClient::sendSetEnabled(bool enabled) {
    return client_.sendLine(ipc::setEnabled(enabled));
}

bool EngineClient::sendNodeSwitch(const std::string& outletId, const std::string& requestId) {
    return client_.sendLine(ipc::nodeSwitch(outletId, requestId));
}

bool EngineClient::sendSetVisible(bool visible) {
    return client_.sendLine(ipc::setVisible(visible));
}

bool EngineClient::sendSubRefresh() { return client_.sendLine(ipc::subRefresh()); }

}  // namespace aps::gui
