// Named-pipe transport for the engine<->GUI control channel.
#pragma once

#include <windows.h>

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

#include "aps/json.hpp"

namespace aps::ipc {

// Engine side: single client, auto re-accept after disconnects.
class PipeServer {
public:
    using MsgHandler = std::function<void(const json::Value&)>;

    bool start(const std::wstring& name, MsgHandler onMsg, std::string* err);
    void stop();

    // Send one JSON line; a stalled reader times out and resets only IPC.
    bool sendLine(const std::string& line);
    bool hasClient() const { return clientConnected_.load(); }

private:
    void acceptLoop();
    void readLoop(HANDLE pipe);

    std::wstring name_;
    MsgHandler onMsg_;
    HANDLE pipe_ = INVALID_HANDLE_VALUE;
    HANDLE stopEvent_ = nullptr;
    std::thread thread_;
    std::atomic<bool> stopping_{false};
    std::atomic<bool> clientConnected_{false};
    std::mutex writeMu_;
};

// GUI side: background connect + read with auto-reconnect (1s backoff).
class PipeClient {
public:
    using MsgHandler = std::function<void(const json::Value&)>;
    using StateHandler = std::function<void(bool connected)>;

    ~PipeClient() { stop(); }

    void start(const std::wstring& name, MsgHandler onMsg, StateHandler onState);
    void stop();
    bool sendLine(const std::string& line);   // false on disconnect/write timeout
    bool connected() const { return connected_.load(); }

private:
    void run();

    std::wstring name_;
    MsgHandler onMsg_;
    StateHandler onState_;
    HANDLE stopEvent_ = nullptr;
    HANDLE resetEvent_ = nullptr;
    std::thread thread_;
    std::atomic<bool> stopping_{false};
    std::atomic<bool> connected_{false};
    std::mutex writeMu_;
    HANDLE pipe_ = INVALID_HANDLE_VALUE;
};

}  // namespace aps::ipc
