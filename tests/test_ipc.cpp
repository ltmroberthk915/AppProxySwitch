// IPC protocol + pipe round-trip tests (in-process server & client).
#include <winsock2.h>

#include <atomic>
#include <chrono>
#include <mutex>

#include "aps/pipe.hpp"
#include "aps/net.hpp"
#include "aps/path_util.hpp"
#include "aps/string_util.hpp"
#include "aps/protocol.hpp"
#include "testlib/appsw_test.h"

using namespace aps;
using namespace aps::ipc;

namespace {
struct WsaInit {
    WsaInit() { net::initWinsock(); }
};
WsaInit g_wsa;
}  // namespace

APS_TEST(ipc, protocol_accepts_valid_messages) {
    json::Value v;
    std::string errType;
    EXPECT_TRUE(parseMessage(hello(1234, "1.0.0"), v, &errType));
    EXPECT_STREQ(v.find("type")->asString(), "HELLO");
    EXPECT_EQ(v.find("pid")->asInt(), 1234);

    EXPECT_TRUE(parseMessage(stop(), v, &errType));
    EXPECT_STREQ(v.find("type")->asString(), "STOP");

    EXPECT_TRUE(parseMessage(flush("rule-1"), v, &errType));
    EXPECT_STREQ(v.find("rule_id")->asString(), "rule-1");

    EXPECT_TRUE(parseMessage(setEnabled(true), v, &errType));
    EXPECT_TRUE(v.find("enabled")->asBool());

    EXPECT_TRUE(parseMessage(setVisible(false), v, &errType));
    EXPECT_FALSE(v.find("visible")->asBool());
    EXPECT_TRUE(parseMessage(setVisible(true), v, &errType));
    EXPECT_TRUE(v.find("visible")->asBool());

    EXPECT_TRUE(parseMessage(welcome(true, "1.0.0", "RUNNING"), v, &errType));
    EXPECT_TRUE(v.find("admin")->asBool());
}

APS_TEST(ipc, protocol_rejects_invalid_messages) {
    json::Value v;
    std::string errType;
    auto checkFails = [&](const std::string& line) {
        EXPECT_FALSE(parseMessage(line, v, &errType));
    };
    checkFails("");
    checkFails("not json");
    checkFails("{}");                          // no type
    checkFails("{\"type\":123}");              // type not a string
    checkFails("{\"type\":\"EXPLODE\"}");      // unknown type
    checkFails("[1,2,3]");                     // not an object
    checkFails("{\"type\":\"LOG\",\"level\":\"info\",\"msg\":\"" + std::string(9000, 'x') +
               "\"}");
}

APS_TEST(ipc, pipe_roundtrip_both_directions) {
    std::wstring name = L"\\\\.\\pipe\\aps-test-" + utf8ToWide(newId());
    std::mutex mu;
    std::vector<json::Value> serverGot;
    std::vector<json::Value> clientGot;

    PipeServer server;
    EXPECT_TRUE(server.start(name, [&](const json::Value& v) {
        std::lock_guard<std::mutex> lk(mu);
        serverGot.push_back(v);
    }, nullptr));

    PipeClient client;
    std::atomic<bool> clientConnected{false};
    client.start(name, [&](const json::Value& v) {
        std::lock_guard<std::mutex> lk(mu);
        clientGot.push_back(v);
    }, [&](bool c) { if (c) clientConnected.store(true); });

    // Wait for the connection (auto-reconnect loop, 1s backoff).
    for (int i = 0; i < 100 && !clientConnected.load(); ++i) Sleep(50);
    EXPECT_TRUE(clientConnected.load());

    // client -> server
    EXPECT_TRUE(client.sendLine(hello(42, "test")));
    for (int i = 0; i < 100; ++i) {
        {
            std::lock_guard<std::mutex> lk(mu);
            if (!serverGot.empty()) break;
        }
        Sleep(50);
    }
    {
        std::lock_guard<std::mutex> lk(mu);
        EXPECT_EQ(serverGot.size(), 1u);
        if (!serverGot.empty()) {
            EXPECT_STREQ(serverGot[0].find("type")->asString(), "HELLO");
            EXPECT_EQ(serverGot[0].find("pid")->asInt(), 42);
        }
    }

    // server -> client
    EXPECT_TRUE(server.sendLine(welcome(true, "1.0.0", "RUNNING")));
    for (int i = 0; i < 100; ++i) {
        {
            std::lock_guard<std::mutex> lk(mu);
            if (!clientGot.empty()) break;
        }
        Sleep(50);
    }
    {
        std::lock_guard<std::mutex> lk(mu);
        EXPECT_EQ(clientGot.size(), 1u);
        if (!clientGot.empty()) {
            EXPECT_STREQ(clientGot[0].find("type")->asString(), "WELCOME");
            EXPECT_TRUE(clientGot[0].find("admin")->asBool());
        }
    }

    client.stop();
    server.stop();
}

APS_TEST(ipc, node_test_request_id_survives_protocol_encoding) {
    json::Value message;
    EXPECT_TRUE(json::Value::parse(ipc::nodeSwitch("auto-kernel","request-123"),message,nullptr));
    EXPECT_TRUE(message.find("outlet") && message.find("outlet")->asString()=="auto-kernel");
    EXPECT_TRUE(message.find("request_id") && message.find("request_id")->asString()=="request-123");
}

namespace {
struct PausedReader {
    HANDLE entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE resume = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::atomic<bool> paused{false};
    void onMessage() {
        if (paused.exchange(true)) return;
        SetEvent(entered);
        // Bound the pre-fix regression too: an infinite write must fail the
        // timing check rather than leave the test process stuck forever.
        WaitForSingleObject(resume, 2500);
    }
    ~PausedReader() { CloseHandle(entered); CloseHandle(resume); }
};

bool waitConnected(const PipeClient& client) {
    for (int i=0; i<100 && !client.connected(); ++i) Sleep(20);
    return client.connected();
}

std::string largeControlMessage() {
    return "{\"type\":\"GETSTATUS\",\"padding\":\""+std::string(60000,'x')+"\"}";
}
}

APS_TEST(ipc, client_write_times_out_when_engine_stops_reading) {
    PausedReader peer;
    std::atomic<bool> recovered{false};
    std::atomic<int> connections{0};
    const auto name=L"\\\\.\\pipe\\aps-stalled-client-"+utf8ToWide(newId());
    PipeServer server;
    EXPECT_TRUE(server.start(name,[&](const json::Value& message){
        peer.onMessage();
        const auto* pid=message.find("pid");
        if(pid&&pid->isNumber()&&pid->asInt()==77)recovered.store(true);
    },nullptr));
    PipeClient client;
    client.start(name,[](const json::Value&){},[&](bool connected){if(connected)++connections;});
    EXPECT_TRUE(waitConnected(client));
    EXPECT_TRUE(client.sendLine(hello(42,"test")));
    EXPECT_EQ(WaitForSingleObject(peer.entered,2000),WAIT_OBJECT_0);
    const auto started=std::chrono::steady_clock::now();
    const auto payload=largeControlMessage();
    const bool sent=client.sendLine(payload)&&client.sendLine(payload);
    const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now()-started).count();
    SetEvent(peer.resume);
    EXPECT_FALSE(sent);
    EXPECT_TRUE(elapsed<1500);
    for(int i=0;i<150&&(connections.load()<2||!client.connected());++i)Sleep(20);
    EXPECT_TRUE(connections.load()>=2);
    EXPECT_TRUE(client.sendLine(hello(77,"recovered")));
    for(int i=0;i<100&&!recovered.load();++i)Sleep(20);
    EXPECT_TRUE(recovered.load());
    client.stop();server.stop();
}

APS_TEST(ipc, client_stop_cancels_a_blocked_command_write) {
    PausedReader peer;
    const auto name=L"\\\\.\\pipe\\aps-stopped-client-"+utf8ToWide(newId());
    PipeServer server;
    EXPECT_TRUE(server.start(name,[&](const json::Value&){peer.onMessage();},nullptr));
    PipeClient client;
    client.start(name,[](const json::Value&){},nullptr);
    EXPECT_TRUE(waitConnected(client));
    EXPECT_TRUE(client.sendLine(hello(42,"test")));
    EXPECT_EQ(WaitForSingleObject(peer.entered,2000),WAIT_OBJECT_0);
    const auto payload=largeControlMessage();
    EXPECT_TRUE(client.sendLine(payload));
    std::thread writer([&]{client.sendLine(payload);});
    Sleep(50);
    const auto started=std::chrono::steady_clock::now();
    client.stop();
    const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now()-started).count();
    SetEvent(peer.resume);
    writer.join();server.stop();
    EXPECT_TRUE(elapsed<1000);
}

APS_TEST(ipc, client_can_reconnect_after_write_failure_before_first_read) {
    PausedReader peer;
    std::atomic<int> connections{0};
    std::atomic<bool> failed{false};
    std::atomic<bool> recovered{false};
    const auto name=L"\\\\.\\pipe\\aps-early-reset-"+utf8ToWide(newId());
    PipeServer server;
    EXPECT_TRUE(server.start(name,[&](const json::Value& message){
        peer.onMessage();
        const auto* pid=message.find("pid");
        if(pid&&pid->isNumber()&&pid->asInt()==77)recovered.store(true);
    },nullptr));
    PipeClient client;
    client.start(name,[](const json::Value&){},[&](bool connected){
        if(!connected || ++connections!=1)return;
        // GUI setup sends HELLO in this callback, before the first read exists.
        if(!client.sendLine(hello(42,"test")))return;
        if(WaitForSingleObject(peer.entered,2000)!=WAIT_OBJECT_0)return;
        const auto payload=largeControlMessage();
        failed.store(!(client.sendLine(payload)&&client.sendLine(payload)));
    });
    for(int i=0;i<125&&!failed.load();++i)Sleep(20);
    SetEvent(peer.resume);
    EXPECT_TRUE(failed.load());
    for(int i=0;i<150&&(connections.load()<2||!client.connected());++i)Sleep(20);
    EXPECT_TRUE(connections.load()>=2);
    EXPECT_TRUE(client.sendLine(hello(77,"recovered")));
    for(int i=0;i<100&&!recovered.load();++i)Sleep(20);
    EXPECT_TRUE(recovered.load());
    client.stop();server.stop();
}

APS_TEST(ipc, server_write_times_out_when_gui_stops_reading) {
    PausedReader peer;
    std::atomic<bool> recovered{false};
    std::atomic<int> connections{0};
    const auto name=L"\\\\.\\pipe\\aps-stalled-server-"+utf8ToWide(newId());
    PipeServer server;
    EXPECT_TRUE(server.start(name,[](const json::Value&){},nullptr));
    PipeClient client;
    client.start(name,[&](const json::Value& message){
        peer.onMessage();
        const auto* state=message.find("state");
        if(state&&state->isString()&&state->asString()=="RECOVERED")recovered.store(true);
    },[&](bool connected){if(connected)++connections;});
    EXPECT_TRUE(waitConnected(client));
    for(int i=0;i<100&&!server.hasClient();++i)Sleep(20);
    EXPECT_TRUE(server.sendLine(welcome(true,"test","RUNNING")));
    EXPECT_EQ(WaitForSingleObject(peer.entered,2000),WAIT_OBJECT_0);
    const auto started=std::chrono::steady_clock::now();
    const auto payload=largeControlMessage();
    const bool sent=server.sendLine(payload)&&server.sendLine(payload);
    const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now()-started).count();
    SetEvent(peer.resume);
    EXPECT_FALSE(sent);
    EXPECT_TRUE(elapsed<1500);
    for(int i=0;i<150&&(connections.load()<2||!server.hasClient());++i)Sleep(20);
    EXPECT_TRUE(connections.load()>=2);
    EXPECT_TRUE(server.sendLine(welcome(true,"test","RECOVERED")));
    for(int i=0;i<100&&!recovered.load();++i)Sleep(20);
    EXPECT_TRUE(recovered.load());
    client.stop();server.stop();
}

APS_TEST(ipc, server_stop_cancels_a_blocked_status_write) {
    PausedReader peer;
    const auto name=L"\\\\.\\pipe\\aps-stopped-server-"+utf8ToWide(newId());
    PipeServer server;
    EXPECT_TRUE(server.start(name,[](const json::Value&){},nullptr));
    PipeClient client;
    client.start(name,[&](const json::Value&){peer.onMessage();},nullptr);
    EXPECT_TRUE(waitConnected(client));
    for(int i=0;i<100&&!server.hasClient();++i)Sleep(20);
    EXPECT_TRUE(server.sendLine(welcome(true,"test","RUNNING")));
    EXPECT_EQ(WaitForSingleObject(peer.entered,2000),WAIT_OBJECT_0);
    const auto payload=largeControlMessage();
    EXPECT_TRUE(server.sendLine(payload));
    std::thread writer([&]{server.sendLine(payload);});
    Sleep(50);
    const auto started=std::chrono::steady_clock::now();
    server.stop();
    const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now()-started).count();
    SetEvent(peer.resume);
    writer.join();client.stop();
    EXPECT_TRUE(elapsed<1000);
}

APS_TEST_MAIN();
