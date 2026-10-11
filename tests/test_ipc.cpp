// IPC protocol + pipe round-trip tests (in-process server & client).
#include <winsock2.h>

#include <atomic>
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

APS_TEST_MAIN();
