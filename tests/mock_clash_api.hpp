// Scriptable Clash external-controller mock for tests (loopback HTTP).
// Supports GET /version, GET /proxies, GET /proxies/{n}/delay, PUT
// /proxies/{g} with programmable responses and request recording.
#pragma once

#ifndef APS_BUILD_TESTS
#error "test-only header"
#endif

#include <winsock2.h>

#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "aps/net.hpp"
#include "aps/json.hpp"

namespace aps::test {

class MockClashApi {
public:
    // node -> latency ms (absent = node times out / dead).
    std::map<std::string, int> latencies;
    // node -> controller-retained delay samples (0 = recorded failure).
    std::map<std::string, std::vector<int>> histories;
    std::string selectorNow = "node-a";
    std::vector<std::string> nodes = {"node-a", "node-b", "node-c"};
    // Optional explicit group set (name -> members): overrides the default
    // single-group response — used by group-membership class tests.
    std::vector<std::pair<std::string, std::vector<std::string>>> groups;
    std::string groupName = "auto";
    std::string mode; // empty models old controllers without runtime metadata
    std::vector<std::string> rulePolicies;
    std::map<std::string, std::string> groupSelections;
    std::map<std::string, std::string> groupTypes;
    std::string secret;              // empty = no auth required
    bool failAllDelays = false;      // simulate "all nodes dead"
    bool useChunked = false;         // respond with Transfer-Encoding: chunked
    // name -> A record IPs (for the /dns/query endpoint)
    std::map<std::string, std::vector<std::string>> dnsAnswers;
    // Simulate a controller outage: /dns/query answers 500.
    std::atomic<bool> dnsFail{false};
    // Old Clash cores (CFW's 1.18) have NO /dns/query route: 404.
    std::atomic<bool> dnsQuery404{false};

    ~MockClashApi() { stop(); }

    bool start(uint16_t port = 0) {
        listener_ = net::makeTcpSocket();
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_addr.S_un.S_addr = htonl(0x7F000001);
        sa.sin_port = htons(port);
        if (bind(listener_, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == SOCKET_ERROR ||
            listen(listener_, SOMAXCONN) == SOCKET_ERROR) {
            net::closeSocket(listener_);
            return false;
        }
        sockaddr_in actual{};
        int len = sizeof(actual);
        getsockname(listener_, reinterpret_cast<sockaddr*>(&actual), &len);
        port_ = ntohs(actual.sin_port);
        stopping_ = false;
        thread_ = std::thread([this] { loop(); });
        return true;
    }

    void stop() {
        stopping_ = true;
        if (listener_ != INVALID_SOCKET) {
            shutdown(listener_, SD_BOTH);
            closesocket(listener_);
            listener_ = INVALID_SOCKET;
        }
        if (thread_.joinable()) thread_.join();
        std::vector<std::thread> ws;
        {
            std::lock_guard<std::mutex> lk(mu_);
            ws.swap(workers_);
        }
        for (auto& t : ws) if (t.joinable()) t.join();
    }

    uint16_t port() const { return port_; }

    std::vector<std::string> switches() {  // group::node of each PUT
        std::lock_guard<std::mutex> lk(mu_);
        return switches_;
    }
    size_t versionHits() {
        std::lock_guard<std::mutex> lk(mu_);
        return versionHits_;
    }
    // PUT /configs bodies (subscription-refresh reloads).
    std::vector<std::string> configsPut() {
        std::lock_guard<std::mutex> lk(mu_);
        return configsPut_;
    }
    bool lastRequestHadSecret() {
        std::lock_guard<std::mutex> lk(mu_);
        return lastHadSecret_;
    }

private:
    void loop() {
        while (!stopping_) {
            sockaddr_in peer{};
            int plen = sizeof(peer);
            SOCKET c = accept(listener_, reinterpret_cast<sockaddr*>(&peer), &plen);
            if (c == INVALID_SOCKET) break;
            std::thread t([this, c] { serve(c); });
            std::lock_guard<std::mutex> lk(mu_);
            workers_.push_back(std::move(t));
        }
    }

    static std::string urlDecode(const std::string& in) {
        std::string out;
        for (size_t i = 0; i < in.size(); ++i) {
            if (in[i] == '%' && i + 2 < in.size()) {
                auto hex = [](char h) -> int {
                    if (h >= '0' && h <= '9') return h - '0';
                    if (h >= 'a' && h <= 'f') return h - 'a' + 10;
                    if (h >= 'A' && h <= 'F') return h - 'A' + 10;
                    return -1;
                };
                int hi = hex(in[i + 1]), lo = hex(in[i + 2]);
                if (hi >= 0 && lo >= 0) {
                    out.push_back(static_cast<char>((hi << 4) | lo));
                    i += 2;
                    continue;
                }
            }
            out.push_back(in[i]);
        }
        return out;
    }

    void serve(SOCKET c) {
        std::string req;
        char buf[4096];
        while (req.find("\r\n\r\n") == std::string::npos && req.size() < 65536) {
            int n = net::recvSome(c, buf, sizeof(buf), 3000);
            if (n <= 0) {
                net::closeSocket(c);
                return;
            }
            req.append(buf, static_cast<size_t>(n));
        }
        std::string firstLine = req.substr(0, req.find("\r\n"));
        std::string method = firstLine.substr(0, firstLine.find(' '));
        std::string path = firstLine.substr(method.size() + 1,
                                            firstLine.find(' ', method.size() + 1) -
                                                method.size() - 1);
        bool hasSecret = !secret.empty() && req.find("Authorization: Bearer " + secret) !=
                                                std::string::npos;
        bool authOk = secret.empty() || hasSecret;

        std::string response;
        if (!authOk) {
            response = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
            net::sendAll(c, response.data(), response.size(), 3000);
            net::closeSocket(c);
            return;
        }
        {
            std::lock_guard<std::mutex> lk(mu_);
            lastHadSecret_ = hasSecret;
        }

        if (path == "/version") {
            {
                std::lock_guard<std::mutex> lk(mu_);
                versionHits_++;
            }
            std::string body = "{\"version\":\"v1.18.8\",\"meta\":true}";
            respond(c, "200 OK", body);
            return;
        }
        if (path == "/proxies") {
            auto esc = [](const std::string& s) {
                std::string o;
                for (char c : s) {
                    if (c == '"' || c == '\\') o += '\\';
                    o += c;
                }
                return o;
            };
            std::string body = "{\"proxies\":{";
            bool firstProxy = true;
            auto appendSelector = [&](const std::string& name,
                                      const std::string& now,
                                      const std::vector<std::string>& members) {
                if (!firstProxy) body += ",";
                firstProxy = false;
                body += "\"" + esc(name) +
                        "\":{\"type\":\"" + esc(groupTypes.count(name) ? groupTypes.at(name) : "Selector") + "\",\"now\":\"" +
                        esc(now) + "\",\"all\":[";
                for (size_t i = 0; i < members.size(); ++i) {
                    if (i) body += ",";
                    body += "\"" + esc(members[i]) + "\"";
                }
                body += "]}";
            };
            if (!groups.empty()) {
                // Explicit multi-group response (group-membership tests).
                for (size_t i = 0; i < groups.size(); ++i) {
                    appendSelector(groups[i].first,
                                   groupSelections.count(groups[i].first) ? groupSelections.at(groups[i].first)
                                       : i == 0 ? selectorNow : std::string(),
                                   groups[i].second);
                }
            } else {
                appendSelector(groupName, selectorNow, nodes);
            }
            for (const auto& [node, samples] : histories) {
                if (!firstProxy) body += ",";
                firstProxy = false;
                body += "\"" + esc(node) +
                        "\":{\"type\":\"Mock\",\"history\":[";
                for (size_t i = 0; i < samples.size(); ++i) {
                    if (i) body += ",";
                    body += "{\"delay\":" + std::to_string(samples[i]) + "}";
                }
                body += "]}";
            }
            body += "}}";
            respond(c, "200 OK", body);
            return;
        }
        if (method == "GET" && path == "/configs" && !mode.empty()) {
            respond(c, "200 OK", "{\"mode\":\"" + mode + "\"}");
            return;
        }
        if (method == "GET" && path == "/rules" && !mode.empty()) {
            json::Value payload = json::Value::makeObject(), rules = json::Value::makeArray();
            for (const auto& policy : rulePolicies) {
                auto rule = json::Value::makeObject(); rule.set("proxy", policy); rules.append(rule);
            }
            payload.set("rules", rules); respond(c, "200 OK", payload.dump());
            return;
        }
        // /proxies/{node}/delay
        if (method == "GET" && path.find("/delay") != std::string::npos) {
            std::string node = path.substr(std::string("/proxies/").size());
            node = node.substr(0, node.find("/delay"));
            node = urlDecode(node);  // percent-encoded by the client
            if (failAllDelays) {
                respond(c, "504 Gateway Timeout", "");
                return;
            }
            auto it = latencies.find(node);
            if (it == latencies.end()) {
                respond(c, "504 Gateway Timeout", "");
                return;
            }
            respond(c, "200 OK", "{\"delay\":" + std::to_string(it->second) + "}");
            return;
        }
        // GET /dns/query?name=...&type=A
        if (method == "GET" && path.find("/dns/query") == 0) {
            if (dnsQuery404.load()) {
                respond(c, "404 Not Found", "");
                return;
            }
            if (dnsFail.load()) {
                respond(c, "500 Internal Server Error", "");
                return;
            }
            std::string name;
            size_t npos = path.find("name=");
            if (npos != std::string::npos) {
                name = path.substr(npos + 5);
                size_t amp = name.find('&');
                if (amp != std::string::npos) name = name.substr(0, amp);
            }
            auto it = dnsAnswers.find(name);
            if (it == dnsAnswers.end() || it->second.empty()) {
                respond(c, "200 OK", "{\"Status\":2,\"Answer\":[]}");
                return;
            }
            std::string body = "{\"Status\":0,\"Answer\":[";
            for (size_t i = 0; i < it->second.size(); ++i) {
                if (i) body += ",";
                body += "{\"name\":\"" + name + ".\",\"type\":1,\"TTL\":60,\"data\":\"" +
                        it->second[i] + "\"}";
            }
            body += "]}";
            respond(c, "200 OK", body);
            return;
        }
        // PUT /configs?force=true (subscription hot-reload)
        if (method == "PUT" && path.find("/configs") == 0) {
            size_t nl = req.find("\r\n\r\n");
            std::string body = nl == std::string::npos ? "" : req.substr(nl + 4);
            {
                std::lock_guard<std::mutex> lk(mu_);
                configsPut_.push_back(body);
            }
            respond(c, "204 No Content", "");
            return;
        }
        // PUT /proxies/{group}
        if (method == "PUT") {
            std::string group = path.substr(std::string("/proxies/").size());
            size_t nl = req.find("\r\n\r\n");
            std::string body = nl == std::string::npos ? "" : req.substr(nl + 4);
            // {"name":"..."}
            std::string node;
            size_t pos = body.find("\"name\"");
            if (pos != std::string::npos) {
                pos = body.find(':', pos);
                size_t q1 = body.find('"', pos + 1);
                size_t q2 = q1 != std::string::npos ? body.find('"', q1 + 1)
                                                    : std::string::npos;
                if (q2 != std::string::npos) node = body.substr(q1 + 1, q2 - q1 - 1);
            }
            {
                std::lock_guard<std::mutex> lk(mu_);
                switches_.push_back(group + "::" + node);
                if (!node.empty()) selectorNow = node;
            }
            respond(c, "204 No Content", "");
            return;
        }
        respond(c, "404 Not Found", "");
    }

    void respond(SOCKET c, const std::string& status, const std::string& body) {
        std::string r;
        if (useChunked && !body.empty()) {
            // Split into two chunks (second may cut mid-multibyte char) to
            // exercise the client's chunked decoder.
            size_t half = body.size() / 2;
            std::printf("[mock] body=%zu half=%zu useChunked=%d\n", body.size(), half,
                        useChunked ? 1 : 0);
            auto hex = [](size_t v) {
                char buf[32];
                snprintf(buf, sizeof(buf), "%zx", v);
                return std::string(buf);
            };
            r = "HTTP/1.1 " + status +
                "\r\nContent-Type: application/json\r\n"
                "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" +
                hex(half) + "\r\n" + body.substr(0, half) + "\r\n" +
                hex(body.size() - half) + "\r\n" + body.substr(half) + "\r\n" +
                "0\r\n\r\n";
        } else {
            r = "HTTP/1.1 " + status +
                "\r\nContent-Type: application/json\r\n"
                "Content-Length: " + std::to_string(body.size()) +
                "\r\nConnection: close\r\n\r\n" + body;
        }
        net::sendAll(c, r.data(), r.size(), 3000);
        net::closeSocket(c);
    }

    SOCKET listener_ = INVALID_SOCKET;
    std::thread thread_;
    std::vector<std::thread> workers_;
    std::atomic<bool> stopping_{false};
    uint16_t port_ = 0;
    std::mutex mu_;
    std::vector<std::string> switches_;
    std::vector<std::string> configsPut_;
    size_t versionHits_ = 0;
    bool lastHadSecret_ = false;
};

}  // namespace aps::test
