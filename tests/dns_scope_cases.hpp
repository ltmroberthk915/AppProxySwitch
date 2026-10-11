// Included by the engine harness after its shared fixtures.
namespace {
std::vector<uint8_t> dns6Packet(uint16_t port, const std::vector<uint8_t>& query) {
    std::vector<uint8_t> p(48 + query.size(), 0);
    p[0] = 0x60; p[6] = 17; p[7] = 64;
    const uint16_t size = htons(static_cast<uint16_t>(8 + query.size()));
    std::memcpy(p.data() + 4, &size, 2);
    p[8] = p[24] = 0xFE; p[9] = p[25] = 0x80;
    p[23] = 2; p[39] = 1;
    const uint16_t sp = htons(port), dp = htons(53);
    std::memcpy(p.data() + 40, &sp, 2);
    std::memcpy(p.data() + 42, &dp, 2);
    std::memcpy(p.data() + 44, &size, 2);
    std::memcpy(p.data() + 48, query.data(), query.size());
    WinDivertHelperCalcChecksums(p.data(), static_cast<UINT>(p.size()), nullptr, 0);
    return p;
}
bool waitDns(Harness& h, size_t count, int timeout = 3000) {
    for (int t = 0; t < timeout && h.device->sentDnsCount() < count; t += 10) Sleep(10);
    return h.device->sentDnsCount() >= count;
}
struct UdpOwnerTable : ITcpTableQuery {
    uint32_t owner = 100;
    std::optional<uint32_t> findOwnerByLocal(uint32_t, uint16_t) override { return std::nullopt; }
    std::optional<uint32_t> findUdpOwnerByLocal(uint32_t, uint16_t) override { return owner; }
    std::optional<uint32_t> findUdpOwnerByLocal6(const std::array<uint8_t,16>&, uint16_t, uint32_t) override { return owner; }
};
}

APS_TEST(engine, scoped_dns_preserves_unlisted_direct_block_and_unknown_queries) {
    for (int variant = 0; variant < 4; ++variant) {
        Harness h;
        auto c = h.makeConfig(); c.routing.dnsCleanupGlobal = false;
        if (variant == 1) c.rules[0].action = "direct";
        if (variant == 2) c.rules[0].action = "block";
        auto table = std::make_unique<UdpOwnerTable>();
        table->owner = variant == 0 ? 200 : (variant == 3 ? 999 : 100);
        h.fakeTcpTable = std::move(table);
        h.start(c);
        size_t count = 0;
        for (int type : {1, 28}) {
            auto query = dnsQueryBytes("domestic.example.com");
            query[query.size()-3] = static_cast<uint8_t>(type);
            const auto v4 = buildUdpPacket(kAppIp, 53100, 0xC0A80301, 53, query);
            const auto v6 = dns6Packet(53100, query);
            h.device->pushDns(v4);
            h.device->pushDns(v6, {true,false,false,true,11});
            EXPECT_TRUE(waitDns(h, count + 2));
            if (h.device->sentDnsCount() >= count + 2) {
                EXPECT_TRUE(h.device->sentDns(count++) == v4);
                EXPECT_TRUE(h.device->sentDns(count++) == v6);
            }
        }
        h.stop();
    }
}

APS_TEST(engine, scoped_dns_proxy_keeps_clean_a_and_aaaa_on_both_families) {
    MockClashApi api;
    api.dnsAnswers["proxy.example.com"] = {"1.2.3.4"}; EXPECT_TRUE(api.start());
    Harness h; auto c = h.makeConfig(); c.routing.dnsCleanupGlobal = false;
    c.proxy.clashApi.port = api.port();
    h.fakeTcpTable = std::make_unique<UdpOwnerTable>();
    h.start(c);
    size_t count = 0;
    for (bool v6 : {false, true}) for (int type : {1,28}) {
        auto q = dnsQueryBytes("proxy.example.com"); q[q.size()-3] = static_cast<uint8_t>(type);
        auto p = v6 ? dns6Packet(53100,q) : buildUdpPacket(kAppIp,53100,0xC0A80301,53,q);
        h.device->pushDns(p,{true,false,false,v6,11});
        EXPECT_TRUE(waitDns(h, ++count));
        if(h.device->sentDnsCount()<count) continue;
        const auto r = h.device->sentDns(count-1); const size_t off = v6 ? 48 : 28;
        EXPECT_TRUE(r.size() >= off + 12);
        EXPECT_EQ(r[off+2] & 0x80, 0x80);
        EXPECT_EQ(r[off+3] & 15, 0);
        EXPECT_EQ(r[off+7], type == 1 ? 1 : 0);
        EXPECT_EQ(r[v6 ? 23 : 15], 1); // DNS server becomes source
    }
    h.stop(); api.stop();
}

APS_TEST(engine, scoped_dns_toggle_and_pause_apply_live_to_both_families) {
    Harness h; auto c = h.makeConfig(); c.routing.dnsCleanup = false;
    h.start(c);
    size_t count = 0;
    for (int mode : {0,1,2,3}) {
        c.routing.dnsCleanup = mode != 0 && mode != 3;
        h.engine->reloadConfig(c); h.engine->setEnabled(mode != 2);
        auto q = dnsQueryBytes("proxy.example.com"); q[q.size()-3] = 28;
        for (bool v6 : {false,true}) {
            auto p = v6 ? dns6Packet(53100,q) : buildUdpPacket(kAppIp,53100,0xC0A80301,53,q);
            h.device->pushDns(p,{true,false,false,v6,11});
            EXPECT_TRUE(waitDns(h,++count));
            if(h.device->sentDnsCount()<count) continue;
            const auto r=h.device->sentDns(count-1);
            if (mode == 1) EXPECT_EQ(r[(v6?48:28)+2]&0x80,0x80);
            else EXPECT_TRUE(r == p);
        }
    }
    h.stop();
}

APS_TEST(engine, scoped_dns_slow_proxy_does_not_block_direct_and_disable_cancels_reply) {
    Harness h; auto c=h.makeConfig(); c.routing.dnsCleanupGlobal=false;
    c.routing.dnsServers={"8.8.8.8"};
    const auto k=makeKernel("verge-mihomo.exe",socks().port(),1);
    std::atomic<bool> entered{false}, release{false};
    h.beforeStart=[&](Engine& e) {
        e.seedDiscoveredKernelsForTest({k});
        e.setDohResolverForTest([&](uint16_t,uint32_t,const std::string&,std::vector<uint32_t>& ips,int,std::string*) {
            entered.store(true);
            for(int i=0;i<300 && !release.load();++i) Sleep(10);
            ips={0x01020304}; return true;
        });
    };
    h.start(c); h.pushConnectEvent(53100,100,0xC0A80301,53,17);
    h.pushConnectEvent(53101,200,0xC0A80301,53,17);
    auto q=dnsQueryBytes("slow.example.com");
    auto proxy=buildUdpPacket(kAppIp,53100,0xC0A80301,53,q);
    auto direct=buildUdpPacket(kAppIp,53101,0xC0A80301,53,q);
    h.device->pushDns(proxy);
    for(int i=0;i<100 && !entered.load();++i) Sleep(10);
    EXPECT_TRUE(entered.load());
    h.device->pushDns(direct);
    EXPECT_TRUE(waitDns(h,1,500));
    if(h.device->sentDnsCount()) EXPECT_TRUE(h.device->sentDns(0)==direct);
    c.routing.dnsCleanup=false; h.engine->reloadConfig(c); release.store(true);
    EXPECT_TRUE(waitDns(h,2));
    if(h.device->sentDnsCount()>1) EXPECT_TRUE(h.device->sentDns(1)==proxy);
    h.stop();
}

APS_TEST(engine, scoped_dns_native_answers_preserve_tls_domain_without_global_cleanup) {
    MockSocks5Server kernel;
    kernel.setBehavior(MockSocksBehavior::EchoConnect); EXPECT_TRUE(kernel.start());
    Harness h; auto c=h.makeConfig(); c.proxy.port=kernel.port();
    c.routing.dnsCleanup=false; c.routing.dnsCleanupGlobal=false;
    h.start(c);
    const auto q=dnsQueryBytes("api.example.invalid");
    h.device->pushDns(buildUdpPacket(kAppIp,53100,0xC0A80301,53,q));
    EXPECT_TRUE(waitDns(h,1));
    std::vector<uint8_t> answer(512);
    answer.resize(dns::buildAResponse({0x1234,"api.example.invalid"},{0xC0000201},answer.data(),answer.size()));
    h.device->pushDns(buildUdpPacket(0xC0A80301,53,kAppIp,53100,answer),{false,false,false,false});
    EXPECT_TRUE(waitDns(h,2));
    for (const std::string name : {"api.example.invalid","unseen.example.invalid"}) {
        SOCKET client=net::makeTcpSocket(); auto local=net::toSockaddr({0x7F000001,0});
        EXPECT_EQ(bind(client,reinterpret_cast<sockaddr*>(&local),sizeof(local)),0);
        int addrLen=sizeof(local); getsockname(client,reinterpret_cast<sockaddr*>(&local),&addrLen);
        const auto port=ntohs(local.sin_port);
        h.pushConnectEvent(port,100,0xC0000201,8443);
        h.device->pushTcp(buildTcpPacket(kAppIp,port,0xC0000201,8443,1,0,0x02));
        for(int i=0;i<100 && !h.engine->nat().findByPort(port);++i) Sleep(20);
        EXPECT_EQ(net::connectWithTimeout(client,{0x7F000001,h.engine->relay().listenPort()},2000,nullptr),0);
        const auto hello=aps::test::tlsHello(name,true);
        EXPECT_EQ(net::sendAll(client,reinterpret_cast<const char*>(hello.data()),hello.size(),2000),0);
        std::vector<uint8_t> reply(hello.size());
        EXPECT_EQ(net::recvExact(client,reinterpret_cast<char*>(reply.data()),reply.size(),3000),static_cast<int>(reply.size()));
        EXPECT_TRUE(reply==hello); net::closeSocket(client);
    }
    size_t domains=0, ips=0;
    for(size_t i=0;i<kernel.requestCount();++i) {
        const auto req=kernel.request(i); if(req.dstPort!=8443) continue;
        if(req.addressType==3) { ++domains; EXPECT_STREQ(req.dstDomain,"api.example.invalid"); }
        else { ++ips; EXPECT_EQ(req.dstIp,0xC0000201u); }
    }
    EXPECT_EQ(domains,1u); EXPECT_EQ(ips,1u);
    h.stop(); kernel.stop();
}
