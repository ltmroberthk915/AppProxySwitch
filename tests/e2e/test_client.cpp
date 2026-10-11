// Minimal HTTP client used as the "target application" in e2e tests.
// Usage: test_client.exe <ipv4> <port>
// Exit 0 on "200 OK" + expected body marker; 1 otherwise.
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdio>
#include <cstring>
#include <string>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <ipv4> <port>\n", argv[0]);
        return 2;
    }
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 2;

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &sa.sin_addr);
    sa.sin_port = htons(static_cast<unsigned short>(std::atoi(argv[2])));

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 1;

    // Non-blocking connect with a 5s timeout.
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    fd_set w, e;
    FD_ZERO(&w); FD_ZERO(&e); FD_SET(s, &w); FD_SET(s, &e);
    timeval tv{5, 0};
    if (select(0, nullptr, &w, &e, &tv) <= 0) {
        closesocket(s);
        std::fprintf(stderr, "connect timeout/refused %s:%s\n", argv[1], argv[2]);
        return 1;
    }
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);

    const char req[] = "GET / HTTP/1.1\r\nHost: aps-e2e\r\nConnection: close\r\n\r\n";
    send(s, req, static_cast<int>(strlen(req)), 0);

    std::string resp;
    char buf[4096];
    ULONGLONG deadline = GetTickCount64() + 10000;
    while (GetTickCount64() < deadline) {
        fd_set r;
        FD_ZERO(&r); FD_SET(s, &r);
        timeval t{1, 0};
        if (select(0, &r, nullptr, nullptr, &t) <= 0) continue;
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, static_cast<size_t>(n));
        if (resp.find("aps-mock-http-ok") != std::string::npos) break;
    }
    closesocket(s);
    bool ok = resp.find("200 OK") != std::string::npos &&
              resp.find("aps-mock-http-ok") != std::string::npos;
    if (!ok) {
        std::fprintf(stderr, "bad response (%zu bytes)\n", resp.size());
    }
    return ok ? 0 : 1;
}
