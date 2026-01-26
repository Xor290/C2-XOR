#include "http_client.h"
#include <windows.h>
#include <wininet.h>
#include <iostream>
#pragma comment(lib, "wininet.lib")

void wininet_error(const char* msg) {
    DWORD err = GetLastError();
    std::cout << "[!] " << msg << " (GetLastError=" << err << ")" << std::endl;
}

std::string http_get(const char* hostname, int port, const std::string& path,
    const std::string& user_agent, const std::string& extra_headers) {

    HINTERNET hInternet = InternetOpenA(user_agent.c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        wininet_error("InternetOpenA failed");
        return "";
    }

    HINTERNET hConnect = InternetConnectA(hInternet, hostname, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        wininet_error("InternetConnectA failed");
        InternetCloseHandle(hInternet);
        return "";
    }

    const char* acceptTypes[] = { "*/*", NULL };
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", path.c_str(), NULL, NULL, acceptTypes,
                                         INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) {
        wininet_error("HttpOpenRequestA failed (GET)");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "";
    }

    std::string headers = extra_headers;
    if (!headers.empty() && headers.back() != '\n') {
        headers += "\r\n";
    }

    BOOL res = HttpSendRequestA(hRequest, headers.c_str(), headers.length(), NULL, 0);
    if (!res) {
        wininet_error("HttpSendRequestA failed (GET)");
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "";
    }

    char buffer[4096];
    DWORD bytesRead = 0;
    std::string result;

    while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead != 0) {
        buffer[bytesRead] = 0;
        result += buffer;
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return result;
}

std::string http_post(const char* hostname, int port, const std::string& path,
    const std::string& user_agent, const std::string& extra_headers, const std::string& data) {

    HINTERNET hInternet = InternetOpenA(user_agent.c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        wininet_error("InternetOpenA failed");
        return "";
    }

    HINTERNET hConnect = InternetConnectA(hInternet, hostname, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        wininet_error("InternetConnectA failed");
        InternetCloseHandle(hInternet);
        return "";
    }

    const char* acceptTypes[] = { "*/*", NULL };
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", path.c_str(), NULL, NULL, acceptTypes,
                                         INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) {
        wininet_error("HttpOpenRequestA failed (POST)");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "";
    }

    std::string headers = extra_headers + "\r\nContent-Type: application/json\r\n";
    BOOL res = HttpSendRequestA(hRequest, headers.c_str(), headers.length(),
                               (LPVOID)data.c_str(), data.length());
    if (!res) {
        wininet_error("HttpSendRequestA failed (POST)");
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "";
    }

    char buffer[4096];
    DWORD bytesRead = 0;
    std::string result;
    while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead != 0) {
        buffer[bytesRead] = 0;
        result += buffer;
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return result;
}
