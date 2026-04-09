#include "http_client.h"
#include <windows.h>
#include <wininet.h>
#include <iostream>
#pragma comment(lib, "wininet.lib")

#ifndef SECURITY_FLAG_IGNORE_UNKNOWN_CA
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA         0x00000100
#endif
#ifndef SECURITY_FLAG_IGNORE_CERT_CN_INVALID
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID    0x00001000
#endif
#ifndef SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID  0x00002000
#endif
#ifndef SECURITY_FLAG_IGNORE_REVOCATION
#define SECURITY_FLAG_IGNORE_REVOCATION         0x00000080
#endif

void wininet_error(const char* msg) {
    DWORD err = GetLastError();
    std::cout << "[!] " << msg << " (GetLastError=" << err << ")" << std::endl;
}

std::string http_get(const char* hostname, int port, const std::string& path,
    const std::string& user_agent, const std::string& extra_headers, bool use_https) {

    HINTERNET hInternet = InternetOpenA(user_agent.c_str(), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        wininet_error("InternetOpenA failed");
        return "";
    }

    // Set timeouts
    DWORD timeout = 30000;
    InternetSetOptionA(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(hInternet, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

    DWORD service_type = INTERNET_SERVICE_HTTP;
    HINTERNET hConnect = InternetConnectA(hInternet, hostname, (INTERNET_PORT)port,
                                          NULL, NULL, service_type, 0, 0);
    if (!hConnect) {
        wininet_error("InternetConnectA failed");
        InternetCloseHandle(hInternet);
        return "";
    }

    const char* acceptTypes[] = { "*/*", NULL };

    DWORD request_flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
                          INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_NO_COOKIES;
    if (use_https) {
        request_flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                         INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    }

    HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", path.c_str(), "HTTP/1.1",
                                          NULL, acceptTypes, request_flags, 0);
    if (!hRequest) {
        wininet_error("HttpOpenRequestA failed (GET)");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "";
    }

    // Set security flags to ignore SSL certificate errors
    if (use_https) {
        DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                        SECURITY_FLAG_IGNORE_REVOCATION;
        InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    }

    std::string headers = extra_headers;
    if (!headers.empty() && headers.back() != '\n') {
        headers += "\r\n";
    }

    BOOL res = FALSE;
    int retries = 3;

    while (retries > 0) {
        res = HttpSendRequestA(hRequest, headers.empty() ? NULL : headers.c_str(),
                              headers.empty() ? 0 : (DWORD)headers.length(), NULL, 0);

        if (res) break;

        DWORD err = GetLastError();
        if (use_https && (err == 12157 || err == 12045 || err == 12044 ||
                          err == ERROR_INTERNET_INVALID_CA ||
                          err == ERROR_INTERNET_SEC_CERT_CN_INVALID ||
                          err == ERROR_INTERNET_SEC_CERT_DATE_INVALID)) {
            DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                            SECURITY_FLAG_IGNORE_REVOCATION |
                            SECURITY_FLAG_IGNORE_WRONG_USAGE;
            InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
            retries--;
        } else {
            break;
        }
    }

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
    const std::string& user_agent, const std::string& extra_headers, const std::string& data, bool use_https) {

    HINTERNET hInternet = InternetOpenA(user_agent.c_str(), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        wininet_error("InternetOpenA failed");
        return "";
    }

    // Set timeouts
    DWORD timeout = 30000;
    InternetSetOptionA(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(hInternet, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

    DWORD service_type = INTERNET_SERVICE_HTTP;
    HINTERNET hConnect = InternetConnectA(hInternet, hostname, (INTERNET_PORT)port,
                                          NULL, NULL, service_type, 0, 0);
    if (!hConnect) {
        wininet_error("InternetConnectA failed");
        InternetCloseHandle(hInternet);
        return "";
    }

    const char* acceptTypes[] = { "*/*", NULL };

    DWORD request_flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
                          INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_NO_COOKIES;
    if (use_https) {
        request_flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                         INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    }

    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", path.c_str(), "HTTP/1.1",
                                          NULL, acceptTypes, request_flags, 0);
    if (!hRequest) {
        wininet_error("HttpOpenRequestA failed (POST)");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "";
    }

    // Set security flags to ignore SSL certificate errors
    if (use_https) {
        DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                        SECURITY_FLAG_IGNORE_REVOCATION;
        InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    }

    std::string headers = "Content-Type: application/json\r\n";
    if (!extra_headers.empty()) {
        headers += extra_headers;
        if (headers.back() != '\n') {
            headers += "\r\n";
        }
    }

    BOOL res = FALSE;
    int retries = 3;

    while (retries > 0) {
        res = HttpSendRequestA(hRequest, headers.c_str(), (DWORD)headers.length(),
                              (LPVOID)data.c_str(), (DWORD)data.length());

        if (res) break;

        DWORD err = GetLastError();
        if (use_https && (err == 12157 || err == 12045 || err == 12044 ||
                          err == ERROR_INTERNET_INVALID_CA ||
                          err == ERROR_INTERNET_SEC_CERT_CN_INVALID ||
                          err == ERROR_INTERNET_SEC_CERT_DATE_INVALID)) {
            DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                            SECURITY_FLAG_IGNORE_REVOCATION |
                            SECURITY_FLAG_IGNORE_WRONG_USAGE;
            InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
            retries--;
        } else {
            break;
        }
    }

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
