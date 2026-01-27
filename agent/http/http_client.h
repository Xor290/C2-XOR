#pragma once
#include <string>

void wininet_error(const char* msg);

// HTTP/HTTPS POST request
std::string http_post(const char* hostname, int port, const std::string& path,
    const std::string& user_agent, const std::string& extra_headers, const std::string& data,
    bool use_https = false);

// HTTP/HTTPS GET request
std::string http_get(
    const char* hostname,
    int port,
    const std::string& path,
    const std::string& user_agent,
    const std::string& extra_headers,
    bool use_https = false
);
