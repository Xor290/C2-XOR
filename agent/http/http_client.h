#pragma once
#include <string>

void wininet_error(const char* msg);
std::string http_post(const char* hostname, int port, const std::string& path,
    const std::string& user_agent, const std::string& extra_headers, const std::string& data);

// HTTP GET request
std::string http_get(
    const char* hostname,
    int port,
    const std::string& path,
    const std::string& user_agent,
    const std::string& extra_headers
);
