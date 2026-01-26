#pragma once
#include <string>
#include <vector>

std::vector<unsigned char> read_file_binary(const std::string& filename);
std::string handle_download(const std::string& filepath);
std::string save_base64_file(const std::string& filename, const std::string& b64_encoded_filecontent);
