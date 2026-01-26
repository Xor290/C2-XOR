#include "file_utils.h"
#include "base64.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>

/**
 * Lit un fichier en mode binaire et retourne un vector<unsigned char>
 */
std::vector<unsigned char> read_file_binary(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + filename);
    }
    
    // Obtenir la taille du fichier
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // Lire tout le contenu dans un vector
    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Error reading file: " + filename);
    }
    
    return buffer;
}

/**
 * Télécharge un fichier (commande 'download')
 * Lit le fichier et retourne son contenu en Base64 dans un format JSON
 */
std::string handle_download(const std::string& filepath) {
    try {
        #ifdef _DEBUG
        std::cout << "[DOWNLOAD] Reading file: " << filepath << std::endl;
        #endif
        
        // Vérifier que le fichier existe
        std::ifstream test(filepath);
        if (!test.good()) {
            return "Error: File not found: " + filepath;
        }
        test.close();
        
        // Lire le fichier
        std::vector<unsigned char> file_data = read_file_binary(filepath);
        
        #ifdef _DEBUG
        std::cout << "[DOWNLOAD] File read successfully: " << file_data.size() << " bytes" << std::endl;
        #endif
        
        // Convertir vector<unsigned char> en string pour base64_encode
        std::string file_data_str(file_data.begin(), file_data.end());
        
        // Encoder en Base64
        std::string b64_encoded = base64_encode(file_data_str);
        
        // Créer un JSON avec les infos du fichier
        std::ostringstream result;
        result << "{'filename':'" << filepath << "',";
        result << "'size':" << file_data.size() << ",";
        result << "'content':'" << b64_encoded << "'}";
        
        return result.str();
    }
    catch (const std::exception& e) {
        return std::string("Error downloading file: ") + e.what();
    }
}

/**
 * Sauvegarde un fichier depuis du contenu Base64
 * Utilisé pour la commande 'upload'
 */
std::string save_base64_file(const std::string& filename, const std::string& b64_encoded_filecontent) {
    try {
        // Décoder le Base64
        std::string decoded = base64_decode(b64_encoded_filecontent);
        
        // Ouvrir le fichier en mode binaire
        std::ofstream outfile(filename, std::ios::binary);
        if (!outfile.is_open()) {
            return "Error: Could not open file for writing: " + filename;
        }
        
        // Écrire les données
        outfile.write(decoded.data(), decoded.size());
        outfile.close();
        
        std::ostringstream result;
        result << "File uploaded successfully: " << filename << " (" << decoded.size() << " bytes)";
        return result.str();
    }
    catch (const std::exception& e) {
        return std::string("Error uploading file: ") + e.what();
    }
}