#include <intrin.h>
#include <array>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

using namespace std;

extern "C" {
    __declspec(dllimport) int __stdcall GetSystemMetrics(int nIndex);
    __declspec(dllimport) void __stdcall GetSystemInfo(void* lpSystemInfo);
    __declspec(dllimport) int __stdcall GlobalMemoryStatusEx(void* lpBuffer);
    __declspec(dllimport) int __stdcall GetDiskFreeSpaceExA(const char* lpDirectoryName, void* lpFreeBytesAvailableToCaller, void* lpTotalNumberOfBytes, void* lpTotalNumberOfFreeBytes);
}

struct MEMORYSTATUSEX {
    unsigned long dwLength;
    unsigned long dwMemoryLoad;
    unsigned long long ullTotalPhys;
    unsigned long long ullAvailPhys;
    unsigned long long ullTotalPageFile;
    unsigned long long ullAvailPageFile;
    unsigned long long ullTotalVirtual;
    unsigned long long ullAvailVirtual;
    unsigned long long ullAvailExtendedVirtual;
};

struct SYSTEM_INFO {
    unsigned long dwOemId;
    unsigned long dwPageSize;
    void* lpMinimumApplicationAddress;
    void* lpMaximumApplicationAddress;
    unsigned long dwActiveProcessorMask;
    unsigned long dwNumberOfProcessors;
    unsigned long dwProcessorType;
    unsigned long dwAllocationGranularity;
    unsigned short wProcessorLevel;
    unsigned short wProcessorRevision;
};

struct ULARGE_INTEGER {
    unsigned long long QuadPart;
};

vector<string> vm_names = { "virtual", "qemu", "vmware", "oracle", "innotek", "vbox", "virtualbox", "hyper-v" };
vector<string> legit_cpu_ids = { "AuthenticAMD", "GenuineIntel" };

bool cpu_hypervisor_bit() {
    array<int, 4> cpuInfo = { 0, 0, 0, 0 };
    __cpuid(cpuInfo.data(), 0x1);
    return (cpuInfo[2] >> 31) & 0x1;
}

bool cpu_id() {
    array<int, 4> cpuInfo = { 0, 0, 0, 0 };
    string cpu = "";
    __cpuid(cpuInfo.data(), 0x0);

    for (int i = 1; i <= 3; i++) {
        int reg = cpuInfo[i];
        cpu += static_cast<char>(reg & 0xff);
        cpu += static_cast<char>((reg >> 8) & 0xff);
        cpu += static_cast<char>((reg >> 16) & 0xff);
        cpu += static_cast<char>((reg >> 24) & 0xff);
    }

    string cpu_lower = cpu;
    transform(cpu_lower.begin(), cpu_lower.end(), cpu_lower.begin(), ::tolower);

    for (const auto& legit : legit_cpu_ids) {
        string legit_lower = legit;
        transform(legit_lower.begin(), legit_lower.end(), legit_lower.begin(), ::tolower);
        if (cpu_lower.find(legit_lower) != string::npos) {
            return false;
        }
    }
    return true; 
}

bool cpu_brand() {
    array<int, 4> cpuInfo = { 0, 0, 0, 0 };
    string cpu = "";
    for (int id = 0x80000002; id <= 0x80000004; id++) {
        __cpuid(cpuInfo.data(), id);
        for (auto i : cpuInfo) {
            cpu += static_cast<char>(i & 0xff);
            cpu += static_cast<char>((i >> 8) & 0xff);
            cpu += static_cast<char>((i >> 16) & 0xff);
            cpu += static_cast<char>((i >> 24) & 0xff);
        }
    }
    
    string cpu_lower = cpu;
    transform(cpu_lower.begin(), cpu_lower.end(), cpu_lower.begin(), ::tolower);
    
    for (const auto& vm_name : vm_names) {
        if (cpu_lower.find(vm_name) != string::npos) {
            return true; 
        }
    }
    return false; 
}

bool screen_resolution() {
    int w = GetSystemMetrics(0); // SM_CXSCREEN
    int h = GetSystemMetrics(1); // SM_CYSCREEN

    if ((w == 1600 && h == 900) || 
        (w == 1920 && h == 1080) || 
        (w == 1920 && h == 1200) || 
        (w == 2560 && h == 1440) || 
        (w == 3840 && h == 2160) ||
        (w == 1366 && h == 768) ||
        (w == 1280 && h == 720) ||
        (w > 3840)) { 
        return false;
    }

    return true;
}

bool memory_amount() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);

    if (GlobalMemoryStatusEx(&statex) == 0) {
        return true;
    }

    return statex.ullTotalPhys < (2ULL * 1024 * 1024 * 1024);
}

bool cpu_cores() {
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    
    return info.dwNumberOfProcessors < 2; 
}

bool disk_space() {
    ULARGE_INTEGER bytes;
    
    if (GetDiskFreeSpaceExA("C:\\", NULL, &bytes, NULL) == 0) {
        return true; 
    }

    return bytes.QuadPart < (20ULL * 1024 * 1024 * 1024);
}

extern "C" bool is_virtual_machine() {
    int detection_count = 0;
    
    if (cpu_hypervisor_bit()) detection_count++;
    if (cpu_id()) detection_count++;
    if (cpu_brand()) detection_count++;
    if (screen_resolution()) detection_count++;
    if (memory_amount()) detection_count++;
    if (cpu_cores()) detection_count++;
    if (disk_space()) detection_count++;
    
    return detection_count >= 1;
}