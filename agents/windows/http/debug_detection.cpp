#include <windows.h>
#include <winternl.h>

bool being_debugged_peb() {
#if defined(_M_X64) || defined(__x86_64__)
    PPEB peb = (PPEB)__readgsqword(0x60);
#elif defined(_M_IX86) || defined(__i386__)
    PPEB peb = (PPEB)__readfsdword(0x30);
#else
    return false;
#endif
    return peb->BeingDebugged;
}

bool anti_debug_basic() {
    if (IsDebuggerPresent()) {
        return true;
    }
    return false;
}

void is_debugged() {
    int detection_method = 0;
    if (anti_debug_basic()) detection_method++;
    if (being_debugged_peb()) detection_method++;

}
