#include <windows.h>


void anti_debug_basic() {
    if (IsDebuggerPresent()) {
        ExitProcess(0);
    }
}
