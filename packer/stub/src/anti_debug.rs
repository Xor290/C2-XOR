/// Vérifie si un debugger est présent via IsDebuggerPresent() WinAPI.
/// Port de anti_debug_basic() depuis debug_detection.cpp
pub fn is_debugger_present_api() -> bool {
    #[cfg(target_os = "windows")]
    unsafe {
        winapi::um::debugapi::IsDebuggerPresent() != 0
    }
    #[cfg(not(target_os = "windows"))]
    false
}

/// Vérifie le flag BeingDebugged dans le PEB.
/// gs:[0x60] = pointeur vers PEB, PEB+0x2 = BeingDebugged
pub fn check_peb_debugger() -> bool {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    unsafe {
        let peb: *const u8;
        let result: u8;
        std::arch::asm!(
            "mov {0}, qword ptr gs:[0x60]",  // lire le pointeur PEB
            "mov {1}, byte ptr [{0}+0x2]",   // lire PEB->BeingDebugged
            out(reg) peb,
            out(reg_byte) result,
            options(nostack, nomem),
        );
        result != 0
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    false
}

/// Retourne true si un debugger est détecté (l'une ou l'autre méthode).
pub fn is_being_debugged() -> bool {
    is_debugger_present_api() || check_peb_debugger()
}
