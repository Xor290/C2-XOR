use std::mem::size_of;
use std::ptr;
use winapi::shared::minwindef::BOOL;
use winapi::shared::ntdef::NT_SUCCESS;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winternl::{NtQueryInformationProcess, PROCESSINFOCLASS};
use winapi::um::winnt::HANDLE;

/// Vérifie si un debugger est présent via IsDebuggerPresent() WinAPI.
/// Port de anti_debug_basic() depuis debug_detection.cpp
pub fn is_debugger_present_winapi() -> bool {
    #[cfg(target_os = "windows")]
    unsafe {
        if winapi::um::debugapi::IsDebuggerPresent() != 0 {
            return true;
        }
        let mut is_remote: BOOL = 0;
        winapi::um::debugapi::CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut is_remote);
        is_remote != 0
    }
    #[cfg(not(target_os = "windows"))]
    false
}

#[cfg(target_os = "windows")]
pub fn is_debugger_present_nt_api() -> bool {
    unsafe {
        let mut debug_port: HANDLE = ptr::null_mut();
        let mut return_length: u32 = 0;

        // ProcessDebugPort = 7
        let status = NtQueryInformationProcess(
            GetCurrentProcess(),
            7 as PROCESSINFOCLASS,
            &mut debug_port as *mut _ as *mut _,
            size_of::<HANDLE>() as u32,
            &mut return_length,
        );

        NT_SUCCESS(status) && !debug_port.is_null()
    }
}

#[cfg(not(target_os = "windows"))]
pub fn is_debugger_present_nt_api() -> bool {
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
            options(nostack),
        );
        result != 0
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    false
}

/// Retourne true si un debugger est détecté (l'une ou l'autre méthode).
pub fn is_being_debugged() -> bool {
    is_debugger_present_winapi() || check_peb_debugger() || is_debugger_present_nt_api()
}
