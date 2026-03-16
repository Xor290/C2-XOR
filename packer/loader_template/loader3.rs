/// Loader PE réflectif — port de pe-exec.cpp
/// Charge un PE64 depuis des octets en mémoire et exécute son entry point.

#[cfg(target_os = "windows")]
use winapi::{
    shared::minwindef::LPVOID,
    um::{
        handleapi::CloseHandle,
        memoryapi::{VirtualAlloc, VirtualFree},
        processthreadsapi::CreateThread,
        synchapi::WaitForSingleObject,
        winnt::{
            IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
            IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_ORDINAL_FLAG64, IMAGE_REL_BASED_DIR64, MEM_COMMIT,
            MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        },
    },
};

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x00004550;
const INFINITE: u32 = 0xFFFFFFFF;

// ─── Structures PE ────────────────────────────────────────────────────────────

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _pad: [u16; 29],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

#[repr(C)]
struct ImageBaseRelocation {
    virtual_address: u32,
    size_of_block: u32,
}

#[repr(C)]
struct ImageImportDescriptor {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
}

#[repr(C)]
struct ImageTlsDirectory64 {
    start_address_of_raw_data: u64,
    end_address_of_raw_data: u64,
    address_of_index: u64,
    address_of_callbacks: u64,
    size_of_zero_fill: u32,
    characteristics: u32,
}

// ─── Loader ───────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub unsafe fn load_and_run(pe_bytes: &[u8]) -> ! {
    let base = pe_bytes.as_ptr();

    // 1. Valider DOS header
    let dos = &*(base as *const ImageDosHeader);
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        std::process::exit(1);
    }

    // 2. Valider NT headers
    let nt = &*((base.add(dos.e_lfanew as usize)) as *const ImageNtHeaders64);
    if nt.signature != IMAGE_NT_SIGNATURE {
        std::process::exit(1);
    }

    // 3. Allouer mémoire RWX pour l'image
    let img_size = nt.optional_header.size_of_image as usize;
    let img_base = VirtualAlloc(
        core::ptr::null_mut(),
        img_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    ) as *mut u8;
    if img_base.is_null() {
        std::process::exit(1);
    }

    // 4. Copier les headers PE
    core::ptr::copy_nonoverlapping(base, img_base, nt.optional_header.size_of_headers as usize);

    // 5. Mapper les sections
    let sect_base = (base
        .add(dos.e_lfanew as usize)
        .add(4)
        .add(core::mem::size_of::<ImageFileHeader>())
        .add(nt.file_header.size_of_optional_header as usize))
        as *const ImageSectionHeader;
    for i in 0..nt.file_header.number_of_sections as usize {
        let sect = &*sect_base.add(i);
        if sect.size_of_raw_data == 0 {
            continue;
        }
        let dst = img_base.add(sect.virtual_address as usize);
        let src = base.add(sect.pointer_to_raw_data as usize);
        core::ptr::copy_nonoverlapping(src, dst, sect.size_of_raw_data as usize);
    }

    // 6. Corriger les imports
    if !fix_imports(img_base, nt) {
        VirtualFree(img_base as LPVOID, 0, MEM_RELEASE);
        std::process::exit(1);
    }

    // 7. Appliquer les relocations
    let delta = img_base as i64 - nt.optional_header.image_base as i64;
    if !apply_relocations(img_base, delta, nt) {
        VirtualFree(img_base as LPVOID, 0, MEM_RELEASE);
        std::process::exit(1);
    }

    // 8. Exécuter les TLS callbacks
    run_tls_callbacks(img_base, nt);

    // 9. Créer un thread sur l'entry point
    let entry_point = img_base.add(nt.optional_header.address_of_entry_point as usize);
    let mut tid: u32 = 0;
    let h_thread = CreateThread(
        core::ptr::null_mut(),
        0,
        Some(core::mem::transmute(entry_point)),
        core::ptr::null_mut(),
        0,
        &mut tid,
    );
    if h_thread.is_null() {
        VirtualFree(img_base as LPVOID, 0, MEM_RELEASE);
        std::process::exit(1);
    }

    WaitForSingleObject(h_thread, INFINITE);
    CloseHandle(h_thread);
    std::process::exit(0);
}

#[cfg(target_os = "windows")]
unsafe fn fix_imports(img: *mut u8, nt: *const ImageNtHeaders64) -> bool {
    let imp_dir = &(*nt).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if imp_dir.virtual_address == 0 {
        return true;
    }

    let mut imp = (img.add(imp_dir.virtual_address as usize)) as *const ImageImportDescriptor;

    while (*imp).name != 0 {
        let mod_name = img.add((*imp).name as usize) as *const i8;
        let h_module = winapi::um::libloaderapi::LoadLibraryA(mod_name);
        if h_module.is_null() {
            return false;
        }

        // Si OriginalFirstThunk == 0, fallback sur FirstThunk (cas MinGW/certains linkers)
        let oft = (*imp).original_first_thunk;
        let mut orig_thunk = if oft != 0 {
            img.add(oft as usize) as *const u64
        } else {
            img.add((*imp).first_thunk as usize) as *const u64
        };
        let mut thunk = (img.add((*imp).first_thunk as usize)) as *mut u64;

        while *orig_thunk != 0 {
            let fn_ptr: *const u8 = if *orig_thunk & IMAGE_ORDINAL_FLAG64 != 0 {
                winapi::um::libloaderapi::GetProcAddress(
                    h_module,
                    (*orig_thunk & 0xFFFF) as *const i8,
                ) as *const u8
            } else {
                // IMAGE_IMPORT_BY_NAME: u16 Hint + char Name[]
                let by_name =
                    img.add((*orig_thunk & 0x7FFFFFFFFFFFFFFF) as usize).add(2) as *const i8;
                winapi::um::libloaderapi::GetProcAddress(h_module, by_name) as *const u8
            };

            if fn_ptr.is_null() {
                return false;
            }
            *thunk = fn_ptr as u64;

            orig_thunk = orig_thunk.add(1);
            thunk = thunk.add(1);
        }

        imp = imp.add(1);
    }
    true
}

#[cfg(target_os = "windows")]
unsafe fn apply_relocations(base: *mut u8, delta: i64, nt: *const ImageNtHeaders64) -> bool {
    if delta == 0 {
        return true;
    }
    let reloc_dir = &(*nt).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
    if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 {
        return true;
    }

    let mut offset = 0usize;
    while offset < reloc_dir.size as usize {
        let block =
            (base.add(reloc_dir.virtual_address as usize + offset)) as *const ImageBaseRelocation;
        let count = ((*block).size_of_block as usize - core::mem::size_of::<ImageBaseRelocation>())
            / core::mem::size_of::<u16>();
        let reloc_data =
            (block as *const u8).add(core::mem::size_of::<ImageBaseRelocation>()) as *const u16;

        for i in 0..count {
            let entry = *reloc_data.add(i);
            let reloc_type = entry >> 12;
            let rva_offset = entry & 0xFFF;
            if reloc_type == IMAGE_REL_BASED_DIR64 as u16 {
                let patch =
                    (base.add((*block).virtual_address as usize + rva_offset as usize)) as *mut i64;
                *patch += delta;
            }
        }
        offset += (*block).size_of_block as usize;
    }
    true
}

#[cfg(target_os = "windows")]
unsafe fn run_tls_callbacks(base: *mut u8, nt: *const ImageNtHeaders64) {
    let tls_dir = &(*nt).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_TLS as usize];
    if tls_dir.virtual_address == 0 {
        return;
    }
    let tls = (base.add(tls_dir.virtual_address as usize)) as *const ImageTlsDirectory64;
    if (*tls).address_of_callbacks == 0 {
        return;
    }
    // address_of_callbacks est une VA absolue (déjà patchée par les relocations)
    let mut callbacks = (*tls).address_of_callbacks as *const u64;
    while *callbacks != 0 {
        let cb: extern "system" fn(*mut u8, u32, *mut u8) = core::mem::transmute(*callbacks);
        cb(base, 1 /* DLL_PROCESS_ATTACH */, core::ptr::null_mut());
        callbacks = callbacks.add(1);
    }
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn load_and_run(_pe_bytes: &[u8]) -> ! {
    panic!("Le loader PE ne fonctionne que sur Windows");
}
