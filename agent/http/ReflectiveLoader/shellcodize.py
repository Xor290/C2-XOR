import pefile
import sys
import os

def extract_text_section(pe_path, out_path):
    pe = pefile.PE(pe_path)
    # Cherche la section .text (nommée généralement ".text")
    text_section = None
    for section in pe.sections:
        if section.Name.rstrip(b'\x00') == b'.text':
            text_section = section
            break
    if text_section is None:
        print("[-] Section .text non trouvée dans", pe_path)
        sys.exit(2)
    # Extraction du code de la section .text
    text_data = text_section.get_data()
    with open(out_path, 'wb') as f:
        f.write(text_data)
    print(f"[+] Section .text extraite: {len(text_data)} octets -> {out_path}")

def concat_files(loader_path, dll_path, output_path):
    try:
        with open(loader_path, 'rb') as loader_file, \
             open(dll_path, 'rb') as dll_file, \
             open(output_path, 'wb') as out_file:
            out_file.write(loader_file.read())
            out_file.write(dll_file.read())
        print(f"[+] Fichier généré : {output_path}")
    except Exception as e:
        print(f"[-] Erreur lors de la concaténation : {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <program.py> [your_dll]")
        sys.exit(1)
    
    pe_path = "./DllLoaderShellcode/x64/Release/Loader.exe"
    out_path = "./loader.x64.o"
    extract_text_section(pe_path, out_path)
    concat_files("./loader.x64.o", sys.argv[1], "./shellcode.bin")
    os.remove(out_path)
