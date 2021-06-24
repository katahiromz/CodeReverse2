#include "dumping.h"
#include <cstring>
#include <ctime>
#include <cstdarg>
#include <cassert>
#include <cctype>
#include "internal.h"

namespace cr2
{

std::string string_of_timestamp(uint32_t timestamp)
{
    std::string ret;
    if (timestamp == 0)
    {
        ret = "(null)";
        return ret;
    }

    std::time_t t = static_cast<time_t>(timestamp);
    char *psz = std::asctime(std::gmtime(&t));
    char *pch = strrchr(psz, '\n');
    if (pch)
        *pch = 0;
    ret = psz;
    return ret;
}

std::string string_of_command_line(int argc, char **argv)
{
    std::string ret;
    for (int i = 0; i < argc; ++i)
    {
        if (i != 0)
            ret += " ";

        std::string str = argv[i];
        if (str.find(' ') != std::string::npos || str.find('\t') != std::string::npos)
        {
            ret += '"';
            ret += str;
            ret += '"';
        }
        else
        {
            ret += str;
        }
    }
    return ret;
}

std::string string_of_os_info(void)
{
    std::string ret;
#ifdef _WIN32
    OSVERSIONINFOA verinfo = { sizeof(verinfo) };
    GetVersionExA(&verinfo);
# ifdef _WIN64
    ret += string_formatted("Windows %u.%u (x64)\n\n", verinfo.dwMajorVersion, verinfo.dwMinorVersion);
# else
    ret += string_formatted("Windows %u.%u (x86)\n\n", verinfo.dwMajorVersion, verinfo.dwMinorVersion);
# endif
#elif defined(__linux__)
    ret += "Linux\n";
#elif defined(__APPLE__)
    ret += "Mac OS\n";
#else
    ret += "Unknown OS\n";
#endif
    return ret;
}

std::string string_of_machine(uint16_t machine)
{
#ifndef IMAGE_FILE_MACHINE_ARMV7
    #define IMAGE_FILE_MACHINE_ARMV7 0x01c4
#endif
    switch (machine)
    {
    case IMAGE_FILE_MACHINE_UNKNOWN: return "IMAGE_FILE_MACHINE_UNKNOWN";
    case IMAGE_FILE_MACHINE_I386: return "IMAGE_FILE_MACHINE_I386";
    case IMAGE_FILE_MACHINE_R3000: return "IMAGE_FILE_MACHINE_R3000";
    case IMAGE_FILE_MACHINE_R4000: return "IMAGE_FILE_MACHINE_R4000";
    case IMAGE_FILE_MACHINE_R10000: return "IMAGE_FILE_MACHINE_R10000";
    case IMAGE_FILE_MACHINE_WCEMIPSV2: return "IMAGE_FILE_MACHINE_WCEMIPSV2";
    case IMAGE_FILE_MACHINE_ALPHA: return "IMAGE_FILE_MACHINE_ALPHA";
    case IMAGE_FILE_MACHINE_SH3: return "IMAGE_FILE_MACHINE_SH3";
    case IMAGE_FILE_MACHINE_SH3DSP: return "IMAGE_FILE_MACHINE_SH3DSP";
    case IMAGE_FILE_MACHINE_SH3E: return "IMAGE_FILE_MACHINE_SH3E";
    case IMAGE_FILE_MACHINE_SH4: return "IMAGE_FILE_MACHINE_SH4";
    case IMAGE_FILE_MACHINE_SH5: return "IMAGE_FILE_MACHINE_SH5";
    case IMAGE_FILE_MACHINE_ARM: return "IMAGE_FILE_MACHINE_ARM";
    case IMAGE_FILE_MACHINE_ARMV7: return "IMAGE_FILE_MACHINE_ARMV7";
    case IMAGE_FILE_MACHINE_THUMB: return "IMAGE_FILE_MACHINE_THUMB";
    case IMAGE_FILE_MACHINE_AM33: return "IMAGE_FILE_MACHINE_AM33";
    case IMAGE_FILE_MACHINE_POWERPC: return "IMAGE_FILE_MACHINE_POWERPC";
    case IMAGE_FILE_MACHINE_POWERPCFP: return "IMAGE_FILE_MACHINE_POWERPCFP";
    case IMAGE_FILE_MACHINE_IA64: return "IMAGE_FILE_MACHINE_IA64";
    case IMAGE_FILE_MACHINE_MIPS16: return "IMAGE_FILE_MACHINE_MIPS16";
    case IMAGE_FILE_MACHINE_ALPHA64: return "IMAGE_FILE_MACHINE_ALPHA64";
    case IMAGE_FILE_MACHINE_MIPSFPU: return "IMAGE_FILE_MACHINE_MIPSFPU";
    case IMAGE_FILE_MACHINE_MIPSFPU16: return "IMAGE_FILE_MACHINE_MIPSFPU16";
    case IMAGE_FILE_MACHINE_TRICORE: return "IMAGE_FILE_MACHINE_TRICORE";
    case IMAGE_FILE_MACHINE_CEF: return "IMAGE_FILE_MACHINE_CEF";
    case IMAGE_FILE_MACHINE_EBC: return "IMAGE_FILE_MACHINE_EBC";
    case IMAGE_FILE_MACHINE_AMD64: return "IMAGE_FILE_MACHINE_AMD64";
    case IMAGE_FILE_MACHINE_M32R: return "IMAGE_FILE_MACHINE_M32R";
    case IMAGE_FILE_MACHINE_CEE: return "IMAGE_FILE_MACHINE_CEE";
    default: return "(unknown machine)";
    }
}

std::string string_of_file_flags(uint16_t w)
{
    std::string ret;
    if (IMAGE_FILE_RELOCS_STRIPPED & w) ret += "IMAGE_FILE_RELOCS_STRIPPED ";
    if (IMAGE_FILE_EXECUTABLE_IMAGE & w) ret += "IMAGE_FILE_EXECUTABLE_IMAGE ";
    if (IMAGE_FILE_LINE_NUMS_STRIPPED & w) ret += "IMAGE_FILE_LINE_NUMS_STRIPPED ";
    if (IMAGE_FILE_LOCAL_SYMS_STRIPPED & w) ret += "IMAGE_FILE_LOCAL_SYMS_STRIPPED ";
    if (IMAGE_FILE_AGGRESIVE_WS_TRIM & w) ret += "IMAGE_FILE_AGGRESIVE_WS_TRIM ";
    if (IMAGE_FILE_LARGE_ADDRESS_AWARE & w) ret += "IMAGE_FILE_LARGE_ADDRESS_AWARE ";
    if (IMAGE_FILE_BYTES_REVERSED_LO & w) ret += "IMAGE_FILE_BYTES_REVERSED_LO ";
    if (IMAGE_FILE_32BIT_MACHINE & w) ret += "IMAGE_FILE_32BIT_MACHINE ";
    if (IMAGE_FILE_DEBUG_STRIPPED & w) ret += "IMAGE_FILE_DEBUG_STRIPPED ";
    if (IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP & w) ret += "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP ";
    if (IMAGE_FILE_NET_RUN_FROM_SWAP & w) ret += "IMAGE_FILE_NET_RUN_FROM_SWAP ";
    if (IMAGE_FILE_SYSTEM & w) ret += "IMAGE_FILE_SYSTEM ";
    if (IMAGE_FILE_DLL & w) ret += "IMAGE_FILE_DLL ";
    if (IMAGE_FILE_UP_SYSTEM_ONLY & w) ret += "IMAGE_FILE_UP_SYSTEM_ONLY ";
    if (IMAGE_FILE_BYTES_REVERSED_HI & w) ret += "IMAGE_FILE_BYTES_REVERSED_HI ";
    return ret;
}

std::string string_of_section_flags(uint32_t dw)
{
    std::string ret;
#ifndef IMAGE_SCN_TYPE_DSECT
    #define IMAGE_SCN_TYPE_DSECT 0x00000001
#endif
#ifndef IMAGE_SCN_TYPE_NOLOAD
    #define IMAGE_SCN_TYPE_NOLOAD 0x00000002
#endif
#ifndef IMAGE_SCN_TYPE_GROUP
    #define IMAGE_SCN_TYPE_GROUP 0x00000004
#endif
#ifndef IMAGE_SCN_TYPE_COPY
    #define IMAGE_SCN_TYPE_COPY 0x00000010
#endif
#ifndef IMAGE_SCN_TYPE_OVER
    #define IMAGE_SCN_TYPE_OVER 0x00000400
#endif
#ifndef IMAGE_SCN_MEM_PROTECTED
    #define IMAGE_SCN_MEM_PROTECTED 0x00004000
#endif
#ifndef IMAGE_SCN_MEM_SYSHEAP
    #define IMAGE_SCN_MEM_SYSHEAP 0x00010000
#endif
    if (IMAGE_SCN_TYPE_DSECT & dw) ret += "IMAGE_SCN_TYPE_DSECT ";
    if (IMAGE_SCN_TYPE_NOLOAD & dw) ret += "IMAGE_SCN_TYPE_NOLOAD ";
    if (IMAGE_SCN_TYPE_GROUP & dw) ret += "IMAGE_SCN_TYPE_GROUP ";
    if (IMAGE_SCN_TYPE_NO_PAD & dw) ret += "IMAGE_SCN_TYPE_NO_PAD ";
    if (IMAGE_SCN_TYPE_COPY & dw) ret += "IMAGE_SCN_TYPE_COPY ";
    if (IMAGE_SCN_CNT_CODE & dw) ret += "IMAGE_SCN_CNT_CODE ";
    if (IMAGE_SCN_CNT_INITIALIZED_DATA & dw) ret += "IMAGE_SCN_CNT_INITIALIZED_DATA ";
    if (IMAGE_SCN_CNT_UNINITIALIZED_DATA & dw) ret += "IMAGE_SCN_CNT_UNINITIALIZED_DATA ";
    if (IMAGE_SCN_LNK_OTHER & dw) ret += "IMAGE_SCN_LNK_OTHER ";
    if (IMAGE_SCN_LNK_INFO & dw) ret += "IMAGE_SCN_LNK_INFO ";
    if (IMAGE_SCN_TYPE_OVER & dw) ret += "IMAGE_SCN_TYPE_OVER ";
    if (IMAGE_SCN_LNK_REMOVE & dw) ret += "IMAGE_SCN_LNK_REMOVE ";
    if (IMAGE_SCN_LNK_COMDAT & dw) ret += "IMAGE_SCN_LNK_COMDAT ";
    if (IMAGE_SCN_MEM_PROTECTED & dw) ret += "IMAGE_SCN_MEM_PROTECTED ";
    if (IMAGE_SCN_NO_DEFER_SPEC_EXC & dw) ret += "IMAGE_SCN_NO_DEFER_SPEC_EXC ";
    if (IMAGE_SCN_GPREL & dw) ret += "IMAGE_SCN_GPREL ";
    if (IMAGE_SCN_MEM_FARDATA & dw) ret += "IMAGE_SCN_MEM_FARDATA ";
    if (IMAGE_SCN_MEM_SYSHEAP & dw) ret += "IMAGE_SCN_MEM_SYSHEAP ";
    if (IMAGE_SCN_MEM_PURGEABLE & dw) ret += "IMAGE_SCN_MEM_PURGEABLE ";
    if (IMAGE_SCN_MEM_16BIT & dw) ret += "IMAGE_SCN_MEM_16BIT ";
    if (IMAGE_SCN_MEM_LOCKED & dw) ret += "IMAGE_SCN_MEM_LOCKED ";
    if (IMAGE_SCN_MEM_PRELOAD & dw) ret += "IMAGE_SCN_MEM_PRELOAD ";
    if (IMAGE_SCN_ALIGN_1BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) ret += "IMAGE_SCN_ALIGN_1BYTES ";
    if (IMAGE_SCN_ALIGN_2BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) ret += "IMAGE_SCN_ALIGN_2BYTES ";
    if (IMAGE_SCN_ALIGN_4BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) ret += "IMAGE_SCN_ALIGN_4BYTES ";
    if (IMAGE_SCN_ALIGN_8BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) ret += "IMAGE_SCN_ALIGN_8BYTES ";
    if (IMAGE_SCN_ALIGN_16BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) ret += "IMAGE_SCN_ALIGN_16BYTES ";
    if (IMAGE_SCN_ALIGN_32BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) ret += "IMAGE_SCN_ALIGN_32BYTES ";
    if (IMAGE_SCN_ALIGN_64BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) ret += "IMAGE_SCN_ALIGN_64BYTES ";
    if (IMAGE_SCN_ALIGN_128BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) ret += "IMAGE_SCN_ALIGN_128BYTES ";
    if (IMAGE_SCN_ALIGN_256BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) ret += "IMAGE_SCN_ALIGN_256BYTES ";
    if (IMAGE_SCN_ALIGN_512BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) ret += "IMAGE_SCN_ALIGN_512BYTES ";
    if (IMAGE_SCN_ALIGN_1024BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) ret += "IMAGE_SCN_ALIGN_1024BYTES ";
    if (IMAGE_SCN_ALIGN_2048BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) ret += "IMAGE_SCN_ALIGN_2048BYTES ";
    if (IMAGE_SCN_ALIGN_4096BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) ret += "IMAGE_SCN_ALIGN_4096BYTES ";
    if (IMAGE_SCN_ALIGN_8192BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) ret += "IMAGE_SCN_ALIGN_8192BYTES ";
    if (IMAGE_SCN_LNK_NRELOC_OVFL & dw) ret += "IMAGE_SCN_LNK_NRELOC_OVFL ";
    if (IMAGE_SCN_MEM_DISCARDABLE & dw) ret += "IMAGE_SCN_MEM_DISCARDABLE ";
    if (IMAGE_SCN_MEM_NOT_CACHED & dw) ret += "IMAGE_SCN_MEM_NOT_CACHED ";
    if (IMAGE_SCN_MEM_NOT_PAGED & dw) ret += "IMAGE_SCN_MEM_NOT_PAGED ";
    if (IMAGE_SCN_MEM_SHARED & dw) ret += "IMAGE_SCN_MEM_SHARED ";
    if (IMAGE_SCN_MEM_EXECUTE & dw) ret += "IMAGE_SCN_MEM_EXECUTE ";
    if (IMAGE_SCN_MEM_READ & dw) ret += "IMAGE_SCN_MEM_READ ";
    if (IMAGE_SCN_MEM_WRITE & dw) ret += "IMAGE_SCN_MEM_WRITE ";
    return ret;
}

std::string string_of_dll_flags(uint16_t w)
{
    std::string ret;
    if (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE & w) ret += "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ";
    if (IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY & w) ret += "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY ";
    if (IMAGE_DLLCHARACTERISTICS_NX_COMPAT & w) ret += "IMAGE_DLLCHARACTERISTICS_NX_COMPAT ";
    if (IMAGE_DLLCHARACTERISTICS_NO_ISOLATION & w) ret += "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION ";
    if (IMAGE_DLLCHARACTERISTICS_NO_SEH & w) ret += "IMAGE_DLLCHARACTERISTICS_NO_SEH ";
    if (IMAGE_DLLCHARACTERISTICS_NO_BIND & w) ret += "IMAGE_DLLCHARACTERISTICS_NO_BIND ";
    if (IMAGE_DLLCHARACTERISTICS_WDM_DRIVER & w) ret += "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER ";
    if (IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE & w) ret += "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE ";
    return ret;
}

std::string string_of_subsystem(uint16_t w)
{
    switch (w)
    {
    case IMAGE_SUBSYSTEM_UNKNOWN: return "IMAGE_SUBSYSTEM_UNKNOWN";
    case IMAGE_SUBSYSTEM_NATIVE: return "IMAGE_SUBSYSTEM_NATIVE";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI: return "IMAGE_SUBSYSTEM_WINDOWS_GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI: return "IMAGE_SUBSYSTEM_WINDOWS_CUI";
    case IMAGE_SUBSYSTEM_OS2_CUI: return "IMAGE_SUBSYSTEM_OS2_CUI";
    case IMAGE_SUBSYSTEM_POSIX_CUI: return "IMAGE_SUBSYSTEM_POSIX_CUI";
    case IMAGE_SUBSYSTEM_NATIVE_WINDOWS: return "IMAGE_SUBSYSTEM_NATIVE_WINDOWS";
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: return "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION: return "IMAGE_SUBSYSTEM_EFI_APPLICATION";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: return "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER";
    case IMAGE_SUBSYSTEM_EFI_ROM: return "IMAGE_SUBSYSTEM_EFI_ROM";
    case IMAGE_SUBSYSTEM_XBOX: return "IMAGE_SUBSYSTEM_XBOX";
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION";
    default: return "(unknown subsystem)";
    }
}

std::string string_formatted(const char *fmt, ...)
{
    char buf[1024];
    va_list va;
    va_start(va, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, va);
    std::string ret = buf;
    va_end(va);
    return ret;
}

std::string string_of_data_directory(const void *data, uint32_t index, bool is_64bit)
{
    auto dir = reinterpret_cast<const IMAGE_DATA_DIRECTORY_DX *>(data);

    const char *name = NULL;
    switch (index)
    {
    case IMAGE_DIRECTORY_ENTRY_EXPORT: name = "IMAGE_DIRECTORY_ENTRY_EXPORT"; break;
    case IMAGE_DIRECTORY_ENTRY_IMPORT: name = "IMAGE_DIRECTORY_ENTRY_IMPORT"; break;
    case IMAGE_DIRECTORY_ENTRY_RESOURCE: name = "IMAGE_DIRECTORY_ENTRY_RESOURCE"; break;
    case IMAGE_DIRECTORY_ENTRY_EXCEPTION: name = "IMAGE_DIRECTORY_ENTRY_EXCEPTION"; break;
    case IMAGE_DIRECTORY_ENTRY_SECURITY: name = "IMAGE_DIRECTORY_ENTRY_SECURITY"; break;
    case IMAGE_DIRECTORY_ENTRY_BASERELOC: name = "IMAGE_DIRECTORY_ENTRY_BASERELOC"; break;
    case IMAGE_DIRECTORY_ENTRY_DEBUG: name = "IMAGE_DIRECTORY_ENTRY_DEBUG"; break;
    case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: name = "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE"; break;
    case IMAGE_DIRECTORY_ENTRY_GLOBALPTR: name = "IMAGE_DIRECTORY_ENTRY_GLOBALPTR"; break;
    case IMAGE_DIRECTORY_ENTRY_TLS: name = "IMAGE_DIRECTORY_ENTRY_TLS"; break;
    case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: name = "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"; break;
    case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: name = "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"; break;
    case IMAGE_DIRECTORY_ENTRY_IAT: name = "IMAGE_DIRECTORY_ENTRY_IAT"; break;
    case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: name = "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"; break;
    case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: name = "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"; break;
    default: name = "(Reserved Directory Entry)"; break;
    }

    if (is_64bit)
    {
        return string_formatted("  %-36s (%2u): AVA 0x%08X%08X, RVA 0x%08X, size 0x%08X (%u)\n",
            name, index, DWORD(dir->AVA >> 32), DWORD(dir->AVA), dir->VirtualAddress, dir->Size, dir->Size);
    }
    else
    {
        return string_formatted("  %-36s (%2u): AVA 0x%08X, RVA 0x%08X, size 0x%08X (%u)\n",
            name, index, DWORD(dir->AVA), dir->VirtualAddress, dir->Size, dir->Size);
    }
}

std::string string_of_data_directories(const void *data, bool is_64bit)
{
    std::string ret;
    auto dd = reinterpret_cast<const IMAGE_DATA_DIRECTORY_DX *>(data);

    ret += "## Data Directories ##\n";
    for (uint32_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i, ++dd)
    {
        ret += string_of_data_directory(dd, i, is_64bit);
    }
    ret += "\n";

    return ret;
}

std::string string_of_dos_header(const void *dos)
{
    const IMAGE_DOS_HEADER *dh = reinterpret_cast<const IMAGE_DOS_HEADER *>(dos);
    if (!dh)
        return "";

    std::string ret;
    ret += "## IMAGE_DOS_HEADER ##\n";
    ret += string_formatted("  e_magic: 0x%04X\n", dh->e_magic);
    ret += string_formatted("  e_cblp: 0x%04X\n", dh->e_cblp);
    ret += string_formatted("  e_cp: 0x%04X\n", dh->e_cp);
    ret += string_formatted("  e_crlc: 0x%04X\n", dh->e_crlc);
    ret += string_formatted("  e_cparhdr: 0x%04X\n", dh->e_cparhdr);
    ret += string_formatted("  e_minalloc: 0x%04X\n", dh->e_minalloc);
    ret += string_formatted("  e_maxalloc: 0x%04X\n", dh->e_maxalloc);
    ret += string_formatted("  e_ss: 0x%04X\n", dh->e_ss);
    ret += string_formatted("  e_sp: 0x%04X\n", dh->e_sp);
    ret += string_formatted("  e_csum: 0x%04X\n", dh->e_csum);
    ret += string_formatted("  e_ip: 0x%04X\n", dh->e_ip);
    ret += string_formatted("  e_cs: 0x%04X\n", dh->e_cs);
    ret += string_formatted("  e_lfarlc: 0x%04X\n", dh->e_lfarlc);
    ret += string_formatted("  e_ovno: 0x%04X\n", dh->e_ovno);
    ret += string_formatted("  e_res[0]: 0x%04X\n", dh->e_res[0]);
    ret += string_formatted("  e_res[1]: 0x%04X\n", dh->e_res[1]);
    ret += string_formatted("  e_res[2]: 0x%04X\n", dh->e_res[2]);
    ret += string_formatted("  e_res[3]: 0x%04X\n", dh->e_res[3]);
    ret += string_formatted("  e_oemid: 0x%04X\n", dh->e_oemid);
    ret += string_formatted("  e_oeminfo: 0x%04X\n", dh->e_oeminfo);
    ret += string_formatted("  e_res2[0]: 0x%04X\n", dh->e_res2[0]);
    ret += string_formatted("  e_res2[1]: 0x%04X\n", dh->e_res2[1]);
    ret += string_formatted("  e_res2[2]: 0x%04X\n", dh->e_res2[2]);
    ret += string_formatted("  e_res2[3]: 0x%04X\n", dh->e_res2[3]);
    ret += string_formatted("  e_res2[4]: 0x%04X\n", dh->e_res2[4]);
    ret += string_formatted("  e_res2[5]: 0x%04X\n", dh->e_res2[5]);
    ret += string_formatted("  e_res2[6]: 0x%04X\n", dh->e_res2[6]);
    ret += string_formatted("  e_res2[7]: 0x%04X\n", dh->e_res2[7]);
    ret += string_formatted("  e_res2[8]: 0x%04X\n", dh->e_res2[8]);
    ret += string_formatted("  e_res2[9]: 0x%04X\n", dh->e_res2[9]);
    ret += string_formatted("  e_lfanew: 0x%08X\n", dh->e_lfanew);
    ret += "\n";
    return ret;
}

std::string string_of_file_header(const void *file)
{
    std::string ret;
    const IMAGE_FILE_HEADER *fh = reinterpret_cast<const IMAGE_FILE_HEADER *>(file);
    ret += "## IMAGE_FILE_HEADER ##\n";
    ret += string_formatted("  Machine: 0x%04X (%s)\n", fh->Machine, string_of_machine(fh->Machine).c_str());
    ret += string_formatted("  NumberOfSections: 0x%04X (%u)\n", fh->NumberOfSections, fh->NumberOfSections);
    ret += string_formatted("  TimeDateStamp: 0x%08X (%s)\n", fh->TimeDateStamp, string_of_timestamp(fh->TimeDateStamp).c_str());
    ret += string_formatted("  PointerToSymbolTable: 0x%08X\n", fh->PointerToSymbolTable);
    ret += string_formatted("  NumberOfSymbols: 0x%08X (%u)\n", fh->NumberOfSymbols, fh->NumberOfSymbols);
    ret += string_formatted("  SizeOfOptionalHeader: 0x%04X (%u)\n", fh->SizeOfOptionalHeader, fh->SizeOfOptionalHeader);
    ret += string_formatted("  Characteristics: 0x%04X (%s)\n", fh->Characteristics, string_of_file_flags(fh->Characteristics).c_str());
    ret += "\n";
    return ret;
}

std::string string_of_optional32(const void *optional)
{
    std::string ret;
    const IMAGE_OPTIONAL_HEADER32 *opt32 =
        reinterpret_cast<const IMAGE_OPTIONAL_HEADER32 *>(optional);

    ret += "## IMAGE_OPTIONAL_HEADER32 ##\n";
    ret += string_formatted("  Magic: 0x%04X\n", opt32->Magic);
    ret += string_formatted("  LinkerVersion: %u.%u\n", opt32->MajorLinkerVersion, opt32->MinorLinkerVersion);
    ret += string_formatted("  SizeOfCode: 0x%08X (%u)\n", opt32->SizeOfCode, opt32->SizeOfCode);
    ret += string_formatted("  SizeOfInitializedData: 0x%08X (%u)\n", opt32->SizeOfInitializedData, opt32->SizeOfInitializedData);
    ret += string_formatted("  SizeOfUninitializedData: 0x%08X (%u)\n", opt32->SizeOfUninitializedData, opt32->SizeOfUninitializedData);
    ret += string_formatted("  AddressOfEntryPoint: 0x%08X\n", opt32->AddressOfEntryPoint);
    ret += string_formatted("  BaseOfCode: 0x%08X\n", opt32->BaseOfCode);
    ret += string_formatted("  BaseOfData: 0x%08X\n", opt32->BaseOfData);
    ret += string_formatted("  ImageBase: 0x%08X\n", opt32->ImageBase);
    ret += string_formatted("  SectionAlignment: 0x%08X\n", opt32->SectionAlignment);
    ret += string_formatted("  FileAlignment: 0x%08X\n", opt32->FileAlignment);
    ret += string_formatted("  OperatingSystemVersion: %u.%u\n", opt32->MajorOperatingSystemVersion, opt32->MinorOperatingSystemVersion);
    ret += string_formatted("  ImageVersion: %u.%u\n", opt32->MajorImageVersion, opt32->MinorImageVersion);
    ret += string_formatted("  SubsystemVersion: %u.%u\n", opt32->MajorSubsystemVersion, opt32->MinorSubsystemVersion);
    ret += string_formatted("  Win32VersionValue: 0x%08X\n", opt32->Win32VersionValue);
    ret += string_formatted("  SizeOfImage: 0x%08X (%u)\n", opt32->SizeOfImage, opt32->SizeOfImage);
    ret += string_formatted("  SizeOfHeaders: 0x%08X (%u)\n", opt32->SizeOfHeaders, opt32->SizeOfHeaders);
    ret += string_formatted("  CheckSum: 0x%08X\n", opt32->CheckSum);
    ret += string_formatted("  Subsystem: 0x%04X (%s)\n", opt32->Subsystem, string_of_subsystem(opt32->Subsystem).c_str());
    ret += string_formatted("  DllCharacteristics: 0x%04X (%s)\n", opt32->DllCharacteristics, string_of_dll_flags(opt32->DllCharacteristics).c_str());
    ret += string_formatted("  SizeOfStackReserve: 0x%08X (%u)\n", opt32->SizeOfStackReserve, opt32->SizeOfStackReserve);
    ret += string_formatted("  SizeOfStackCommit: 0x%08X (%u)\n", opt32->SizeOfStackCommit, opt32->SizeOfStackCommit);
    ret += string_formatted("  SizeOfHeapReserve: 0x%08X (%u)\n", opt32->SizeOfHeapReserve, opt32->SizeOfHeapReserve);
    ret += string_formatted("  SizeOfHeapCommit: 0x%08X (%u)\n", opt32->SizeOfHeapCommit, opt32->SizeOfHeapCommit);
    ret += string_formatted("  LoaderFlags: 0x%08X\n", opt32->LoaderFlags);
    ret += string_formatted("  NumberOfRvaAndSizes: 0x%08X (%u)\n", opt32->NumberOfRvaAndSizes, opt32->NumberOfRvaAndSizes);
    ret += "\n";

    return ret;
}

std::string string_of_optional64(const void *optional)
{
    std::string ret;
    const IMAGE_OPTIONAL_HEADER64 *opt64 =
        reinterpret_cast<const IMAGE_OPTIONAL_HEADER64 *>(optional);

    ret += "## IMAGE_OPTIONAL_HEADER64 ##\n";
    ret += string_formatted("  Magic: 0x%04X\n", opt64->Magic);
    ret += string_formatted("  LinkerVersion: %u.%u\n", opt64->MajorLinkerVersion, opt64->MinorLinkerVersion);
    ret += string_formatted("  SizeOfCode: 0x%08X (%u)\n", opt64->SizeOfCode, opt64->SizeOfCode);
    ret += string_formatted("  SizeOfInitializedData: 0x%08X (%u)\n", opt64->SizeOfInitializedData, opt64->SizeOfInitializedData);
    ret += string_formatted("  SizeOfUninitializedData: 0x%08X (%u)\n", opt64->SizeOfUninitializedData, opt64->SizeOfUninitializedData);
    ret += string_formatted("  AddressOfEntryPoint: 0x%08X\n", opt64->AddressOfEntryPoint);
    ret += string_formatted("  BaseOfCode: 0x%08X\n", opt64->BaseOfCode);
    ret += string_formatted("  ImageBase: 0x%016llX\n", opt64->ImageBase);
    ret += string_formatted("  SectionAlignment: 0x%08X\n", opt64->SectionAlignment);
    ret += string_formatted("  FileAlignment: 0x%08X\n", opt64->FileAlignment);
    ret += string_formatted("  OperatingSystemVersion: %u.%u\n", opt64->MajorOperatingSystemVersion, opt64->MinorOperatingSystemVersion);
    ret += string_formatted("  ImageVersion: %u.%u\n", opt64->MajorImageVersion, opt64->MinorImageVersion);
    ret += string_formatted("  SubsystemVersion: %u.%u\n", opt64->MajorSubsystemVersion, opt64->MinorSubsystemVersion);
    ret += string_formatted("  Win32VersionValue: 0x%08X\n", opt64->Win32VersionValue);
    ret += string_formatted("  SizeOfImage: 0x%08X (%u)\n", opt64->SizeOfImage, opt64->SizeOfImage);
    ret += string_formatted("  SizeOfHeaders: 0x%08X (%u)\n", opt64->SizeOfHeaders, opt64->SizeOfHeaders);
    ret += string_formatted("  CheckSum: 0x%08X\n", opt64->CheckSum);
    ret += string_formatted("  Subsystem: 0x%04X (%s)\n", opt64->Subsystem, string_of_subsystem(opt64->Subsystem).c_str());
    ret += string_formatted("  DllCharacteristics: 0x%04X (%s)\n", opt64->DllCharacteristics, string_of_dll_flags(opt64->DllCharacteristics).c_str());
    ret += string_formatted("  SizeOfStackReserve: 0x%016llX (%llu)\n", opt64->SizeOfStackReserve, opt64->SizeOfStackReserve);
    ret += string_formatted("  SizeOfStackCommit: 0x%016llX (%llu)\n", opt64->SizeOfStackCommit, opt64->SizeOfStackCommit);
    ret += string_formatted("  SizeOfHeapReserve: 0x%016llX (%llu)\n", opt64->SizeOfHeapReserve, opt64->SizeOfHeapReserve);
    ret += string_formatted("  SizeOfHeapCommit: 0x%016llX (%llu)\n", opt64->SizeOfHeapCommit, opt64->SizeOfHeapCommit);
    ret += string_formatted("  LoaderFlags: 0x%08X\n", opt64->LoaderFlags);
    ret += string_formatted("  NumberOfRvaAndSizes: 0x%08X (%u)\n", opt64->NumberOfRvaAndSizes, opt64->NumberOfRvaAndSizes);
    ret += "\n";

    return ret;
}

std::string string_of_section_header(const void *section_header, uint32_t index, bool is_64bit)
{
    std::string ret;
    auto sh = reinterpret_cast<const IMAGE_SECTION_HEADER_DX *>(section_header);

    ret += string_formatted("## Section Header #%u ##\n", index + 1);

    ret += "  Name: ";
    for (uint32_t i = 0; i < IMAGE_SIZEOF_SHORT_NAME && sh->Name[i] != 0; ++i)
        ret += static_cast<char>(sh->Name[i]);
    ret += "\n";

    ret += string_formatted("  VirtualSize: 0x%08X (%u)\n", sh->Misc.VirtualSize, sh->Misc.VirtualSize);
    ret += string_formatted("  VirtualAddress: 0x%08X (RVA)\n", sh->VirtualAddress);
    if (is_64bit)
        ret += string_formatted("  VirtualAddress: 0x%08X%08X (AVA)\n", DWORD(sh->AVA >> 32), DWORD(sh->AVA));
    else
        ret += string_formatted("  VirtualAddress: 0x%08X (AVA)\n", DWORD(sh->AVA));
    ret += string_formatted("  SizeOfRawData: 0x%08X (%u)\n", sh->SizeOfRawData, sh->SizeOfRawData);
    ret += string_formatted("  PointerToRawData: 0x%08X\n", sh->PointerToRawData);
    ret += string_formatted("  PointerToRelocations: 0x%08X\n", sh->PointerToRelocations);
    ret += string_formatted("  PointerToLinenumbers: 0x%08X\n", sh->PointerToLinenumbers);
    ret += string_formatted("  NumberOfRelocations: 0x%08X (%u)\n", sh->NumberOfRelocations, sh->NumberOfRelocations);
    ret += string_formatted("  NumberOfLinenumbers: 0x%08X (%u)\n", sh->NumberOfLinenumbers, sh->NumberOfLinenumbers);
    ret += string_formatted("  Characteristics: 0x%08X (%s)\n", sh->Characteristics, string_of_section_flags(sh->Characteristics).c_str());
    ret += "\n";

    return ret;
}

std::string string_of_section_headers(const void *section_headers, uint32_t count, bool is_64bit)
{
    std::string ret;
    auto sh = reinterpret_cast<const IMAGE_SECTION_HEADER_DX *>(section_headers);
    for (uint32_t i = 0; i < count; ++i)
    {
        ret += string_of_section_header(&sh[i], i, is_64bit);
    }
    return ret;
}

std::string string_of_addr32(uint32_t addr)
{
    return string_formatted("%08X", addr);
}

std::string string_of_addr64(uint64_t addr)
{
    return string_formatted("%016llX", addr);
}

static const char *s_hex = "0123456789ABCDEF";

std::string string_of_hex_dump32(const void *memory, size_t size, uint32_t base_addr)
{
    std::string ret;
    const BYTE *pb = reinterpret_cast<const BYTE *>(memory);
    const BYTE *pbEnd = pb + size;

    ret += "+ADDRESS +0 +1 +2 +3 +4 +5 +6 +7  +8 +9 +A +B +C +D +E +F  0123456789ABCDEF\n";

    char buf[4];
    while (size > 0)
    {
        const BYTE *pb0 = pb;

        ret += string_of_addr32(base_addr);
        ret += " ";

        for (int i = 0; i < 8; ++i, ++pb)
        {
            if (&pb0[i] < pbEnd)
            {
                buf[0] = s_hex[*pb >> 4];
                buf[1] = s_hex[*pb & 0xF];
                buf[2] = ' ';
                buf[3] = 0;
                ret += buf;
            }
            else
            {
                ret += "   ";
            }
        }
        ret += " ";

        for (int i = 8; i < 16; ++i, ++pb)
        {
            if (&pb0[i] < pbEnd)
            {
                buf[0] = s_hex[*pb >> 4];
                buf[1] = s_hex[*pb & 0xF];
                buf[2] = ' ';
                buf[3] = 0;
                ret += buf;
            }
            else
            {
                ret += "   ";
            }
        }
        ret += " ";

        for (int i = 0; i < 16; ++i)
        {
            if (&pb0[i] < pbEnd)
            {
                if (pb0[i] == 0 || pb0[i] == ' ')
                    ret += ' ';
                else if (std::isprint(pb0[i]))
                    ret += pb0[i];
                else
                    ret += '.';
            }
            else
            {
                ret += " ";
            }
        }
        ret += "\n";

        if (size < 16)
            break;

        base_addr += 16;
        size -= 16;
    }

    return ret;
}

std::string string_of_hex_dump64(const void *memory, size_t size, uint64_t base_addr)
{
    std::string ret;
    const BYTE *pb = reinterpret_cast<const BYTE *>(memory);
    const BYTE *pbEnd = pb + size;

    ret += "+ADDRESS         +0 +1 +2 +3 +4 +5 +6 +7  +8 +9 +A +B +C +D +E +F  0123456789ABCDEF\n";

    char buf[4];
    while (size > 0)
    {
        const BYTE *pb0 = pb;

        ret += string_of_addr64(base_addr);
        ret += " ";

        for (int i = 0; i < 8; ++i, ++pb)
        {
            if (&pb0[i] < pbEnd)
            {
                buf[0] = s_hex[*pb >> 4];
                buf[1] = s_hex[*pb & 0xF];
                buf[2] = ' ';
                buf[3] = 0;
                ret += buf;
            }
            else
            {
                ret += "   ";
            }
        }
        ret += " ";

        for (int i = 8; i < 16; ++i, ++pb)
        {
            if (&pb0[i] < pbEnd)
            {
                buf[0] = s_hex[*pb >> 4];
                buf[1] = s_hex[*pb & 0xF];
                buf[2] = ' ';
                buf[3] = 0;
                ret += buf;
            }
            else
            {
                ret += "   ";
            }
        }
        ret += " ";

        for (int i = 0; i < 16; ++i)
        {
            if (&pb0[i] < pbEnd)
            {
                if (pb0[i] == 0 || pb0[i] == ' ')
                    ret += ' ';
                else if (std::isprint(pb0[i]))
                    ret += pb0[i];
                else
                    ret += '.';
            }
            else
            {
                ret += " ";
            }
        }
        ret += "\n";

        if (size < 16)
            break;

        base_addr += 16;
        size -= 16;
    }

    return ret;
}

std::string string_of_imports(const IMAGE_IMPORT_DESCRIPTOR *imports, const ImportTable& table, bool is_64bit)
{
    std::string ret;

    ret += "## Imports ##\n";
    if (!imports || table.empty())
    {
        ret += "No imports.\n\n";
        return ret;
    }

    ret += string_formatted("  Characteristics: 0x%08X (%u)\n", imports->Characteristics, imports->Characteristics);
    ret += string_formatted("  TimeDateStamp: 0x%08X (%s)\n", imports->TimeDateStamp, string_of_timestamp(imports->TimeDateStamp).c_str());
    ret += string_formatted("  Name: 0x%08X (%u)\n", imports->Name, imports->Name);
    ret += string_formatted("  FirstThunk: 0x%08X (%u)\n", imports->FirstThunk, imports->FirstThunk);
    if (is_64bit)
        ret += string_formatted("  %14s %8s %16s %16s %s\n", "Module", "hint", "RVA", "VA", "Function");
    else
        ret += string_formatted("  %14s %8s %8s %8s %s\n", "Module", "hint", "RVA", "VA", "Function");

    for (auto& entry : table)
    {
        std::string hint;

        if (entry.func_name[0])
        {
            if (entry.hint != -1)
                hint = string_formatted("%8X", entry.hint);
            if (is_64bit)
            {
                ret += string_formatted("%8s %016llX %016llX %s!%s\n",
                    hint.c_str(),
                    entry.rva,
                    entry.va,
                    entry.module.c_str(),
                    entry.func_name.c_str());
            }
            else
            {
                ret += string_formatted("%8s %08X %08X %s!%s\n",
                    hint.c_str(),
                    static_cast<uint32_t>(entry.rva),
                    static_cast<uint32_t>(entry.va),
                    entry.module.c_str(),
                    entry.func_name.c_str());
            }
        }
        else
        {
            std::string name = string_formatted("%d", entry.ordinal);
            if (is_64bit)
            {
                if (entry.hint != -1)
                    hint = string_formatted("%8X", entry.hint);
                ret += string_formatted("%8s %016llX %016llX %s!%s\n",
                    hint.c_str(),
                    entry.rva,
                    entry.va,
                    entry.module.c_str(),
                    name.c_str());
            }
            else
            {
                if (entry.hint != -1)
                    hint = string_formatted("%8X", entry.hint);
                ret += string_formatted("%8s %08X %08X %s!%s\n",
                    hint.c_str(),
                    static_cast<uint32_t>(entry.rva),
                    static_cast<uint32_t>(entry.va),
                    entry.module.c_str(),
                    name.c_str());
            }
        }
    }

    ret += "\n";
    return ret;
}

std::string string_of_exports(const char *module, const IMAGE_EXPORT_DIRECTORY *exports, const ExportTable& table, bool is_64bit)
{
    std::string ret;

    ret += "## Exports ##\n";
    if (!exports || table.empty())
    {
        ret += "No exports.\n\n";
        return ret;
    }

    ret += string_formatted("  Characteristics: 0x%08X (%u)\n", exports->Characteristics, exports->Characteristics);
    ret += string_formatted("  TimeDateStamp: 0x%08X (%s)\n", exports->TimeDateStamp, string_of_timestamp(exports->TimeDateStamp).c_str());
    ret += string_formatted("  MajorVersion: 0x%04X (%u)\n", exports->MajorVersion, exports->MajorVersion);
    ret += string_formatted("  MinorVersion: 0x%04X (%u)\n", exports->MinorVersion, exports->MinorVersion);
    ret += string_formatted("  Name: 0x%08X (%u)\n", exports->Name, exports->Name);
    ret += string_formatted("  Base: 0x%08X (%u)\n", exports->Base, exports->Base);
    ret += string_formatted("  NumberOfFunctions: 0x%08X (%u)\n", exports->NumberOfFunctions, exports->NumberOfFunctions);
    ret += string_formatted("  NumberOfNames: 0x%08X (%u)\n", exports->NumberOfNames, exports->NumberOfNames);
    ret += string_formatted("  AddressOfFunctions: 0x%08X (%u)\n", exports->AddressOfFunctions, exports->AddressOfFunctions);
    ret += string_formatted("  AddressOfNames: 0x%08X (%u)\n", exports->AddressOfNames, exports->AddressOfNames);
    ret += string_formatted("  AddressOfNameOrdinals: 0x%08X (%u)\n", exports->AddressOfNameOrdinals, exports->AddressOfNameOrdinals);

    if (is_64bit)
        ret += string_formatted("%11s %4s %16s %16s %s\n", "ordinal", "hint", "RVA", "VA", "name");
    else
        ret += string_formatted("%11s %4s %8s %8s %s\n", "ordinal", "hint", "RVA", "VA", "name");
    for (auto& entry : table)
    {
        auto name = entry.name;
        if (name.empty())
            name = string_formatted("%u", entry.ordinal);

        auto hint = string_formatted("%4X", entry.hint);
        if (entry.hint == -1)
            hint = "";

        std::string rva, va;
        if (is_64bit)
        {
            rva = string_formatted("%016llX", entry.rva);
            va = string_formatted("%016llX", entry.va);
        }
        else
        {
            rva = string_formatted("%08X", static_cast<uint32_t>(entry.rva));
            va = string_formatted("%08X", static_cast<uint32_t>(entry.va));
        }

        if (entry.forwarded_to[0])
        {
            rva = "";
            va = "";
        }

        if (is_64bit)
        {
            ret += string_formatted("%11d %4s %16s %16s %s!%s",
                entry.ordinal, hint.c_str(), rva.c_str(), va.c_str(), module, name.c_str());
        }
        else
        {
            ret += string_formatted("%11d %4s %8s %8s %s!%s",
                entry.ordinal, hint.c_str(), rva.c_str(), va.c_str(), module, name.c_str());
        }

        if (entry.forwarded_to[0])
        {
            ret += string_formatted(" (forwarded to %s)", entry.forwarded_to.c_str());
        }
        ret += "\n";
    }

    ret += "\n";
    return ret;
}

std::string string_of_delay(const DelayTable& table, bool is_64bit)
{
    std::string ret;

    ret += "## Delay ##\n";
    if (table.empty())
    {
        ret += "No delays.\n\n";
        return ret;
    }

    if (is_64bit)
        ret += string_formatted("  %14s %8s %8s %16s %s\n", "Module", "HMODULE", "hint", "VA", "Function");
    else
        ret += string_formatted("  %14s %8s %8s %8s %s\n", "Module", "HMODULE", "hint", "VA", "Function");

    for (auto& entry : table)
    {
        std::string hint;
        if (entry.func_name[0])
        {
            if (entry.hint != -1)
                hint = string_formatted("%8X", entry.hint);
            if (is_64bit)
            {
                ret += string_formatted("%16s %016llX %8s %016llX %s\n",
                    entry.module.c_str(),
                    entry.hmodule,
                    hint.c_str(),
                    entry.va,
                    entry.func_name.c_str());
            }
            else
            {
                ret += string_formatted("%16s %08X %8s %08X %s\n",
                    entry.module.c_str(),
                    static_cast<uint32_t>(entry.hmodule),
                    hint.c_str(),
                    static_cast<uint32_t>(entry.va),
                    entry.func_name.c_str());
            }
        }
        else
        {
            std::string name = string_formatted("Ordinal %6d", entry.ordinal);
            if (entry.hint != -1)
                hint = string_formatted("%8X", entry.hint);
            if (is_64bit)
            {
                ret += string_formatted("%16s %016llX %8s %016llX %s\n",
                    entry.module.c_str(),
                    entry.hmodule,
                    hint.c_str(),
                    entry.va,
                    name.c_str());
            }
            else
            {
                ret += string_formatted("%16s %08X %8s %08X %s\n",
                    entry.module.c_str(),
                    static_cast<uint32_t>(entry.hmodule),
                    hint.c_str(),
                    static_cast<uint32_t>(entry.va),
                    name.c_str());
            }
        }
    }
    ret += "\n";

    return ret;
}

std::string string_of_disasm(DisAsmData& data, bool is_64bit)
{
    std::string ret;

    auto& ava_to_func = data.ava_to_func;
    auto& names = data.names;

    ret += "## DisAsm ##\n";
    if (ava_to_func.empty())
    {
        ret += "No disassembly.\n\n";
        return ret;
    }

    for (auto& pair : ava_to_func)
    {
        ret += "proc ";

        auto it = names.find(pair.first);
        if (it != names.end())
        {
            ret += it->second;
        }
        else
        {
            ret += "Func";
            if (is_64bit)
                ret += string_of_addr64(pair.first);
            else
                ret += string_of_addr32(static_cast<uint32_t>(pair.first));
        }

        ret += " Label_";
        if (is_64bit)
            ret += string_of_addr64(pair.first);
        else
            ret += string_of_addr32(static_cast<uint32_t>(pair.first));

        ret += "\n";
        ret += "attrs ";
        for (auto& attr : pair.second.attributes)
        {
            ret += attr;
        }
        ret += "\n";

        if (pair.second.call_from.size())
        {
            ret += "# call_from :";
            for (auto& from : pair.second.call_from)
            {
                ret += " ";
                if (is_64bit)
                    ret += string_of_addr64(from);
                else
                    ret += string_of_addr32(static_cast<uint32_t>(from));
            }
            ret += "\n";
        }

        if (pair.second.call_to.size())
        {
            ret += "# call_to :";
            for (auto& to : pair.second.call_to)
            {
                ret += " ";
                if (is_64bit)
                    ret += string_of_addr64(to);
                else
                    ret += string_of_addr32(static_cast<uint32_t>(to));
            }
            ret += "\n";
        }

        if (pair.second.jump_to.size())
        {
            ret += "# jump_to :";
            for (auto& to : pair.second.jump_to)
            {
                ret += " ";
                if (is_64bit)
                    ret += string_of_addr64(to);
                else
                    ret += string_of_addr32(static_cast<uint32_t>(to));
            }
            ret += "\n";
        }

        auto& ava_to_asm = pair.second.ava_to_asm;
        for (auto& pair2 : ava_to_asm)
        {
            if (pair2.first == pair.first ||
                pair2.second.jump_from.size())
            {
                ret += "Label_";
                if (is_64bit)
                    ret += string_of_addr64(pair2.first);
                else
                    ret += string_of_addr32(static_cast<uint32_t>(pair2.first));

                ret += ":\n";
            }

            if (is_64bit)
                ret += string_of_addr64(pair2.first);
            else
                ret += string_of_addr32(pair2.first);
            ret += ": ";
            ret += pair2.second.cooked;

            if (pair2.second.jump_from.size())
            {
                ret += " # jump_from :";
                for (auto& from : pair2.second.jump_from)
                {
                    ret += " ";
                    if (is_64bit)
                        ret += string_of_addr64(from);
                    else
                        ret += string_of_addr32(static_cast<uint32_t>(from));
                }
            }
            ret += "\n";
        }

        ret += "end proc\n\n";
    }

    return ret;
}

} // namespace cr2
