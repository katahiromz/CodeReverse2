#include "PEModule.h"
#include "dumping.h"
#include "internal.h"
#include <cstring>
#include <cctype>
#include <cassert>
#include "udis86/udis86.h"

namespace cr2
{

static uint64_t
get_disasm_first_imm_operand(const std::string& disasm)
{
    const char *pch = strchr(disasm.c_str(), ' ');
    if (!pch)
        return invalid_ava;

    pch++;
    char *endptr;
    uint64_t imm = strtoll(pch, &endptr, 16);
    if (*endptr != 0)
        return invalid_ava;
    return imm;
}

static uint64_t
get_disasm_first_mem_operand(const std::string& disasm, uint64_t ip)
{
    const char *pch = strchr(disasm.c_str(), '[');
    if (!pch)
        return invalid_ava;

    pch++;
    if (memcmp(pch, "rip+", 4) == 0 || memcmp(pch, "eip+", 4) == 0)
    {
        uint64_t mem = strtoll(&pch[4], NULL, 16);
        return mem + ip;
    }
    else if (memcmp(pch, "0x", 2) == 0)
    {
        uint64_t mem = strtoll(pch, NULL, 16);
        return mem;
    }
    return invalid_ava;
}


PEModuleImpl *
PEModule::impl()
{
    return reinterpret_cast<PEModuleImpl *>(m_pimpl.get());
}

const PEModuleImpl *
PEModule::impl() const
{
    return reinterpret_cast<const PEModuleImpl *>(m_pimpl.get());
}

PEModule::PEModule() : Module(std::make_shared<PEModuleImpl>())
{
    memset(impl()->data_directories, 0, sizeof(impl()->data_directories));
}

PEModule::PEModule(const char *filename) : Module(std::make_shared<PEModuleImpl>())
{
    Module::load(filename);
}

PEModule::PEModule(const wchar_t *filename) : Module(std::make_shared<PEModuleImpl>())
{
    Module::load(filename);
}

bool PEModule::load(const char *filename)
{
    return Module::load(filename);
}

bool PEModule::load(const wchar_t *filename)
{
    return Module::load(filename);
}

bool PEModule::load(FILE *fp)
{
    memset(impl()->data_directories, 0, sizeof(impl()->data_directories));

    if (!Module::load(fp))
        return false;

    // "MZ"
    IMAGE_DOS_HEADER *dos = file_map_typed<IMAGE_DOS_HEADER>();
    IMAGE_NT_HEADERS *nt = NULL;
    if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew != 0)
    {
        nt = file_map_typed<IMAGE_NT_HEADERS>(dos->e_lfanew);
    }

    // "PE\0\0"
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
    {
        assert(0);
        unload();
        return false;
    }

    IMAGE_NT_HEADERS32 *nt32 = reinterpret_cast<IMAGE_NT_HEADERS32 *>(nt);
    IMAGE_NT_HEADERS64 *nt64 = reinterpret_cast<IMAGE_NT_HEADERS64 *>(nt);

    IMAGE_FILE_HEADER *file = &nt->FileHeader;
    IMAGE_OPTIONAL_HEADER32 *optional32 = NULL;
    IMAGE_OPTIONAL_HEADER64 *optional64 = NULL;
    IMAGE_SECTION_HEADER *sh;
    IMAGE_DATA_DIRECTORY *dd;

    switch (file->SizeOfOptionalHeader)
    {
    case sizeof(IMAGE_OPTIONAL_HEADER32):
        optional32 = &nt32->OptionalHeader;
        if (optional32->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            return false;
        sh = IMAGE_FIRST_SECTION(nt32);
        dd = reinterpret_cast<IMAGE_DATA_DIRECTORY *>(optional32->DataDirectory);
        break;

    case sizeof(IMAGE_OPTIONAL_HEADER64):
        optional64 = &nt64->OptionalHeader;
        if (optional64->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return false;
        sh = IMAGE_FIRST_SECTION(nt64);
        dd = reinterpret_cast<IMAGE_DATA_DIRECTORY *>(optional64->DataDirectory);
        break;

    default:
        assert(0);
        unload();
        return false;
    }

    impl()->dos = dos;
    impl()->nt = nt;
    impl()->file = file;
    impl()->optional32 = optional32;
    impl()->optional64 = optional64;

    if (auto NumberOfSections = impl()->file->NumberOfSections)
    {
        delete[] impl()->section_headers;
        impl()->section_headers = new IMAGE_SECTION_HEADER_DX[NumberOfSections];
        for (uint32_t i = 0; i < NumberOfSections; ++i)
        {
            memcpy(&impl()->section_headers[i], &sh[i], sizeof(sh[i]));
            if (sh[i].VirtualAddress && sh[i].Misc.VirtualSize)
                impl()->section_headers[i].AVA = ava_from_rva(sh[i].VirtualAddress);
            else
                impl()->section_headers[i].AVA = 0;
        }
    }

    for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i)
    {
        memcpy(&impl()->data_directories[i], &dd[i], sizeof(dd[i]));
        if (dd[i].VirtualAddress && dd[i].Size)
            impl()->data_directories[i].AVA = ava_from_rva(dd[i].VirtualAddress);
        else
            impl()->data_directories[i].AVA = 0;
    }

    if (!_map_image())
        return false;

    return true;
}

bool PEModule::is_32bit() const
{
    assert(is_loaded());
    return impl()->optional32 != NULL;
}

bool PEModule::is_64bit() const
{
    assert(is_loaded());
    return impl()->optional64 != NULL;
}

uint32_t PEModule::get_file_flags() const
{
    assert(is_loaded());
    return impl()->file->Characteristics;
}

uint32_t PEModule::get_subsystem() const
{
    assert(is_loaded());

    if (is_64bit())
        return impl()->optional64->Subsystem;
    else if (is_32bit())
        return impl()->optional32->Subsystem;
    return 0;
}

bool PEModule::is_dll() const
{
    return (get_file_flags() & IMAGE_FILE_DLL) != 0;
}

bool PEModule::is_cui() const
{
    return get_subsystem() == IMAGE_SUBSYSTEM_WINDOWS_CUI;
}

bool PEModule::is_gui() const
{
    return get_subsystem() == IMAGE_SUBSYSTEM_WINDOWS_GUI;
}

bool PEModule::is_rva_code(uint64_t rva) const
{
    auto sh = section_from_rva(rva);
    if (sh && sh->Characteristics & IMAGE_SCN_CNT_CODE)
        return true;
    return false;
}

bool PEModule::is_rva_readable(uint64_t rva) const
{
    auto sh = section_from_rva(rva);
    if (sh && sh->Characteristics & IMAGE_SCN_MEM_READ)
        return true;
    return false;
}

bool PEModule::is_rva_writable(uint64_t rva) const
{
    auto sh = section_from_rva(rva);
    if (sh && sh->Characteristics & IMAGE_SCN_MEM_WRITE)
        return true;
    return false;
}

void PEModule::unload()
{
    m_pimpl.reset();
    m_pimpl = std::make_shared<PEModuleImpl>();
}

bool PEModule::is_loaded() const
{
    return Module::is_loaded() && impl()->nt != NULL;
}

uint32_t PEModule::size_of_headers() const
{
    assert(is_loaded());
    if (is_64bit())
        return impl()->optional64->SizeOfHeaders;
    else if (is_32bit())
        return impl()->optional32->SizeOfHeaders;
    return 0;
}

uint32_t PEModule::size_of_image() const
{
    assert(is_loaded());
    if (is_64bit())
        return impl()->optional64->SizeOfImage;
    else if (is_32bit())
        return impl()->optional32->SizeOfImage;
    return 0;
}

uint32_t PEModule::base_of_code() const
{
    assert(is_loaded());
    if (is_64bit())
        return impl()->optional64->BaseOfCode;
    else if (is_32bit())
        return impl()->optional32->BaseOfCode;
    return 0;
}

uint64_t PEModule::rva_of_entry_point() const
{
    assert(is_loaded());
    if (is_64bit())
        return impl()->optional64->AddressOfEntryPoint;
    else if (is_32bit())
        return impl()->optional32->AddressOfEntryPoint;
    return 0;
}

bool PEModule::is_valid_ava(uint64_t ava) const
{
    assert(is_loaded());
    if (is_64bit())
    {
        const uint64_t begin = impl()->optional64->ImageBase;
        const uint64_t end = begin + impl()->optional64->SizeOfImage;
        return begin <= ava && ava < end;
    }
    else if (is_32bit())
    {
        const uint64_t begin = impl()->optional32->ImageBase;
        const uint64_t end = begin + impl()->optional32->SizeOfImage;
        return begin <= ava && ava < end;
    }
    return 0;
}

uint64_t PEModule::ava_from_rva(uint64_t rva) const
{
    assert(is_loaded());
    if (is_64bit())
    {
        return impl()->optional64->ImageBase + rva;
    }
    else if (is_32bit())
    {
        return impl()->optional32->ImageBase + rva;
    }
    return 0;
}

uint64_t PEModule::rva_from_ava(uint64_t ava) const
{
    assert(is_loaded());
    if (is_64bit())
    {
        return ava - impl()->optional64->ImageBase;
    }
    else if (is_32bit())
    {
        return ava - impl()->optional32->ImageBase;
    }
    return 0;
}

template <typename T>
bool do_get(std::string& binary, const T *ptr)
{
    if (ptr == NULL)
        return false;

    size_t size = sizeof(*ptr);
    binary.resize(size);
    std::memcpy(&binary[0], ptr, size);
    return true;
}

bool PEModule::get_binary(const std::string& group_name, std::string& binary) const
{
    if (!is_loaded())
        return false;

    if (group_name == "dos")
    {
        return do_get(binary, impl()->dos);
    }
    else if (group_name == "file")
    {
        return do_get(binary, impl()->file);
    }
    else if (group_name == "nt32" && is_32bit())
    {
        return do_get(binary, impl()->nt32);
    }
    else if (group_name == "nt64" && is_64bit())
    {
        return do_get(binary, impl()->nt64);
    }
    else if (group_name == "optional32" && is_32bit())
    {
        return do_get(binary, impl()->optional32);
    }
    else if (group_name == "optional64" && is_64bit())
    {
        return do_get(binary, impl()->optional64);
    }

    return Module::get_binary(group_name, binary);
}

PIMAGE_SECTION_HEADER PEModule::section_from_rva(uint64_t rva) const
{
    assert(is_loaded());

    uint32_t count = impl()->file->NumberOfSections;
    IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(impl()->nt);

    while (count-- > 0)
    {
        // section->VirtualAddress is not an absolute virtual address but an RVA
        if (section->VirtualAddress <= rva &&
            rva < section->VirtualAddress + section->SizeOfRawData)
        {
            return reinterpret_cast<PIMAGE_SECTION_HEADER>(section);
        }
        ++section;
    }

    return NULL;
}

void *PEModule::pointer_from_rva(uint64_t rva)
{
    assert(is_loaded());
    return image_map_typed<BYTE>() + static_cast<uintptr_t>(rva);
}

const void *PEModule::pointer_from_rva(uint64_t rva) const
{
    assert(is_loaded());
    return image_map_typed<BYTE>() + static_cast<uintptr_t>(rva);
}

uint64_t PEModule::rva_from_pointer(const void *pointer) const
{
    assert(is_loaded());
    return reinterpret_cast<const char *>(pointer) - image_map_typed<char>();
}

void *PEModule::data_from_dir(uint16_t iDir, size_t *pSize)
{
    assert(is_loaded());

    if (pSize)
        *pSize = 0;

    if (is_64bit())
    {
        auto opt = impl()->optional64;
        if (opt->NumberOfRvaAndSizes <= iDir)
            return NULL;

        auto& dir = opt->DataDirectory[iDir];
        auto offset = dir.VirtualAddress;   // not an absolute virtual address but an RVA
        if (!offset)
            return NULL;
        if (pSize)
            *pSize = dir.Size;

        return pointer_from_rva(offset);
    }
    else if (is_32bit())
    {
        auto opt = impl()->optional32;
        if (opt->NumberOfRvaAndSizes <= iDir)
            return NULL;

        auto& dir = opt->DataDirectory[iDir];
        auto offset = dir.VirtualAddress;   // not an absolute virtual address but an RVA
        if (!offset)
            return NULL;
        if (pSize)
            *pSize = dir.Size;

        return pointer_from_rva(offset);
    }

    return NULL;
}

const void *PEModule::data_from_dir(uint16_t dir, size_t *pSize) const
{
    return const_cast<PEModule *>(this)->data_from_dir(dir, pSize);
}

uint16_t PEModule::get_dir_from_rva(uint64_t rva) const
{
    assert(is_loaded());

    if (is_64bit())
    {
        auto opt = impl()->optional64;
        for (uint32_t iDir = 0; iDir < opt->NumberOfRvaAndSizes; ++iDir)
        {
            auto& dir = opt->DataDirectory[iDir];
            auto size = dir.Size;
            auto offset = dir.VirtualAddress;
            if (offset <= rva && rva < offset + size)
                return iDir;
        }
    }
    else if (is_32bit())
    {
        auto opt = impl()->optional32;
        for (uint32_t iDir = 0; iDir < opt->NumberOfRvaAndSizes; ++iDir)
        {
            auto& dir = opt->DataDirectory[iDir];
            auto size = dir.Size;
            auto offset = dir.VirtualAddress;
            if (offset <= rva && rva < offset + size)
                return iDir;
        }
    }

    return -1;
}

bool PEModule::_map_image()
{
    impl()->image.resize(size_of_image());
    std::memcpy(&impl()->image[0], &impl()->binary[0], size_of_headers());

    uint32_t count = impl()->file->NumberOfSections;
    for (uint32_t i = 0; i < count; ++i)
    {
        auto entry = &impl()->section_headers[i];
        if (entry->PointerToRawData)
        {
            std::memcpy(&impl()->image[entry->VirtualAddress],
                        &impl()->binary[entry->PointerToRawData],
                        entry->SizeOfRawData);
        }
    }

    return true;
}

void *PEModule::image_map(uint64_t rva, uint32_t size)
{
    if (impl()->image.size() < rva + size)
        return NULL;
    auto ptr = &impl()->image[0];
    return ptr + rva;
}

const void *PEModule::image_map(uint64_t rva, uint32_t size) const
{
    if (impl()->image.size() < rva + size)
        return NULL;
    auto ptr = &impl()->image[0];
    return ptr + rva;
}

uint32_t PEModule::reverse_image_map(const void *ptr) const
{
    auto begin = &impl()->image[0];
    auto end = begin + impl()->image.size();
    if (begin <= ptr && ptr < end)
        return reinterpret_cast<const char *>(ptr) - begin;
    return 0;
}

const IMAGE_SECTION_HEADER *PEModule::get_section_header(int iSection) const
{
    return &(impl()->section_headers)[iSection];
}

/////////////////////////////////////////////////////////////////////////////
// Imports

IMAGE_IMPORT_DESCRIPTOR *
PEModule::get_imports(size_t *pSize)
{
    return get_dir_data<IMAGE_IMPORT_DESCRIPTOR>(IMAGE_DIRECTORY_ENTRY_IMPORT, pSize);
}

const IMAGE_IMPORT_DESCRIPTOR *
PEModule::get_imports(size_t *pSize) const
{
    return get_dir_data<IMAGE_IMPORT_DESCRIPTOR>(IMAGE_DIRECTORY_ENTRY_IMPORT, pSize);
}

bool PEModule::enum_import_items32(IMPORT_PROC32 callback, void *user_data) const
{
    auto pImports = get_imports();
    if (!pImports)
        return false;

    for (; pImports->Characteristics != 0; ++pImports)
    {
        auto pINT = ptr_from_rva<IMAGE_THUNK_DATA32>(pImports->OriginalFirstThunk);
        auto pIAT = ptr_from_rva<IMAGE_THUNK_DATA32>(pImports->FirstThunk);

        while (pINT->u1.AddressOfData != 0 && pIAT->u1.Function != 0)
        {
            if (!callback(pImports, pINT, pIAT, user_data))
                return false;

            ++pINT;
            ++pIAT;
        }
    }

    return true;
}

bool PEModule::enum_import_items64(IMPORT_PROC64 callback, void *user_data) const
{
    auto pImports = get_imports();
    if (!pImports)
        return false;

    for (; pImports->Characteristics != 0; ++pImports)
    {
        auto pINT = ptr_from_rva<IMAGE_THUNK_DATA64>(pImports->OriginalFirstThunk);
        auto pIAT = ptr_from_rva<IMAGE_THUNK_DATA64>(pImports->FirstThunk);

        while (pINT->u1.AddressOfData != 0 && pIAT->u1.Function != 0)
        {
            if (!callback(pImports, pINT, pIAT, user_data))
                return false;

            ++pINT;
            ++pIAT;
        }
    }

    return true;
}

struct LoadImportTable
{
    const PEModule *s_this;
    ImportTable *table;
};

static bool
do_load_import_table_proc32(const IMAGE_IMPORT_DESCRIPTOR *pImports,
                            const IMAGE_THUNK_DATA32 *pINT,
                            const IMAGE_THUNK_DATA32 *pIAT, void *user_data)
{
    LoadImportTable *load = reinterpret_cast<LoadImportTable *>(user_data);
    const PEModule *s_this = load->s_this;
    ImportTable *table = load->table;

    auto module = normalize_module_name(s_this->ptr_from_rva<char>(pImports->Name));
    auto rva = pIAT->u1.Function;
    auto va = s_this->ava_from_rva(rva);

    if (IMAGE_SNAP_BY_ORDINAL32(pINT->u1.Ordinal))
    {
        auto ordinal = (WORD)IMAGE_ORDINAL32(pINT->u1.Ordinal);
        ImportEntry entry = { module, rva, va, "", ordinal, -1 };
        table->push_back(entry);
    }
    else
    {
        auto pName = s_this->ptr_from_rva<IMAGE_IMPORT_BY_NAME>(pINT->u1.AddressOfData);
        auto name = reinterpret_cast<const char *>(pName->Name);
        ImportEntry entry = { module, rva, va, name, -1, pName->Hint };
        table->push_back(entry);
    }

    return true;
}

static bool
do_load_import_table_proc64(const IMAGE_IMPORT_DESCRIPTOR *pImports,
                            const IMAGE_THUNK_DATA64 *pINT,
                            const IMAGE_THUNK_DATA64 *pIAT, void *user_data)
{
    LoadImportTable *load = reinterpret_cast<LoadImportTable *>(user_data);
    const PEModule *s_this = load->s_this;
    ImportTable *table = load->table;

    auto module = normalize_module_name(s_this->ptr_from_rva<char>(pImports->Name));
    auto rva = pIAT->u1.Function;
    auto va = s_this->ava_from_rva(rva);

    if (IMAGE_SNAP_BY_ORDINAL64(pINT->u1.Ordinal))
    {
        auto ordinal = (WORD)IMAGE_ORDINAL64(pINT->u1.Ordinal);
        ImportEntry entry = { module, rva, va, "", ordinal, -1 };
        table->push_back(entry);
    }
    else
    {
        auto pName = s_this->ptr_from_rva<IMAGE_IMPORT_BY_NAME>(pINT->u1.AddressOfData);
        auto name = reinterpret_cast<const char *>(pName->Name);
        ImportEntry entry = { module, rva, va, name, 0, pName->Hint };
        table->push_back(entry);
    }

    return true;
}

bool PEModule::load_import_table(ImportTable& table) const
{
    assert(is_loaded());
    table.clear();

    LoadImportTable load = { this, &table };

    if (is_64bit())
        return enum_import_items64(do_load_import_table_proc64, &load);
    else if (is_32bit())
        return enum_import_items32(do_load_import_table_proc32, &load);
    return false;
}

/////////////////////////////////////////////////////////////////////////////
// Exports

IMAGE_EXPORT_DIRECTORY *
PEModule::get_exports(size_t *pSize)
{
    return get_dir_data<IMAGE_EXPORT_DIRECTORY>(IMAGE_DIRECTORY_ENTRY_EXPORT, pSize);
}

const IMAGE_EXPORT_DIRECTORY *
PEModule::get_exports(size_t *pSize) const
{
    return get_dir_data<IMAGE_EXPORT_DIRECTORY>(IMAGE_DIRECTORY_ENTRY_EXPORT, pSize);
}

bool PEModule::enum_export_items(EXPORT_PROC callback, void *user_data) const
{
    size_t size = 0;
    auto pExports = get_exports(&size);
    if (!pExports)
        return false;

    uint32_t cFuncs = pExports->NumberOfFunctions;
    uint32_t cNames = pExports->NumberOfNames;
    auto funcs = ptr_from_rva<uint32_t>(pExports->AddressOfFunctions);
    auto names = ptr_from_rva<uint32_t>(pExports->AddressOfNames);
    auto ordinals = ptr_from_rva<uint16_t>(pExports->AddressOfNameOrdinals);

    int hint = 0;
    for (uint32_t iName = 0; iName < cNames; ++iName, ++hint)
    {
        int ordinal = pExports->Base + ordinals[iName];
        auto rva = funcs[ordinals[iName]];
        auto va = ava_from_rva(rva);

        const char *name = ptr_from_rva<char>(names[iName]);

        const char *forwarded_to = NULL;
        const void *ptr = ptr_from_rva<char>(rva);
        if (pExports <= ptr && ptr <= reinterpret_cast<const char *>(pExports) + size)
        {
            forwarded_to = reinterpret_cast<const char *>(ptr);
        }

        if (!callback(pExports, name, rva, va, ordinal, hint, forwarded_to, user_data))
            return false;
    }
    for (uint32_t iFunc = 0; iFunc < cFuncs; ++iFunc)
    {
        if (funcs[iFunc] == 0)
            continue;

        int ordinal = pExports->Base + iFunc;
        auto rva = funcs[iFunc];
        auto va = ava_from_rva(rva);

        const char *name = NULL;
        for (uint32_t iName = 0; iName < cNames; ++iName)
        {
            if (ordinals[iName] == iFunc)
            {
                name = ptr_from_rva<char>(names[iName]);
                break;
            }
        }
        if (name)
            continue;

        const char *forwarded_to = NULL;
        const void *ptr = ptr_from_rva<char>(rva);
        if (pExports <= ptr && ptr <= reinterpret_cast<const char *>(pExports) + size)
        {
            forwarded_to = reinterpret_cast<const char *>(ptr);
        }

        if (!callback(pExports, name, rva, va, ordinal, -1, forwarded_to, user_data))
            return false;
    }

    return true;
}

static bool
do_load_export_table_proc(const IMAGE_EXPORT_DIRECTORY *pExports,
                          const char *name, uint64_t rva, uint64_t va,
                          int ordinal, int hint, const char *forwarded_to,
                          void *user_data)
{
    ExportTable *table = reinterpret_cast<ExportTable *>(user_data);
    ExportEntry entry =
    {
        (name ? name : ""), rva, va, ordinal, hint,
        (forwarded_to ? forwarded_to : "")
    };
    table->push_back(entry);
    return true;
}

bool PEModule::load_export_table(ExportTable& table) const
{
    assert(is_loaded());
    table.clear();
    return enum_export_items(do_load_export_table_proc, &table);
}

/////////////////////////////////////////////////////////////////////////////
// Delay

ImgDelayDescr *
PEModule::get_delay(size_t *pSize)
{
    return get_dir_data<ImgDelayDescr>(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, pSize);
}

const ImgDelayDescr *
PEModule::get_delay(size_t *pSize) const
{
    return get_dir_data<ImgDelayDescr>(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, pSize);
}

bool PEModule::enum_delay_items32(DELAY_PROC32 callback, void *user_data) const
{
    auto delay = get_delay();
    if (!delay)
        return false;

    for (; delay->rvaHmod != 0; ++delay)
    {
        auto module = ptr_from_rva<char>(delay->rvaDLLName);
        auto hModule = impl()->optional32->ImageBase + delay->rvaHmod;
        auto pINT = image_map_typed<IMAGE_THUNK_DATA32>(delay->rvaINT);
        auto pIAT = image_map_typed<IMAGE_THUNK_DATA32>(delay->rvaIAT);

        while (pINT->u1.AddressOfData != 0 && pIAT->u1.Function != 0)
        {
            if (!callback(module, hModule, pINT, pIAT, user_data))
                return false;

            ++pINT;
            ++pIAT;
        }
    }

    return true;
}

bool PEModule::enum_delay_items64(DELAY_PROC64 callback, void *user_data) const
{
    auto delay = get_delay();
    if (!delay)
        return false;

    for (; delay->rvaHmod != 0; ++delay)
    {
        auto module = ptr_from_rva<char>(delay->rvaDLLName);
        auto hModule = impl()->optional64->ImageBase + delay->rvaHmod;
        auto pINT = image_map_typed<IMAGE_THUNK_DATA64>(delay->rvaINT);
        auto pIAT = image_map_typed<IMAGE_THUNK_DATA64>(delay->rvaIAT);

        while (pINT->u1.AddressOfData != 0 && pIAT->u1.Function != 0)
        {
            if (!callback(module, hModule, pINT, pIAT, user_data))
                return false;

            ++pINT;
            ++pIAT;
        }
    }

    return true;
}

struct LoadDelayTable
{
    const PEModule *s_this;
    DelayTable *table;
};

static bool
do_load_delay_proc32(const char *module, uint32_t hModule,
                     const IMAGE_THUNK_DATA32 *pINT,
                     const IMAGE_THUNK_DATA32 *pIAT, void *user_data)
{
    LoadDelayTable *load = reinterpret_cast<LoadDelayTable *>(user_data);
    const PEModule *s_this = load->s_this;
    DelayTable *table = load->table;

    auto va = pIAT->u1.Function;

    if (IMAGE_SNAP_BY_ORDINAL32(pINT->u1.Ordinal))
    {
        auto ordinal = (WORD)IMAGE_ORDINAL32(pINT->u1.Ordinal);
        DelayEntry entry = { module, hModule, va, "", ordinal, -1 };
        table->push_back(entry);
    }
    else
    {
        auto pName = s_this->ptr_from_rva<IMAGE_IMPORT_BY_NAME>(pINT->u1.AddressOfData);
        auto name = reinterpret_cast<const char *>(pName->Name);
        DelayEntry entry = { module, hModule, va, name, -1, pName->Hint};
        table->push_back(entry);
    }

    return true;
}

static bool
do_load_delay_proc64(const char *module, uint64_t hModule,
                     const IMAGE_THUNK_DATA64 *pINT,
                     const IMAGE_THUNK_DATA64 *pIAT, void *user_data)
{
    LoadDelayTable *load = reinterpret_cast<LoadDelayTable *>(user_data);
    const PEModule *s_this = load->s_this;
    DelayTable *table = load->table;

    auto va = pIAT->u1.Function;

    if (IMAGE_SNAP_BY_ORDINAL64(pINT->u1.Ordinal))
    {
        auto ordinal = (WORD)IMAGE_ORDINAL64(pINT->u1.Ordinal);
        DelayEntry entry = { module, hModule, va, "", ordinal, -1 };
        table->push_back(entry);
    }
    else
    {
        auto pName = s_this->ptr_from_rva<IMAGE_IMPORT_BY_NAME>(pINT->u1.AddressOfData);
        auto name = reinterpret_cast<const char *>(pName->Name);
        DelayEntry entry = { module, hModule, va, name, -1, pName->Hint };
        table->push_back(entry);
    }

    return true;
}

bool PEModule::load_delay_table(DelayTable& table) const
{
    assert(is_loaded());
    table.clear();
    LoadDelayTable load = { this, &table };

    if (is_64bit())
        return enum_delay_items64(do_load_delay_proc64, &load);
    else if (is_32bit())
        return enum_delay_items32(do_load_delay_proc32, &load);
    return false;
}

/////////////////////////////////////////////////////////////////////////////

bool PEModule::start_disasm(DisAsmData& data) const
{
    auto& names = data.names;

    if (is_dll())
        names[ava_from_rva(rva_of_entry_point())] = m_module_name + "!_DllMainCRTStartup";
    else if (is_gui())
        names[ava_from_rva(rva_of_entry_point())] = m_module_name + "!WinMainCRTStartup";
    else
        names[ava_from_rva(rva_of_entry_point())] = m_module_name + "!mainCRTStartup";

    if (load_import_table(data.imports))
    {
        for (auto& entry : data.imports)
        {
            auto module = entry.module;
            auto str = module + "!";
            if (entry.func_name.empty())
            {
                names[ava_from_rva(entry.rva)] = str +
                    string_formatted("%u", entry.ordinal);
            }
            else
            {
                names[ava_from_rva(entry.rva)] = str + entry.func_name;
            }
        }
    }

    if (load_export_table(data.exports))
    {
        for (auto& entry : data.exports)
        {
            if (!is_rva_code(entry.rva))
                continue;

            auto str = m_module_name + "!";
            if (entry.name.empty())
            {
                names[ava_from_rva(entry.rva)] =
                    str + string_formatted("%u", entry.ordinal);
            }
            else
            {
                names[ava_from_rva(entry.rva)] = str + entry.name;
            }
        }
    }

    if (load_delay_table(data.delays))
    {
        for (auto& entry : data.delays)
        {
            auto module = entry.module;
            auto i = module.find('.');
            if (i != std::string::npos)
            {
                module = module.substr(0, i);
            }

            auto str = module + "!";
            if (entry.func_name.empty())
            {
                names[entry.va] = str + string_formatted("%u", entry.ordinal);
            }
            else
            {
                names[entry.va] = str + entry.func_name;
            }
        }
    }

    return true;
}

bool PEModule::end_disasm(DisAsmData& data) const
{
    auto& names = data.names;
    auto& ava_to_func = data.ava_to_func;

    for (auto& pair : ava_to_func)
    {
        auto& ava = pair.first;
        auto& func = pair.second;
        auto it = names.find(pair.first);
        if (it == names.end())
        {
            auto& name = names[ava];
            if (is_64bit())
            {
                name = "Func" + string_of_addr64(ava);
            }
            else
            {
                name = "Func" + string_of_addr32(static_cast<uint32_t>(ava));
            }
            if (func.atmark && name.find("@") == name.npos)
            {
                name += string_formatted("@%u", func.atmark);
            }
        }
    }

    for (auto& pair : ava_to_func)
    {
        auto& ava = pair.first;
        auto& func = pair.second;

        for (auto& pair2 : func.ava_to_asm)
        {
            auto& code = pair2.second;
            uint64_t imm, mem;
            switch (code.mnemonic)
            {
            case UD_Icall:
                imm = get_disasm_first_imm_operand(code.raw);
                mem = get_disasm_first_mem_operand(code.raw, 0);
                if (imm != invalid_ava)
                {
                    auto it = names.find(imm);
                    if (it != names.end())
                    {
                        auto& name = it->second;
                        if (name.find("imp.") == 0)
                        {
                            code.cooked = "call ";
                            code.cooked += name.substr(strlen("imp."));
                        }
                        else
                        {
                            code.cooked = "call ";
                            code.cooked += name;
                        }
                        if (code.cooked.find("@") == code.cooked.npos)
                        {
                            if (func.atmark)
                                code.cooked += string_formatted("@%u", func.atmark);
                        }
                    }
                }
                else if (mem != 0 && mem != invalid_ava)
                {
                    auto it = names.find(mem);
                    if (it != names.end())
                    {
                        code.cooked = "call ";
                        code.cooked += it->second;
                    }
                }
                break;

            case UD_Ijmp:
            case UD_Ija: case UD_Ijae: case UD_Ijb: case UD_Ijbe:
            case UD_Ijcxz: case UD_Ijecxz: case UD_Ijg: case UD_Ijge:
            case UD_Ijl: case UD_Ijle: case UD_Ijno: case UD_Ijnp:
            case UD_Ijns: case UD_Ijnz: case UD_Ijo: case UD_Ijp:
            case UD_Ijrcxz: case UD_Ijs: case UD_Ijz:
                imm = get_disasm_first_imm_operand(code.raw);
                if (imm != invalid_ava)
                {
                    std::string str = code.raw;
                    size_t index = str.find(' ');
                    if (index != std::string::npos)
                    {
                        std::string operands = str.substr(index + 1);
                        if (memcmp(operands.c_str(), "0x", 2) == 0)
                        {
                            auto ava = strtoll(operands.c_str(), NULL, 16);
                            std::string addr;
                            if (is_64bit())
                                addr = string_of_addr64(ava);
                            else
                                addr = string_of_addr32(static_cast<uint32_t>(ava));

                            str = code.raw.substr(0, index);
                            code.cooked = str + " Label_" + addr;
                        }
                    }
                }
                break;

            default:
                break;
            }
        }
    }

    return true;
}

bool PEModule::get_entry_points(std::unordered_set<uint64_t>& avas) const
{
    avas.clear();
    avas.insert(ava_from_rva(rva_of_entry_point()));

    ExportTable table;
    if (load_export_table(table))
    {
        for (auto& entry : table)
        {
            if (!is_rva_code(entry.rva))
                continue;

            if (entry.forwarded_to.empty())
                avas.insert(ava_from_rva(entry.rva));
        }
    }

    return true;
}

bool PEModule::do_disasm(DisAsmData& data) const
{
    NameMap& names = data.names;
    std::map<uint64_t, Func>& ava_to_func = data.ava_to_func;
    ava_to_func.clear();

    std::unordered_set<uint64_t> avas;
    if (!get_entry_points(avas))
        return false;

    for (auto& ava : avas)
    {
        Func func;
        if (do_disasm_func(data, ava, func))
        {
            func.attributes.insert("[[entry]]");
            ava_to_func[ava] = func;
        }
    }

    for (auto& ava : impl()->additional_func_avas)
    {
        Func func;
        if (do_disasm_func(data, ava, func))
        {
            ava_to_func[ava] = func;
        }
    }

retry:
    for (auto& pair : ava_to_func)
    {
        Func& func = pair.second;
        for (auto to : func.call_to)
        {
            auto rva = rva_from_ava(to);
            if (!is_rva_code(rva))
                continue;

            auto it = ava_to_func.find(to);
            if (it == ava_to_func.end())
            {
                Func func;
                if (do_disasm_func(data, to, func))
                {
                    ava_to_func[to] = func;
                    goto retry;
                }
            }
            else
            {
                it->second.call_from.insert(pair.first);
            }
        }
    }

    return true;
}

static const PEModule *s_this = NULL;
static uint64_t s_ava = 0;

/*static*/ int PEModule::input_hook_x(ud* u)
{
    return s_this->input_hook(u);
}

int PEModule::input_hook(ud* u) const
{
    uint64_t rva = rva_from_ava(s_ava);
    uint8_t byte = *ptr_from_rva<uint8_t>(rva);
    ++s_ava;
    return byte;
}

bool PEModule::do_disasm_func(DisAsmData& data, uint64_t ava, Func& func) const
{
    NameMap& names = data.names;
    s_this = this;
    func.ava = ava;

    ud_t ud;
    ud_init(&ud);
    ud_set_input_hook(&ud, input_hook_x);
    ud_set_mode(&ud, (is_64bit() ? 64 : 32));
    ud_set_syntax(&ud, UD_SYN_INTEL);

    bool first = true;
    func.attributes.insert("[[noreturn]]");
retry:
    for (;;)
    {
        s_ava = ava;
        ud_set_pc(&ud, ava);
        if (!ud_disassemble(&ud))
            break;

        std::string disasm = ud_insn_asm(&ud);
        func.ava_to_asm[ava].raw = disasm;
        func.ava_to_asm[ava].cooked = disasm;
        auto bytes = int(s_ava - ava);
        func.ava_to_asm[ava].bytes = bytes;

        std::string hex;
        for (int i = 0; i < bytes; ++i)
        {
            if (i != 0)
                hex += ' ';
            auto rva = rva_from_ava(ava);
            hex += string_formatted("%02X", *ptr_from_rva<uint8_t>(rva + i));
        }
        func.ava_to_asm[ava].hex = hex;

        bool is_quit = false;
        auto ip = ava + bytes;
        uint64_t imm = get_disasm_first_imm_operand(disasm);
        uint64_t mem = get_disasm_first_mem_operand(disasm, ip);
        func.ava_to_asm[ava].mnemonic = ud.mnemonic;

        switch (ud.mnemonic)
        {
        case UD_Icall:
            switch (ud.operand[0].type)
            {
            case UD_OP_IMM:
            case UD_OP_JIMM:
                if (imm != invalid_ava)
                {
                    func.call_to.insert(imm);
                }
                break;
            case UD_OP_MEM:
                if (mem != invalid_ava)
                {
                    auto rva = rva_from_ava(mem);
                    if (!is_rva_writable(rva) ||
                        get_dir_from_rva(rva) == IMAGE_DIRECTORY_ENTRY_IMPORT)
                    {
                        uint64_t to;
                        if (is_64bit())
                        {
                            to = *ptr_from_rva<uint64_t>(rva);
                        }
                        else if (is_32bit())
                        {
                            to = *ptr_from_rva<uint32_t>(rva);
                        }
                        else
                        {
                            assert(0);
                        }

                        auto call_to = ava_from_rva(to);
                        auto it = names.find(call_to);
                        if (it != names.end())
                        {
                            func.ava_to_asm[ava].cooked = "call ";
                            func.ava_to_asm[ava].cooked += it->second;
                        }
                    }
                }
                break;
            default:
                break;
            }
            break;

        case UD_Ijmp:
            is_quit = true;
            switch (ud.operand[0].type)
            {
            case UD_OP_IMM:
            case UD_OP_JIMM:
                func.jump_to.insert(imm);
                func.ava_to_asm[ava].jump_to = imm;
                break;
            default:
                if (first && mem != invalid_ava)
                {
                    func.attributes.insert("[[jumponly]]");
                    func.attributes.erase("[[noreturn]]");

                    uint64_t jump_to;
                    if (is_64bit())
                    {
                        jump_to = *ptr_from_rva<uint64_t>(rva_from_ava(mem));
                    }
                    else if (is_32bit())
                    {
                        jump_to = *ptr_from_rva<uint32_t>(rva_from_ava(mem));
                    }
                    else
                    {
                        assert(0);
                    }

                    uint64_t to = ava_from_rva(jump_to);

                    if (names.find(to) != names.end())
                    {
                        std::string name = "imp.";
                        name += names[to];
                        names[func.ava] = name;
                    }
                }
                break;
            }
            break;

        case UD_Ija: case UD_Ijae: case UD_Ijb: case UD_Ijbe:
        case UD_Ijcxz: case UD_Ijecxz: case UD_Ijg: case UD_Ijge:
        case UD_Ijl: case UD_Ijle: case UD_Ijno: case UD_Ijnp:
        case UD_Ijns: case UD_Ijnz: case UD_Ijo: case UD_Ijp:
        case UD_Ijrcxz: case UD_Ijs: case UD_Ijz:
            switch (ud.operand[0].type)
            {
            case UD_OP_IMM:
            case UD_OP_JIMM:
                func.jump_to.insert(imm);
                func.ava_to_asm[ava].jump_to = imm;
                break;
            default:
                break;
            }
            break;

        case UD_Iret: case UD_Iretf:
        case UD_Iiretd: case UD_Iiretq: case UD_Iiretw:
            if (imm != invalid_ava)
            {
                func.atmark = uint32_t(imm);
                auto it = names.find(func.ava);
                if (it != names.end())
                {
                    auto& name = it->second;
                    if (name.find('@') == name.npos)
                        name += string_formatted("@%u", func.atmark);
                }
            }
            is_quit = true;
            func.attributes.erase("[[noreturn]]");
            switch (ud.operand[0].type)
            {
            case UD_OP_IMM:
            case UD_OP_JIMM:
                func.attributes.insert("[[stdcall]]");
                break;
            default:
                func.attributes.insert("[[cdecl]]");
                break;
            }
            break;
        }

        ava = s_ava;

        first = false;
        if (is_quit)
            break;
    }

    for (auto& to : func.jump_to)
    {
        auto it = func.ava_to_asm.find(to);
        if (it == func.ava_to_asm.end())
        {
            ava = to;
            goto retry;
        }
    }

    for (auto& pair : func.ava_to_asm)
    {
        auto to = pair.second.jump_to;
        if (to != invalid_ava)
        {
            auto it = func.ava_to_asm.find(to);
            if (it != func.ava_to_asm.end())
            {
                it->second.jump_from.insert(pair.first);
            }
        }
    }

    return true;
}

bool PEModule::add_func_by_ava(uint64_t ava)
{
    if (!is_valid_ava(ava))
        return false;

    auto rva = rva_from_ava(ava);
    if (!is_rva_code(rva))
        return false;

    impl()->additional_func_avas.push_back(ava);
    return true;
}

std::string decode_hex(const char *hex)
{
    std::string ret;

    while (*hex)
    {
        while (std::isspace(*hex))
            ++hex;

        char byte;
        if ('0' <= *hex && *hex <= '9')
            byte = *hex - '0';
        else if ('A' <= *hex && *hex <= 'F')
            byte = *hex + (10 - 'A');
        else if ('a' <= *hex && *hex <= 'f')
            byte = *hex + (10 - 'a');
        else
            break;
        ++hex;
        byte <<= 4;
        if ('0' <= *hex && *hex <= '9')
            byte |= *hex - '0';
        else if ('A' <= *hex && *hex <= 'F')
            byte |= *hex + (10 - 'A');
        else if ('a' <= *hex && *hex <= 'f')
            byte |= *hex + (10 - 'a');
        else
            break;
        ++hex;
        ret += byte;
    }

    return ret;
}

std::string PEModule::write(uint64_t ava, uint32_t size, const char *hex, bool force)
{
    std::string binary;
    if (hex && *hex)
        binary = decode_hex(hex);
    if (binary.size() < size)
        binary.resize(size);

    std::string ret;
    ret += "## Write Memory ##\n";

    for (size_t i = 0; i < size; ++i)
    {
        auto addr = ava + i;
        if (is_64bit())
            ret += string_of_addr64(addr) + ": ";
        else
            ret += string_of_addr32(addr) + ": ";
        if (!is_valid_ava(addr))
        {
            ret += "Not valid address.\n";
            break;
        }
        auto rva = rva_from_ava(addr);
        if (!force && !is_rva_writable(rva))
        {
            ret += "Not writable.\n";
            break;
        }
        auto ptr = ptr_from_rva<uint8_t>(rva);
        if (force || is_rva_readable(rva))
            ret += string_formatted("%02X --> %02X\n", (uint8_t)*ptr, (uint8_t)binary[i]);
        else
            ret += string_formatted("(unreadable) --> %02X\n", (uint8_t)binary[i]);
        *ptr = binary[i];
    }

    ret += "\n";
    return ret;
}

std::string PEModule::read(uint64_t ava, uint32_t size, bool force)
{
    std::string ret;
    ret += "## Read Memory ##\n";

    for (size_t i = 0; i < size; ++i)
    {
        auto addr = ava + i;
        if (is_64bit())
            ret += string_of_addr64(addr) + ": ";
        else
            ret += string_of_addr32(addr) + ": ";
        if (!is_valid_ava(addr))
        {
            ret += "Not valid address.\n";
            break;
        }
        auto rva = rva_from_ava(addr);
        if (!force && !is_rva_readable(rva))
        {
            ret += "Not readable.\n";
            break;
        }
        auto ptr = ptr_from_rva<uint8_t>(rva);
        ret += string_formatted("%02X\n", (uint8_t)*ptr);
    }

    ret += "\n";
    return ret;
}

/////////////////////////////////////////////////////////////////////////////
// Dumping

std::string PEModule::dump(const std::string& name, bool show_addr, bool show_hex) const
{
    assert(is_loaded());

    if (name == "all")
    {
        std::string ret;
        ret += dump("dos");
        ret += dump("file");
        ret += dump("optional");
        ret += dump("datadir");
        ret += dump("sections");
        ret += dump("imports");
        ret += dump("exports");
        ret += dump("delay");
        ret += dump("disasm", show_addr, show_hex);
        return ret;
    }

    if (name == "dos")
        return string_of_dos_header(impl()->dos);
    if (name == "file")
        return string_of_file_header(impl()->file);
    if (name == "optional")
    {
        if (is_64bit())
            return string_of_optional64(impl()->optional64);
        else if (is_32bit())
            return string_of_optional32(impl()->optional32);
    }
    if (name == "optional32" && is_32bit())
        return string_of_optional32(impl()->optional32);
    if (name == "optional64" && is_64bit())
        return string_of_optional64(impl()->optional64);
    if (name == "datadir")
        return string_of_data_directories(&impl()->data_directories, is_64bit());
    if (name == "sections")
        return string_of_section_headers(impl()->section_headers, impl()->file->NumberOfSections, is_64bit());
    if (name == "imports")
    {
        ImportTable table;
        load_import_table(table);
        return string_of_imports(get_imports(), table, is_64bit());
    }
    if (name == "exports")
    {
        ExportTable table;
        load_export_table(table);
        return string_of_exports(m_module_name.c_str(), get_exports(), table, is_64bit());
    }
    if (name == "delay")
    {
        DelayTable table;
        load_delay_table(table);
        return string_of_delay(table, is_64bit());
    }
    if (name == "disasm")
    {
        DisAsmData data;
        start_disasm(data);
        do_disasm(data);
        end_disasm(data);
        return string_of_disasm(data, show_addr, show_hex, is_64bit());
    }

    return Module::dump(name);
}

} // namespace cr2
