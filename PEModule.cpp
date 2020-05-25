#include "PEModule.h"
#include "dumping.h"
#include "internal.h"
#include <cstring>
#include <cassert>
#include "udis86/udis86.h"

namespace cr2
{

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
}

PEModule::PEModule(const char *filename) : Module(std::make_shared<PEModuleImpl>())
{
    Module::load(filename);
}

PEModule::PEModule(const wchar_t *filename) : Module(std::make_shared<PEModuleImpl>())
{
    Module::load(filename);
}

PEModule::PEModule(FILE *fp) : Module(std::make_shared<PEModuleImpl>())
{
    load(fp);
}

bool PEModule::load(const char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp)
        return false;
    bool ret = load(fp);
    fclose(fp);
    return ret;
}

bool PEModule::load(const wchar_t *filename)
{
#ifdef _WIN32
    FILE *fp = _wfopen(filename, L"rb");
    if (!fp)
        return false;
    bool ret = load(fp);
    fclose(fp);
    return ret;
#else
    return false;
#endif
}

bool PEModule::load(FILE *fp)
{
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
    impl()->section_headers = sh;
    impl()->data_directories = dd;

    if (!_map_image())
        return false;

    store_func_names();
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
    const PEModule *this_;
    ImportTable *table;
};

static bool
do_load_import_table_proc32(const IMAGE_IMPORT_DESCRIPTOR *pImports,
                            const IMAGE_THUNK_DATA32 *pINT,
                            const IMAGE_THUNK_DATA32 *pIAT, void *user_data)
{
    LoadImportTable *load = reinterpret_cast<LoadImportTable *>(user_data);
    const PEModule *this_ = load->this_;
    ImportTable *table = load->table;

    auto module = this_->ptr_from_rva<char>(pImports->Name);
    auto rva = pIAT->u1.Function;

    if (IMAGE_SNAP_BY_ORDINAL32(pINT->u1.Ordinal))
    {
        auto ordinal = (WORD)IMAGE_ORDINAL32(pINT->u1.Ordinal);
        ImportEntry entry = { module, rva, "", ordinal, -1 };
        table->push_back(entry);
    }
    else
    {
        auto pName = this_->ptr_from_rva<IMAGE_IMPORT_BY_NAME>(pINT->u1.AddressOfData);
        auto name = reinterpret_cast<const char *>(pName->Name);
        ImportEntry entry = { module, rva, name, -1, pName->Hint };
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
    const PEModule *this_ = load->this_;
    ImportTable *table = load->table;

    auto module = this_->ptr_from_rva<char>(pImports->Name);
    auto rva = pIAT->u1.Function;

    if (IMAGE_SNAP_BY_ORDINAL64(pINT->u1.Ordinal))
    {
        auto ordinal = (WORD)IMAGE_ORDINAL64(pINT->u1.Ordinal);
        ImportEntry entry = { module, rva, "", ordinal, -1 };
        table->push_back(entry);
    }
    else
    {
        auto pName = this_->ptr_from_rva<IMAGE_IMPORT_BY_NAME>(pINT->u1.AddressOfData);
        auto name = reinterpret_cast<const char *>(pName->Name);
        ImportEntry entry = { module, rva, name, 0, pName->Hint };
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

        const char *name = ptr_from_rva<char>(names[iName]);

        const char *forwarded_to = NULL;
        const void *ptr = ptr_from_rva<char>(rva);
        if (pExports <= ptr && ptr <= reinterpret_cast<const char *>(pExports) + size)
        {
            forwarded_to = reinterpret_cast<const char *>(ptr);
        }

        if (!callback(pExports, name, rva, ordinal, hint, forwarded_to, user_data))
            return false;
    }
    for (uint32_t iFunc = 0; iFunc < cFuncs; ++iFunc)
    {
        if (funcs[iFunc] == 0)
            continue;

        int ordinal = pExports->Base + iFunc;
        auto rva = funcs[iFunc];

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

        if (!callback(pExports, name, rva, ordinal, -1, forwarded_to, user_data))
            return false;
    }

    return true;
}

static bool
do_load_export_table_proc(const IMAGE_EXPORT_DIRECTORY *pExports,
                          const char *name, uint64_t rva,
                          int ordinal, int hint, const char *forwarded_to,
                          void *user_data)
{
    ExportTable *table = reinterpret_cast<ExportTable *>(user_data);
    ExportEntry entry =
    {
        (name ? name : ""), rva, ordinal, hint,
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
    const PEModule *this_;
    DelayTable *table;
};

bool do_load_delay_proc32(const char *module, uint32_t hModule,
                          const IMAGE_THUNK_DATA32 *pINT,
                          const IMAGE_THUNK_DATA32 *pIAT, void *user_data)
{
    LoadDelayTable *load = reinterpret_cast<LoadDelayTable *>(user_data);
    const PEModule *this_ = load->this_;
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
        auto pName = this_->ptr_from_rva<IMAGE_IMPORT_BY_NAME>(pINT->u1.AddressOfData);
        auto name = reinterpret_cast<const char *>(pName->Name);
        DelayEntry entry = { module, hModule, va, name, -1, pName->Hint};
        table->push_back(entry);
    }

    return true;
}

bool do_load_delay_proc64(const char *module, uint32_t hModule,
                          const IMAGE_THUNK_DATA64 *pINT,
                          const IMAGE_THUNK_DATA64 *pIAT, void *user_data)
{
    LoadDelayTable *load = reinterpret_cast<LoadDelayTable *>(user_data);
    const PEModule *this_ = load->this_;
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
        auto pName = this_->ptr_from_rva<IMAGE_IMPORT_BY_NAME>(pINT->u1.AddressOfData);
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

bool PEModule::store_func_names()
{
    auto& names = impl()->names;
    if (is_dll())
        names[ava_from_rva(rva_of_entry_point())] = "_DllMainCRTStartup";
    else if (is_gui())
        names[ava_from_rva(rva_of_entry_point())] = "WinMainCRTStartup";
    else
        names[ava_from_rva(rva_of_entry_point())] = "mainCRTStartup";

    ImportTable imports;
    if (load_import_table(imports))
    {
        for (auto& entry : imports)
        {
            names[ava_from_rva(entry.rva)] = entry.func_name;
        }
    }

    ExportTable exports;
    if (load_export_table(exports))
    {
        for (auto& entry : exports)
        {
            if (entry.name.empty())
            {
                names[ava_from_rva(entry.rva)] =
                    string_formatted("ExportOrdinal_%u", entry.ordinal);
            }
            else
            {
                names[ava_from_rva(entry.rva)] = entry.name;
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
            if (entry.forwarded_to.empty())
                avas.insert(ava_from_rva(entry.rva));
        }
    }

    return true;
}

bool PEModule::do_disasm(std::map<uint64_t, Func>& ava_to_func) const
{
    ava_to_func.clear();

    std::unordered_set<uint64_t> avas;
    if (!get_entry_points(avas))
        return false;

    for (auto& ava : avas)
    {
        Func func;
        if (do_disasm_func(ava, func))
        {
            ava_to_func[ava] = func;
        }
    }

    return true;
}

static const PEModule *this_ = NULL;
static uint64_t s_ava;

/*static*/ int PEModule::input_hook_x(ud_t* u)
{
    return this_->input_hook(u);
}

int PEModule::input_hook(ud_t* u) const
{
    uint64_t rva = rva_from_ava(s_ava);
    uint8_t byte = *ptr_from_rva<uint8_t>(rva);
    ++s_ava;
    return byte;
}

bool PEModule::do_disasm_func(uint64_t func_ava, Func& func) const
{
    this_ = this;
    uint64_t ava;
    ava = func_ava;

    ud_t ud;
    ud_init(&ud);
    ud_set_input_hook(&ud, input_hook_x);
    ud_set_mode(&ud, (is_64bit() ? 64 : 32));
    ud_set_syntax(&ud, UD_SYN_INTEL);

    for (;;)
    {
        s_ava = ava;
        ud_set_pc(&ud, ava);
        if (!ud_disassemble(&ud))
            break;

        std::string disasm = ud_insn_asm(&ud);
        func.ava_to_disasm[ava].disasm = disasm;
        func.ava_to_disasm[ava].bytes = int(s_ava - ava);
        ava = s_ava;
        if (disasm.find("ret") != std::string::npos)
            break;
    }

    return true;
}

/////////////////////////////////////////////////////////////////////////////
// Dumping

std::string PEModule::dump(const std::string& name) const
{
    assert(is_loaded());

    if (name == "all")
    {
        std::string ret;
        ret += dump("dos");
        ret += dump("file");
        ret += dump("optional");
        ret += dump("sections");
        ret += dump("imports");
        ret += dump("exports");
        ret += dump("delay");
        ret += dump("disasm");
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
    if (name == "sections")
    {
        std::string ret;
        auto sh = impl()->section_headers;
        uint32_t i, count = impl()->file->NumberOfSections;
        for (i = 0; i < count; ++i)
        {
            ret += string_of_section_header(&sh[i], i);
        }
        return ret;
    }
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
        return string_of_exports(get_exports(), table, is_64bit());
    }
    if (name == "delay")
    {
        DelayTable table;
        load_delay_table(table);
        return string_of_delay(table, is_64bit());
    }
    if (name == "disasm")
    {
        std::map<uint64_t, Func> ava_to_func;
        if (do_disasm(ava_to_func))
            return string_of_disasm(ava_to_func, impl()->names, is_64bit());
    }

    return Module::dump(name);
}

} // namespace cr2
