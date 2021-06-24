#pragma once

#include "Module.h"
#include "ports.h"
#include "cr2.hpp"

struct ud;

namespace cr2
{

//
// PE Module class
//

struct PEModuleImpl;

class PEModule : public Module
{
public:
    PEModule();
    PEModule(const char *filename);
    PEModule(const wchar_t *filename);

    virtual bool is_loaded() const;
    bool load(const char *filename);
    bool load(const wchar_t *filename);
    virtual void unload();

          void *image_map(uint64_t rva = 0, uint32_t size = 1);
    const void *image_map(uint64_t rva = 0, uint32_t size = 1) const;

    template <typename T>
    T *image_map_typed(uint64_t rva = 0)
    {
        return reinterpret_cast<T *>(image_map(rva, sizeof(T)));
    }
    template <typename T>
    const T *image_map_typed(uint64_t rva = 0) const
    {
        return reinterpret_cast<const T *>(image_map(rva, sizeof(T)));
    }

    uint32_t reverse_image_map(const void *ptr) const;

    bool is_32bit() const;
    bool is_64bit() const;
    bool is_dll() const;
    bool is_cui() const;
    bool is_gui() const;

    uint32_t get_file_flags() const;
    uint32_t get_subsystem() const;

    // NOTE: AVA is absolute virtual address.
    bool is_valid_ava(uint64_t ava) const;
    uint64_t ava_from_rva(uint64_t rva) const;
    uint64_t rva_from_ava(uint64_t ava) const;

          void *pointer_from_rva(uint64_t rva);
    const void *pointer_from_rva(uint64_t rva) const;
    uint64_t rva_from_pointer(const void *pointer) const;

    template <typename T>
    T *ptr_from_rva(uint64_t rva)
    {
        return reinterpret_cast<T *>(pointer_from_rva(rva));
    }
    template <typename T>
    const T *ptr_from_rva(uint64_t rva) const
    {
        return reinterpret_cast<const T *>(pointer_from_rva(rva));
    }

    PIMAGE_SECTION_HEADER section_from_rva(uint64_t rva) const;
    const IMAGE_SECTION_HEADER *get_section_header(int iSection) const;

    uint32_t size_of_headers() const;
    uint32_t size_of_image() const;
    uint32_t base_of_code() const;
    uint64_t rva_of_entry_point() const;
    bool is_rva_code(uint64_t rva) const;
    bool is_rva_readable(uint64_t rva) const;
    bool is_rva_writable(uint64_t rva) const;

    virtual bool get_binary(const std::string& group_name, std::string& binary) const;

    template <typename T>
    T *get_dir_data(uint16_t dir, size_t *pSize = NULL)
    {
        return reinterpret_cast<T *>(data_from_dir(dir, pSize));
    }
    template <typename T>
    const T *get_dir_data(uint16_t dir, size_t *pSize = NULL) const
    {
        return reinterpret_cast<const T *>(data_from_dir(dir, pSize));
    }

    uint16_t get_dir_from_rva(uint64_t rva) const;

    /////////////////////////////////////////////////////////////////////////
    // Imports
          IMAGE_IMPORT_DESCRIPTOR *get_imports(size_t *pSize = NULL);
    const IMAGE_IMPORT_DESCRIPTOR *get_imports(size_t *pSize = NULL) const;

    bool load_import_table(ImportTable& table) const;
    bool enum_import_items32(IMPORT_PROC32 callback, void *user_data = NULL) const;
    bool enum_import_items64(IMPORT_PROC64 callback, void *user_data = NULL) const;

    /////////////////////////////////////////////////////////////////////////
    // Exports
          IMAGE_EXPORT_DIRECTORY *get_exports(size_t *pSize = NULL);
    const IMAGE_EXPORT_DIRECTORY *get_exports(size_t *pSize = NULL) const;

    bool load_export_table(ExportTable& table) const;
    bool enum_export_items(EXPORT_PROC callback, void *user_data = NULL) const;

    /////////////////////////////////////////////////////////////////////////
    // Delay
    ImgDelayDescr *get_delay(size_t *pSize = NULL);
    const ImgDelayDescr *get_delay(size_t *pSize = NULL) const;

    bool load_delay_table(DelayTable& table) const;
    bool enum_delay_items32(DELAY_PROC32 callback, void *user_data = NULL) const;
    bool enum_delay_items64(DELAY_PROC64 callback, void *user_data = NULL) const;

    /////////////////////////////////////////////////////////////////////////
    // DisAsm

    bool get_entry_points(std::unordered_set<uint64_t>& avas) const;
    bool do_disasm(DisAsmData& data) const;
    bool do_disasm_func(DisAsmData& data, uint64_t ava, Func& func) const;

    static int input_hook_x(ud* u);
    int input_hook(ud* u) const;
    bool add_func_by_ava(uint64_t ava);
    std::string read(uint64_t ava, uint32_t size, bool force = false);
    std::string write(uint64_t ava, uint32_t size, const char *hex = NULL, bool force = false);

    /////////////////////////////////////////////////////////////////////////
    // Dumping
    std::string dump(const std::string& name) const;

protected:
    PEModuleImpl *impl();
    const PEModuleImpl *impl() const;
    virtual bool load(FILE *fp);

          void *data_from_dir(uint16_t dir, size_t *pSize = NULL);
    const void *data_from_dir(uint16_t dir, size_t *pSize = NULL) const;

    bool _map_image();
    bool start_disasm(DisAsmData& data) const;
    bool end_disasm(DisAsmData& data) const;
};

} // namespace cr2
