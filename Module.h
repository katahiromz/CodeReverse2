#pragma once

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace cr2
{

struct ModuleImpl;

std::string normalize_module_name(std::string name);

class Module
{
public:
    Module();
    Module(const char *filename);
    Module(const wchar_t *filename);
    virtual ~Module();

    virtual bool is_loaded() const;
    bool load(const char *filename);
    bool load(const wchar_t *filename);
    virtual void unload();

          void *file_map(uint64_t rva = 0, uint32_t size = 1);
    const void *file_map(uint64_t rva = 0, uint32_t size = 1) const;
    uint64_t reverse_file_map(const void *ptr) const;

    template <typename T>
    T *file_map_typed(uint64_t rva = 0)
    {
        return reinterpret_cast<T *>(file_map(rva, sizeof(T)));
    }
    template <typename T>
    const T *file_map_typed(uint64_t rva = 0) const
    {
        return reinterpret_cast<const T *>(file_map(rva, sizeof(T)));
    }

    const std::string& binary() const;

    bool empty() const;
    size_t size() const;

    virtual bool get_binary(const std::string& group_name, std::string& binary) const;
    bool get_binary(const std::string& group_name, void *binary, size_t size) const;

    /////////////////////////////////////////////////////////////////////////
    // Dumping
    std::string dump(const std::string& name) const;

protected:
    std::shared_ptr<ModuleImpl> m_pimpl;
    std::string m_module_name;
    bool m_bIsExeOrDll;
    uint32_t m_dwBinaryType;
    uint32_t m_file_attrs;
    std::string m_creation_time;
    std::string m_last_access_time;
    std::string m_last_write_time;
    std::string m_fullpath;
    std::string m_cFileName;
    std::string m_cAlternateFileName;

    void set_module_name(const char *filename);
    void get_binary_type(const char *filename);
    void get_file_details(const char *filename);

    Module(std::shared_ptr<ModuleImpl> pimpl) : m_pimpl(pimpl)
    {
        m_bIsExeOrDll = false;
        m_dwBinaryType = 0;
        m_file_attrs = -1;
    }

    virtual bool load(FILE *fp);

private:
    Module(const Module&) /* = delete */;
    Module& operator=(const Module&) /* = delete */;
};

} // namespace cr2
