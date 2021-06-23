#pragma once

#include <cstdint>
#include <vector>
#ifdef _WIN32
    #include <windows.h>
    #include <delayimp.h>
#else
    #include "won32.h"
#endif

namespace cr2
{

/////////////////////////////////////////////////////////////////////////////
// Imports

typedef bool (*IMPORT_PROC32)(const IMAGE_IMPORT_DESCRIPTOR *pImports,
                              const IMAGE_THUNK_DATA32 *pINT,
                              const IMAGE_THUNK_DATA32 *pIAT,
                              void *user_data);

typedef bool (*IMPORT_PROC64)(const IMAGE_IMPORT_DESCRIPTOR *pImports,
                              const IMAGE_THUNK_DATA64 *pINT,
                              const IMAGE_THUNK_DATA64 *pIAT,
                              void *user_data);

struct ImportEntry
{
    std::string module;
    uint64_t rva;
    uint64_t va;
    std::string func_name;
    int ordinal;
    int hint;
};
typedef std::vector<ImportEntry> ImportTable;

/////////////////////////////////////////////////////////////////////////////
// Exports

typedef bool (*EXPORT_PROC)(const IMAGE_EXPORT_DIRECTORY *pExports,
    const char *name, uint64_t rva, uint64_t va, int ordinal, int hint, const char *forwarded_to,
    void *user_data);

struct ExportEntry
{
    std::string name;
    uint64_t rva;
    uint64_t va;
    int ordinal;
    int hint;
    std::string forwarded_to;
};
typedef std::vector<ExportEntry> ExportTable;

/////////////////////////////////////////////////////////////////////////////
// DelayImport

typedef bool (*DELAY_PROC32)(const char *module, uint32_t hmod,
                             const IMAGE_THUNK_DATA32 *pINT,
                             const IMAGE_THUNK_DATA32 *pIAT, void *user_data);
typedef bool (*DELAY_PROC64)(const char *module, uint64_t hmod,
                             const IMAGE_THUNK_DATA64 *pINT,
                             const IMAGE_THUNK_DATA64 *pIAT, void *user_data);

struct DelayEntry
{
    std::string module;
    uint64_t hmodule;
    uint64_t va;
    std::string func_name;
    int ordinal;
    int hint;
};
typedef std::vector<DelayEntry> DelayTable;

} // namespace cr2
