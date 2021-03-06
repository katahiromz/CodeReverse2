#pragma once

#include "PEModule.h"

/////////////////////////////////////////////////////////////////////////////

namespace cr2
{

struct ModuleImpl
{
    std::string binary;

    ModuleImpl()
    {
    }

    virtual ~ModuleImpl()
    {
    }

private:
    ModuleImpl(const ModuleImpl&);
    ModuleImpl& operator=(const ModuleImpl&);
};

struct PEModuleImpl : public ModuleImpl
{
    std::string image;
    IMAGE_DOS_HEADER *dos;
    IMAGE_FILE_HEADER *file;
    union
    {
        IMAGE_NT_HEADERS *nt;
        IMAGE_NT_HEADERS32 *nt32;
        IMAGE_NT_HEADERS64 *nt64;
    };
    IMAGE_OPTIONAL_HEADER32 *optional32;
    IMAGE_OPTIONAL_HEADER64 *optional64;
    IMAGE_SECTION_HEADER *section_headers;
    IMAGE_DATA_DIRECTORY *data_directories;
    NameMap func_names;

    PEModuleImpl()
        : dos(NULL)
        , file(NULL)
        , nt(NULL)
        , optional32(NULL)
        , optional64(NULL)
        , section_headers(NULL)
        , data_directories(NULL)
    {
    }

    virtual ~PEModuleImpl()
    {
    }
};

} // namespace cr2
