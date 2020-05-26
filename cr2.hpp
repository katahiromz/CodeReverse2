#pragma once

#include <string>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include "ports.h"

namespace cr2
{

static const uint64_t invalid_ava = 0xFFFFFFFFFFFFFFFF;

struct AsmCode
{
    int bytes;
    std::string disasm;
    std::set<uint64_t> jump_from;
    uint64_t jump_to = invalid_ava;
    int mnemonic;
};

enum CONVENTION
{
    C_UNKNOWN,
    C_CDECL,
    C_STDCALL,
    C_FASTCALL,
    C_THISCALL,
    C_JUMPFUNC
};

struct Func
{
    uint64_t ava = invalid_ava;
    std::string name;
    std::map<uint64_t, AsmCode> ava_to_asm;
    CONVENTION convention = C_UNKNOWN;
    std::set<uint64_t> call_from;
    std::set<uint64_t> call_to;
    std::set<uint64_t> jump_to;
    bool is_entry = false;
};

typedef std::unordered_map<uint64_t, std::string> NameMap;

struct DisAsmData
{
    std::unordered_set<uint64_t> entry_points;
    NameMap names;
    std::map<uint64_t, Func> ava_to_func;
    ImportTable imports;
    ExportTable exports;
    DelayTable delays;
};

}
