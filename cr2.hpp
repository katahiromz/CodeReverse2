#pragma once

#include <string>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace cr2
{

static const uint64_t invalid_ava = 0xFFFFFFFFFFFFFFFF;

struct DisAsm
{
    int bytes;
    std::string disasm;
    std::set<uint64_t> jump_from;
    uint64_t jump_to = invalid_ava;
};

enum CONVENTION
{
    C_UNKNOWN,
    C_CDECL,
    C_STDCALL,
    C_FASTCALL,
    C_THISCALL
};

struct Func
{
    uint64_t ava = invalid_ava;
    std::string name;
    std::map<uint64_t, DisAsm> ava_to_disasm;
    CONVENTION convention = C_UNKNOWN;
    std::set<uint64_t> call_from;
    std::set<uint64_t> call_to;
    std::set<uint64_t> jump_to;
    bool is_entry = false;
};

}
