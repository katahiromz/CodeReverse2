#pragma once

#include <string>
#include <map>
#include <unordered_map>
#include <unordered_set>

namespace cr2
{

struct DisAsm
{
    int bytes;
    std::string disasm;
};

struct Func
{
    uint64_t ava;
    std::string name;
    std::map<uint64_t, DisAsm> ava_to_disasm;
};

}
