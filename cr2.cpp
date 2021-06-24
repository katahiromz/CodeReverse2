#include "PEModule.h"
#include "dumping.h"

void show_version(void)
{
    printf("####################################\n");
    printf("# CodeReverse2 0.3.5 by katahiromz #\n");
    printf("####################################\n");
}

void show_help(void)
{
    show_version();
    std::puts(
        "Usage: cr2 [options] [input-file]\n"
        "Options:\n"
        "--help                Show this message.\n"
        "--version             Show version info.\n"
        "--add-func AVA        Add an additional function AVA.\n"
        "--read AVA SIZE       Read the module memory.\n"
        "--write AVA SIZE HEX  Write the module memory.\n"
        "--show-addr           Show address in disassembly code.\n"
        "--show-hex            Show hexadecimals in disassembly code.\n"
        "--force               Force reading/writing even if not readable/writable.\n"
        "\n"
        "* AVA stands for 'absolute virtual address'.\n");
}

struct READ_WRITE_INFO
{
    bool do_write;
    uint64_t ava;
    uint32_t size;
    std::string hex;
};

int main(int argc, char **argv)
{
    if (argc <= 1)
    {
        show_help();
        return 0;
    }

    std::string file;
    std::vector<uint64_t> func_avas;
    std::vector<READ_WRITE_INFO> read_write;
    bool force = false;
    bool show_addr = false, show_hex = false;
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg[0] != '-')
        {
            if (file.empty())
            {
                file = arg;
            }
            else
            {
                fprintf(stderr, "ERROR: Too many arguments\n");
                return 1;
            }
            continue;
        }
        if (arg == "--help")
        {
            show_help();
            return 0;
        }
        if (arg == "--version")
        {
            show_version();
            return 0;
        }
        if (arg == "--show-addr")
        {
            show_addr = true;
            continue;
        }
        if (arg == "--show-hex")
        {
            show_hex = true;
            continue;
        }
        if (arg == "--force")
        {
            force = true;
            continue;
        }
        if (arg == "--add-func")
        {
            arg = argv[++i];
            auto ava = std::strtoull(arg.c_str(), NULL, 16);
            func_avas.push_back(ava);
            continue;
        }
        if (arg == "--read")
        {
            std::string ava_str = argv[++i];
            std::string size_str = argv[++i];
            auto ava = std::strtoull(ava_str.c_str(), NULL, 16);
            auto size = std::strtoul(size_str.c_str(), NULL, 0);
            READ_WRITE_INFO info = {
                false, ava, size
            };
            read_write.push_back(info);
            continue;
        }
        if (arg == "--write")
        {
            std::string ava_str = argv[++i];
            std::string size_str = argv[++i];
            std::string hex = argv[++i];
            auto ava = std::strtoull(ava_str.c_str(), NULL, 16);
            auto size = std::strtoul(size_str.c_str(), NULL, 0);
            READ_WRITE_INFO info = {
                true, ava, size, hex
            };
            read_write.push_back(info);
            continue;
        }
    }

    std::string text;
    text += cr2::string_of_command_line(argc, argv);
    text += cr2::string_of_os_info();

    cr2::PEModule mod;
    if (!mod.load(file.c_str()))
    {
        fprintf(stderr, "ERROR: Cannot load '%s'\n", file.c_str());
        return -1;
    }

    for (auto ava : func_avas)
    {
        mod.add_func_by_ava(ava);
    }

    for (auto& info : read_write)
    {
        if (info.do_write)
            text += mod.write(info.ava, info.size, info.hex.c_str(), force);
        else
            text += mod.read(info.ava, info.size, force);
    }

    text += mod.dump("all", show_addr, show_hex);
    fputs(text.c_str(), stdout);

    return 0;
}
