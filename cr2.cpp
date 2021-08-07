#include "PEModule.h"
#include "dumping.h"

#define VERSION_INFO "CodeReverse2 2.4.3 by katahiromz\n"

void show_version(void)
{
    std::puts(VERSION_INFO);
}

void show_help(void)
{
    show_version();
    std::puts(
        "Usage: cr2 [options] [input.exe [output.asm]]\n"
        "Options:\n"
        " --help                Show this message.\n"
        " --version             Show version info.\n"
        " --add-func AVA        Add an additional function AVA.\n"
        " --read AVA SIZE       Read the module memory.\n"
        " --write AVA \"HEX\"     Write the module memory.\n"
        " --addr                Show address in disassembly code.\n"
        " --hex                 Show hexadecimals in disassembly code.\n"
        " --force               Force reading/writing even if not readable/writable.\n"
        " --dump WHAT           Specify what to dump (default: all).\n"
        " --syscall AVA win32ksvc.h     Specify system call table.\n"
        "\n"
        "* AVA stands for 'absolute virtual address'.\n"
        "* WHAT is either all, dos, fileh, opt, datadir, sections, imports, exports,\n"
        "  delay, or disasm.");
}

struct READ_WRITE_INFO
{
    bool do_write;
    uint64_t ava;
    uint32_t size;
    std::string hex;
};

struct SYSCALL
{
    uint64_t ava;
    std::string file;
    std::vector<std::string> func_names;
};

int main(int argc, char **argv)
{
    if (argc <= 1)
    {
        show_help();
        return 0;
    }

    std::string input, output;
    std::vector<std::string> dump_targets;
    std::vector<uint64_t> func_avas;
    std::vector<READ_WRITE_INFO> read_write;
    SYSCALL syscall;
    bool force = false;
    bool show_addr = false, show_hex = false;
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg[0] != '-')
        {
            if (input.empty())
            {
                input = arg;
            }
            else if (output.empty())
            {
                output = arg;
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
        if (arg == "--addr")
        {
            show_addr = true;
            continue;
        }
        if (arg == "--hex")
        {
            show_hex = true;
            continue;
        }
        if (arg == "--force")
        {
            force = true;
            continue;
        }
        if (arg == "--dump")
        {
            arg = argv[++i];
            if (arg == "all" || arg == "dos" || arg == "fileh" ||
                arg == "opt" || arg == "datadir" || arg == "sections" ||
                arg == "imports" || arg == "exports" || arg == "delay" ||
                arg == "disasm")
            {
                dump_targets.push_back(arg);
                continue;
            }
            else
            {
                fprintf(stderr, "ERROR: Invalid what to dump '%s'\n", arg.c_str());
                show_help();
                return 1;
            }
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
            auto size = uint32_t(std::strtoul(size_str.c_str(), NULL, 0));
            READ_WRITE_INFO info = {
                false, ava, size
            };
            read_write.push_back(info);
            continue;
        }
        if (arg == "--write")
        {
            std::string ava_str = argv[++i];
            std::string hex = argv[++i];
            auto ava = std::strtoull(ava_str.c_str(), NULL, 16);
            READ_WRITE_INFO info = {
                true, ava, 0, hex
            };
            read_write.push_back(info);
            continue;
        }
        if (arg == "--syscall")
        {
            std::string ava_str = argv[++i];
            std::string file = argv[++i];
            auto ava = std::strtoull(ava_str.c_str(), NULL, 16);
            syscall.ava = ava;
            syscall.file = file;
        }
    }

    std::string text;
    text += VERSION_INFO;
    text += cr2::string_of_command_line(argc, argv);
    text += cr2::string_of_os_info();

    cr2::PEModule mod;
    if (!mod.load(input.c_str()))
    {
        fprintf(stderr, "ERROR: Cannot load file '%s'\n", input.c_str());
        return -1;
    }

    for (auto ava : func_avas)
    {
        mod.add_func_by_ava(ava);
    }

    for (auto& info : read_write)
    {
        if (info.do_write)
            text += mod.write(info.ava, info.hex.c_str(), force);
        else
            text += mod.read(info.ava, info.size, force);
    }

    if (syscall.file.size())
    {
        FILE *fin = fopen(syscall.file.c_str(), "r");
        if (!fin)
        {
            fprintf(stderr, "ERROR: Cannot read file '%s'\n", syscall.file.c_str());
            return 1;
        }
        char buf[256];
        while (fgets(buf, sizeof(buf), fin))
        {
            if (char *pch = strstr(buf, "//"))
                *pch = 0;
            if (char *pch1 = strstr(buf, "SVC_("))
            {
                if (char *pch2 = strchr(pch1, ','))
                {
                    pch1 += 5;
                    *pch2 = 0;
                    std::string name = "Nt";
                    name += pch1;
                    syscall.func_names.push_back(name);
                }
            }
        }
        fclose(fin);

        text += mod.set_syscall(syscall.ava, syscall.func_names);
    }

    if (dump_targets.empty())
        dump_targets.push_back("all");

    for (auto& what : dump_targets)
    {
        text += mod.dump(what.c_str(), show_addr, show_hex);
    }

    if (output.empty())
    {
        fputs(text.c_str(), stdout);
    }
    else
    {
        if (FILE *fp = fopen(output.c_str(), "w"))
        {
            fputs(text.c_str(), fp);
            fclose(fp);
        }
        else
        {
            fprintf(stderr, "ERROR: Cannot write file '%s'\n", output.c_str());
        }
    }

    return 0;
}
