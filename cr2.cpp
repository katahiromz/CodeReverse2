#include "PEModule.h"
#include "dumping.h"

void show_version(void)
{
    printf("##################################\n");
    printf("# CodeReverse2 0.3 by katahiromz #\n");
    printf("##################################\n");
}

void show_help(void)
{
    show_version();
    printf("Usage: cr2 [options] [input-file]\n");
    printf("Options:\n");
    printf("--help  Show this message.\n");
    printf("--version  Show version information.\n");
    printf("--add-func AVA  Add an additional function AVA (absolute V.A.).\n");
    printf("--read AVA SIZE  Read the module memory.\n");
}

int main(int argc, char **argv)
{
    if (argc <= 1)
    {
        show_help();
        return 0;
    }

    std::string arg = argv[1];
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

    printf("## CommandLine ##\n");
    printf("%s\n\n", cr2::string_of_command_line(argc, argv).c_str());

    printf("## OS Info ##\n");
    printf("%s", cr2::string_of_os_info().c_str());

    cr2::PEModule mod;
    if (!mod.load(arg.c_str()))
    {
        fprintf(stderr, "ERROR: Cannot load '%s'\n", arg.c_str());
        return -1;
    }

    std::string text;
    for (int i = 1; i < argc; ++i)
    {
        std::string str = argv[i];
        if (str == "--add-func")
        {
            str = argv[++i];
            auto ava = std::strtoull(str.c_str(), NULL, 16);
            mod.add_func_by_ava(ava);
        }
        if (str == "--read")
        {
            std::string ava_str = argv[++i];
            std::string size_str = argv[++i];
            auto ava = std::strtoull(ava_str.c_str(), NULL, 16);
            auto size = std::strtoull(size_str.c_str(), NULL, 0);
            text += mod.read(ava, size);
        }
    }

    text += mod.dump("all");
    fputs(text.c_str(), stdout);

    return 0;
}
