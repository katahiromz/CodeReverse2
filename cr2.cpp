#include "PEModule.h"

void show_version(void)
{
    printf("##################################\n");
    printf("# CodeReverse2 0.0 by katahiromz #\n");
    printf("##################################\n");
}

void show_help(void)
{
    show_version();
    printf("Usage: cr2 [options] [input-file]\n");
    printf("Options:\n");
    printf("--help    Show this message.\n");
    printf("--version Show version information.\n");
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

    std::string commandline;
    for (int i = 0; i < argc; ++i)
    {
        if (i != 0)
            commandline += " ";

        std::string str = argv[i];
        if (str.find(' ') != std::string::npos || str.find('\t') != std::string::npos)
        {
            commandline += '"';
            commandline += str;
            commandline += '"';
        }
        else
        {
            commandline += str;
        }
    }

    printf("## CommandLine ##\n");
    printf("%s\n\n", commandline.c_str());

    cr2::PEModule mod;
    if (!mod.load(arg.c_str()))
    {
        fprintf(stderr, "ERROR: Cannot load '%s'\n", arg.c_str());
        return -1;
    }

    std::string text = mod.dump("all");
    fputs(text.c_str(), stdout);

    return 0;
}
