#include <windows.h>

extern "C"
{
    int WINAPI Foo(int n)
    {
        return n + 1;
    }

    int WINAPI Bar(int n)
    {
        return n + 2;
    }
}

BOOL WINAPI
DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
