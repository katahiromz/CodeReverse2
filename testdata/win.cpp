#include <windows.h>

INT WINAPI
WinMain(HINSTANCE   hInstance,
        HINSTANCE   hPrevInstance,
        LPSTR       lpCmdLine,
        INT         nCmdShow)
{
    MessageBoxA(NULL, "Hello, world", "Hello", MB_ICONINFORMATION);
    return 0;
}
