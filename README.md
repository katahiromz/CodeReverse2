# CodeReverse2

[![CMake](https://github.com/katahiromz/CodeReverse2/actions/workflows/cmake.yml/badge.svg)](https://github.com/katahiromz/CodeReverse2/actions/workflows/cmake.yml) [![AppVeyor](https://ci.appveyor.com/api/projects/status/edlugu5nm86snvou?svg=true)](https://ci.appveyor.com/project/katahiromz/codereverse2)

![CodeReverse](CodeReverse.png)

CodeReverse2 is a command-line reverse-engineering tool for Windows executables.
It works on Windows, Linux and MacOS.

## Example of output

```txt
CodeReverse2 2.3.8 by katahiromz

## CommandLine ##
C:\dev\CodeReverse2\cr2.exe shell32.dll --addr --hex --read 7CAB1C86 20

## OS Info ##
Windows 10.0 (x86)

## Read Memory ##
+ADDRESS +0 +1 +2 +3 +4 +5 +6 +7  +8 +9 +A +B +C +D +E +F  0123456789ABCDEF
7CAB1C86 8B FF 56 33 F6 39 35 04  EE AE 7C 75 07 B8 05 40  ..V3.95...|u...@
7CAB1C96 00 80 5E C3                                        .^.            
20 (0x14) bytes read.

## IMAGE_DOS_HEADER ##
  e_magic: 0x5A4D
  e_cblp: 0x0090
...

proc Func7CAB1C86 Label_7CAB1C86
attrs [[cdecl]]
# call_from : 7C90FCCE
# call_to : 7CAB19E3 7CAB1A37 7CAB1C55
# jump_to : 7CAB1C9A 7CAB1CAB 7CAB1D08
Label_7CAB1C86:
7CAB1C86: 8B FF                                    mov edi, edi
7CAB1C88: 56                                       push esi
7CAB1C89: 33 F6                                    xor esi, esi
7CAB1C8B: 39 35 04 EE AE 7C                        cmp [0x7caeee04], esi
7CAB1C91: 75 07                                    jnz Label_7CAB1C9A
...
```

## Usage

```txt
Usage: cr2 [options] [input.exe]
Options:
 --help                Show this message.
 --version             Show version info.
 --add-func AVA        Add an additional function AVA.
 --read AVA SIZE       Read the module memory.
 --write AVA "HEX"     Write the module memory.
 --addr                Show address in disassembly code.
 --hex                 Show hexadecimals in disassembly code.
 --force               Force reading/writing even if not readable/writable.
 --dump WHAT           Specify what to dump (default: all).
 --syscall AVA win32ksvc.h     Specify system call table.

* AVA stands for 'absolute virtual address'.
* WHAT is either all, dos, fileh, opt, datadir, sections, imports, exports,
  delay, or disasm.
```

Under construction...
