# CodeReverse2

[![CMake](https://github.com/katahiromz/CodeReverse2/actions/workflows/cmake.yml/badge.svg)](https://github.com/katahiromz/CodeReverse2/actions/workflows/cmake.yml) [![AppVeyor](https://ci.appveyor.com/api/projects/status/edlugu5nm86snvou?svg=true)](https://ci.appveyor.com/project/katahiromz/codereverse2)

![CodeReverse](CodeReverse.png)

CodeReverse2 is a reverse-engineering tool for Windows executables.
It works on Windows, Linux and MacOS.

## Usage

```txt
Usage: cr2 [options] [input-file]
Options:
--help                Show this message.
--version             Show version info.
--add-func AVA        Add an additional function AVA.
--read AVA SIZE       Read the module memory.
--write AVA SIZE HEX  Write the module memory.
--addr                Show address in disassembly code.
--hex                 Show hexadecimals in disassembly code.
--force               Force reading/writing even if not readable/writable.

* AVA stands for 'absolute virtual address'.
```

Under construction...
