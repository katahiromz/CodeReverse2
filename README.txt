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

* AVA stands for 'absolute virtual address'.
* WHAT is either all, dos, fileh, opt, datadir, sections, imports, exports,
  delay, or disasm.
