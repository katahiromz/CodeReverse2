cr2.exe testdata\data-x64\console.exe > testdata\data-x64\console.cr2.txt
cr2.exe testdata\data-x64\win.exe > testdata\data-x64\win.cr2.txt
cr2.exe testdata\data-x64\dll.dll > testdata\data-x64\dll.cr2.txt

dumpbin /HEADERS /IMPORTS /EXPORTS testdata\data-x64\console.exe > testdata\data-x64\console.dumpbin.txt
dumpbin /HEADERS /IMPORTS /EXPORTS testdata\data-x64\win.exe > testdata\data-x64\win.dumpbin.txt
dumpbin /HEADERS /IMPORTS /EXPORTS testdata\data-x64\dll.dll > testdata\data-x64\dll.dumpbin.txt
