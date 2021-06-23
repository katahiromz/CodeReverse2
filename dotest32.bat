cr2.exe testdata\data-x86\console.exe > testdata\data-x86\console.cr2.txt
cr2.exe testdata\data-x86\win.exe > testdata\data-x86\win.cr2.txt
cr2.exe testdata\data-x86\dll.dll > testdata\data-x86\dll.cr2.txt

dumpbin /HEADERS /IMPORTS /EXPORTS testdata\data-x86\console.exe > testdata\data-x86\console.dumpbin.txt
dumpbin /HEADERS /IMPORTS /EXPORTS testdata\data-x86\win.exe > testdata\data-x86\win.dumpbin.txt
dumpbin /HEADERS /IMPORTS /EXPORTS testdata\data-x86\dll.dll > testdata\data-x86\dll.dumpbin.txt
