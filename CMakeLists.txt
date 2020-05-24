# CMakeLists.txt --- CMake project settings
#    ex) cmake -G "Visual Studio 9 2008"
#    ex) cmake -DCMAKE_BUILD_TYPE=Release -G "MSYS Makefiles"
##############################################################################

# CMake minimum version
cmake_minimum_required(VERSION 2.4)

# enable testing
enable_testing()

# project name and languages
project(CodeReverse2 C CXX)

# use C++11
set(CMAKE_CXX_STANDARD 11)

##############################################################################

# subdirectories
subdirs(udis86)

# libcr2.a
add_library(cr2 STATIC dumping.cpp Module.cpp PEModule.cpp)

# cr2.exe
add_executable(CodeReverse2 cr2.cpp)
target_link_libraries(CodeReverse2 PRIVATE cr2)
set_target_properties(CodeReverse2 PROPERTIES OUTPUT_NAME "cr2")

##############################################################################
# testing

add_test(NAME x86-console
    COMMAND $<TARGET_FILE:CodeReverse2> ${CMAKE_CURRENT_SOURCE_DIR}/testdata/data-x86/console.exe)
add_test(NAME x86-win
    COMMAND $<TARGET_FILE:CodeReverse2> ${CMAKE_CURRENT_SOURCE_DIR}/testdata/data-x86/win.exe)
add_test(NAME x86-dll
    COMMAND $<TARGET_FILE:CodeReverse2> ${CMAKE_CURRENT_SOURCE_DIR}/testdata/data-x86/dll.dll)
add_test(NAME x64-console
    COMMAND $<TARGET_FILE:CodeReverse2> ${CMAKE_CURRENT_SOURCE_DIR}/testdata/data-x64/console.exe)
add_test(NAME x64-win
    COMMAND $<TARGET_FILE:CodeReverse2> ${CMAKE_CURRENT_SOURCE_DIR}/testdata/data-x64/win.exe)
add_test(NAME x64-dll
    COMMAND $<TARGET_FILE:CodeReverse2> ${CMAKE_CURRENT_SOURCE_DIR}/testdata/data-x64/dll.dll)
