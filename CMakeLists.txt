# CMakeLists.txt --- CMake project settings
#    ex) cmake -G "Visual Studio 9 2008"
#    ex) cmake -DCMAKE_BUILD_TYPE=Release -G "MSYS Makefiles"
##############################################################################

# CMake minimum version
cmake_minimum_required(VERSION 3.0)

# enable testing
enable_testing()

# project name and languages
project(CodeReverse2 C CXX)

# use C++11
set(CMAKE_CXX_STANDARD 11)

# use static
if (WIN32)
    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        # using Clang
        set(CMAKE_C_FLAGS "-static")
        set(CMAKE_CXX_FLAGS "-static")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        # using GCC
        set(CMAKE_C_FLAGS "-static")
        set(CMAKE_CXX_FLAGS "-static")
    elseif (MSVC)
        # replace "/MD" with "/MT" (building without runtime DLLs)
        set(CompilerFlags
            CMAKE_C_FLAGS
            CMAKE_C_FLAGS_DEBUG
            CMAKE_C_FLAGS_MINSIZEREL
            CMAKE_C_FLAGS_RELEASE
            CMAKE_C_FLAGS_RELWITHDEBINFO
            CMAKE_CXX_FLAGS
            CMAKE_CXX_FLAGS_DEBUG
            CMAKE_CXX_FLAGS_MINSIZEREL
            CMAKE_CXX_FLAGS_RELEASE
            CMAKE_CXX_FLAGS_RELWITHDEBINFO)
        foreach(CompilerFlags ${CompilerFlags})
            string(REPLACE "/MD" "/MT" ${CompilerFlags} "${${CompilerFlags}}")
        endforeach()
    endif()
endif()

##############################################################################

# kill security warnings
add_definitions(-D_CRT_SECURE_NO_WARNINGS)

# subdirectories
subdirs(udis86)

# include directories
include_directories(udis86 udis86/libudis86)

# cr2.exe
add_executable(cr2 cr2.cpp dumping.cpp Module.cpp PEModule.cpp)
target_link_libraries(cr2 PRIVATE udis86)

# install cr2.exe
install(TARGETS cr2 DESTINATION bin)

##############################################################################
# testing

add_test(NAME x86-console
    COMMAND $<TARGET_FILE:cr2> ${CMAKE_CURRENT_SOURCE_DIR}/testdata/data-x86/console.exe)
add_test(NAME x86-win
    COMMAND $<TARGET_FILE:cr2> ${CMAKE_CURRENT_SOURCE_DIR}/testdata/data-x86/win.exe)
add_test(NAME x86-dll
    COMMAND $<TARGET_FILE:cr2> ${CMAKE_CURRENT_SOURCE_DIR}/testdata/data-x86/dll.dll)
add_test(NAME x64-console
    COMMAND $<TARGET_FILE:cr2> ${CMAKE_CURRENT_SOURCE_DIR}/testdata/data-x64/console.exe)
add_test(NAME x64-win
    COMMAND $<TARGET_FILE:cr2> ${CMAKE_CURRENT_SOURCE_DIR}/testdata/data-x64/win.exe)
add_test(NAME x64-dll
    COMMAND $<TARGET_FILE:cr2> ${CMAKE_CURRENT_SOURCE_DIR}/testdata/data-x64/dll.dll)
