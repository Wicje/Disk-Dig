cmake_minimum_required(VERSION 3.16)
project(DiskDig LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)

set(CUI_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CUI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/CUI)

add_executable(diskdig
    src/main.cpp
    src/core/Types.cpp
    src/core/RawReader.cpp
    src/core/DeviceEnumerator.cpp
    src/core/PartitionTable.cpp
    src/core/Scanner.cpp
    src/core/Recovery.cpp
    src/core/ext4/Ext4Scanner.cpp
    src/core/fat/FatScanner.cpp
    src/core/ntfs/NtfsScanner.cpp
    src/core/carver/Carver.cpp
    src/gui/App.cpp
)
target_include_directories(diskdig PRIVATE src third_party/CUI/include)
target_link_libraries(diskdig PRIVATE cui::cui)
cui_app_target(diskdig)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(diskdig PRIVATE -Wall -Wextra -Wno-missing-field-initializers)
endif()
