cmake_minimum_required(VERSION 3.20)
project(ddcore LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_definitions(-DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX)
add_compile_options(-Wall -Wextra -Wno-unused-parameter)

add_library(ddcore STATIC
    src/common.cpp
    src/registry.cpp
    src/garbage.cpp
    src/dead_registry.cpp
    src/startup.cpp
    src/dead_registry_more.cpp
    src/proc.cpp
    src/inspect.cpp
    src/sysinfo.cpp
    src/drivers.cpp
    src/net.cpp
    src/pe.cpp
    src/blocklist.cpp
    src/firewall.cpp
    src/network.cpp
    src/geoip.cpp
    src/ip.cpp
    src/ipinfo.cpp
    src/traffic.cpp
    src/threat.cpp
    src/antivirus.cpp
    src/online.cpp src/audit.cpp src/audit_checks.cpp src/audit_engine.cpp src/tweaks.cpp src/secrets.cpp
    src/json.cpp)
target_include_directories(ddcore PUBLIC include)
target_link_libraries(ddcore PUBLIC advapi32 shell32 ole32 crypt32 bcrypt version uuid winhttp psapi iphlpapi ws2_32 shlwapi sqlite3)

add_executable(ddc src/main.cpp)
target_link_libraries(ddc PRIVATE ddcore -static -municode)

add_executable(ddcore_tests tests/tests.cpp tests/tests2.cpp tests/tests3.cpp tests/tests4.cpp tests/tests5.cpp tests/tests6.cpp tests/tests7.cpp tests/tests8.cpp tests/tests9.cpp tests/tests10.cpp tests/tests11.cpp tests/tests12.cpp tests/tests13.cpp)
target_link_libraries(ddcore_tests PRIVATE ddcore -static)

enable_testing()
add_test(NAME ddcore_tests COMMAND ddcore_tests)

# the world map data is embedded as a resource (id 2, see ui/app.rc); windres finds it in the build folder
configure_file(${CMAKE_SOURCE_DIR}/data/world_countries.json ${CMAKE_BINARY_DIR}/world_countries.json COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/data/dd_cleaner.ico ${CMAKE_BINARY_DIR}/dd_cleaner.ico COPYONLY)
file(GLOB UI_SOURCES CONFIGURE_DEPENDS ui/*.cpp)
add_executable(DD_Cleaner WIN32 ${UI_SOURCES} ui/app.rc)
target_link_libraries(DD_Cleaner PRIVATE ddcore -municode -static comctl32 comdlg32 uxtheme dwmapi shell32 ole32 uuid user32 gdi32)
