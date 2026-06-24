cmake_minimum_required(VERSION 3.10)
project(TEESimulator)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions")
foreach(config RELEASE RELWITHDEBINFO MINSIZEREL)
    string(APPEND CMAKE_CXX_FLAGS_${config} " -O3 -flto=full")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS_${config}
           " -flto=full -Wl,-O3 -Wl,--gc-sections -Wl,--icf=all -Wl,--as-needed -Wl,--build-id=none -Wl,--no-eh-frame-hdr")
    string(APPEND CMAKE_EXE_LINKER_FLAGS_${config}
           " -flto=full -Wl,-O3 -Wl,--gc-sections -Wl,--icf=all -Wl,--as-needed -Wl,--build-id=none -Wl,--no-eh-frame-hdr")
endforeach()

# LSPlt configuration
OPTION(LSPLT_BUILD_SHARED OFF)
add_subdirectory(external/LSPlt/lsplt/src/main/jni)

add_compile_definitions(BINDER_DISABLE_NATIVE_HANDLE)
add_library(utils SHARED stub/stub_utils.cpp)
target_include_directories(utils PUBLIC external/AOSP/include)

add_library(binder SHARED stub/stub_binder.cpp)
target_include_directories(binder PUBLIC external/AOSP/include)
target_link_libraries(binder PRIVATE utils)

add_executable(libinject.so inject/main.cpp inject/utils.cpp)
target_include_directories(libinject.so PUBLIC include)
target_link_libraries(libinject.so PRIVATE lsplt_static)

add_library(${CMAKE_PROJECT_NAME} SHARED binder_interceptor.cpp)
target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC external/linux-kernel/include include)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE binder lsplt_static utils)

