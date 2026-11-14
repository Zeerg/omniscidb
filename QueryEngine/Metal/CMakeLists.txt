cmake_minimum_required(VERSION 3.25)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(HeavyDBMetal LANGUAGES CXX OBJCXX)
  set(CMAKE_CXX_STANDARD 17)
  enable_testing()
endif()

if(NOT APPLE)
  message(FATAL_ERROR "The Metal runtime requires macOS")
endif()

find_library(METAL_FRAMEWORK Metal REQUIRED)
find_library(FOUNDATION_FRAMEWORK Foundation REQUIRED)
add_library(HeavyDBMetal STATIC MetalRuntime.mm MetalQuery.cpp)
target_include_directories(HeavyDBMetal PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
set_source_files_properties(MetalRuntime.mm PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
target_link_libraries(HeavyDBMetal PUBLIC ${METAL_FRAMEWORK} ${FOUNDATION_FRAMEWORK})

add_executable(MetalRuntimeTest MetalRuntimeTest.cpp)
target_link_libraries(MetalRuntimeTest PRIVATE HeavyDBMetal)
add_test(NAME MetalRuntimeTest COMMAND MetalRuntimeTest)

add_executable(MetalGraphTest MetalGraphTest.cpp)
target_link_libraries(MetalGraphTest PRIVATE HeavyDBMetal)
add_test(NAME MetalGraphTest COMMAND MetalGraphTest)
