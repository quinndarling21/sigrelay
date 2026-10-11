cmake_minimum_required(VERSION 3.16)

project(sigrelay LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-Wall -Wextra)

add_library(sigrelay STATIC
  src/sigrelay.c
)
target_include_directories(sigrelay
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(sigrelayd
  src/main.c
)
target_link_libraries(sigrelayd PRIVATE sigrelay)
