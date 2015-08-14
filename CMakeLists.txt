cmake_minimum_required(VERSION 2.8 FATAL_ERROR)
project(simterpose C)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

option(WARN_ERRORS "Show all warning and fail if any warning is found" OFF)
option(DEBUG_MODE  "Compile Simterpose with debugging symbols" OFF)

# Find dependencies:
find_library(M_LIB m)
find_package(Threads REQUIRED)
find_package(SimGrid REQUIRED)

include_directories(${SIMGRID_INCLUDE_DIRS})
include_directories(src/include)

if(WARN_ERRORS)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-prototypes -Wmissing-declarations")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wpointer-arith -Wwrite-strings")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused -Wno-unused-function -Wno-unused-parameter")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-strict-aliasing -Wno-format-nonliteral")
endif()

if(DEBUG_MODE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
endif()

add_subdirectory(src)
add_subdirectory(tests/apps)
