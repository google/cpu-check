# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required (VERSION 3.2)

# Options
# Use clang/llvm by default.
option(USE_CLANG "build with clang" ON)
# Build semi-statically by default.
option(BUILD_STATIC "build targets semi-statically linked" ON)

if (NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release)
endif(NOT CMAKE_BUILD_TYPE)

if (USE_CLANG)
        set(CMAKE_C_COMPILER clang)
        set(CMAKE_CXX_COMPILER clang++)
        set(CC clang)
        set(CXX clang++)
endif(USE_CLANG)

if (BUILD_STATIC)
        set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
	set(CMAKE_EXE_LINKER_FLAGS "-static-libstdc++ -static-libgcc")
endif(BUILD_STATIC)

project (cpu_check VERSION 20181130 LANGUAGES C CXX)


# Begin Google local change

# We use an in tree copy of boringSSL by default.
option(USE_BORINGSSL "build with boringSSL" OFF)

option(IN_GOOGLE3 "building in google3" OFF)

# The vendors subdirectories may not be present.
find_path(
  VENDORS_AMD_PATH
  NAMES amd.cc
  PATHS ${CMAKE_CURRENT_SOURCE_DIR}/vendors/amd
  NO_DEFAULT_PATH
)

find_path(
  VENDORS_INTEL_PATH
  NAMES intel.cc
  PATHS ${CMAKE_CURRENT_SOURCE_DIR}/vendors/intel
  NO_DEFAULT_PATH
)
# End Google local change

# Config header
configure_file (
	"${PROJECT_SOURCE_DIR}/config.h.in"
	"${PROJECT_BINARY_DIR}/config.h"
)
include_directories("${PROJECT_BINARY_DIR}")

set(CMAKE_C_FLAGS_DEBUG "-g -Wall -O0")
set(CMAKE_CXX_FLAGS_DEBUG "-g -Wall -O0")
set(CMAKE_C_FLAGS_RELEASE "-Wall -O2")
set(CMAKE_CXX_FLAGS_RELEASE "-Wall -O2")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)	# we want c11 not gnu11
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)	# we want c++17 not gnu++17

add_executable(cpu_check cpu_check.cc)
add_executable(crc32c_test crc32c_test.cc)

add_library(farmhash third_party/farmhash/src/farmhash.cc)
add_library(crc32c crc32c.c)
add_library(fvt_controller fvt_controller.cc)
add_library(utils utils.cc)

# Begin Google local change
if (VENDORS_AMD_PATH)
  add_library(amd ${VENDORS_AMD_PATH}/amd.cc)
  add_library(hsmp ${VENDORS_AMD_PATH}/hsmp.cc)
  target_link_libraries(amd hsmp pci)
  set(VENDORS_LIBS ${VENDORS_LIBS} amd)
endif(VENDORS_AMD_PATH)

if (VENDORS_INTEL_PATH)
  add_library(intel ${VENDORS_INTEL_PATH}/intel.cc)
  set(VENDORS_LIBS ${VENDORS_LIBS} intel)
endif(VENDORS_INTEL_PATH)
# End Google local change

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-march=sandybridge" ARCH_SANDYBRIDGE)
if(ARCH_SANDYBRIDGE)
	target_compile_options(farmhash PUBLIC -march=sandybridge)
	target_compile_options(crc32c PUBLIC -march=sandybridge)
endif(ARCH_SANDYBRIDGE)

target_link_libraries(cpu_check crc32c farmhash)
# Begin Google local change
target_link_libraries(cpu_check fvt_controller ${VENDORS_LIBS} utils)
# End Google local change
target_link_libraries(crc32c_test crc32c)

# Needs pthreads
find_package(Threads REQUIRED)
target_link_libraries(cpu_check Threads::Threads)

# Needs zlib
find_package (ZLIB REQUIRED)
if(ZLIB_INCLUDE_DIRS)
	include_directories(${ZLIB_INCLUDE_DIRS})
endif(ZLIB_INCLUDE_DIRS)
if(ZLIB_LIBRARIES)
	target_link_libraries(cpu_check ${ZLIB_LIBRARIES})
endif(ZLIB_LIBRARIES)

# Begin Google local change
if(USE_BORINGSSL)
  set(BORINGSSL_PATH ${CMAKE_CURRENT_SOURCE_DIR}/boringssl)
  add_subdirectory(${BORINGSSL_PATH})
  set(BORINGSSL_INCLUDE_DIRS ${BORINGSSL_PATH}/include)
  include_directories("${BORINGSSL_PATH}/include")
  target_link_libraries(cpu_check ssl crypto)
else(USE_BORINGSSL)
# End Google local change

# Needs OpenSSL
find_package (OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIRS})
target_link_libraries(cpu_check ${OPENSSL_LIBRARIES})

# Static linking of OpenSSL may require -ldl, link it if found.
find_library (dl dl)
if(dl)
	target_link_libraries(cpu_check dl)
endif(dl)

# Begin Google local change
endif(USE_BORINGSSL)
# End Google local change

install (TARGETS cpu_check DESTINATION bin)
