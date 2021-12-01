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
project (cpu_check VERSION 20181130 LANGUAGES C CXX)

# Options
# Use clang/llvm by default.
option(USE_CLANG "build with clang" ON)
# Build semi-statically by default.
option(BUILD_STATIC "build targets semi-statically linked" ON)

if (NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release)
endif(NOT CMAKE_BUILD_TYPE)



# Config header
configure_file (
	"${PROJECT_SOURCE_DIR}/config.h.in"
	"${PROJECT_BINARY_DIR}/config.h"
)
include_directories("${PROJECT_BINARY_DIR}")

if (USE_CLANG)
	set(CMAKE_C_COMPILER clang)
	set(CMAKE_CXX_COMPILER clang++)
	set(CC clang)
	set(CXX clang++)
endif(USE_CLANG)

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

# Third party library - available as git submodule
add_library(farmhash third_party/farmhash/src/farmhash.cc)

add_library(avx avx.cc)
add_library(compressor compressor.cc)
add_library(crc32c crc32c.c)
add_library(crypto crypto.cc)
add_library(fvt_controller fvt_controller.cc)
add_library(hasher hasher.cc)
add_library(malign_buffer malign_buffer.cc)
add_library(pattern_generator pattern_generator.cc)
add_library(silkscreen silkscreen.cc)
add_library(utils utils.cc)
add_library(vendors vendors/intel/intel.cc)


include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-march=sandybridge" ARCH_SANDYBRIDGE)
if(ARCH_SANDYBRIDGE)
	target_compile_options(farmhash PUBLIC -march=sandybridge)
	target_compile_options(crc32c PUBLIC -march=sandybridge)
endif(ARCH_SANDYBRIDGE)

if (BUILD_STATIC)
	set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
endif(BUILD_STATIC)

# Needs abseil
find_package(absl REQUIRED)
target_link_libraries(compressor absl::status absl::strings)
target_link_libraries(crypto absl::status absl::strings)
target_link_libraries(fvt_controller absl::strings)
target_link_libraries(malign_buffer absl::strings)
target_link_libraries(silkscreen absl::status absl::strings)
target_link_libraries(utils absl::strings)
target_link_libraries(cpu_check absl::failure_signal_handler absl::statusor absl::strings absl::symbolize)

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
  target_link_libraries(compressor ${ZLIB_LIBRARIES})
  target_link_libraries(hasher ${ZLIB_LIBRARIES})
endif(ZLIB_LIBRARIES)


# Needs OpenSSL
find_package (OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIRS})
target_link_libraries(cpu_check ${OPENSSL_LIBRARIES})
target_link_libraries(crypto ${OPENSSL_LIBRARIES})
target_link_libraries(hasher ${OPENSSL_LIBRARIES})

# Static linking of OpenSSL may require -ldl, link it if found.
find_library (dl dl)
if(dl)
	target_link_libraries(cpu_check dl)
endif(dl)



# link malign_buffer first as it has a lot of dependencies.
target_link_libraries(malign_buffer utils)

target_link_libraries(crc32c_test crc32c)
target_link_libraries(compressor malign_buffer)
target_link_libraries(crypto malign_buffer)
target_link_libraries(hasher crc32c farmhash malign_buffer utils)
target_link_libraries(pattern_generator malign_buffer)
target_link_libraries(silkscreen utils)

target_link_libraries(cpu_check avx compressor crc32c crypto fvt_controller hasher malign_buffer pattern_generator silkscreen utils vendors)

install (TARGETS cpu_check DESTINATION bin)
