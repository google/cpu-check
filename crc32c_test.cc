// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <string.h>

#include <iostream>
#include <random>

#include "crc32c.h"

extern "C" {
uint32_t crc32c_hw(const char *, size_t);
uint32_t crc32c_sw(const char *, size_t);
}

const int MINSIZE = 1;
const int MAXSIZE = 1048576;

int main(int argc, char **argv) {
#if defined(__x86_64__) || defined(__i386__)
  std::knuth_b rndeng((std::random_device()()));
  std::uniform_int_distribution<int> size_dist(MINSIZE, MAXSIZE);
  std::uniform_int_distribution<int> d_dist(0, 255);
  std::string buf;
  for (int i = 0; i < 100; i++) {
    size_t len = size_dist(rndeng);
    buf.resize(len);
    for (size_t j = 0; j < len; j++) {
      buf[j] = d_dist(rndeng);
    }
    uint32_t crc_hw = crc32c_hw(buf.data(), len);
    uint32_t crc_sw = crc32c_sw(buf.data(), len);
    if (crc_hw != crc_sw) {
      fprintf(stderr, "crc mismatch: hw 0x%08x vs sw 0x%08x buffer len %ld\n",
              crc_hw, crc_sw, len);
    }
    buf.clear();
  }
#endif  // defined(__x86_64__) || defined(__i386__)
  return 0;
}
