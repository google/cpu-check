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

#ifndef THIRD_PARTY_CPU_CHECK_COMPRESSOR_H_
#define THIRD_PARTY_CPU_CHECK_COMPRESSOR_H_

#include <string>

#include "malign_buffer.h"
#include "absl/status/status.h"

namespace cpu_check {

class Compressor {
 public:
  virtual ~Compressor() {}
  virtual std::string Name() const = 0;

  // Compresses 'm' into 'compressed'.
  virtual absl::Status Compress(const MalignBuffer &m,
                                MalignBuffer *compressed) const = 0;

  // Decompresses 'compressed' into 'm'.
  virtual absl::Status Decompress(const MalignBuffer &compressed,
                                  MalignBuffer *m) const = 0;
};

class Zlib : public Compressor {
 public:
  std::string Name() const override { return "ZLIB"; }
  absl::Status Compress(const MalignBuffer &m,
                        MalignBuffer *compressed) const override;
  absl::Status Decompress(const MalignBuffer &compressed,
                          MalignBuffer *m) const override;
};

};      // namespace cpu_check
#endif  // THIRD_PARTY_CPU_CHECK_COMPRESSOR_H_
