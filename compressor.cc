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

#include "compressor.h"

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include <zlib.h>

namespace cpu_check {

absl::Status Zlib::Compress(const MalignBuffer &m,
                            MalignBuffer *compressed) const {
  uLongf olen = compressBound(m.size());
  compressed->resize(olen);
  int err = compress2(reinterpret_cast<Bytef *>(compressed->data()), &olen,
                      reinterpret_cast<const Bytef *>(m.data()), m.size(),
                      Z_BEST_SPEED);
  if (err != Z_OK) {
    return absl::Status(
        absl::StatusCode::kInternal,
        absl::StrFormat("Zlib compression failed: %d srcLen: %d destLen: %d",
                        err, m.size(), olen));
  }
  compressed->resize(olen);
  return absl::OkStatus();
}

absl::Status Zlib::Decompress(const MalignBuffer &compressed,
                              MalignBuffer *m) const {
  uLongf olen = m->size();
  int err = uncompress(reinterpret_cast<Bytef *>(m->data()), &olen,
                       reinterpret_cast<const Bytef *>(compressed.data()),
                       compressed.size());
  if (err != Z_OK) {
    return absl::Status(
        absl::StatusCode::kInternal,
        absl::StrFormat("Zlib decompression failed: %d srcLen: %d destLen: %d",
                        err, compressed.size(), olen));
  }
  m->resize(olen);
  return absl::OkStatus();
}

};  // namespace cpu_check
