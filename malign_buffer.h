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

#ifndef THIRD_PARTY_CPU_CHECK_MALIGN_BUFFER_H_
#define THIRD_PARTY_CPU_CHECK_MALIGN_BUFFER_H_

#include <random>
#include <string>

#include "absl/strings/string_view.h"

namespace cpu_check {

// Data buffer supporting various alignments, copy mechanisms, and verification
// methods.
class MalignBuffer {
 public:
  struct PunchedHole {
    std::string ToString() const;
    size_t start = 0;
    size_t length = 0;
    unsigned char v = 0x53;
  };

  enum CopyMethod {
    kMemcpy,
    kRepMov,
    kSseBy128,
    kAvxBy256,
    kAvxBy512,
  };

  // Returns name of given CopyMethod.
  static std::string ToString(CopyMethod m);

  static const size_t kPageSize;
  static const size_t kCacheLineSize;

  // Returns a random alignment offset in range [0..kPageSize-1].
  static size_t RandomAlignment(uint64_t seed);

  // Helper to make MSAN happy. NOP if memory sanitizer is not enabled.
  static void InitializeMemoryForSanitizer(char* addr, size_t size);

  // Constructs MalignBuffer of specified capacity.
  MalignBuffer(size_t capacity);

  // Constructs and initializes MalignBuffer with specified alignment and
  // content. Useful for unit tests.
  // REQUIRES:
  //   alignment_offset < kPageSize
  MalignBuffer(size_t alignment_offset, absl::string_view s);

  ~MalignBuffer();

  // Initializes buffer to specified alignment.
  // REQUIRES:
  //   alignment_offset < kPageSize
  //   length <= this.capacity_.
  void Initialize(size_t alignment_offset, size_t length);

  const char* data() const { return buffer_address_; }
  char* data() { return buffer_address_; }
  size_t size() const { return length_; }

  // REQUIRES length <= capacity_.
  void resize(size_t length);

  // Compares 'this' to 'that' returning empty string if identical.
  // If not identical, returns a syndrome, currently Hamming distance,
  // corrupted subrange bounds, and the diffs.
  std::string Syndrome(const MalignBuffer& that) const;

  // Validated data copy from source to 'this'.
  // 'this' must be appropriately sized.
  // Returns syndrome upon copy failure.
  std::string CopyFrom(const MalignBuffer& that, CopyMethod m);

  // Unvalidated copy to 'this'.
  void CopyFrom(absl::string_view src, CopyMethod m);
  void CopyFrom(size_t pos, absl::string_view src, CopyMethod m);

  // Randomly flushes cache lines.
  void RandomFlush(std::knuth_b* rng) const;

  // Conventional or rep;sto memset operation, according to 'use_rep_stos'.
  void Memset(size_t offset, unsigned char v, size_t length, bool use_rep_stos);

  // Memsets buffer to 'hole.v', using rep;stos operation if
  // 'use_rep_stos' set;
  void PunchHole(const PunchedHole& hole, bool use_rep_stos);

  // Hints to the OS to release the buffer's memory.
  void MadviseDontNeed() const;

  // Returns random PunchedHole within 'this'.
  MalignBuffer::PunchedHole RandomPunchedHole(uint64_t seed) const;

 private:
  static size_t RoundUpToPageSize(size_t k);
  std::string CorruptionSyndrome(const MalignBuffer& that) const;
  std::string CrackId(uint64_t) const;

  const size_t capacity_;
  void* base_address_ = nullptr;

  size_t alignment_offset_ = 0;
  size_t length_ = 0;  // Usable length
  char* buffer_address_ = nullptr;
};

}  // namespace cpu_check
#endif  // THIRD_PARTY_CPU_CHECK_MALIGN_BUFFER_H_
