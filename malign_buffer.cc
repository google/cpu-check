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

#include "malign_buffer.h"

#include <cstddef>

#if defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#endif

#include <sys/mman.h>
#include <unistd.h>

#include <cstdlib>
#include <iomanip>
#include <sstream>

#include "log.h"
#include "utils.h"

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#undef HAS_FEATURE_MEMORY_SANITIZER
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#define HAS_FEATURE_MEMORY_SANITIZER
#endif
#endif

#if defined(__i386__) || defined(__x86_64__)
#define X86_TARGET_ATTRIBUTE(s) __attribute__((target(s)))
#else
#define X86_TARGET_ATTRIBUTE(s)
#endif

namespace cpu_check {
namespace {

inline void __movsb(char *dst, const char *src, size_t size) {
#if defined(__i386__) || defined(__x86_64__)
  __asm__ __volatile__("rep movsb"
                       : "+D"(dst), "+S"(src), "+c"(size)
                       :
                       : "memory");
#else
  LOG(FATAL) << "Cannot rep;movsb";
#endif
}

inline void __stosb(void *dst, unsigned char c, size_t size) {
#if defined(__i386__) || defined(__x86_64__)
  __asm__ __volatile__("rep stosb" : "+D"(dst), "+c"(size) : "a"(c) : "memory");
#else
  LOG(FATAL) << "Cannot rep;stosb";
#endif
}

inline void __sse_128_memcpy(char *dst, const char *src, size_t size) {
#if (defined(__i386__) || defined(__x86_64__))
  size_t blks = size / 16;
  for (int i = 0; i < blks; i++) {
    _mm_storeu_si128(
        reinterpret_cast<__m128i *>(dst) + i,
        _mm_loadu_si128(reinterpret_cast<const __m128i *>(src) + i));
  }
  memcpy(dst + blks * 16, src + blks * 16, size - blks * 16);
#else
  LOG(FATAL) << "SSE not available";
#endif
}

X86_TARGET_ATTRIBUTE("avx")
inline void __avx_256_memcpy(char *dst, const char *src, size_t size) {
#if (defined(__i386__) || defined(__x86_64__))
  size_t blks = size / 32;
  for (int i = 0; i < blks; i++) {
    _mm256_storeu_si256(
        reinterpret_cast<__m256i *>(dst) + i,
        _mm256_loadu_si256(reinterpret_cast<const __m256i *>(src) + i));
  }
  memcpy(dst + blks * 32, src + blks * 32, size - blks * 32);
#else
  LOG(FATAL) << "x86 only";
#endif
}

X86_TARGET_ATTRIBUTE("avx512f")
inline void __avx_512_memcpy(char *dst, const char *src, size_t size) {
#if (defined(__i386__) || defined(__x86_64__))
  size_t blks = size / 64;
  for (int i = 0; i < blks; i++) {
    _mm512_storeu_si512(
        reinterpret_cast<__m512i *>(dst) + i,
        _mm512_loadu_si512(reinterpret_cast<const __m512i *>(src) + i));
  }
  memcpy(dst + blks * 64, src + blks * 64, size - blks * 64);
#else
  LOG(FATAL) << "x86 only";
#endif
}
}  // namespace

size_t MalignBuffer::RoundUpToPageSize(size_t k) {
  return ((k + kPageSize - 1) / kPageSize) * kPageSize;
}

size_t CacheLineSize() {
    size_t lineSize = 0;
    size_t sizeofLineSize = sizeof(lineSize);
    sysctlbyname("hw.cachelinesize", &lineSize, &sizeofLineSize, 0, 0);
    return lineSize;
}

// Helper to make MSAN happy. NOP if memory sanitizer is not enabled.
void MalignBuffer::InitializeMemoryForSanitizer(char *addr, size_t size) {
#ifdef HAS_FEATURE_MEMORY_SANITIZER
  std::default_random_engine rnd;
  std::uniform_int_distribution<int> dist(std::numeric_limits<char>::min(),
                                          std::numeric_limits<char>::max());
  for (size_t i = 0; i < size; i++) {
    addr[i] = dist(rnd);
  }
#endif
}

const size_t MalignBuffer::kPageSize = sysconf(_SC_PAGESIZE);
#if defined(__APPLE__)
    const size_t MalignBuffer::kCacheLineSize = CacheLineSize();
#else
    const size_t MalignBuffer::kCacheLineSize = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
#endif

std::string MalignBuffer::ToString(CopyMethod m) {
  switch (m) {
    case kMemcpy:
      return "memcpy";
    case kRepMov:
      return "rep;mov";
    case kSseBy128:
      return "sse:128";
    case kAvxBy256:
      return "avx:256";
    case kAvxBy512:
      return "avx:512";
  }
}

size_t MalignBuffer::RandomAlignment(uint64_t seed) {
  std::knuth_b rng(seed);
  return std::uniform_int_distribution<size_t>(0, kPageSize - 1)(rng);
}

MalignBuffer::MalignBuffer(size_t capacity)
    : capacity_(capacity),
      base_address_(
          aligned_alloc(kPageSize, RoundUpToPageSize(capacity) + kPageSize)) {
  if (base_address_ == nullptr) {
    LOG(FATAL) << "Failed allocate for capacity: " << capacity;
  }
  // There are lots of places that use unitialized MalignBuffer.  So just
  // fill some pseudo-random bytes if cpu_check is compiled with msan.
  InitializeMemoryForSanitizer(static_cast<char *>(base_address_), capacity_);
}
MalignBuffer::MalignBuffer(size_t alignment_offset, absl::string_view s)
    : MalignBuffer(s.size() + alignment_offset) {
  Initialize(alignment_offset, s.size());
  CopyFrom(s, kMemcpy);
}

MalignBuffer::~MalignBuffer() { free(base_address_); }

void MalignBuffer::Initialize(size_t alignment_offset, size_t length) {
  if (length > capacity_) {
    LOG(FATAL) << "Length: " << length << " Capacity: " << capacity_;
  }
  if (alignment_offset >= kPageSize) {
    LOG(FATAL) << "Alignment: " << alignment_offset
               << " PageSize: " << kPageSize;
  }
  alignment_offset_ = alignment_offset;
  length_ = length;
  buffer_address_ = static_cast<char *>(base_address_) + alignment_offset_;
}

void MalignBuffer::resize(size_t length) {
  Initialize(alignment_offset_, length);
}

std::string MalignBuffer::CopyFrom(const MalignBuffer &that, CopyMethod m) {
  CopyFrom(absl::string_view(that.data(), that.size()), m);
  return Syndrome(that);
}

void MalignBuffer::CopyFrom(absl::string_view src, CopyMethod m) {
  if (size() != src.size()) {
    LOG(FATAL) << "this.size: " << size() << " src.size:" << src.size();
  }
  CopyFrom(0, src, m);
}

void MalignBuffer::CopyFrom(size_t pos, absl::string_view src, CopyMethod m) {
  if (pos + src.size() > size()) {
    LOG(FATAL) << "this.size: " << size() << " src.size:" << src.size()
               << " pos: " << pos;
  }
  switch (m) {
    case kMemcpy:
      // Assumes memcpy doesn't use rep;movsb; false in lots of environments.
      memcpy(data() + pos, src.data(), src.size());
      break;
    case kRepMov:
      __movsb(data() + pos, src.data(), src.size());
      break;
    case kSseBy128:
      __sse_128_memcpy(data() + pos, src.data(), src.size());
      break;
    case kAvxBy256:
      __avx_256_memcpy(data() + pos, src.data(), src.size());
      break;
    case kAvxBy512:
      __avx_512_memcpy(data() + pos, src.data(), src.size());
      break;
  }
}

std::string MalignBuffer::Syndrome(const MalignBuffer &that) const {
  std::stringstream s;
  std::string syndrome = CorruptionSyndrome(that);
  if (syndrome.empty()) return "";
  s << syndrome << ", \"this\": \"" << static_cast<const void *>(data())
    << "\", "
    << "\"that\": \"" << static_cast<const void *>(that.data()) << "\"";
  return s.str();
}

std::string MalignBuffer::CorruptionSyndrome(const MalignBuffer &that) const {
  std::stringstream s;
  if (size() != that.size()) {
    s << Json("unequalSizeThis", static_cast<uint64_t>(size())) << ", "
      << Json("unequalSizeThat", static_cast<uint64_t>(that.size()));
    return s.str();
  }
  bool failed_memcmp = memcmp(data(), that.data(), that.size());

  int wrong_bytes = 0;
  int wrong_bits = 0;
  int byte_faults = 0;
  int first_wrong = INT_MAX;
  int last_wrong = INT_MIN;
  std::vector<int> lane_errors(8, 0);
  for (size_t i = 0; i < size(); i++) {
    unsigned char a = *(data() + i);
    unsigned char b = *(that.data() + i);
    unsigned char d = a ^ b;
    if (d) {
      first_wrong = std::min<int>(first_wrong, i);
      last_wrong = std::max<int>(last_wrong, i);
      byte_faults |= d;
      wrong_bytes++;
      wrong_bits += __builtin_popcount(d);
      for (size_t i = 0; i < 8; i++) {
        if ((d >> i) & 1) {
          lane_errors[i]++;
        }
      }
    }
  }
  if (wrong_bits || wrong_bytes) {
    const int range_width = (last_wrong - first_wrong) + 1;
    s << Json("cmpResult",
              (failed_memcmp ? "Failed_Memcmp" : "**Passed_Memcmp**"))
      << ", " << Json("wrongByteCount", wrong_bytes) << ", "
      << Json("wrongBitCount", wrong_bits) << ", "
      << Json("corruptionWidth", range_width) << ", "
      << Json("corruptStart", first_wrong) << ", "
      << Json("corruptByteBitMask", byte_faults) << ", "
      << "\"byBitLane\": [";
    for (size_t i = 0; i < 8; i++) {
      if (i) s << ", ";
      s << lane_errors[i];
    }
    s << " ] ";
    // Dump up to 64 corrupted locations.
    std::stringstream dump;
    dump << " \"byteErrors\": [ " << std::hex;
    uint64_t buf_a = 0;
    uint64_t buf_b = 0;
    for (size_t k = 0; k < std::min(64, range_width); k++) {
      uint8_t a = *(data() + first_wrong + k);
      uint8_t b = *(that.data() + first_wrong + k);
      if (k) dump << ", ";
      dump << "[ " << std::setw(2) << "\"0x" << static_cast<int>(a) << "\", "
           << std::setw(2) << "\"0x" << static_cast<int>(b) << "\" ";
      buf_a = (buf_a >> 8) | static_cast<uint64_t>(a) << 56;
      buf_b = (buf_b >> 8) | static_cast<uint64_t>(b) << 56;
      if ((k >= 7) && (7 == ((first_wrong + k) % 8))) {
        dump << ", " << CrackId(buf_a) << ", " << CrackId(buf_b);
        buf_a = 0;
        buf_b = 0;
      }
      dump << " ]";
    }
    dump << " ] ";
    return s.str() + ", " + dump.str();
  } else {
    if (!failed_memcmp) return "";
    return Json("cmpResult", "**Failed_Memcmp**");
  }
}

std::string MalignBuffer::CrackId(uint64_t v) const {
  std::stringstream s;
  s << std::hex << " [\"0x" << std::setw(4) << (v >> 48) << "\", \"0x"
    << std::setw(6) << ((v >> 24) & 0xffffff) << "\", \"0x" << std::setw(6)
    << (v & 0xffffff) << "\"]";
  return s.str();
}

void MalignBuffer::RandomFlush(std::knuth_b *rng) const {
#if defined(__i386__) || defined(__x86_64__)
  // Note: no barriers used.
  const char *p = buffer_address_ + alignment_offset_;
  while (p < buffer_address_ + length_) {
    if (std::uniform_int_distribution<int>(0, 1)(*rng)) {
      __builtin_ia32_clflush(p);
    }
    p += kCacheLineSize;
  }
#endif
}

std::string MalignBuffer::PunchedHole::ToString() const {
  if (length) {
    return JsonRecord("hole", Json("start", start) + ", " +
                                  Json("length", length) + ", " +
                                  Json("v", static_cast<int>(v)));
  } else {
    return JsonNull("hole");
  }
}

void MalignBuffer::Memset(size_t offset, unsigned char v, size_t length,
                          bool use_rep_stos) {
  if (use_rep_stos) {
    __stosb(data() + offset, v, length);
  } else {
    memset(data() + offset, v, length);
  }
}

void MalignBuffer::PunchHole(const PunchedHole &hole, bool use_rep_stos) {
  if (hole.length) {
    Memset(hole.start, hole.v, hole.length, use_rep_stos);
  }
}

// Hints to the OS to release the buffer's memory.
void MalignBuffer::MadviseDontNeed() const {
  // Round up the buffer start address to a page boundary.
  intptr_t start = ((intptr_t)data() + kPageSize - 1) & ~(kPageSize - 1);
  // Round down the buffer end address to a page boundary.
  intptr_t end = ((intptr_t)(data() + size() - 1)) & ~(kPageSize - 1);
  if (end > start) {
    const size_t length = end - start;
    if (madvise((char *)start, length, MADV_DONTNEED) == -1) {
      LOG(WARN) << "tid "
                << " madvise(MADV_DONTNEED) failed: " << strerror(errno)
                << " length: " << length;
    }
  }
}

MalignBuffer::PunchedHole MalignBuffer::RandomPunchedHole(uint64_t seed) const {
  std::knuth_b rng(seed);
  MalignBuffer::PunchedHole hole;
  hole.length = std::uniform_int_distribution<size_t>(
      1, std::min<size_t>(length_, 8192))(rng);
  hole.start =
      std::uniform_int_distribution<size_t>(0, length_ - hole.length)(rng);
  return hole;
}

}  // namespace cpu_check
