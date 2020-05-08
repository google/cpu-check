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

#undef NDEBUG
#include "config.h"

#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#endif
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#ifdef IN_GOOGLE3
#include "third_party/zlib/zlib.h"
#else
#include <zlib.h>
#endif

#include <algorithm>
#include <atomic>
#include <cassert>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <list>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifdef IN_GOOGLE3
#include "third_party/openssl/crypto.h"
#include "third_party/openssl/evp.h"
#else
#include <openssl/crypto.h>
#include <openssl/evp.h>
#endif

#ifdef IN_GOOGLE3
#include "third_party/absl/debugging/failure_signal_handler.h"
#include "third_party/absl/debugging/symbolize.h"
#endif

#include "crc32c.h"
#include "third_party/farmhash/src/farmhash.h"
#include "fvt_controller.h"
#include "log.h"
#include "utils.h"

#if defined(__i386__) || defined(__x86_64__)
#define X86_TARGET_ATTRIBUTE(s)  __attribute__ ((target (s)))
#else
#define X86_TARGET_ATTRIBUTE(s)
#endif

#undef HAS_FEATURE_MEMORY_SANITIZER
#if defined(__has_feature)
#  if __has_feature(memory_sanitizer)
#define HAS_FEATURE_MEMORY_SANITIZER
#  endif
#endif

// Helper to make MSAN happy. NOP if memory sanitizer is not enabled.
void InitializeMemoryForSanitizer(char* addr, size_t size) {
#ifdef HAS_FEATURE_MEMORY_SANITIZER
  std::default_random_engine rnd;
  std::uniform_int_distribution<int> dist(std::numeric_limits<char>::min(),
                                          std::numeric_limits<char>::max());
  for (size_t i = 0; i < size; i++) {
    addr[i] = dist(rnd);
  }
#endif
}

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
  __asm__ __volatile__("rep stosb"
                       : "+D"(dst), "+c"(size)
                       : "a"(c)
                       : "memory");
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

static const double t0 = TimeInSeconds();

static void SleepForMillis(int64_t millis) {
  // LOG(INFO) << "sleeping " << millis;
  int64_t micros = 1000 * millis;
  while (micros > 0) {
    int mm = std::min<int>(1000000, micros);
    int rc = usleep(mm);
    if (rc) {
      LOG(ERROR) << "cant sleep";
    }
    micros -= mm;
  }
}

static long pagesize = sysconf(_SC_PAGESIZE);
static long cache_line_size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);

std::string HexData(const char *s, uint32_t l) {
  const char d[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  std::string o;
  o.resize(l << 1);
  for (uint32_t i = 0; i < l; i++) {
    uint8_t b = s[i];
    o[(i << 1)] = d[(b >> 4) & 0xf];
    o[(i << 1) + 1] = d[b & 0xf];
  }
  return o;
}

std::string HexStr(const std::string &s) { return HexData(s.data(), s.size()); }

std::atomic_bool exiting(false);
std::atomic_uintmax_t errorCount(0);
std::atomic_uintmax_t successCount(0);
static constexpr uintmax_t kErrorLimit = 2000;

#if defined(__i386__) || defined(__x86_64__)
const bool is_x86 = true;
#else
const bool is_x86 = false;
#endif

// So-called Logistic Map with parameter 4.0.
// Floating point approximation aside, if 0 < v < 1 then 0 < ChaoticF1(v) < 1.
static inline double ChaoticF1(double v) {
  return 4.0 * v * (1.0 - v);
}

#if defined(__i386__) || defined(__x86_64__)
static bool can_do_avx() {
  __builtin_cpu_init();
  return __builtin_cpu_supports("avx");
}

static bool can_do_avx512f() {
  __builtin_cpu_init();
  return __builtin_cpu_supports("avx512f");
}

static bool can_do_fma() {
  __builtin_cpu_init();
  return __builtin_cpu_supports("fma");
}

static bool can_do_fvt() {
  return geteuid() == 0;   // need write access to MSRs.
}

#else
static bool can_do_avx() { return false; }
static bool can_do_avx512f() { return false; }
static bool can_do_fma() { return false; }
static bool can_do_fvt() { return false; }  // x86-only for now.
#endif

bool do_madvise = true;
bool do_repmovsb = is_x86;
bool do_sse_128_memcpy = is_x86;
bool do_avx_256_memcpy = can_do_avx();
bool do_avx_512_memcpy = can_do_avx512f();
bool do_avx_heavy = can_do_avx();
bool do_compress = true;
bool do_encrypt = true;
bool do_hashes = true;
bool do_misalign = true;
bool do_hop = true;
bool do_ssl_self_check = true;
bool do_flush = false;  // Default: disabled for now
bool do_provenance = false;
bool do_repstosb = is_x86;
bool do_freq_sweep = false;
bool do_freq_hi_lo = false;
bool do_noise = false;
bool do_invert_cores = false;
int fixed_min_frequency = 0;
int fixed_max_frequency = 0;
bool do_fvt = can_do_fvt();
bool do_fast_string_ops = true;
int seconds_per_freq = 300;
uintmax_t error_limit = kErrorLimit;

bool SetAffinity(int id) {
  int err = 0;
#ifdef __linux__
  cpu_set_t cset;
  CPU_ZERO(&cset);
  CPU_SET(id, &cset);
  err = sched_setaffinity(0, sizeof(cset), &cset);
  std::atomic_thread_fence(std::memory_order_seq_cst);
  if (err) {
    err = errno;
  }
#elif defined(__NetBSD__)
  cpuset_t *cset;
  cset = cpuset_create();
  if (cset == nullptr) {
    LOG(ERROR) << "cpuset_create failed: " << strerror(errno);
    return false;
  }
  cpuset_set(id, cset);
  err = pthread_setaffinity_np(pthread_self(), cpuset_size(cset), cset);
  std::atomic_thread_fence(std::memory_order_seq_cst);
  cpuset_destroy(cset);
#endif
  if (err != 0) {
    LOG_EVERY_N_SECS(WARN, 30)
        << "setaffinity to tid: " << id << " failed: " << strerror(err);
  }
  return err == 0;
}

std::vector<std::string> ReadDict() {
  // Dictionary search paths
  static const char *dicts[] = {
      "/usr/share/dict/words",
      "words",
  };
  std::vector<std::string> words;
  std::ifstream f;

  for (const auto &d : dicts) {
    f.open(d, std::ifstream::in);
    if (f.is_open()) break;
    f.clear();
  }

  if (!f.is_open()) return words;

  LOG(DEBUG) << "Reading words.";

  std::string word;
  while (!f.eof()) {
    std::getline(f, word);
    words.push_back(word);
  }
  f.close();
  LOG(DEBUG) << "Read " << words.size() << " words.";
  std::sort(words.begin(), words.end(),
            [](const std::string &a, const std::string &b) {
              return a.size() < b.size();
            });
  return words;
}

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

  static std::string ToString(CopyMethod m) {
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

  // Provides buffer with specified alignment.
  MalignBuffer(size_t capacity)
      : capacity_(capacity),
        base_address_(aligned_alloc(pagesize, capacity + pagesize)) {
    assert(base_address_);
    // There are lots of places that use unitialized MalignBuffer.  So just
    // fill some pseudo-random bytes if cpu_check is compiled with msan.
    InitializeMemoryForSanitizer(static_cast<char*>(base_address_), capacity_);
  }
  ~MalignBuffer() { free(base_address_); }

  // REQUIRES: alignment_offset + length <= capacity_.
  void Initialize(size_t alignment_offset, size_t length);

  const char* data() const { return buffer_address_; }
  char* data() { return buffer_address_; }
  size_t size() const { return length_; }

  // REQUIRES alignment_offset + length <= capacity_.
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
  void CopyFrom(const char* src, size_t length, CopyMethod m);
  void CopyFrom(size_t pos, const char* src, size_t length, CopyMethod m);

  // Randomly flushes cache lines.
  void RandomFlush(std::knuth_b* rng) const;

  // Conventional or rep;sto memset operation, according to 'use_rep_stos'.
  void Memset(size_t offset, unsigned char v, size_t length, bool use_rep_stos);

  // Memsets buffer to 'hole.v', using rep;stos operation if
  // 'use_rep_stos' set;
  void PunchHole(const PunchedHole& hole, bool use_rep_stos);

 private:
  std::string CorruptionSyndrome(const MalignBuffer& that) const;
  std::string CrackId(uint64_t) const;

  const size_t capacity_;
  void* base_address_ = nullptr;

  size_t alignment_offset_ = 0;
  size_t length_ = 0;    // Usable length
  char* buffer_address_ = nullptr;
};

void MalignBuffer::Initialize(size_t alignment_offset, size_t length) {
  assert(alignment_offset + length <= capacity_);
  alignment_offset_ = alignment_offset;
  length_ = length;
  buffer_address_ = static_cast<char*>(base_address_) + alignment_offset_;
}

void MalignBuffer::resize(size_t length) {
  Initialize(alignment_offset_, length);
}

std::string MalignBuffer::CopyFrom(const MalignBuffer& that, CopyMethod m) {
  CopyFrom(that.data(), that.size(), m);
  return Syndrome(that);
}

void MalignBuffer::CopyFrom(const char* src, size_t length, CopyMethod m) {
  assert(size() == length);
  CopyFrom(0, src, length, m);
}

void MalignBuffer::CopyFrom(size_t pos, const char* src, size_t length,
                            CopyMethod m) {
assert(pos + length <= size());
switch (m) {
  case kMemcpy:
    // Assumes memcpy doesn't use rep;movsb; false in lots of environments.
    memcpy(data() + pos, src, length);
    break;
  case kRepMov:
    __movsb(data() + pos, src, length);
    break;
  case kSseBy128:
    __sse_128_memcpy(data() + pos, src, length);
    break;
  case kAvxBy256:
    __avx_256_memcpy(data() + pos, src, length);
    break;
  case kAvxBy512:
    __avx_512_memcpy(data() + pos, src, length);
    break;
}
}

std::string MalignBuffer::Syndrome(const MalignBuffer& that) const {
  std::stringstream s;
  std::string syndrome = CorruptionSyndrome(that);
  if (syndrome.empty()) return "";
  s << syndrome << ", \"this\": \"" << static_cast<const void *>(data())
    << "\", "
    << "\"that\": \"" << static_cast<const void *>(that.data()) << "\"";
  return s.str();
}

std::string MalignBuffer::CorruptionSyndrome(const MalignBuffer& that) const {
  std::stringstream s;
  if (size() != that.size()) {
    s << Json("unequalSizeThis", size()) << ", "
      << Json("unequalSizeThat", that.size());
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

void MalignBuffer::RandomFlush(std::knuth_b* rng) const {
#if defined(__i386__) || defined(__x86_64__)
  // Note: no barriers used.
  const char* p = buffer_address_ + alignment_offset_;
  while (p < buffer_address_ + length_) {
    if (std::uniform_int_distribution<int>(0, 1)(*rng)) {
      __builtin_ia32_clflush(p);
    }
    p += cache_line_size;
  }
#endif
}

std::string MalignBuffer::PunchedHole::ToString() const {
  if (length) {
    return JsonRecord("hole",
                      Json("start", start) + ", " + Json("length", length)
                      + ", " + Json("v", static_cast<int>(v)));
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

void MalignBuffer::PunchHole(const PunchedHole& hole, bool use_rep_stos) {
  if (hole.length) {
    Memset(hole.start, hole.v, hole.length, use_rep_stos);
  }
}

// x86 AVX usage has complicated core power effects. This code tries
// to provoke some power transitions that don't otherwise happen.
// While it's at it, it lightly checks results, but that's not the central
// goal. ToDo: maybe toughen the correctness checking.
//
// The power policies are governed by a number of opaque parameters; this code
// is based on a lot of guesses.

class Avx {
 public:
  Avx() {}

  // Activate AVX depending on throw of the dice.
  // Returns syndrome if computational error detected.
  std::string MaybeGoHot();

  // Does a bit of computing if in a "hot" mode.
  // Returns syndrome if computational error detected.
  std::string BurnIfAvxHeavy();

 private:
  constexpr static int kIterations = 5000;
  std::string Avx256(int rounds);
  std::string Avx256FMA(int rounds);
  std::string Avx512(int rounds);
  int level_ = 0;
  std::knuth_b rng_;
};

std::string Avx::MaybeGoHot() {
  if (std::uniform_int_distribution<int>(0, 1)(rng_)) {
    // Don't provoke.
    level_ = 0;
    return "";
  }
  if (can_do_avx512f()) {
    // Processor supports both AVX and AVX512.
    level_ = std::uniform_int_distribution<int>(0, 1)(rng_) ? 3 : 5;
  } else {
    // Processor supports only AVX.
    level_ = 3;
  }
  return BurnIfAvxHeavy();
}

std::string Avx::BurnIfAvxHeavy() {
  if (level_ == 3) {
    return can_do_fma() ? Avx256FMA(kIterations) : Avx256(kIterations);
  }
  if (level_ == 5) {
    return Avx512(kIterations);
  }
  return "";
}

// See notes for Avx512 below
X86_TARGET_ATTRIBUTE("avx")
std::string Avx::Avx256(int rounds) {
#if (defined(__i386__) || defined(__x86_64__))
  const __m256d minus_four = _mm256_set1_pd(-4.0);
  __m256d x[4];
  for (int k = 0; k < 4; k++) {
    x[k] =
        _mm256_set1_pd(std::uniform_real_distribution<double>(0.0, 1.0)(rng_));
  }
  double *gross_x[4] = {
      reinterpret_cast<double *>(&x[0]),
      reinterpret_cast<double *>(&x[1]),
      reinterpret_cast<double *>(&x[2]),
      reinterpret_cast<double *>(&x[3]),
  };
  for (int i = 0; i < rounds; i++) {
    __m256d a[4];
    a[0] = _mm256_sub_pd(_mm256_mul_pd(x[0], x[0]), x[0]);
    a[1] = _mm256_sub_pd(_mm256_mul_pd(x[1], x[1]), x[1]);
    a[2] = _mm256_sub_pd(_mm256_mul_pd(x[2], x[2]), x[2]);
    a[3] = _mm256_sub_pd(_mm256_mul_pd(x[3], x[3]), x[3]);
    x[0] = _mm256_mul_pd(minus_four, a[0]);
    x[1] = _mm256_mul_pd(minus_four, a[1]);
    x[2] = _mm256_mul_pd(minus_four, a[2]);
    x[3] = _mm256_mul_pd(minus_four, a[3]);
  }
  for (int k = 1; k < 4; k++) {
    for (int i = 0; i < 4; i++) {
      if (gross_x[k][i] != gross_x[k][0]) {
        return "avx256 pd";
      }
    }
  }
#endif
  return "";
}

// See notes for Avx512 below
X86_TARGET_ATTRIBUTE("avx,fma")
std::string Avx::Avx256FMA(int rounds) {
#if (defined(__i386__) || defined(__x86_64__))
  const __m256d minus_four = _mm256_set1_pd(-4.0);
  __m256d x[4];
  for (int k = 0; k < 4; k++) {
    x[k] =
        _mm256_set1_pd(std::uniform_real_distribution<double>(0.0, 1.0)(rng_));
  }
  double *gross_x[4] = {
      reinterpret_cast<double *>(&x[0]),
      reinterpret_cast<double *>(&x[1]),
      reinterpret_cast<double *>(&x[2]),
      reinterpret_cast<double *>(&x[3]),
  };
  for (int i = 0; i < rounds; i++) {
    __m256d a[4];
    a[0] = _mm256_fmsub_pd(x[0], x[0], x[0]);
    a[1] = _mm256_fmsub_pd(x[1], x[1], x[1]);
    a[2] = _mm256_fmsub_pd(x[2], x[2], x[2]);
    a[3] = _mm256_fmsub_pd(x[3], x[3], x[3]);
    x[0] = _mm256_mul_pd(minus_four, a[0]);
    x[1] = _mm256_mul_pd(minus_four, a[1]);
    x[2] = _mm256_mul_pd(minus_four, a[2]);
    x[3] = _mm256_mul_pd(minus_four, a[3]);
  }
  for (int k = 1; k < 4; k++) {
    for (int i = 0; i < 4; i++) {
      if (gross_x[k][i] != gross_x[k][0]) {
        return "avx256 pd";
      }
    }
  }
#endif
  return "";
}

// Interleave AVX512 parallel calculation of iterates of f(x) = 4x(1-x).
// Hope compiler too dumb to see through this.
X86_TARGET_ATTRIBUTE("avx512f")
std::string Avx::Avx512(int rounds) {
#if (defined(__i386__) || defined(__x86_64__))
  const __m512d minus_four = _mm512_set1_pd(-4.0);
  __m512d x[4];
  for (int k = 0; k < 4; k++) {
    x[k] =
        _mm512_set1_pd(std::uniform_real_distribution<double>(0.0, 1.0)(rng_));
  }

  double *gross_x[4] = {
      reinterpret_cast<double *>(&x[0]),
      reinterpret_cast<double *>(&x[1]),
      reinterpret_cast<double *>(&x[2]),
      reinterpret_cast<double *>(&x[3]),
  };

  for (int i = 0; i < rounds; i++) {
    __m512d a[4];
    a[0] = _mm512_fmsub_pd(x[0], x[0], x[0]);
    a[1] = _mm512_fmsub_pd(x[1], x[1], x[1]);
    a[2] = _mm512_fmsub_pd(x[2], x[2], x[2]);
    a[3] = _mm512_fmsub_pd(x[3], x[3], x[3]);
    x[0] = _mm512_mul_pd(minus_four, a[0]);
    x[1] = _mm512_mul_pd(minus_four, a[1]);
    x[2] = _mm512_mul_pd(minus_four, a[2]);
    x[3] = _mm512_mul_pd(minus_four, a[3]);
  }

  for (int k = 1; k < 4; k++) {
    for (int i = 0; i < 7; i++) {
      if (gross_x[k][i] != gross_x[k][0]) {
        return "avx512 pd";
      }
    }
  }
#endif
  return "";
}

// Produces noise of all kinds by running intermittently.
// There's a coarse cycle with four fine phases:
//   Phase 0: Off
//   Phase 1: High-speed on-off
//   Phase 2: On
//   Phase 3: High-speed on-off
class NoiseScheduler {
 public:
  // The following constants are just plain made up outta whole cloth.
  // You could consider various power regulation time constants and thermal
  // intertia and so forth. Or just make it up.
  static constexpr int kCoarseMillis = 5000;  // Coarse period in millis
  static constexpr int kFineMillis = 50;      // Fine period in millis

  // Blocks until next scheduled activity
  static void BlockUntilOn() {
    bool was_blocked = false;
    while (true) {
      int64_t t = 1e3 * TimeInSeconds();
      int64_t coarse_block = t / kCoarseMillis;
      int64_t phase = coarse_block % 4;
      if (phase == 2) {
        if (was_blocked) {
          // LOG(INFO) << "Coarse grained unblock";
        }
        was_blocked = false;
        return;  // On
      }
      if (phase == 0) {
        // Wait til next phase and then re-evaluate.
        SleepForMillis(((coarse_block + 1) * kCoarseMillis) - t);
        was_blocked = true;
        continue;
      }
      // Fine phase.
      int64_t fine_block = t / kFineMillis;
      if (fine_block % 2) {
        if (was_blocked) {
          // LOG(INFO) << "Fine grained unblock";
        }
        was_blocked = false;
        return;  // Fine-grained on
      }
      // Wait til next fine block and then re-evaluate.
      SleepForMillis(((fine_block + 1) * kFineMillis) - t);
      was_blocked = true;
    }
  }
};

// Rudimentary coherence/uncore tester.
// Randomly assigns each slot of a seemingly shared buffer to a single tid,
// creating only "false sharing".
// Thus each slot, regardless of alignment, must obey program order unless the
// machine is broken.
// To be toughened, e.g.:
//   Widen the slots a bit
//   Control the sharing more tightly, e.g. each cache line split between 2 tids
//   Maybe checksum the indices to distinguish core-local compute errors from
//   coherence errors, but that's perhaps easier said than done effectively.
// As it stands, it may be particularly hard to localize failures. Though that's
// always going to be a bit hard, which is the point. One technique might be
// to leave this alone and to run on subsets of cores and sockets.
class Silkscreen {
 public:
  static constexpr size_t kSize = 1000 * 1000;  // Size of buffer

  Silkscreen(const std::vector<int> &tid_list);
  ~Silkscreen() { free(buffer_address_); }

  // Writes value derived from 'round' into all slots owned by 'tid'.
  // Returns number of slots written.
  uint64_t WriteMySlots(int tid, uint64_t round);

  // Returns JSON-formatted error string if slot 'k' belongs to 'tid' and has
  // value not properly corresponding with 'round'.
  // Returns "=" if slot 'k' belongs to 'tid' and has expected value.
  // Otherwise, if slot 'k' does not belong to 'tid', returns empty string.
  std::string CheckMySlot(int tid, uint64_t round, size_t k) const;

 private:
  int owner(size_t k) const { return owner_[k]; }
  size_t size() const { return owner_.size(); }
  const char* data(size_t k) const { return buffer_address_ + k; }
  char* data(size_t k) { return buffer_address_ + k; }

  std::vector<uint16_t> owner_;  // const after initialization
  char* buffer_address_ = nullptr;
};

Silkscreen::Silkscreen(const std::vector<int> &tid_list)
    : buffer_address_(static_cast<char*>(aligned_alloc(
        pagesize,
        pagesize * ((kSize + pagesize - 1) / pagesize) ))) {
  std::knuth_b rng;
  std::uniform_int_distribution<size_t> dist(0, tid_list.size() - 1);
  for (size_t k = 0; k < kSize; k++) {
    size_t w = dist(rng);
    owner_.push_back(tid_list[w]);
  }
}

uint64_t Silkscreen::WriteMySlots(int tid, uint64_t round) {
  uint64_t j = 0;
  for (size_t k = 0; k < kSize; k++) {
    if (owner(k) == tid) {
      *data(k) = static_cast<char>(round);
      j++;
    }
  }
  return j;
}

std::string Silkscreen::CheckMySlot(int tid, uint64_t round, size_t k) const {
  if (owner(k) != tid) return "";
  const int v = *data(k);
  const int w = static_cast<char>(round);
  if (v == w) return "=";
  return
      Json("position", k) + ", " + Json("is", v) + ", " + Json("expected", w);
}

class Worker {
 public:
  // Does not take ownership of 'silkscreen'.
  Worker(int pid, const std::vector<std::string> *words,
        std::vector<int> tid_list, int tid, Silkscreen *silkscreen)
      : pid_(pid), tid_(tid), words_(words), tid_list_(tid_list),
        silkscreen_(silkscreen), rndeng_(std::random_device()()) {
  }
  ~Worker() {}
  void Run();

 private:
  static constexpr size_t kBufMin = 12;
#ifdef HAVE_FEATURE_MEMORY_SANITIZER
    // Use smaller buffers if cpu_check is built with msan.  Otherwise
    // we will time out in testing.
    static constexpr size_t kBufMax = 1 << 16;  // 64 KiB
#else
  static constexpr size_t kBufMax = 1 << 20;  // 1 MiB
#endif

  struct FloatingPointResults {
    bool operator!=(const FloatingPointResults& other) const {
      return d != other.d;
    }

    double d = 0.0;
  };

  typedef struct {
    const char *name;
    FloatingPointResults (Worker::*func)(
        uint32_t seed, MalignBuffer::CopyMethod copy_method,
        bool use_repstos, MalignBuffer*) const;
  } generatorItem;

  struct BufferSet {
    void Alloc(std::unique_ptr<MalignBuffer> *p) {
      const size_t kBufCap = kBufMax + 23 * pagesize;
      if (!*p) {
        p->reset(new MalignBuffer(kBufCap));
      }
    }

    std::unique_ptr<MalignBuffer> original;
    std::unique_ptr<MalignBuffer> compressed;
    std::unique_ptr<MalignBuffer> encrypted;
    std::unique_ptr<MalignBuffer> copied;
    std::unique_ptr<MalignBuffer> decrypted;
    std::unique_ptr<MalignBuffer> decompressed;
    std::unique_ptr<MalignBuffer> re_made;
  };

  FloatingPointResults FillBufferSystematic(
      uint32_t unused_seed, MalignBuffer::CopyMethod copy_method,
      bool use_repstos, MalignBuffer* b) const;
  FloatingPointResults FillBufferRandomData(
      uint32_t seed, MalignBuffer::CopyMethod copy_method,
      bool use_repstos, MalignBuffer* b) const;
  FloatingPointResults FillBufferRandomText(
      uint32_t seed, MalignBuffer::CopyMethod copy_method,
      bool use_repstos, MalignBuffer* b) const;
  FloatingPointResults FillBufferGrilledCheese(
      uint32_t seed, MalignBuffer::CopyMethod copy_method,
      bool use_repstos, MalignBuffer* b) const;

  void MadviseDontNeed(const MalignBuffer &s) const;
  size_t Alignment();
  void MaybeFlush(const MalignBuffer &s);
  // Attempts to schedules CPU frequency using the Worker's.
  // FVTController object.  Returns the scheduled frequency or
  // 0 if there is no FVTController available.
  int ScheduledMHz() const;
  MalignBuffer::CopyMethod CopyMethod();
  std::string FVT() const;
  MalignBuffer::PunchedHole PunchedHole(size_t bufsize);
  FloatingPointResults GenerateData(
      const generatorItem& generator,
      const MalignBuffer::PunchedHole& hole,
      uint32_t seed, MalignBuffer::CopyMethod copy_method,
      bool use_repstos, MalignBuffer* b) const;

  // Emits a failure record.
  // TODO: bump error count here, and maybe log, instead of at every
  // call site.
  std::string Jfail(const std::string &err, const std::string &v) {
    if (errorCount > error_limit) {
      exiting = true;
      LOG(INFO) << "I am quitting after " << errorCount << " errors";
    }
    return "{ " + JsonRecord("fail", Json("err", err) + ", " + v) + ", " +
           JTag() + " }";
  }

  // Array of random data generators.
  static const std::vector<generatorItem> kGenerators;

  const uint64_t pid_;
  const int tid_;
  const std::vector<std::string> *words_;
  const std::vector<int> tid_list_;
  Silkscreen* const silkscreen_;

  // We don't really need "good" random numbers.
  // std::mt19937_64 rndeng_;
  std::knuth_b rndeng_;
  uint64_t round_ = 0;

  std::unique_ptr<FVTController> fvt_controller_;
};

const std::vector<Worker::generatorItem> Worker::kGenerators = {
    {"SYSTEMATIC", &Worker::FillBufferSystematic},
    {"DATA", &Worker::FillBufferRandomData},
    {"TEXT", &Worker::FillBufferRandomText},
    {"CHEESE", &Worker::FillBufferGrilledCheese},
};

std::string Worker::FVT() const {
  if (fvt_controller_ == nullptr) return "";
  return fvt_controller_->FVT();
}

int Worker::ScheduledMHz() const {
  if (fvt_controller_ == nullptr) {
    return 0;
  }

  if (fixed_min_frequency && (fixed_min_frequency == fixed_max_frequency)) {
    // User-specified fixed frequency.
    return fixed_min_frequency;
  }
  if (!do_freq_sweep && !do_freq_hi_lo
      && !fixed_min_frequency && !fixed_max_frequency) {
    // Run at maximum frequency.
    return fvt_controller_->limit_mHz();
  }

  const int low_f =
      fixed_min_frequency ? fixed_min_frequency : fvt_controller_->kMinTurboMHz;
  // hi_f cannot exceed limit
  const int limit_mHz = fvt_controller_->limit_mHz();
  const int hi_f = fixed_max_frequency
                       ? std::min<int>(fixed_max_frequency, limit_mHz)
                       : limit_mHz;

  int64_t t = TimeInSeconds() / seconds_per_freq;
  if (do_freq_hi_lo) {
    const int step = t % 2;
    return step ? low_f : hi_f;
  } else {
    const int steps = 1 + (hi_f - low_f) / 100;
    const int full_ramps = t / steps;
    const bool upwards = full_ramps % 2;
    const int step = t % steps;
    return upwards ? low_f + 100 * step : hi_f - 100 * step;
  }
}

// Fills 'b' with a systematic pattern.
// Returns iterate of chaotic floating point function of 'seed', with some
// reciprocal torture.
Worker::FloatingPointResults Worker::FillBufferSystematic(
    uint32_t seed, MalignBuffer::CopyMethod copy_method,
    bool use_repstos, MalignBuffer* b) const {
  // Format: 2 bytes of PID, 3 bytes of round number, 3 bytes of offset.
  // Note: Perhaps should be AC-modulated. Perhaps should be absolute aligned
  // for easier recognition.
  // Note: appropriate for LE machines only.
  FloatingPointResults fp;
  fp.d = std::max<uint32_t>(seed, 2);
  for (size_t i = 0; i * 8 < b->size(); i++) {
    const size_t p = 8 * i;
    const size_t k = std::min<size_t>(8, b->size() - p);
    const uint64_t v =
        ((pid_ & 0xffff) << 48)
        | ((round_ & 0xffffff) << 24) | (i & 0xffffff);
    for (size_t m = 0; m < k; m++) {
      (b->data())[p + m] = *(reinterpret_cast<const char*>(&v) + m);
    }
    fp.d = 1.0 / ChaoticF1(1.0 / fp.d);
  }
  fp.d = 1.0 / fp.d;
  return fp;
}

Worker::FloatingPointResults Worker::FillBufferRandomData(
    uint32_t seed, MalignBuffer::CopyMethod copy_method,
    bool use_repstos, MalignBuffer* b) const {
  std::knuth_b rng(seed);
  std::uniform_int_distribution<uint64_t>
      dist(0, std::numeric_limits<uint64_t>::max());
  size_t p = 0;
  const size_t length = b->size();
  // Repeatedly append random number (one to eight) random bytes.
  while (p < length) {
    const size_t max_span = std::min<size_t>(length - p, 8);
    const size_t z = std::uniform_int_distribution<size_t>(1, max_span)(rng);
    const uint64_t v = dist(rng);
    b->CopyFrom(p, reinterpret_cast<const char*>(&v), z, copy_method);
    p += z;
  }
  return FloatingPointResults();
}

Worker::FloatingPointResults Worker::FillBufferRandomText(
    uint32_t seed, MalignBuffer::CopyMethod copy_method,
    bool use_repstos, MalignBuffer* b) const {
  std::knuth_b rng(seed);
  std::exponential_distribution<double> dist(20);
  const size_t bufsize = b->size();
  size_t pos = 0;
  while (pos < bufsize) {
    const size_t r = std::min(static_cast<size_t>(dist(rng) * words_->size()),
                              words_->size() - 1);
    const auto &word = (*words_)[r];
    const size_t wordlen = word.size();
    if (pos + wordlen >= bufsize) {
      break;
    }
    b->CopyFrom(pos, word.c_str(), wordlen, copy_method);
    pos += wordlen;
    if (pos < bufsize) {
      b->Memset(pos, ' ', 1, use_repstos);
      pos++;
    }
  }
  // Pad with spaces
  b->Memset(pos, ' ', bufsize - pos, use_repstos);
  return FloatingPointResults();
}

// memset (conventional or rep;stos) randomly aligned, random width, randomly
// overlapped stretches of buffer. Constants aim to hit multiple times in cache
// lines and buffers. Untuned and based on nothing but hunches.
Worker::FloatingPointResults Worker::FillBufferGrilledCheese(
    uint32_t seed, MalignBuffer::CopyMethod copy_method, bool use_repstos,
    MalignBuffer* b) const {
  std::knuth_b rng(seed);
  const size_t kAdvance = 15;
  const size_t kWindow = 64;
  unsigned char flavor = 0;
  b->Memset(0, 0, b->size(), use_repstos);
  for (int base = kWindow; base < b->size(); base += kAdvance) {
    if (std::uniform_int_distribution<int>(0, 1)(rng)) continue;
    flavor++;
    const size_t start =
        std::uniform_int_distribution<size_t>(base - kWindow, base)(rng);
    const size_t end = std::uniform_int_distribution<int>(start, base)(rng);
    b->Memset(start, flavor, 1 + end - start, use_repstos);
  }
  return FloatingPointResults();
}

Worker::FloatingPointResults Worker::GenerateData(
    const generatorItem& generator,
    const MalignBuffer::PunchedHole& hole,
    uint32_t seed, MalignBuffer::CopyMethod copy_method,
    bool use_repstos,
    MalignBuffer* b) const {
  const FloatingPointResults f =
      (this->*generator.func)(seed, copy_method, use_repstos, b);
  b->PunchHole(hole, use_repstos);
  return f;
}

// Hints to the OS to release the buffer's memory.
void Worker::MadviseDontNeed(const MalignBuffer &s) const {
  // Round up the buffer start address to a page boundary.
  intptr_t start = ((intptr_t) s.data() + pagesize - 1) & ~(pagesize - 1);
  // Round down the buffer end address to a page boundary.
  intptr_t end = ((intptr_t) (s.data() + s.size() - 1)) & ~(pagesize - 1);
  if (end - start >= pagesize) {
    if (madvise((char *)start, end - start, MADV_DONTNEED) == -1) {
      LOG(WARN) << "tid " << tid_
                << " madvise(MADV_DONTNEED) failed: " << strerror(errno);
    }
  }
}

void Worker::MaybeFlush(const MalignBuffer& s) {
  // Half the time, tell the OS to release the destination buffer.
  if (do_flush && std::uniform_int_distribution<int>(0, 1)(rndeng_)) {
    s.RandomFlush(&rndeng_);
  }
}

size_t Worker::Alignment() {
  return do_misalign ?
      std::uniform_int_distribution<size_t>(0, pagesize)(rndeng_) : 0;
}

MalignBuffer::CopyMethod Worker::CopyMethod() {
  std::vector<MalignBuffer::CopyMethod> v;
  v.push_back(MalignBuffer::kMemcpy);
  if (do_repmovsb) {
    // Weight rep;mov more heavily.
    for (int i = 0; i < 3; i++) {
      v.push_back(MalignBuffer::kRepMov);
    }
  }
  if (do_sse_128_memcpy) v.push_back(MalignBuffer::kSseBy128);
  if (do_avx_256_memcpy) v.push_back(MalignBuffer::kAvxBy256);
  if (do_avx_512_memcpy) v.push_back(MalignBuffer::kAvxBy512);
  size_t k = std::uniform_int_distribution<int>(0, v.size() - 1)(rndeng_);
  return v[k];
}

MalignBuffer::PunchedHole Worker::PunchedHole(size_t bufsize) {
  MalignBuffer::PunchedHole hole;
  hole.length =
      std::uniform_int_distribution<size_t>(
          1, std::min<size_t>(bufsize, 8192))(rndeng_);
  hole.start =
      std::uniform_int_distribution<size_t>(
          0, bufsize - hole.length)(rndeng_);
  return hole;
}

std::string OpenSSL_Hash(const MalignBuffer &s, const EVP_MD *type) {
  EVP_MD_CTX *ctx;
  ctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(ctx, type, nullptr);
  std::string hash;
  hash.resize(EVP_MD_CTX_size(ctx));
  InitializeMemoryForSanitizer(hash.data(), EVP_MD_CTX_size(ctx));
  EVP_DigestUpdate(ctx, s.data(), s.size());
  EVP_DigestFinal_ex(ctx, (uint8_t *)&hash[0], nullptr);
  EVP_MD_CTX_destroy(ctx);
  return HexStr(hash);
}

void Worker::Run() {
  // Array of hash/checksum routines.
  typedef struct {
    const char *name;
    std::string (*func)(const MalignBuffer &);
  } hashItem;
  std::vector<hashItem> hashers = {
      {
          "MD5",
          [](const MalignBuffer &s) -> std::string {
            return OpenSSL_Hash(s, EVP_md5());
          },
      },
      {
          "SHA1",
          [](const MalignBuffer &s) -> std::string {
            return OpenSSL_Hash(s, EVP_sha1());
          },
      },
      {
          "SHA256",
          [](const MalignBuffer &s) -> std::string {
            return OpenSSL_Hash(s, EVP_sha256());
          },
      },
      {
          "SHA512",
          [](const MalignBuffer &s) -> std::string {
            return OpenSSL_Hash(s, EVP_sha512());
          },
      },
      {
          "ADLER32",  // exported by zlib
          [](const MalignBuffer &s) -> std::string {
            uLong c = adler32(0, Z_NULL, 0);
            c = adler32(c, (const Bytef *)s.data(), s.size());
            return HexData((const char *)&c, sizeof(c));
          },
      },
      {
          "CRC32",  // exported by zlib.
          [](const MalignBuffer &s) -> std::string {
            uLong c = crc32(0, Z_NULL, 0);
            c = crc32(c, (const Bytef *)s.data(), s.size());
            return HexData((const char *)&c, sizeof(c));
          },
      },
      {
          "CRC32C",  // crc32 instruction on SSSE3
          [](const MalignBuffer &s) -> std::string {
            uint32_t c = crc32c(s.data(), s.size());
            return HexData((const char *)&c, sizeof(c));
          },
      },
      {
          "FarmHash64",  // Google farmhash
          [](const MalignBuffer &s) -> std::string {
            uint64_t c = util::Hash64(s.data(), s.size());
            return HexData((const char *)&c, sizeof(c));
          },
      },
  };

  // Array of compression routines.
  typedef struct {
    const char *name;
    int (*enc)(MalignBuffer *, const MalignBuffer &);
    int (*dec)(MalignBuffer *, const MalignBuffer &);
  } compressorItem;
  std::vector<compressorItem> compressors = {
      {
          "ZLIB",
          [](MalignBuffer *o, const MalignBuffer &s) {
            uLongf olen = compressBound(s.size());
            o->resize(olen);
            int err = compress2((Bytef *)o->data(), &olen, (Bytef *)s.data(),
                                s.size(), Z_BEST_SPEED);
            if (err != Z_OK) {
              LOG(DEBUG) << "zlib compression failed: " << err
                         << " srclen: " << s.size()
                         << " destlen: " << o->size();
              return err;
            }
            o->resize(olen);
            return 0;
          },
          [](MalignBuffer *o, const MalignBuffer &s) {
            uLongf olen = o->size();
            int err = uncompress((Bytef *)o->data(), &olen, (Bytef *)s.data(),
                                 s.size());
            if (err != Z_OK) {
              LOG(DEBUG) << "zlib decompression failed: " << err
                         << " srclen: " << s.size()
                         << " destlen: " << o->size();
              return err;
            }
            o->resize(olen);
            return 0;
          },
      },
  };

  // Choose generator and compressor uniformly.
  std::uniform_int_distribution<int> gen_dist(
      0, do_provenance ? 0 : kGenerators.size() - 1);
  auto Gen = std::bind(gen_dist, rndeng_);
  std::uniform_int_distribution<int> comp_dist(0, compressors.size() - 1);
  auto Comp = std::bind(comp_dist, rndeng_);

  // Run one randomly-chosen hash routine each round.
  size_t hash_choice;
  std::string hash_value;

  EVP_CIPHER_CTX *cipher_ctx;
  cipher_ctx = EVP_CIPHER_CTX_new();

  // Creates FVT controller if we can do so.
  if (do_fvt) {
    fvt_controller_ = FVTController::Create(tid_);
    fvt_controller_->SetCurrentFreqLimitMhz(fvt_controller_->limit_mHz());
    fvt_controller_->ControlFastStringOps(do_fast_string_ops);
    LOG(INFO) << "Tid: " << tid_
              << " Enables: " << fvt_controller_->InterestingEnables();
  }

  // MalignBuffers are allocated once if !do_madvise. Otherwise they are
  // reallocated each iteration of the main loop, creating much more memory
  // allocator work, which may itself exhibit, and suffer from, CPU defects.
  std::unique_ptr<BufferSet> b;

  uint64_t expected_slot_count = 0;

  Avx avx;

  while (!exiting) {
    if (std::thread::hardware_concurrency() > 1) {
      if (!SetAffinity(tid_)) {
        LOG(WARN) << "Couldnt run on " << tid_ << " sleeping a bit";
        sleep(30);
        continue;
      }
    }
    round_++;
    if (!b) {
      b.reset(new BufferSet);
    }

    if (do_noise) {
      NoiseScheduler::BlockUntilOn();
    }

    const int turbo_mhz = ScheduledMHz();  // 0 if no FVT.
    if (fvt_controller_ != nullptr) {
      fvt_controller_->SetCurrentFreqLimitMhz(turbo_mhz);
      fvt_controller_->MonitorFrequency();
    }

    auto Turbo = [&turbo_mhz](){
      return Json("turbo", turbo_mhz);
    };

    auto Tid = [this](int tid) {
      return "{ " + Json("tid", tid) + (do_fvt ? ", " + FVT() : "") + " }";
    };

    auto Writer = [this, Tid](){
      return "\"writer\": " + Tid(tid_);
    };

    LOG_EVERY_N_SECS(INFO, 30) << Jstat(
        Json("elapsed_s", static_cast<uint64_t>(TimeInSeconds() - t0)) + ", " +
        Json("failures", errorCount.load()) + ", " +
        Json("successes", successCount.load()) + ", " + Writer() +
        (fvt_controller_ != nullptr
             ? ", " + Json("meanFreq", fvt_controller_->GetMeanFreqMhz()) +
                   ", " + Json("maxFreq", fvt_controller_->max_mHz())
             : ""));

    if (do_avx_heavy) {
      const std::string e = avx.MaybeGoHot();
      if (!e.empty()) {
        LOG(ERROR) << Jfail(e, Writer() + ", " + Turbo());
        errorCount++;
      }
    }

#ifdef USE_BORINGSSL
    if (do_ssl_self_check && BORINGSSL_self_test() == 0) {
      LOG(ERROR) << Jfail("BORINGSSL_self_test", Writer() + ", " + Turbo());
      errorCount++;
      continue;
    }
#endif

    const bool madvise =
        do_madvise && std::uniform_int_distribution<int>(0, 1)(rndeng_);

    const size_t bufsize =
        std::uniform_int_distribution<size_t>(kBufMin, kBufMax)(rndeng_);
    auto &gen = kGenerators[Gen()];
    auto &comp = compressors[Comp()];

    const MalignBuffer::PunchedHole hole = PunchedHole(bufsize);

    const MalignBuffer::CopyMethod copy_method = CopyMethod();

    const bool use_repstos =
        do_repstosb && std::uniform_int_distribution<int>(0, 1)(rndeng_);

    auto BlockSummary = [&]() {
      std::stringstream block_summary;
      block_summary
        << Json("pattern", gen.name) << ", "
        << Json("copy", MalignBuffer::ToString(copy_method)) << ", "
        << Json("memset", use_repstos ? "rep;sto" : "memset") << ", "
        << JsonBool("madvise", madvise) << ", "
        << Json("size", bufsize) << ", "
        << Json("pid", pid_) << ", "
        << Json("round", round_) << ", "
        << hole.ToString();
      return block_summary.str();
    };

    auto WriterInfo = [&](){
      return Writer() + ", " + Turbo() + ", " + BlockSummary();
    };

    if (round_ > 1) {
      uint64_t slots_read = 0;
      uint64_t errs_this_round = 0;
      const uint64_t kErrLimit = 20;
      for (size_t k = 0; k < Silkscreen::kSize; k++) {
        const std::string err = silkscreen_->CheckMySlot(tid_, round_ - 1, k);
        if (!err.empty()) {
          slots_read++;
          if (err != "=") {
            errs_this_round++;
            if (errs_this_round <= kErrLimit) {
              errorCount++;
              LOG(ERROR) << Jfail("Silkscreen", JsonRecord("syndrome", err) +
                                                    ", " + WriterInfo());
            } else {
              // When Silkscreen fails, it often fails, on several bad machines,
              // in a surprising way: all slots owned by reading tid are
              // are corrupt, in a way that suggests the previous round's
              // writes never happened. Weird, and deserves some study, but
              // meanwhile the log spew is suppressed.
            }
          }
        }
      }
      if (errs_this_round > kErrLimit) {
        LOG(ERROR) << Jfail(
            "Silkscreen",
            JsonRecord("syndrome", Json("many_errors", errs_this_round) + ", " +
                                       Json("slots_read", slots_read)) +
                ", " + WriterInfo());
        errorCount++;
      }
      if (expected_slot_count != slots_read) {
        LOG(ERROR) << Jfail("Silkscreen",
                            Json("read", slots_read) + ", " +
                                Json("expected", expected_slot_count) + ", " +
                                WriterInfo());
        errorCount++;
      }
    }
    const uint64_t slots_written = silkscreen_->WriteMySlots(tid_, round_);
    if (!expected_slot_count) {
      expected_slot_count = slots_written;
    }
    if (expected_slot_count != slots_written) {
      LOG(ERROR) << Jfail("Silkscreen",
                          Json("written", slots_written) + ", " +
                              Json("expected", expected_slot_count) + ", " +
                              WriterInfo());
      errorCount++;
    }

    if (do_avx_heavy) {
      // If we tried to do AVX heavy stuff. Try to run AVX heavy again to try
      // to spike current.
      const std::string e = avx.BurnIfAvxHeavy();
      if (!e.empty()) {
        LOG(ERROR) << Jfail(e, Writer() + ", " + Turbo());
        errorCount++;
      }
    }

    const auto buffer_seed = rndeng_();
    if (!b->original) b->Alloc(&b->original);
    b->original->Initialize(Alignment(), bufsize);
    const FloatingPointResults f =
        GenerateData(gen, hole, buffer_seed,
                     copy_method, use_repstos, b->original.get());
    MaybeFlush(*b->original);

    MalignBuffer* head = b->original.get();

    if (do_hashes) {
      hash_choice =
          std::uniform_int_distribution<size_t>(0, hashers.size() - 1)(rndeng_);
      hash_value = hashers[hash_choice].func(*head);
    }

    if (do_compress) {
      // Run our randomly chosen compressor.
      if (!b->compressed) b->Alloc(&b->compressed);
      b->compressed->Initialize(Alignment(), bufsize);
      MaybeFlush(*b->compressed);

      const int err = comp.enc(b->compressed.get(), *head);
      LOG(DEBUG) << WriterInfo()
                 << " original->size(): " << head->size()
                 << ", compressed.size(): " << b->compressed->size() << ".";
      if (err) {
        LOG(ERROR) << Jfail("Compression",
                            Json("syndrome", err) + ", " + WriterInfo());
        errorCount++;
        continue;
      }
      MaybeFlush(*b->compressed);
      head = b->compressed.get();
      LOG(DEBUG) << WriterInfo() << "compress done.";
      if (exiting) break;
    }

    const unsigned char key[33] = "0123456789abcdef0123456789abcdef";
    const std::string ivec(b->original->data(), kBufMin);
    unsigned char gmac[16];

    const MalignBuffer* const unencrypted = head;
    if (do_encrypt) {
      // Encrypt.
      if (!b->encrypted) b->Alloc(&b->encrypted);
      b->encrypted->Initialize(Alignment(), head->size());
      MaybeFlush(*b->encrypted);
      int enc_len = 0, enc_unused_len = 0;
      EVP_CipherInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, key,
                        (unsigned char *)ivec.data(), 1);

      if (madvise) MadviseDontNeed(*b->encrypted);
      if (EVP_CipherUpdate(
              cipher_ctx, (unsigned char *)b->encrypted->data(), &enc_len,
              (unsigned char *)head->data(), head->size()) != 1) {
        LOG(ERROR) << Jfail("EVP_CipherUpdate", WriterInfo());
        errorCount++;
        EVP_CIPHER_CTX_cleanup(cipher_ctx);
        continue;
      }
      if (EVP_CipherFinal_ex(cipher_ctx, nullptr, &enc_unused_len) != 1) {
        LOG(ERROR) << Jfail("encrypt_EVP_CipherFinal_ex", WriterInfo());
        errorCount++;
        EVP_CIPHER_CTX_cleanup(cipher_ctx);
        continue;
      }
      enc_len += enc_unused_len;
      if (enc_len != (int)b->encrypted->size()) {
        std::stringstream ss;
        ss << "enc_length: " << enc_len << " vs: " << b->encrypted->size();
        LOG(ERROR) << Jfail("encrypt_length_mismatch",
                            Json("syndrome", ss.str()) + ", " + WriterInfo());
        errorCount++;
        EVP_CIPHER_CTX_cleanup(cipher_ctx);
        continue;
      }
      if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, sizeof(gmac),
                              gmac) != 1) {
        LOG(ERROR) << Jfail("EVP_CTRL_GCM_GET_TAG", WriterInfo());
        errorCount++;
        EVP_CIPHER_CTX_cleanup(cipher_ctx);
        continue;
      }
      EVP_CIPHER_CTX_cleanup(cipher_ctx);
      MaybeFlush(*b->encrypted);
      head = b->encrypted.get();
      LOG(DEBUG) << "Encrypt done " << WriterInfo();
      if (exiting) break;
    }

    // Make a copy.
    if (!b->copied) b->Alloc(&b->copied);
    b->copied->Initialize(Alignment(), head->size());
    MaybeFlush(*b->copied);
    if (madvise) MadviseDontNeed(*b->copied);
    std::string syndrome = b->copied->CopyFrom(*head, copy_method);

    if (!syndrome.empty()) {
      LOG(ERROR) << Jfail(
          "writer-detected-copy",
          JsonRecord("syndrome", syndrome) + ", " + WriterInfo());
      errorCount++;
      continue;
    }
    MaybeFlush(*b->copied);

    // Switch to an alternate CPU.

    int newcpu = tid_;
    if (do_hop && std::thread::hardware_concurrency() > 1) {
      std::vector<int> cpus;
      for (int i : tid_list_) {
        if (i == tid_) continue;
        cpus.push_back(i);
      }
      if (!cpus.empty()) {
        int cpuoff =
            std::uniform_int_distribution<int>(0, cpus.size() - 1)(rndeng_);
        newcpu = cpus[cpuoff];
        cpus.erase(cpus.begin() + cpuoff);
        if (!SetAffinity(newcpu)) {
          // Tough luck, can't run on chosen CPU.
          // Validate on same cpu we were on.
          newcpu = tid_;
        }
      }
    }

    auto Reader = [&Tid, &newcpu](){
      return "\"reader\": " + Tid(newcpu);
    };
    auto WriterReaderInfo = [&](){
      return
          Writer() + ", " + Reader() + ", " + Turbo() + ", " + BlockSummary();
    };

    // Re-verify buffer copy
    syndrome = b->copied->Syndrome(*head);
    if (!syndrome.empty()) {
      LOG(ERROR) << Jfail(
          "copy", JsonRecord("syndrome", syndrome) + ", " + WriterInfo());
      errorCount++;
      continue;
    }

    MaybeFlush(*b->copied);
    head = b->copied.get();

    if (do_encrypt) {
      // Decrypt.
      if (!b->decrypted) b->Alloc(&b->decrypted);
      b->decrypted->Initialize(Alignment(), head->size());
      MaybeFlush(*b->decrypted);

      int dec_len = 0, dec_extra_len = 0;
      EVP_CipherInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, key,
                        (unsigned char *)ivec.data(), 0);
      if (madvise) MadviseDontNeed(*b->decrypted);
      if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, sizeof(gmac),
                              gmac) != 1) {
        LOG(ERROR) << Jfail("EVP_CTRL_GCM_SET_TAG", WriterReaderInfo());
        errorCount++;
        EVP_CIPHER_CTX_cleanup(cipher_ctx);
        continue;
      }
      if (EVP_CipherUpdate(
              cipher_ctx, (unsigned char *)b->decrypted->data(), &dec_len,
              (unsigned char *)head->data(), head->size()) != 1) {
        LOG(ERROR) << Jfail("decryption", WriterReaderInfo());
        errorCount++;
        EVP_CIPHER_CTX_cleanup(cipher_ctx);
        continue;
      }
      if (EVP_CipherFinal_ex(
              cipher_ctx, (unsigned char *)(b->decrypted->data() + dec_len),
              &dec_extra_len) != 1) {
        LOG(ERROR) << Jfail("decrypt_EVP_CipherFinal_ex", WriterReaderInfo());
        errorCount++;
        EVP_CIPHER_CTX_cleanup(cipher_ctx);
        continue;
      }
      dec_len += dec_extra_len;
      EVP_CIPHER_CTX_cleanup(cipher_ctx);
      if (dec_len != (int)b->decrypted->size()) {
        std::stringstream ss;
        ss << "dec_length: " << dec_len << " vs: " << b->decrypted->size();
        LOG(ERROR) << Jfail("decrypt_length_mismatch",
                            Json("syndrome", ss.str()) + ", " +
                            WriterReaderInfo());
        errorCount++;
        continue;
      }
      MaybeFlush(*b->decrypted);
      head = b->decrypted.get();
      syndrome = unencrypted->Syndrome(*head);
      if (!syndrome.empty()) {
        LOG(ERROR) << Jfail(
            "decryption_mismatch",
            JsonRecord("syndrome", syndrome) + ", " + WriterReaderInfo());
        errorCount++;
        continue;
      }
      LOG(DEBUG) << WriterReaderInfo() << " decrypt done";
      if (exiting) break;
    }

    if (do_compress) {
      // Run decompressor.
      if (!b->decompressed) b->Alloc(&b->decompressed);
      b->decompressed->Initialize(Alignment(), bufsize);
      MaybeFlush(*b->decompressed);

      if (madvise) MadviseDontNeed(*b->decompressed);
      const int err = comp.dec(b->decompressed.get(), *head);
      if (err) {
        LOG(ERROR) << Jfail("uncompression",
                            Json("syndrome", err) + ", " + WriterReaderInfo());
        errorCount++;
        continue;
      }
      if (b->decompressed->size() != bufsize) {
        std::stringstream ss;
        ss << "dec_length: " << b->decompressed->size() << " vs: " << bufsize;
        LOG(ERROR) << Jfail(
            "decompressed_size",
            Json("syndrome", ss.str()) + ", " + WriterReaderInfo());
        errorCount++;
        continue;
      }
      MaybeFlush(*b->decompressed);
      head = b->decompressed.get();
      LOG(DEBUG) << WriterReaderInfo() << " uncompress done";
    }

    if (!b->re_made) b->Alloc(&b->re_made);
    b->re_made->Initialize(Alignment(), bufsize);
    const FloatingPointResults f_r =
        GenerateData(gen, hole, buffer_seed,
                     copy_method, use_repstos, b->re_made.get());
    syndrome = b->original->Syndrome(*b->re_made);

    if (!syndrome.empty()) {
      LOG(ERROR) << Jfail("re-make", JsonRecord("syndrome", syndrome) + ", " +
                                         WriterReaderInfo());
      errorCount++;
      continue;
    }

    if (f != f_r) {
      std::stringstream ss;
      ss << "Was: " << f.d << " Is: " << f_r.d;
      LOG(ERROR) << Jfail(
          "fp-double", Json("syndrome", ss.str()) + ", " + WriterReaderInfo());
      errorCount++;
      continue;
    }

    if (do_hashes) {
      // Re-run hash func.
      std::string hash = hashers[hash_choice].func(*head);
      if (hash_value != hash) {
        std::stringstream ss;
        ss << "hash was: " << hash_value << " is: " << hash;
        LOG(ERROR) << Jfail(
            "hash", Json("syndrome", ss.str()) + ", " + WriterReaderInfo());
        errorCount++;
        continue;
      }
      LOG(DEBUG) << WriterReaderInfo() << " rehash done";
    }

    // Release MalignBuffer memory allocations.
    if (do_madvise) b.reset(nullptr);

    successCount++;
  }
  EVP_CIPHER_CTX_free(cipher_ctx);
  LOG(INFO) << "tid " << tid_ << " exiting.";
}

static void UsageIf(bool v) {
  if (!v) return;
  LOG(ERROR) << "Usage cpu_check [-a] [-b] [-c] [-d] [-e] [-F] [-h]"
             << " [-m] [-nN] [-p] [-qNNN] [-r] [-x] [-X] [-s] [-Y] [-H] [-kXXX]"
             << " [-z] [-cn,n,...,n] [-fMinF[-MaxF]] [-tNNN] [-u]"
             << "\n  a: Do not misalign"
             << "\n  b: Do not run BoringSSL self check"
             << "\n  c: Explicit list of CPUs"
             << "\n  d: Do not rep stosb"
             << "\n  e: Do not encrypt"
             << "\n  f: Fixed specified turbo frequency (multiple of 100)"
             << "\n  g: Do not touch frequency, voltage and thermal controls"
             << "\n  F: Randomly flush caches (inverted option)"
             << "\n  h: Do not hash"
             << "\n  m: Do not madvise, do not malloc per iteration"
             << "\n  l: Do not provoke heavy AVX power fluctuations"
             << "\n  n: Generate noise"
             << "\n  N: Generate noise, invert -c"
             << "\n  p: Corrupt data provenance"
             << "\n  q: Quit if more than N errors"
             << "\n  r: Do not repmovsb"
             << "\n  t: Timeout in seconds"
             << "\n  x: Do not use AVX:256"
             << "\n  X: Do use AVX512"
             << "\n  s: Do not switch CPUs for verification"
             << "\n  u: Do not use fast string ops"
             << "\n  Y: Do frequency sweep"
             << "\n  H: Slam between low and high frequency"
             << "\n  k: Frequency step period (default 300)"
             << "\n  z: Do not compress/uncompress";
  exit(2);
}

int main(int argc, char **argv) {
  std::vector<int> tid_list;
  int64_t timeout = 0;

#ifdef IN_GOOGLE3
  // Initialize the symbolizer to get a human-readable stack trace.
  absl::InitializeSymbolizer(argv[0]);
  absl::FailureSignalHandlerOptions options;
  absl::InstallFailureSignalHandler(options);
#endif

  for (int i = 1; i < argc; i++) {
    const char *flag = argv[i];
    UsageIf(flag[0] != '-');
    for (flag++; *flag != 0; flag++) {
      switch (*flag) {
        case 'a':
          do_misalign = false;
          break;
        case 'b':
          do_ssl_self_check = false;
          break;
        case 'c':
          {
            std::string c = "";
            for (flag++; *flag != 0; flag++) {
              c += *flag;
            }
            std::stringstream s(c);
            int t;
            while (s >> t) {
              tid_list.push_back(t);
              if (s.peek() == ',') s.ignore();
            }
          }
          break;
        case 'd':
          do_repstosb = false;
          break;
        case 'e':
          do_encrypt = false;
          break;
        case 'f':
          {
            std::string c(++flag);
            flag += c.length();
            std::stringstream s(c);
            s >> fixed_min_frequency;
            fixed_max_frequency = fixed_min_frequency;
            if (s.get() == '-') {
              s >> fixed_max_frequency;
              do_freq_sweep = true;
            }
          }
          break;
        case 'F':
          do_flush = true;
          break;
        case 'g':
          do_fvt = false;
          break;
        case 'H':
          do_freq_hi_lo = true;
          break;
        case 'h':
          do_hashes = false;
          break;
        case 'l':
          do_avx_heavy = false;
          break;
        case 'm':
          do_madvise = false;
          break;
        case 'n':
          do_noise = true;
          break;
        case 'N':
          do_noise = true;
          do_invert_cores = true;
          do_encrypt = false;
          do_hashes = false;
          do_compress = false;
          do_madvise = false;
          do_hop = false;
          break;
        case 'p':
          do_provenance = true;
          do_encrypt = false;
          do_hashes = false;
          do_compress = false;
          break;
        case 'q':
          {
            std::string c(++flag);
            flag += c.length();
            std::stringstream s(c);
            s >> error_limit;
          }
          break;
        case 'r':
          do_repmovsb = false;
          break;
        case 's':
          do_hop = false;
          break;
        case 'u':
          do_fast_string_ops = false;
          break;
        case 'x':
          do_avx_256_memcpy = false;
          break;
        case 'X':
          do_avx_512_memcpy = true;
          break;
        case 'Y':
          do_freq_sweep = true;
          break;
        case 'k':
          {
            std::string c(++flag);
            flag += c.length();
            std::stringstream s(c);
            s >> seconds_per_freq;
          }
          break;
        case 't':
          {
            std::string c(++flag);
            flag += c.length();
            std::stringstream s(c);
            s >> timeout;
          }
          break;
        case 'z':
          do_compress = false;
          break;
        default:
          UsageIf(true);
      }
      if (*flag == 0) break;
    }
  }

  LOG(INFO) << "Starting " << argv[0] << " version " cpu_check_VERSION
            << (do_misalign ? "" : " No misalign ")
            << (do_repstosb ? "" : " No repstosb")
            << (!do_flush ? "" : " Cache-line flush ")
            << (do_encrypt ? "" : " No encryption ")
            << (do_hashes ? "" : " No hash ")
            << (do_madvise ? "" : " No madvise ")
            << (do_provenance ? " Provenance " : "")
            << (do_repmovsb ? "" : " No repmovsb ")
            << (do_sse_128_memcpy ? "" : " No SSE:128 ")
            << (do_avx_256_memcpy ? "" : " No AVX:256 ")
            << (do_avx_512_memcpy ? "" : " No AVX:512 ")
            << (do_avx_heavy ? " AVX_heavy " : "")
            << (do_compress ? "" : " No compression ")
            << (do_hop ? "" : " No thread_switch ")
            << (do_ssl_self_check ? "" : " No BoringSSL self check")
            << (!do_freq_sweep ? "" : " FrequencySweep ")
            << (!do_freq_hi_lo ? "" : " FreqHiLo ")
            << (do_noise ? " NOISE" : "")
            << (do_fast_string_ops ? "" : " No FastStringOps");

  std::vector<std::thread *> threads;
  std::vector<Worker *> workers;
  std::vector<std::string> words = ReadDict();
  if (words.empty()) {
    LOG(ERROR) << "No word list found.";
    exit(1);
  }
  int cpus = std::thread::hardware_concurrency();
  LOG(INFO) << "Detected hardware concurrency: " << cpus;

  if (do_invert_cores) {
    // Clumsily complement the tid_list in -N mode.
    std::vector<int> v;
    for (int i = 0; i < cpus; i++) {
      if (std::find(tid_list.begin(), tid_list.end(), i) == tid_list.end()) {
        v.push_back(i);
      }
    }
    tid_list = v;
  }

  if (tid_list.empty()) {
    for (int i = 0; i < cpus; i++) {
      tid_list.push_back(i);
    }
  } else {
    for (int t : tid_list) {
      LOG(INFO) << "Explicitly testing cpu: " << t;
    }
  }


  // Silkscreen instance shared by all threads.
  Silkscreen silkscreen(tid_list);

  for (int tid : tid_list) {
    workers.push_back(new Worker(getpid(), &words, tid_list, tid, &silkscreen));
    threads.push_back(new std::thread(&Worker::Run, workers.back()));
  }
  signal(SIGTERM, [](int) { exiting = true; });
  signal(SIGINT, [](int) { exiting = true; });

  struct timeval last_cpu = {0, 0};
  double last_time = t0;
  while (!exiting) {
    sleep(60);
    struct rusage ru;
    double secs = TimeInSeconds();
    if (timeout > 0 && secs >= t0 + timeout) {
      exiting = true;
    }
    double secondsPerError = (secs - t0) / errorCount.load();
    if (getrusage(RUSAGE_SELF, &ru) == -1) {
      LOG(ERROR) << "getrusage failed: " << strerror(errno);
    } else {
      float cpu = (((ru.ru_utime.tv_sec - last_cpu.tv_sec) * 1000000.0) +
                   (ru.ru_utime.tv_usec - last_cpu.tv_usec)) /
                  1000000.0;
      LOG(INFO) << "Errors: " << errorCount.load()
                << " Successes: " << successCount.load()
                << " CPU " << cpu / (secs - last_time) << " s/s"
                << " Seconds Per Error: " << secondsPerError;
      last_cpu = ru.ru_utime;
    }
    last_time = secs;
  }

  // shutting down.
  for (auto &t : threads) {
    t->join();
    delete t;
  }
  for (auto w : workers) {
    delete w;
  }
  LOG(ERROR) << errorCount.load() << " ERRORS, " << successCount.load()
             << " SUCCESSES.";
  LOG(INFO) << "Exiting.";
  exit(errorCount != 0);
}
