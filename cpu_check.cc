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

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <time.h>

#include <algorithm>
#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <functional>
#include <iostream>
#include <limits>
#include <list>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "config.h"
#include "absl/debugging/failure_signal_handler.h"
#include "absl/debugging/symbolize.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"

#include "avx.h"
#include "compressor.h"
#include "crypto.h"
#include "fvt_controller.h"
#include "hasher.h"
#include "log.h"
#include "malign_buffer.h"
#include "pattern_generator.h"
#include "silkscreen.h"
#include "stopper.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "utils.h"

#undef HAS_FEATURE_MEMORY_SANITIZER
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#define HAS_FEATURE_MEMORY_SANITIZER
#endif
#endif

using cpu_check::MalignBuffer;

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

std::atomic_uintmax_t errorCount(0);
std::atomic_uintmax_t successCount(0);
static constexpr uintmax_t kErrorLimit = 2000;

#if defined(__i386__) || defined(__x86_64__)
const bool is_x86 = true;
#else
const bool is_x86 = false;
#endif

#if defined(__i386__) || defined(__x86_64__)

static bool can_do_fvt() {
  return geteuid() == 0;  // need write access to MSRs.
}

#else

static bool can_do_fvt() { return false; }  // x86-only for now.

#endif

bool do_madvise = true;
bool do_repmovsb = is_x86;
bool do_sse_128_memcpy = is_x86;
bool do_avx_256_memcpy = Avx::can_do_avx();
bool do_avx_512_memcpy = Avx::can_do_avx512f();
bool do_avx_heavy = Avx::can_do_avx();
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

class Worker {
 public:
  // Does not take ownership of 'silkscreen' or 'stopper'.
  Worker(int pid, std::vector<int> tid_list, int tid,
         cpu_check::Silkscreen *silkscreen, Stopper *stopper)
      : pid_(pid),
        tid_(tid),
        tid_list_(tid_list),
        silkscreen_(silkscreen),
        stopper_(stopper),
        rndeng_(std::random_device()()) {}
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

  struct BufferSet {
    void Alloc(std::unique_ptr<MalignBuffer> *p) {
      if (!*p) {
        // Allocate buffer larger than kBufMax because compression can, in some
        // cases of random plain text, cause some expansion.
        p->reset(new MalignBuffer(2 * kBufMax + 1024));
      }
    }

    // The buffers holding successive data transformations. Some transformations
    // are optional, so some buffers may be unused.
    std::unique_ptr<MalignBuffer> original;
    std::unique_ptr<MalignBuffer> compressed;
    std::unique_ptr<MalignBuffer> encrypted;
    std::unique_ptr<MalignBuffer> copied;
    std::unique_ptr<MalignBuffer> decrypted;
    std::unique_ptr<MalignBuffer> decompressed;
    std::unique_ptr<MalignBuffer> re_made;

    // The plain-text buffer that was encrypted, if encryption was performed.
    MalignBuffer *pre_encrypted = nullptr;
    // The result of the series of transformations up to, but not including,
    // the final copy.
    MalignBuffer *pre_copied = nullptr;
  };

  // Computation parameters.
  struct Choices {
    bool madvise;
    bool use_repstos;
    bool exercise_floating_point;
    MalignBuffer::CopyMethod copy_method;
    cpu_check::PatternGenerator const *pattern_generator = nullptr;
    cpu_check::Hasher const *hasher = nullptr;
    size_t buf_size;
    MalignBuffer::PunchedHole hole;
    std::string summary;
  };

  // Various checksums produced in the course of the series of data
  // transformations.
  struct Checksums {
    std::string hash_value;
    cpu_check::FloatingPointResults floating_point_results;
    cpu_check::Crypto::CryptoPurse crypto_purse;
  };

  uint64_t Seed() { return std::uniform_int_distribution<uint64_t>()(rndeng_); }
  size_t Alignment();
  void MaybeFlush(const MalignBuffer &s);

  // Attempts to schedules CPU frequency using the Worker's.
  // FVTController object.  Returns the scheduled frequency or
  // 0 if there is no FVTController available.
  int ScheduledMHz() const;
  MalignBuffer::CopyMethod CopyMethod();
  std::string FVT() const;

  // Returns 'Choices' that seed the data transformations.
  Choices MakeChoices(BufferSet *b);

  // Performs a series of data transformations.
  // Returns an error status if computation is detected to be corrupt.
  absl::StatusOr<Checksums> DoComputations(const std::string &writer_ident,
                                           const Choices &choices,
                                           BufferSet *b);

  // Inverts DoComputations, checking correctness of results.
  // Returns an error status if corruption is detected.
  absl::Status CheckComputations(const std::string &writer_reader_ident,
                                 const Choices &choices,
                                 const Checksums &checksums, BufferSet *b);

  // Emits a failure record.
  // TODO: bump error count here, and maybe log, instead of at every
  // call site.
  std::string Jfail(absl::string_view err, const absl::string_view v) {
    if (errorCount > error_limit) {
      stopper_->Stop();
      LOG(INFO) << "I am quitting after " << errorCount << " errors";
    }
    return "{ " + JsonRecord("fail", absl::StrCat(Json("err", err), ", ", v)) +
           ", " + JTag() + " }";
  }

  absl::Status ReturnError(absl::string_view err, const absl::string_view v) {
    return absl::Status(absl::StatusCode::kInternal, Jfail(err, v));
  }

  std::string Suspect(int tid) {
    return absl::StrFormat("Suspect LPU: %d", tid);
  }

  // Returns two tids to be used for checking computation. If 'do_hop',
  // CheckerTids avoids duplication and avoids 'tid_' if it can.
  std::vector<int> CheckerTids();

  const uint64_t pid_;
  const int tid_;
  const std::vector<int> tid_list_;
  cpu_check::Silkscreen *const silkscreen_;
  Stopper *const stopper_;

  // We don't really need "good" random numbers.
  // std::mt19937_64 rndeng_;
  std::knuth_b rndeng_;
  uint64_t round_ = 0;
  Avx avx_;
  cpu_check::PatternGenerators pattern_generators_;
  cpu_check::Hashers hashers_;
  cpu_check::Zlib zlib_;

  std::unique_ptr<FVTController> fvt_controller_;
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
  if (!do_freq_sweep && !do_freq_hi_lo && !fixed_min_frequency &&
      !fixed_max_frequency) {
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

void Worker::MaybeFlush(const MalignBuffer &s) {
  // Half the time, tell the OS to release the destination buffer.
  if (do_flush && std::uniform_int_distribution<int>(0, 1)(rndeng_)) {
    s.RandomFlush(&rndeng_);
  }
}

size_t Worker::Alignment() {
  return do_misalign ? MalignBuffer::RandomAlignment(Seed()) : 0;
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

Worker::Choices Worker::MakeChoices(BufferSet *b) {
  Choices c;
  c.madvise = do_madvise && std::uniform_int_distribution<int>(0, 1)(rndeng_);
  c.copy_method = CopyMethod();

  c.use_repstos =
      do_repstosb && std::uniform_int_distribution<int>(0, 1)(rndeng_);

  // Exercise floating point (in pattern generators) relatively rarely because
  // it's expensive and it doesn't catch a lot of machines.
  c.exercise_floating_point =
      std::uniform_int_distribution<int>(0, 20)(rndeng_) == 0;

  c.pattern_generator = &pattern_generators_.RandomGenerator(round_);
  c.hasher = &hashers_.RandomHasher(round_);

  c.buf_size = std::uniform_int_distribution<size_t>(kBufMin, kBufMax)(rndeng_);
  if (!b->original) b->Alloc(&b->original);
  b->original->Initialize(Alignment(), c.buf_size);
  c.hole = b->original->RandomPunchedHole(Seed());

  c.summary = absl::StrCat(
      Json("pattern", c.pattern_generator->Name()), ", ",
      Json("hash", c.hasher->Name()), ", ",
      Json("copy", MalignBuffer::ToString(c.copy_method)), ", ",
      Json("memset", c.use_repstos ? "rep;sto" : "memset"), ", ",
      JsonBool("madvise", c.madvise), ", ",
      Json("size", static_cast<uint64_t>(c.buf_size)), ", ", Json("pid", pid_),
      ", ", Json("round", round_), ", ", c.hole.ToString());

  return c;
}

absl::StatusOr<Worker::Checksums> Worker::DoComputations(
    const std::string &writer_ident, const Choices &choices, BufferSet *b) {
  Checksums checksums;
  if (do_avx_heavy) {
    const std::string e = avx_.MaybeGoHot();
    if (!e.empty()) {
      return ReturnError(e, writer_ident);
    }
  }

  if (do_ssl_self_check) {
    auto s = cpu_check::Crypto::SelfTest();
    if (!s.ok()) {
      return ReturnError(s.message(), writer_ident);
    }
  }

  auto s = silkscreen_->WriteMySlots(tid_, round_);
  if (!s.ok()) {
    return ReturnError("Silkscreen",
                       absl::StrCat(s.message(), ", ", writer_ident));
  }

  if (do_avx_heavy) {
    // If we tried to do AVX heavy stuff. Try to run AVX heavy again to try
    // to spike current.
    const std::string e = avx_.BurnIfAvxHeavy();
    if (!e.empty()) {
      return ReturnError(e, writer_ident);
    }
  }

  checksums.floating_point_results = pattern_generators_.Generate(
      *choices.pattern_generator, choices.hole, round_, choices.copy_method,
      choices.use_repstos, choices.exercise_floating_point, b->original.get());
  MaybeFlush(*b->original);

  MalignBuffer *head = b->original.get();

  if (do_hashes) {
    checksums.hash_value = choices.hasher->Hash(*head);
  }

  if (do_compress) {
    // Run our randomly chosen compressor.
    if (!b->compressed) b->Alloc(&b->compressed);
    b->compressed->Initialize(Alignment(), choices.buf_size);
    MaybeFlush(*b->compressed);

    const auto s = zlib_.Compress(*head, b->compressed.get());
    if (!s.ok()) {
      return ReturnError(
          "Compression",
          absl::StrCat(Json("syndrome", s.message()), ", ", writer_ident));
    }
    MaybeFlush(*b->compressed);
    head = b->compressed.get();
  }

  b->pre_encrypted = head;
  if (do_encrypt) {
    // Encrypt.
    if (!b->encrypted) b->Alloc(&b->encrypted);
    b->encrypted->Initialize(Alignment(), head->size());
    MaybeFlush(*b->encrypted);
    if (choices.madvise) b->encrypted->MadviseDontNeed();

    auto s = cpu_check::Crypto::Encrypt(*head, b->encrypted.get(),
                                        &checksums.crypto_purse);
    if (!s.ok()) {
      return ReturnError(s.message(), writer_ident);
    }

    MaybeFlush(*b->encrypted);
    head = b->encrypted.get();
  }

  // Make a copy.
  b->pre_copied = head;
  if (!b->copied) b->Alloc(&b->copied);
  b->copied->Initialize(Alignment(), head->size());
  MaybeFlush(*b->copied);
  if (choices.madvise) b->copied->MadviseDontNeed();
  std::string syndrome = b->copied->CopyFrom(*head, choices.copy_method);

  if (!syndrome.empty()) {
    return ReturnError(
        "writer-detected-copy",
        absl::StrCat(JsonRecord("syndrome", syndrome), ", ", writer_ident));
  }
  MaybeFlush(*b->copied);
  return checksums;
}

absl::Status Worker::CheckComputations(const std::string &writer_reader_ident,
                                       const Choices &choices,
                                       const Checksums &checksums,
                                       BufferSet *b) {
  // Re-verify buffer copy
  std::string syndrome = b->copied->Syndrome(*b->pre_copied);
  if (!syndrome.empty()) {
    return ReturnError("copy", absl::StrCat(JsonRecord("syndrome", syndrome),
                                            ", ", writer_reader_ident));
  }

  MaybeFlush(*b->copied);
  MalignBuffer *head = b->copied.get();

  if (do_encrypt) {
    // Decrypt.
    if (!b->decrypted) b->Alloc(&b->decrypted);
    b->decrypted->Initialize(Alignment(), head->size());
    MaybeFlush(*b->decrypted);

    if (choices.madvise) b->decrypted->MadviseDontNeed();
    auto s = cpu_check::Crypto::Decrypt(*head, checksums.crypto_purse,
                                        b->decrypted.get());
    if (!s.ok()) {
      return ReturnError(s.message(), writer_reader_ident);
    }

    MaybeFlush(*b->decrypted);
    head = b->decrypted.get();
    syndrome = b->pre_encrypted->Syndrome(*head);
    if (!syndrome.empty()) {
      return ReturnError("decryption_mismatch",
                         absl::StrCat(JsonRecord("syndrome", syndrome), ", ",
                                      writer_reader_ident));
    }
  }

  if (do_compress) {
    // Run decompressor.
    if (!b->decompressed) b->Alloc(&b->decompressed);
    b->decompressed->Initialize(Alignment(), choices.buf_size);
    MaybeFlush(*b->decompressed);

    if (choices.madvise) b->decompressed->MadviseDontNeed();
    const auto s = zlib_.Decompress(*head, b->decompressed.get());
    if (!s.ok()) {
      return ReturnError("uncompression",
                         absl::StrCat(Json("syndrome", s.message()), ", ",
                                      writer_reader_ident));
    }
    if (b->decompressed->size() != choices.buf_size) {
      std::stringstream ss;
      ss << "dec_length: " << b->decompressed->size()
         << " vs: " << choices.buf_size;
      return ReturnError(
          "decompressed_size",
          absl::StrCat(Json("syndrome", ss.str()), ", ", writer_reader_ident));
    }
    MaybeFlush(*b->decompressed);
    head = b->decompressed.get();
  }

  if (!b->re_made) b->Alloc(&b->re_made);
  b->re_made->Initialize(Alignment(), choices.buf_size);
  const cpu_check::FloatingPointResults f_r = pattern_generators_.Generate(
      *choices.pattern_generator, choices.hole, round_, choices.copy_method,
      choices.use_repstos, choices.exercise_floating_point, b->re_made.get());
  syndrome = b->original->Syndrome(*b->re_made);

  if (!syndrome.empty()) {
    return ReturnError("re-make", absl::StrCat(JsonRecord("syndrome", syndrome),
                                               ", ", writer_reader_ident));
  }

  if (checksums.floating_point_results != f_r) {
    std::stringstream ss;
    ss << "Was: " << checksums.floating_point_results.d << " Is: " << f_r.d;
    return ReturnError("fp-double", absl::StrCat(Json("syndrome", ss.str()),
                                                 ", ", writer_reader_ident));
  }

  if (do_hashes) {
    // Re-run hash func.
    const std::string hash = choices.hasher->Hash(*head);
    if (checksums.hash_value != hash) {
      std::stringstream ss;
      ss << "hash was: " << checksums.hash_value << " is: " << hash;
      return ReturnError("hash", absl::StrCat(Json("syndrome", ss.str()), ", ",
                                              writer_reader_ident));
    }
  }

  auto s = silkscreen_->CheckMySlots(tid_, round_);
  if (!s.ok()) {
    return ReturnError("Silkscreen",
                       absl::StrCat(s.message(), ", ", writer_reader_ident));
  }
  return absl::OkStatus();
}

std::vector<int> Worker::CheckerTids() {
  constexpr int kCheckers = 2;
  if (!do_hop) {
    return std::vector<int>(kCheckers, tid_);
  }
  std::vector<int> candidates;
  for (int i : tid_list_) {
    if (i != tid_) candidates.push_back(i);
  }
  std::shuffle(candidates.begin(), candidates.end(), rndeng_);
  std::vector<int> v;
  v.reserve(kCheckers);
  for (int i = 0; i < kCheckers; i++) {
    v.push_back(i < candidates.size() ? candidates[i] : tid_);
  }
  return v;
}

void Worker::Run() {
  const double t0 = TimeInSeconds();

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
  std::unique_ptr<BufferSet> b = std::make_unique<BufferSet>();

  while (!stopper_->Expired()) {
    if (std::thread::hardware_concurrency() > 1) {
      if (!SetAffinity(tid_)) {
        LOG(WARN) << "Couldnt run on " << tid_ << " sleeping a bit";
        stopper_->BoundedSleep(30);
        continue;
      }
    }
    round_++;

    if (do_madvise) {
      // Release and reallocate MalignBuffers.
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

    auto Turbo = [&turbo_mhz]() { return Json("turbo", turbo_mhz); };

    auto Tid = [this](int tid) {
      return "{ " + Json("tid", tid) + (do_fvt ? ", " + FVT() : "") + " }";
    };

    auto Writer = [this, Tid]() { return "\"writer\": " + Tid(tid_); };

    LOG_EVERY_N_SECS(INFO, 30) << Jstat(
        Json("elapsed_s", static_cast<uint64_t>(TimeInSeconds() - t0)) + ", " +
        Json("failures", static_cast<uint64_t>(errorCount.load())) + ", " +
        Json("successes", static_cast<uint64_t>(successCount.load())) + ", " + Writer() +
        (fvt_controller_ != nullptr
             ? ", " + Json("meanFreq", fvt_controller_->GetMeanFreqMhz()) +
                   ", " + Json("maxFreq", fvt_controller_->max_mHz())
             : ""));

    const Choices choices = MakeChoices(b.get());
    const std::string writer_ident =
        absl::StrCat(Writer(), ", ", Turbo(), ", ", choices.summary);

    auto s = DoComputations(writer_ident, choices, b.get());
    if (!s.ok()) {
      LOG(ERROR) << s.status().message();
      LOG(ERROR) << Suspect(tid_);
      errorCount++;
      continue;
    }
    const Checksums checksums = s.value();

    // Check the computation. Twice if the first check fails.
    const std::vector<int> checker_tids = CheckerTids();
    std::vector<int> failing_tids;
    for (int c : checker_tids) {
      int newcpu = c;
      if (!SetAffinity(newcpu)) {
        // Tough luck, can't run on chosen CPU.
        // Validate on same cpu we were on.
        newcpu = tid_;
      }

      auto Reader = [&Tid, &newcpu]() { return "\"reader\": " + Tid(newcpu); };
      const std::string writer_reader_ident = absl::StrCat(
          Writer(), ", ", Reader(), ", ", Turbo(), ", ", choices.summary);

      const absl::Status check_status =
          CheckComputations(writer_reader_ident, choices, checksums, b.get());
      if (check_status.ok()) {
        // It suffices to check just once if the checker confirms that
        // computation was correct.
        break;
      } else {
        failing_tids.push_back(newcpu);
        LOG(ERROR) << check_status.message();
        errorCount++;
      }
    }
    if (!failing_tids.empty()) {
      // Guess which LPU is the most likely culprit. The guess is pretty good
      // for low failure rate LPUs that haven't corrupted crucial common state.
      if (failing_tids.size() > 1) {
        // Both checkers think the computation was wrong, likely culprit is the
        // writer.
        LOG(ERROR) << Suspect(tid_);
      } else {
        // Only one checker thinks the computation was wrong. Likely he's the
        // culprit since the other checker and the writer agree.
        LOG(ERROR) << Suspect(failing_tids[0]);
      }
      continue;
    }
    successCount++;
  }
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

  // Initialize the symbolizer to get a human-readable stack trace.
  absl::InitializeSymbolizer(argv[0]);
  absl::FailureSignalHandlerOptions options;
  absl::InstallFailureSignalHandler(options);

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
        case 'c': {
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
        } break;
        case 'd':
          do_repstosb = false;
          break;
        case 'e':
          do_encrypt = false;
          break;
        case 'f': {
          std::string c(++flag);
          flag += c.length();
          std::stringstream s(c);
          s >> fixed_min_frequency;
          fixed_max_frequency = fixed_min_frequency;
          if (s.get() == '-') {
            s >> fixed_max_frequency;
            do_freq_sweep = true;
          }
        } break;
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
        case 'q': {
          std::string c(++flag);
          flag += c.length();
          std::stringstream s(c);
          s >> error_limit;
        } break;
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
        case 'k': {
          std::string c(++flag);
          flag += c.length();
          std::stringstream s(c);
          s >> seconds_per_freq;
        } break;
        case 't': {
          std::string c(++flag);
          flag += c.length();
          std::stringstream s(c);
          s >> timeout;
        } break;
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

  const double t0 = TimeInSeconds();

  // Silkscreen instance shared by all threads.
  cpu_check::Silkscreen silkscreen(tid_list);

  static Stopper stopper(timeout);  // Shared by all threads

  for (int tid : tid_list) {
    workers.push_back(
        new Worker(getpid(), tid_list, tid, &silkscreen, &stopper));
    threads.push_back(new std::thread(&Worker::Run, workers.back()));
  }

  signal(SIGTERM, [](int) { stopper.Stop(); });
  signal(SIGINT, [](int) { stopper.Stop(); });

  struct timeval last_cpu = {0, 0};
  double last_time = t0;
  while (!stopper.Expired()) {
    stopper.BoundedSleep(60);
    struct rusage ru;
    double secs = TimeInSeconds();
    double secondsPerError = (secs - t0) / errorCount.load();
    if (getrusage(RUSAGE_SELF, &ru) == -1) {
      LOG(ERROR) << "getrusage failed: " << strerror(errno);
    } else {
      float cpu = (((ru.ru_utime.tv_sec - last_cpu.tv_sec) * 1000000.0) +
                   (ru.ru_utime.tv_usec - last_cpu.tv_usec)) /
                  1000000.0;
      LOG(INFO) << "Errors: " << errorCount.load()
                << " Successes: " << successCount.load() << " CPU "
                << cpu / (secs - last_time) << " s/s"
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
