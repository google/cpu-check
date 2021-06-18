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

#include "pattern_generator.h"

#include <unistd.h>

#include <cmath>
#include <cstdint>
#include <fstream>

#include "log.h"

namespace cpu_check {
namespace {

// So-called Logistic Map with parameter 4.0.
// Floating point approximation aside, if v is in the closed unit interval than
// ChaoticF1(v) is in the closed unit interval.
template <typename T>
T ChaoticF1(T v) {
  return 4.0 * v * (1.0 - v);
}

// Reciprocal-like function valid over closed unit interval.
template <typename T>
T Recip(T v) {
  return 1.0 / (v + 0.1);
}

// Inverse of Recip for v in closed unit interval.
template <typename T>
T Unrecip(T v) {
  return (1.0 / v) - 0.1;
}

template <typename T>
T ReciprocatedChaos(T v) {
  return Recip(ChaoticF1(Unrecip(v)));
}

std::vector<std::string> ReadDict() {
  // Dictionary search paths
  static const char* dicts[] = {
      "/usr/share/dict/words",
      "words",
  };
  std::vector<std::string> words;
  std::ifstream f;

  for (const auto& d : dicts) {
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
            [](const std::string& a, const std::string& b) {
              return a.size() < b.size();
            });
  return words;
}
}  // namespace

FloatingPointResults FillBufferSystematic::Generate(
    uint64_t round, MalignBuffer::CopyMethod copy_method, bool use_repstos,
    bool exercise_floating_point, MalignBuffer* b) const {
  const uint64_t pid = getpid();

  // Format: 2 bytes of PID, 3 bytes of round number, 3 bytes of offset.
  // Note: Perhaps should be AC-modulated. Perhaps should be absolute aligned
  // for easier recognition.
  // Note: appropriate for LE machines only.
  FloatingPointResults fp;
  fp.d = std::max<uint64_t>(round, 2);
  for (size_t i = 0; i * 8 < b->size(); i++) {
    const size_t p = 8 * i;
    const size_t k = std::min<size_t>(8, b->size() - p);
    const uint64_t v =
        ((pid & 0xffff) << 48) | ((round & 0xffffff) << 24) | (i & 0xffffff);
    for (size_t m = 0; m < k; m++) {
      (b->data())[p + m] = *(reinterpret_cast<const char*>(&v) + m);
    }
    if (exercise_floating_point) {
      fp.d = ReciprocatedChaos<double>(fp.d);
    }
  }
  return fp;
}

FloatingPointResults FillBufferRandom::Generate(
    uint64_t round, MalignBuffer::CopyMethod copy_method, bool use_repstos,
    bool exercise_floating_point, MalignBuffer* b) const {
  std::knuth_b rng(round);
  std::uniform_int_distribution<uint64_t> dist(
      0, std::numeric_limits<uint64_t>::max());
  FloatingPointResults fp;
  fp.f = std::max<uint64_t>(round, 2);
  size_t p = 0;
  const size_t length = b->size();
  // Repeatedly append random number (one to eight) random bytes.
  while (p < length) {
    const size_t max_span = std::min<size_t>(length - p, 8);
    const size_t z = std::uniform_int_distribution<size_t>(1, max_span)(rng);
    const uint64_t v = dist(rng);
    b->CopyFrom(p, absl::string_view(reinterpret_cast<const char*>(&v), z),
                copy_method);
    p += z;
    if (exercise_floating_point) {
      fp.f = ReciprocatedChaos<float>(fp.f);
    }
  }
  return fp;
}

FloatingPointResults FillBufferText::Generate(
    uint64_t round, MalignBuffer::CopyMethod copy_method, bool use_repstos,
    bool exercise_floating_point, MalignBuffer* b) const {
  std::knuth_b rng(round);
  std::exponential_distribution<double> dist(20);
  FloatingPointResults fp;
  fp.ld = std::max<uint64_t>(round, 2);
  const size_t bufsize = b->size();
  size_t pos = 0;
  while (pos < bufsize) {
    const size_t r = std::min(static_cast<size_t>(dist(rng) * words_.size()),
                              words_.size() - 1);
    const auto& word = words_[r];
    const size_t wordlen = word.size();
    if (pos + wordlen >= bufsize) {
      break;
    }
    b->CopyFrom(pos, word, copy_method);
    pos += wordlen;
    if (pos < bufsize) {
      b->Memset(pos, ' ', 1, use_repstos);
      pos++;
    }
    if (exercise_floating_point) {
      fp.ld = ReciprocatedChaos<long double>(fp.ld);
    }
  }
  // Pad with spaces
  b->Memset(pos, ' ', bufsize - pos, use_repstos);
  return fp;
}

FloatingPointResults FillBufferGrilledCheese::Generate(
    uint64_t round, MalignBuffer::CopyMethod copy_method, bool use_repstos,
    bool exercise_floating_point, MalignBuffer* b) const {
  std::knuth_b rng(round);
  FloatingPointResults fp;
  fp.f = std::max<uint64_t>(round, 2);
  fp.d = std::max<uint64_t>(round, 2);
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
    if (exercise_floating_point) {
      fp.f = ReciprocatedChaos<float>(fp.f);
      fp.d = ReciprocatedChaos<double>(fp.d);
    }
  }
  return fp;
}

PatternGenerators::PatternGenerators() : words_(ReadDict()) {
  generators_.emplace_back(new FillBufferSystematic());
  generators_.emplace_back(new FillBufferRandom());

  if (!words_.empty()) {
    generators_.emplace_back(new FillBufferText(words_));
  } else {
    LOG(WARN) << "No word list found, skipping Text patterns";
  }

  generators_.emplace_back(new FillBufferGrilledCheese());
}

const PatternGenerator& PatternGenerators::RandomGenerator(
    uint64_t round) const {
  std::knuth_b rng(round);
  const size_t k =
      std::uniform_int_distribution<size_t>(0, generators_.size() - 1)(rng);
  return *generators_[k];
}

FloatingPointResults PatternGenerators::Generate(
    const PatternGenerator& generator, const MalignBuffer::PunchedHole& hole,
    uint64_t round, MalignBuffer::CopyMethod copy_method, bool use_repstos,
    bool exercise_floating_point, MalignBuffer* b) const {
  const FloatingPointResults f = generator.Generate(
      round, copy_method, use_repstos, exercise_floating_point, b);
  b->PunchHole(hole, use_repstos);
  return f;
}
}  // namespace cpu_check
