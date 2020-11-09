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

#ifndef THIRD_PARTY_CPU_CHECK_PATTERN_GENERATOR_H_
#define THIRD_PARTY_CPU_CHECK_PATTERN_GENERATOR_H_

#include <memory>
#include <string>

#include "malign_buffer.h"

namespace cpu_check {

class PatternGenerators;

struct FloatingPointResults {
  bool operator==(const FloatingPointResults& other) const {
    return f == other.f && d == other.d && ld == other.ld;
  }
  bool operator!=(const FloatingPointResults& other) const {
    return f != other.f || d != other.d || ld != other.ld;
  }

  float f = 0.0;
  double d = 0.0;
  long double ld = 0.0;
};

class PatternGenerator {
 public:
  virtual ~PatternGenerator() {}
  virtual std::string Name() const = 0;

  virtual FloatingPointResults Generate(uint64_t round,
                                        MalignBuffer::CopyMethod copy_method,
                                        bool use_repstos,
                                        bool exercise_floating_point,
                                        MalignBuffer*) const = 0;
};

// Fills buffer with a systematic pattern.
// Returns iterate of chaotic floating point function of 'seed', with some
// reciprocal torture.
class FillBufferSystematic : public PatternGenerator {
 public:
  std::string Name() const override { return "Systematic"; }
  FloatingPointResults Generate(uint64_t round,
                                MalignBuffer::CopyMethod copy_method,
                                bool use_repstos, bool exercise_floating_point,
                                MalignBuffer*) const override;
};

// Fills buffer with a random pattern.
// Returns iterate of chaotic floating point function of 'seed', with some
// reciprocal torture.
class FillBufferRandom : public PatternGenerator {
 public:
  std::string Name() const override { return "Random"; }
  FloatingPointResults Generate(uint64_t round,
                                MalignBuffer::CopyMethod copy_method,
                                bool use_repstos, bool exercise_floating_point,
                                MalignBuffer*) const override;
};

// Fills buffer with a compressible pattern.
// Returns iterate of chaotic floating point function of 'seed', with some
// reciprocal torture.
class FillBufferText : public PatternGenerator {
 public:
  FillBufferText(const std::vector<std::string>& words) : words_(words) {}
  std::string Name() const override { return "Text"; }
  FloatingPointResults Generate(uint64_t round,
                                MalignBuffer::CopyMethod copy_method,
                                bool use_repstos, bool exercise_floating_point,
                                MalignBuffer*) const override;

 private:
  const std::vector<std::string>& words_;
};

// memset (conventional or rep;stos) randomly aligned, random width, randomly
// overlapped stretches of buffer. Constants aim to hit multiple times in
// cache lines and buffers. Untuned and based on nothing but hunches.
class FillBufferGrilledCheese : public PatternGenerator {
 public:
  std::string Name() const override { return "Cheese"; }
  FloatingPointResults Generate(uint64_t round,
                                MalignBuffer::CopyMethod copy_method,
                                bool use_repstos, bool exercise_floating_point,
                                MalignBuffer*) const override;
};

class PatternGenerators {
 public:
  PatternGenerators();
  const PatternGenerator& RandomGenerator(uint64_t round) const;

  FloatingPointResults Generate(const PatternGenerator& generator,
                                const MalignBuffer::PunchedHole& hole,
                                uint64_t round,
                                MalignBuffer::CopyMethod copy_method,
                                bool use_repstos, bool exercise_floating_point,
                                MalignBuffer* b) const;

  const std::vector<std::string>& words() const { return words_; }

 private:
  const std::vector<std::string> words_;
  std::vector<std::unique_ptr<PatternGenerator>> generators_;
};
}  // namespace cpu_check
#endif  // THIRD_PARTY_CPU_CHECK_PATTERN_GENERATOR_H_
