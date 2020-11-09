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

#include <random>
#include <string>

#ifndef THIRD_PARTY_CPU_CHECK_AVX_H_
#define THIRD_PARTY_CPU_CHECK_AVX_H_

// x86 AVX usage has complicated core power effects. This code tries
// to provoke some power transitions that don't otherwise happen.
// While it's at it, it lightly checks results, but that's not the central
// goal. ToDo: maybe toughen the correctness checking.
//
// The power policies are governed by a number of opaque parameters; this code
// is based on a lot of guesses.
//
// Not thread safe.
class Avx {
 public:
  static bool can_do_avx();
  static bool can_do_avx512f();
  static bool can_do_fma();

  Avx() {}

  // Activate AVX depending on throw of the dice.
  // Returns syndrome if computational error detected, empty string otherwise.
  std::string MaybeGoHot();

  // Does a bit of computing if in a "hot" mode.
  // Returns syndrome if computational error detected, empty string otherwise.
  std::string BurnIfAvxHeavy();

 private:
  constexpr static int kIterations = 5000;
  std::string Avx256(int rounds);
  std::string Avx256FMA(int rounds);
  std::string Avx512(int rounds);
  int level_ = 0;
  std::knuth_b rng_;
};

#endif  // THIRD_PARTY_CPU_CHECK_AVX_H_
