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

#include "avx.h"

#if defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#endif

#if defined(__i386__) || defined(__x86_64__)
#define X86_TARGET_ATTRIBUTE(s) __attribute__((target(s)))
#else
#define X86_TARGET_ATTRIBUTE(s)
#endif

#if defined(__i386__) || defined(__x86_64__)

bool Avx::can_do_avx() {
  __builtin_cpu_init();
  return __builtin_cpu_supports("avx");
}

bool Avx::can_do_avx512f() {
  __builtin_cpu_init();
  return __builtin_cpu_supports("avx512f");
}

bool Avx::can_do_fma() {
  __builtin_cpu_init();
  return __builtin_cpu_supports("fma");
}

#else

bool Avx::can_do_avx() { return false; }
bool Avx::can_do_avx512f() { return false; }
bool Avx::can_do_fma() { return false; }

#endif

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
  for (int k = 0; k < 4; k++) {
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
  for (int k = 0; k < 4; k++) {
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

  for (int k = 0; k < 4; k++) {
    for (int i = 0; i < 7; i++) {
      if (gross_x[k][i] != gross_x[k][0]) {
        return "avx512 pd";
      }
    }
  }
#endif
  return "";
}
