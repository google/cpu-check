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

#include "silkscreen.h"

#include <unistd.h>

#include <random>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "utils.h"

namespace cpu_check {
static const size_t kPageSize = sysconf(_SC_PAGESIZE);

Silkscreen::Silkscreen(const std::vector<int> &tid_list)
    : buffer_address_(static_cast<char *>(aligned_alloc(
          kPageSize, kPageSize * ((kSize + kPageSize - 1) / kPageSize)))) {
  std::knuth_b rng;
  std::uniform_int_distribution<size_t> dist(0, tid_list.size() - 1);
  for (size_t k = 0; k < kSize; k++) {
    size_t w = dist(rng);
    const int o = tid_list[w];
    slot_count_[o]++;
    owner_.push_back(o);
  }
}

absl::Status Silkscreen::WriteMySlots(int tid, uint64_t round) {
  uint64_t j = 0;
  for (size_t k = 0; k < kSize; k++) {
    if (owner(k) == tid) {
      *data(k) = static_cast<char>(round);
      j++;
    }
  }
  if (j != slot_count_[tid]) {
    std::string err = absl::StrCat(Json("written", j), ", ",
                                   Json("expected", slot_count_[tid]));
    return absl::Status(absl::StatusCode::kInternal, err);
  }
  return absl::OkStatus();
}

// When Silkscreen fails, it often fails, on several bad machines,
// in a surprising way: all slots owned by reading tid are
// are corrupt, in a way that suggests the previous round's
// writes never happened. Weird, and deserves some study, but
// meanwhile the log spew is suppressed by reporting only the last
// error and the error count.
absl::Status Silkscreen::CheckMySlots(int tid, uint64_t round) const {
  const char expected = static_cast<char>(round);
  uint64_t slots_read = 0;
  uint64_t error_count = 0;
  std::string last_error;

  for (size_t k = 0; k < Silkscreen::kSize; k++) {
    if (owner(k) != tid) continue;
    slots_read++;
    const char v = *data(k);
    if (v == expected) continue;
    error_count++;
    last_error = absl::StrCat(Json("position", static_cast<uint64_t>(k)), ", ",
                              Json("is", v), ", ", Json("expected", expected));
  }
  if (slot_count(tid) != slots_read) {
    last_error = absl::StrCat(Json("read", slots_read), ", ",
                              Json("expected", slot_count(tid)));
    error_count++;
  }
  if (error_count > 0) {
    return absl::Status(
        absl::StatusCode::kInternal,
        absl::StrCat(last_error, ", ", Json("errors", error_count)));
  } else {
    return absl::OkStatus();
  }
}
}  // namespace cpu_check
