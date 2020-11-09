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

#include <map>
#include <vector>
#include "absl/status/status.h"

#ifndef THIRD_PARTY_CPU_CHECK_SILKSCREEN_H_
#define THIRD_PARTY_CPU_CHECK_SILKSCREEN_H_

namespace cpu_check {
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

  Silkscreen(const std::vector<int>& tid_list);
  ~Silkscreen() { free(buffer_address_); }

  // Writes value derived from 'round' into all slots owned by 'tid'.
  // Returns non-OK Status with JSON-formatted message upon error.
  absl::Status WriteMySlots(int tid, uint64_t round);

  // Checks all slots owned by 'tid' for value appropriate to 'round'.
  // Returns non-OK Status with JSON-formatted message upon error.
  absl::Status CheckMySlots(int tid, uint64_t round) const;

 private:
  int owner(size_t k) const { return owner_[k]; }
  size_t size() const { return owner_.size(); }
  int slot_count(int owner) const { return slot_count_.at(owner); }
  const char* data(size_t k) const { return buffer_address_ + k; }
  char* data(size_t k) { return buffer_address_ + k; }

  std::vector<uint16_t> owner_;    // const after initialization
  std::map<int, int> slot_count_;  // const after initialization
  char* const buffer_address_;
};
}  // namespace cpu_check
#endif  // THIRD_PARTY_CPU_CHECK_SILKSCREEN_H_
