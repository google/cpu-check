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

#ifndef THIRD_PARTY_CPU_CHECK_STOPPER_H_
#define THIRD_PARTY_CPU_CHECK_STOPPER_H_

#include <unistd.h>

#include <atomic>
#include <cmath>

#include "utils.h"

class Stopper {
 public:
  // Infinite timeout if 'timeout' <= 0.
  Stopper(int timeout)
      : t_stop_(timeout <= 0 ? std::numeric_limits<double>::infinity()
                             : TimeInSeconds() + timeout) {}

  // Returns true if time has expired or Stop has been invoked.
  // Thread safe.
  bool Expired() const { return stopped_ || TimeInSeconds() > t_stop_; }

  // Sleeps for the minimum of 't' and remaining run time.
  // Thread safe.
  void BoundedSleep(int t) const {
    if (std::isinf(t_stop_)) {
      sleep(t);
    } else {
      const double remaining = t_stop_ - TimeInSeconds();
      if (!stopped_ && remaining > 0) {
        sleep(std::min<int>(t, ceil(remaining)));
      }
    }
  }

  // Causes timeout to expire now.
  // Thread safe.
  void Stop() { stopped_ = true; }

 private:
  const double t_stop_;
  std::atomic_bool stopped_ = false;
};

#endif  // THIRD_PARTY_CPU_CHECK_STOPPER_H_
