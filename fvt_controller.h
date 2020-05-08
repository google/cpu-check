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

#ifndef FVT_CONTROLLER_
#define FVT_CONTROLLER_

#include <fcntl.h>
#include <unistd.h>

#include <memory>
#include <sstream>

#include "log.h"
#include "utils.h"

// Frequency, Voltage and Thermal (FVT) controller.
class FVTController {
 public:
  static constexpr int kMinTurboMHz = 1000;

 protected:
  explicit FVTController(int cpu) : cpu_(cpu) {
    ResetFrequencyMeter();
  }

 public:
  virtual ~FVTController() {}

  static std::unique_ptr<FVTController> Create(int cpu);

  // Monitor per-cpu (or core) frequency control.
  void MonitorFrequency() {
    const double t = TimeInSeconds();
    const int f = GetCurrentFreqMhz();
    sum_mHz_ += (t - previous_sample_time_) * f;
    previous_sample_time_ = t;

    const int mHz = GetCurrentFreqLimitMhz();
    if (mHz != max_mHz_) {
      LOG_EVERY_N_SECS(INFO, 10) << "Cpu: " << cpu_
          << " max turbo frequency control changed to: " << mHz;
      max_mHz_ = mHz;
    }
  }

  // Set the current CPU frequency limit. Warning: do this to both threads of
  // HT pair. Requires 'mhz' multiple of 100, within legitimate range.
  virtual void SetCurrentFreqLimitMhz(int mhz) = 0;

  // Returns the absolute maximum CPU frequency.
  virtual int GetAbsoluteFreqLimitMhz() = 0;

  // Dont put much stock in this method, it's probably a lousy way to do things.
  int GetMeanFreqMhz() const {
    return sum_mHz_ / (previous_sample_time_ - t0_);
  }

  int max_mHz() const { return max_mHz_; }

  int limit_mHz() const { return limit_mhz_; }

  // Returns true if automatic Power Management enabled.
  virtual bool PowerManaged() const = 0;

  // Returns frequency, thermal, and voltage condition.
  virtual std::string FVT() = 0;

  virtual std::string InterestingEnables() const = 0;

  // TODO: separate this from FVT controller.
  virtual void ControlFastStringOps(bool enable) = 0;

 protected:
  // Returns the current CPU frequency limit in MHz.
  virtual int GetCurrentFreqLimitMhz() = 0;

  // Returns the current CPU frequency in MHz.
  virtual int GetCurrentFreqMhz() = 0;

  void ResetFrequencyMeter() {
    t0_ = TimeInSeconds();
    previous_sample_time_ = t0_;
    sum_mHz_ = 0.0;
  }

  const int cpu_;
  double t0_ = 0.0;
  int limit_mhz_ = 0;  // const after init
  int max_mHz_ = 0;
  double sum_mHz_ = 0.0;
  double previous_sample_time_ = 0.0;
};

class X86FVTController : public FVTController {
 public:
  struct CPUIDResult {
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
  };

  explicit X86FVTController(int cpu) : FVTController(cpu) {
    std::stringstream dev;
    dev << "/dev/cpu/" << cpu << "/msr";
    fd_ = open(dev.str().c_str(), O_RDWR);
    if (fd_ < 0) {
      LOG(ERROR) << "Cannot open: " << dev.str()
          << " Running me as root?";
    }
  }
  ~X86FVTController() override {
    if (fd_ >= 0) close(fd_);
  }

  // Only works for Linux on x86-64
  static void GetCPUId(int cpu, uint32_t eax, CPUIDResult* result);

  // Return the vendor string from CPUID
  static std::string CPUIDVendorString();

 protected:
    uint64_t ReadMsr(uint32_t reg) const {
    if (fd_ < 0) return 0;
    uint64_t v = 0;
    int rc = pread(fd_, &v, sizeof(v), reg);
    if (rc != sizeof(v)) {
      LOG_EVERY_N_SECS(ERROR, 60) << "Unable to read cpu: " << cpu_
          << " reg: " << std::hex << reg;
    }
    return v;
  }

  void WriteMsr(uint32_t reg, uint64_t v) const {
    if (fd_ < 0) return;
    int rc = pwrite(fd_, &v, sizeof(v), reg);
    if (rc != sizeof(v)) {
      fprintf(stderr, "rc = %d sizeof(v) = %lu\n", rc, sizeof(v));
      LOG_EVERY_N_SECS(ERROR, 60) << "Unable to write cpu: " << cpu_
          << " reg: " << std::hex << reg;
    }
  }

 private:
  static std::string CPUIDVendorStringUncached();

  int fd_ = -1;
};

extern std::unique_ptr<FVTController> NewAMDFVTController(int cpu);
extern std::unique_ptr<FVTController> NewIntelFVTController(int cpu);

#endif // FVT_CONTROLLER_
