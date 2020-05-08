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

// Intel platform specific code

#include <atomic>
#include <cassert>
#include <memory>

#include "../../fvt_controller.h"
#include "../../log.h"

namespace {

class IntelFVTController : public X86FVTController {
 public:
  explicit IntelFVTController(int cpu)
    : X86FVTController(cpu) {
    limit_mhz_ = GetAbsoluteFreqLimitMhzImpl();
    // Set initial Turbo frequency to max.
    SetCurrentMaxFreqMhzImpl(limit_mhz_);
  }

  ~IntelFVTController() override {
    // Upon exit, set Turbo frequency to max.
    SetCurrentMaxFreqMhzImpl(limit_mhz_);
  }

  // Sets current maximum frequency. Warning: do this to both threads of HT
  // pair. Requires 'mhz' multiple of 100, within legitimate range.
  void SetCurrentFreqLimitMhz(int mhz) override {
    SetCurrentMaxFreqMhzImpl(mhz);
  }

  // Returns absolute maximum CPU frequency.
  int GetAbsoluteFreqLimitMhz() override {
    return GetAbsoluteFreqLimitMhzImpl();
  }

  // Returns true if automatic Power Management enabled.
  bool PowerManaged() const override {
    return ReadMsr(k_IA32_PM_ENABLE) & 0x1;
  }

  // Returns frequency, thermal, and voltage condition.
  std::string FVT() override {
    constexpr double kVoltageScale = 1.0 / (1 << 13);
    const uint64_t v = ReadMsr(k_IA32_THERM_STATUS);
    const bool valid = (v >> 31) & 0x1;
    const int c = valid ? (v >> 16) & 0x7f : 0;
    const bool current_limit = (v >> 12) & 0x1;
    const bool power_limit = (v >> 10) & 0x1;
    const bool critical = (v >> 4) & 0x1;
    const bool proc_hot = v & 0x1;  // AKA "Thermal Status"
    const uint64_t p = ReadMsr(k_IA32_PERF_STATUS);
    const double voltage = ((p >> 32) & 0xffff) * kVoltageScale;
    const int f = GetCurrentFreqMhz();
    std::stringstream s;
    s << (critical ? "Critical " : "")
        << (proc_hot ? "ProcIsHot " : "")
        << (current_limit ? "CurrentLimit " : "")
        << (power_limit ? "PowerLimit " : "");
    return Json("f", f) + ", " + Json("voltage", voltage) + ", " +
           Json("margin", c) +
           (s.str().empty() ? "" : ", " + Json("pow_states", s.str()));
  }

  std::string InterestingEnables() const override {
    const uint64_t v = ReadMsr(k_IA32_MISC_ENABLE);
    const bool fast_strings = v & 0x1;
    const bool auto_thermal_control = (v >> 3) & 0x1;
    const bool pm = PowerManaged();
    std::stringstream s;
    s << (fast_strings ? "FastStrings " : "")
        << (auto_thermal_control ? "AutoThermalControl " : "")
        << (pm ? "PowerManagement" : "");
    return s.str();
  }

  // TODO: separate this from FVT controller.
  void ControlFastStringOps(bool enable) override {
    uint64_t v = ReadMsr(k_IA32_MISC_ENABLE);
    v = (v & ~0x1) | (enable & 0x1);
    WriteMsr(k_IA32_MISC_ENABLE, v);
  }

 private:
  static constexpr int k_SEND_COMMAND = 0x150;
  static constexpr int k_IA32_PERF_STATUS = 0x198;
  static constexpr int k_IA32_PERF_CTL = 0x199;
  static constexpr int k_IA32_THERM_STATUS = 0x19c;
  static constexpr int k_IA32_MISC_ENABLE = 0x1a0;
  static constexpr int k_MSR_TURBO_RATIO_LIMIT = 0x1ad;
  static constexpr int k_IA32_PM_ENABLE = 0x770;

  // Returns the current CPU frequency limit. This is not virtual so that we
  // can call this from constructor and destructor safely.
  int GetCurrentFreqLimitMhzImpl() {
    uint64_t v = ReadMsr(k_IA32_PERF_CTL);
    return ((v >> 8) & 0xff) * 100;
  }

  int GetCurrentFreqLimitMhz() override {
    return GetCurrentFreqLimitMhzImpl();
  }

  int GetCurrentFreqMhz() override {
    uint64_t v = ReadMsr(k_IA32_PERF_STATUS);
    return ((v >> 8) & 0xff) * 100;
  }

  // This sets the current maximum CPU frequency. This is not virtual so that we
  // can call this from constructor and destructor safely.
  void SetCurrentMaxFreqMhzImpl(int mhz) {
    if (mhz == max_mHz_) return;
    if (PowerManaged()) {
      LOG_EVERY_N_SECS(ERROR, 10) << "Cpu: " << cpu_
          << "Cannot set turbo freq while Power Management enabled!";
    }
    ResetFrequencyMeter();
    int hundreds = mhz / 100;
    assert(100 * hundreds == mhz);
    assert(mhz >= kMinTurboMHz);
    assert(mhz <= limit_mhz_);
    uint64_t v = hundreds << 8;
    WriteMsr(k_IA32_PERF_CTL, v);
    max_mHz_ = mhz;
    LOG_EVERY_N_SECS(INFO, 15) << "Set cpu: " << cpu_
                               << " max turbo freq to: " << mhz << " MHz";
  }

  // Returns the absolute maximum frequency.
  int GetAbsoluteFreqLimitMhzImpl() {
    uint64_t v = ReadMsr(k_MSR_TURBO_RATIO_LIMIT);
    return (v & 0xff) * 100;
  }
};

}  // namespace

std::unique_ptr<FVTController> NewIntelFVTController(int cpu) {
  return std::unique_ptr<FVTController> (new IntelFVTController(cpu));
}
