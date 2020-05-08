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

#include "config.h"
#include "fvt_controller.h"

#include <error.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>

#include <atomic>
#undef NDEBUG
#include <cassert>
#include <cstring>
#include <memory>
#include <mutex>

#include "fvt_controller.h"
#include "log.h"

namespace {

class NonX86FVTController : public FVTController {
 public:
  explicit NonX86FVTController(int cpu) : FVTController(cpu) {}
  ~NonX86FVTController() override {}
  void SetCurrentFreqLimitMhz(int mhz) override {
    LOG(FATAL) << "Unsupported platform";
  }
  // Returns the maximum supported CPU frequency.
  int GetAbsoluteFreqLimitMhz() override {
    LOG(FATAL) << "Unsupported platform";
    return 0;
  }
  // Returns true if automatic Power Management enabled.
  bool PowerManaged() const override {
    LOG(FATAL) << "Unsupported platform";
    return false;
  }
  std::string FVT() override {
    LOG(FATAL) << "Unsupported platform";
    return "";
  }
  std::string InterestingEnables() const override {
    LOG(FATAL) << "Unsupported platform";
    return "";
  }
  void ControlFastStringOps(bool enable) override {
    LOG(FATAL) << "Unsupported platform";
  }

 protected:
  int GetCurrentFreqLimitMhz() override {
    LOG(FATAL) << "Unsupported platform";
    return 0;
  }
  int GetCurrentFreqMhz() override {
    LOG(FATAL) << "Unsupported platform";
    return 0;
  }
};

static const char IntelVendorString[] = "GenuineIntel";
static const char AMDVendorString[] = "AuthenticAMD";

}  // namespace

// Only works for Linux on x86-64
void X86FVTController::GetCPUId(int cpu, uint32_t eax, CPUIDResult* result) {
  constexpr size_t kCPUIDPathMax = 1024;
  char CPUIDPath[kCPUIDPathMax];
  snprintf(CPUIDPath, sizeof(CPUIDPath), "/dev/cpu/%d/cpuid", cpu);
  int fd = open(CPUIDPath, O_RDONLY);
  assert(fd >= 0);
  ssize_t byte_read = pread(fd, result, sizeof(*result), eax);
  if (byte_read != sizeof(*result)) {
    LOG(FATAL) << "CPUID " << std::hex << eax << "failed.";
  }
  close(fd);
}

std::string X86FVTController::CPUIDVendorStringUncached() {
  char buffer[12];
  CPUIDResult result;
  GetCPUId(0, 0, &result);
  memcpy(buffer + 0, &result.ebx, 4);
  memcpy(buffer + 4, &result.edx, 4);
  memcpy(buffer + 8, &result.ecx, 4);
  return std::string(buffer, sizeof(buffer));
}

std::string X86FVTController::CPUIDVendorString() {
  static const std::string vendor_string = CPUIDVendorStringUncached();
  return vendor_string;
}

std::unique_ptr<FVTController> FVTController::Create(int cpu) {
#if defined(__i386__) || defined(__x86_64__)
  const std::string vendor_string = X86FVTController::CPUIDVendorString();
#ifdef VENDORS_INTEL_PATH
  if (vendor_string == IntelVendorString) {
    return NewIntelFVTController(cpu);
  }
#endif
#ifdef VENDORS_AMD_PATH
  if (vendor_string == AMDVendorString) {
    return NewAMDFVTController(cpu);
  }
#endif
  LOG(FATAL) << "Unsupported x86 vendor";
  return nullptr;
#else
  return std::unique_ptr<FVTController>(new NonX86FVTController(cpu));
#endif
}
