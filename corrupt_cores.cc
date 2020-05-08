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

// Analyzes cpu_check failure tids to produce list of condemned
// cores. Usually there's just one defective core.
//
// One way to extract tids from logs is extract_tids.sh.
// Pipe its output to this program.
//
// By default, this code assumes 28 core dual socket machines.

#include <algorithm>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

#include "log.h"

class BadCore {
 public:
  BadCore(int sockets, int cores_per_socket)
      : sockets_(sockets), cores_per_socket_(cores_per_socket) {}

  // Condemns thread 'tid'.
  void Condemn(int tid) {
    std::vector<int> c({TidToCanonicalCore(tid)});
    accused_.push_back(c);
  }

  // Condemns one of 'tid_1' and 'tid_2'.
  void Accuse(int tid_1, int tid_2) {
    std::vector<int> c({TidToCanonicalCore(tid_1), TidToCanonicalCore(tid_2)});
    accused_.push_back(c);
  }

  // Greedy condemnation.
  void Condemn() {
    while (!accused_.empty()) {
      CondemnWorst();
    }
  }

  // Returns string naming the condemned cores.
  std::string Condemnations() const {
    if (condemned_.empty()) {
      return "None";
    }
    std::stringstream s;
    if (ambiguous_) {
      s << "AMBIGUOUS ";
    }
    for (auto &c : condemned_) {
      s << CanonicalCoreToString(c.first) << " (" << c.second << ") ";
    }
    return s.str();
  }

  // Returns true if tid within legitimate range.
  bool Plausible(int tid) const {
    return (tid >= 0) && (tid < (2 * sockets_ * cores_per_socket_));
  }

 private:
  // Condemns worst offender.
  void CondemnWorst() {
    int worst = -1;
    int worst_k = -1;
    bool ambiguous = false;
    for (int c = 0; c < sockets_ * cores_per_socket_; c++) {
      const int k = AccusationCount(c);
      if (k == 0) continue;
      if (k > worst_k) {
        worst = c;
        worst_k = k;
        ambiguous = false;
      } else {
        if (k == worst_k) {
          ambiguous = true;
        }
      }
    }
    ambiguous_ |= ambiguous;
    condemned_.push_back({worst, worst_k});
    Dispose(worst);
  }

  // Returns number of accusations against 'canonical_core'.
  int AccusationCount(int canonical_core) const {
    int k = 0;
    for (auto &v : accused_) {
      if (std::find(v.begin(), v.end(), canonical_core) != v.end()) {
        k++;
      }
    }
    return k;
  }

  // Delete accusations that include 'canonical_core'.
  void Dispose(int canonical_core) {
    std::vector<std::vector<int>> temp;
    for (auto &v : accused_) {
      if (std::find(v.begin(), v.end(), canonical_core) == v.end()) {
        temp.push_back(v);
      }
    }
    accused_ = temp;
  }

  int TidToCanonicalCore(int tid) const {
    return tid % (sockets_ * cores_per_socket_);
  }

  std::string CanonicalCoreToString(int canonical_core) const {
    const int socket = canonical_core / cores_per_socket_;
    const int a = canonical_core;
    const int b = canonical_core + sockets_ * cores_per_socket_;
    std::stringstream s;
    s << "CPU" << socket << " HT" << a << "-" << b;
    return s.str();
  }

  const int sockets_;
  const int cores_per_socket_;
  std::vector<std::vector<int>> accused_;
  std::vector<std::pair<int, int>> condemned_;
  bool ambiguous_ = false;
};

static void UsageIf(bool v) {
  if (!v) return;
  LOG(ERROR) << "Usage corrupt_cores [-c cores_per_socket] [-s sockets]";
  exit(2);
}

int main(int argc, char **argv) {
  int sockets = 2;            // Default: dual socket
  int cores_per_socket = 28;  // Default: C28
  for (int i = 1; i < argc; i++) {
    const char *flag = argv[i];
    UsageIf(flag[0] != '-');
    for (flag++; *flag != 0; flag++) {
      switch (*flag) {
        case 'c': {
          std::string c(++flag);
          flag += c.length();
          std::stringstream s(c);
          UsageIf((s >> cores_per_socket).fail());
          break;
        }
        case 's': {
          std::string c(++flag);
          flag += c.length();
          std::stringstream s(c);
          UsageIf((s >> sockets).fail());
          break;
        }
        default:
          UsageIf(true);
      }
      if (*flag == 0) break;
    }
  }

  std::string line;
  BadCore bad(sockets, cores_per_socket);

  while (std::getline(std::cin, line)) {
    std::istringstream ss(line);
    int a = 9999;
    if ((ss >> a).fail() || !bad.Plausible(a)) {
      LOG(ERROR) << "Bad input: '" << line << "'";
      continue;
    }
    while (ss.peek() == ' ') ss.ignore();
    if (ss.eof()) {
      bad.Condemn(a);
    } else {
      int b = 9999;
      if ((ss >> b).fail() || !bad.Plausible(b)) {
        LOG(ERROR) << "Bad input: '" << line << "'";
        continue;
      }
      bad.Accuse(a, b);
    }
  }
  bad.Condemn();
  printf("Condemned %s\n", bad.Condemnations().c_str());
}
