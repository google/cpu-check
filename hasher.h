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

#ifndef THIRD_PARTY_CPU_CHECK_HASH_H_
#define THIRD_PARTY_CPU_CHECK_HASH_H_

#include <memory>
#include <string>
#include <vector>

#include "malign_buffer.h"

namespace cpu_check {

class Hasher {
 public:
  virtual ~Hasher() {}
  virtual std::string Name() const = 0;
  virtual std::string Hash(const MalignBuffer &b) const = 0;
};

class Md5 : public Hasher {
 public:
  std::string Name() const override { return "MD5"; }
  std::string Hash(const MalignBuffer &b) const override;
};

class Sha1 : public Hasher {
 public:
  std::string Name() const override { return "SHA1"; }
  std::string Hash(const MalignBuffer &b) const override;
};

class Sha256 : public Hasher {
 public:
  std::string Name() const override { return "SHA256"; }
  std::string Hash(const MalignBuffer &b) const override;
};

class Sha512 : public Hasher {
 public:
  std::string Name() const override { return "SHA512"; }
  std::string Hash(const MalignBuffer &b) const override;
};

class Adler32 : public Hasher {
 public:
  std::string Name() const override { return "ADLER32"; }
  std::string Hash(const MalignBuffer &b) const override;
};

class Crc32 : public Hasher {
 public:
  std::string Name() const override { return "CRC32"; }
  std::string Hash(const MalignBuffer &b) const override;
};

class Crc32C : public Hasher {
 public:
  std::string Name() const override { return "CRC32C"; }
  std::string Hash(const MalignBuffer &b) const override;
};

class FarmHash64 : public Hasher {
 public:
  std::string Name() const override { return "FarmHash64"; }
  std::string Hash(const MalignBuffer &b) const override;
};

class Hashers {
 public:
  Hashers();

  // Returns a randomly selected hasher.
  const Hasher &RandomHasher(uint64_t seed) const;

  const std::vector<std::unique_ptr<Hasher>> &hashers() const {
    return hashers_;
  }

 private:
  std::vector<std::unique_ptr<Hasher>> hashers_;
};
}  // namespace cpu_check
#endif  // THIRD_PARTY_CPU_CHECK_HASH_H_
