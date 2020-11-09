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

#include "hasher.h"

#include "crc32c.h"
#include "utils.h"
#include "third_party/farmhash/src/farmhash.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <zlib.h>

namespace cpu_check {
namespace {
std::string OpenSSL_Hash(const MalignBuffer &s, const EVP_MD *type) {
  EVP_MD_CTX *ctx;
  ctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(ctx, type, nullptr);
  std::string hash;
  hash.resize(EVP_MD_CTX_size(ctx));
  MalignBuffer::InitializeMemoryForSanitizer(hash.data(), EVP_MD_CTX_size(ctx));
  EVP_DigestUpdate(ctx, s.data(), s.size());
  EVP_DigestFinal_ex(ctx, (uint8_t *)&hash[0], nullptr);
  EVP_MD_CTX_destroy(ctx);
  return HexStr(hash);
}
}  // namespace

std::string Md5::Hash(const MalignBuffer &b) const {
  return OpenSSL_Hash(b, EVP_md5());
}

std::string Sha1::Hash(const MalignBuffer &b) const {
  return OpenSSL_Hash(b, EVP_sha1());
}

std::string Sha256::Hash(const MalignBuffer &b) const {
  return OpenSSL_Hash(b, EVP_sha256());
}

std::string Sha512::Hash(const MalignBuffer &b) const {
  return OpenSSL_Hash(b, EVP_sha512());
}

std::string Adler32::Hash(const MalignBuffer &b) const {
  uLong c = adler32(0, Z_NULL, 0);
  c = adler32(c, reinterpret_cast<const Bytef *>(b.data()), b.size());
  return HexData(reinterpret_cast<const char *>(&c), sizeof(c));
}

std::string Crc32::Hash(const MalignBuffer &b) const {
  uLong c = crc32(0, Z_NULL, 0);
  c = crc32(c, reinterpret_cast<const Bytef *>(b.data()), b.size());
  return HexData(reinterpret_cast<const char *>(&c), sizeof(c));
}

std::string Crc32C::Hash(const MalignBuffer &b) const {
  const uint32_t c = crc32c(b.data(), b.size());
  return HexData(reinterpret_cast<const char *>(&c), sizeof(c));
}

std::string FarmHash64::Hash(const MalignBuffer &b) const {
  const uint64_t c = util::Hash64(b.data(), b.size());
  return HexData(reinterpret_cast<const char *>(&c), sizeof(c));
}

Hashers::Hashers() {
  hashers_.emplace_back(new Md5);
  hashers_.emplace_back(new Sha1);
  hashers_.emplace_back(new Sha256);
  hashers_.emplace_back(new Sha512);
  hashers_.emplace_back(new Adler32);
  hashers_.emplace_back(new Crc32);
  hashers_.emplace_back(new Crc32C);
  hashers_.emplace_back(new FarmHash64);
}

const Hasher &Hashers::RandomHasher(uint64_t seed) const {
  std::knuth_b rng(seed);
  const size_t k =
      std::uniform_int_distribution<size_t>(0, hashers_.size() - 1)(rng);
  return *hashers_[k];
}
}  // namespace cpu_check
