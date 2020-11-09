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

#ifndef THIRD_PARTY_CPU_CHECK_CRYPTO_H_
#define THIRD_PARTY_CPU_CHECK_CRYPTO_H_

#include "malign_buffer.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace cpu_check {

class Crypto {
 public:
  // Encryption produces these values, which are consumed by decryption.
  struct CryptoPurse {
    unsigned char i_vec[12];
    unsigned char gmac_tag[16];
  };

  // Encrypts 'plain_text' to 'cipher_text' and stores i_vec and gmac
  // in 'purse'.
  static absl::Status Encrypt(const MalignBuffer &plain_text,
                              MalignBuffer *cipher_text, CryptoPurse *purse);

  // Decrypts 'cipher_text' into 'plain_text' using i_vec and gmac from 'purse'.
  static absl::Status Decrypt(const MalignBuffer &cipher_text,
                              const CryptoPurse &purse,
                              MalignBuffer *plain_text);

  // Runs crypto self test, if available.
  static absl::Status SelfTest();

 private:
  // Returns kInternal error and frees context 'cipher_ctx'.
  static absl::Status ReturnError(absl::string_view message,
                                  EVP_CIPHER_CTX *cipher_ctx);
};

};      // namespace cpu_check
#endif  // THIRD_PARTY_CPU_CHECK_CRYPTO_H_
