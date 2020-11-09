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

#include "crypto.h"

#include "config.h"
#include "absl/status/status.h"

namespace cpu_check {

namespace {
constexpr unsigned char key[33] = "0123456789abcdef0123456789abcdef";
};  // namespace

absl::Status Crypto::Encrypt(const MalignBuffer &plain_text,
                             MalignBuffer *cipher_text, CryptoPurse *purse) {
  memset(purse->i_vec, 0, sizeof(purse->i_vec));
  memcpy(purse->i_vec, plain_text.data(),
         std::min(plain_text.size(), sizeof(purse->i_vec)));

  int enc_len = 0;
  int enc_unused_len = 0;
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();

  EVP_CipherInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, key, purse->i_vec, 1);
  if (EVP_CipherUpdate(
          cipher_ctx,
          reinterpret_cast<unsigned char *>(cipher_text->data()),
          &enc_len, reinterpret_cast<const unsigned char *>(plain_text.data()),
          plain_text.size()) != 1) {
    return ReturnError("EVP_CipherUpdate", cipher_ctx);
  }
  if (EVP_CipherFinal_ex(cipher_ctx, nullptr, &enc_unused_len) != 1) {
    return ReturnError("encrypt_EVP_CipherFinal_ex", cipher_ctx);
  }
  enc_len += enc_unused_len;
  if (enc_len != (int)cipher_text->size()) {
    return ReturnError("encrypt_length_mismatch", cipher_ctx);
  }
  if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG,
                          sizeof(purse->gmac_tag), purse->gmac_tag) != 1) {
    return ReturnError("EVP_CTRL_GCM_GET_TAG", cipher_ctx);
  }
  EVP_CIPHER_CTX_free(cipher_ctx);
  return absl::OkStatus();
}

absl::Status Crypto::Decrypt(const MalignBuffer &cipher_text,
                             const CryptoPurse &purse,
                             MalignBuffer *plain_text) {
  int dec_len = 0;
  int dec_extra_len = 0;
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();

  EVP_CipherInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, key, purse.i_vec, 0);

  // Make a non-const copy of gmac_tag because that's what EVP_CIPHER_CTX_ctrl
  // requires, even though it won't be modified in this use.
  unsigned char copied_tag[sizeof(purse.gmac_tag)];
  memcpy(copied_tag, purse.gmac_tag, sizeof(purse.gmac_tag));

  if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, sizeof(copied_tag),
                          reinterpret_cast<void *>(copied_tag)) != 1) {
    return ReturnError("EVP_CTRL_GCM_SET_TAG", cipher_ctx);
  }
  if (EVP_CipherUpdate(
          cipher_ctx, reinterpret_cast<unsigned char *>(plain_text->data()),
          &dec_len, reinterpret_cast<const unsigned char *>(cipher_text.data()),
          cipher_text.size()) != 1) {
    return ReturnError("Decryption", cipher_ctx);
  }
  if (EVP_CipherFinal_ex(
          cipher_ctx,
          reinterpret_cast<unsigned char *>(plain_text->data() + dec_len),
          &dec_extra_len) != 1) {
    return ReturnError("decrypt_EVP_CipherFinal_ex", cipher_ctx);
  }
  dec_len += dec_extra_len;
  if (dec_len != (int)plain_text->size()) {
    return ReturnError("decrypt_length_mismatch", cipher_ctx);
  }
  EVP_CIPHER_CTX_free(cipher_ctx);
  return absl::OkStatus();
}

absl::Status Crypto::SelfTest() {
#ifdef USE_BORINGSSL
  if (BORINGSSL_self_test() == 0) {
    return absl::Status(absl::StatusCode::kInternal, "BORINGSSL_self_test");
  }
#endif

  return absl::OkStatus();
}

absl::Status Crypto::ReturnError(absl::string_view message,
                                 EVP_CIPHER_CTX *cipher_ctx) {
  EVP_CIPHER_CTX_free(cipher_ctx);
  return absl::Status(absl::StatusCode::kInternal, message);
}
};  // namespace cpu_check
