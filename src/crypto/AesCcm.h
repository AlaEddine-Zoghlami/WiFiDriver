#pragma once
#include <cstdint>
#include <cstddef>
namespace apfpv { namespace crypto {
// AES-128-CCM as used by CCMP (8-byte MIC, 13-byte nonce, L=2).
// decrypt: returns true if MIC valid; out gets plaintext (clen-8 bytes).
bool aes_ccm_decrypt(const uint8_t key[16], const uint8_t* nonce, size_t nlen,
                     const uint8_t* aad, size_t aadlen,
                     const uint8_t* ct, size_t ctlen, uint8_t* out);
void aes_ccm_encrypt(const uint8_t key[16], const uint8_t* nonce, size_t nlen,
                     const uint8_t* aad, size_t aadlen,
                     const uint8_t* pt, size_t ptlen, uint8_t* out /* ptlen+8 */);
}}

namespace apfpv { namespace crypto {
// AES-128 ECB single-block (for key-wrap). out=enc(in) under key.
void aes128_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void aes128_ecb_decrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
// RFC 3394 AES Key Unwrap. n = number of 64-bit blocks in wrapped-8. Returns
// true if integrity check (A == A6A6A6A6A6A6A6A6) passes. out = n*8 bytes.
bool aes_key_unwrap(const uint8_t kek[16], const uint8_t* wrapped, size_t wlen, uint8_t* out);
// RFC 3394 AES Key Wrap (inverse). out = (plen+8) bytes. plen multiple of 8, >= 16.
void aes_key_wrap(const uint8_t kek[16], const uint8_t* plain, size_t plen, uint8_t* out);
}}
