#ifndef SDTMF_SHA256_H
#define SDTMF_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void sdtmf_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void sdtmf_hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len, uint8_t out[32]);
void sdtmf_pbkdf2_hmac_sha256(const uint8_t *pw, size_t pw_len,
                              const uint8_t *salt, size_t salt_len,
                              uint32_t iters, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif
