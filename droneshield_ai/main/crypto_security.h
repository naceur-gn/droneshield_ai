/* HMAC-SHA256 signing/verification with constant-time comparison. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Build canonical message: device_id|seq|timestamp|command|canonical_params */
int dshl_build_canonical(const char *device_id, uint64_t seq, int64_t timestamp,
                         const char *command, const char *canonical_params,
                         char *out, size_t out_len);

/* HMAC-SHA256(key, canonical) -> 64 lowercase hex chars in out_hex. */
bool dshl_hmac_hex(const char *key, const char *canonical_msg,
                   char *out_hex, size_t out_hex_len);

/* Decode 64 hex chars to 32 bytes. */
bool dshl_hex_decode(const char *hex, uint8_t *out, size_t out_len);

/* Constant-time compare of two buffers of equal length. */
bool dshl_const_time_eq(const uint8_t *a, const uint8_t *b, size_t len);

/* Verify message signature: rebuild canonical, compute HMAC, constant-time compare. */
bool dshl_verify_command(const char *device_id, uint64_t seq, int64_t timestamp,
                         const char *command, const char *canonical_params,
                         const char *signature_hex);
