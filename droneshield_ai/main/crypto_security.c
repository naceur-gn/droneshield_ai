#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "mbedtls/md.h"

#include "crypto_security.h"
#include "app_config.h"

static const char *TAG = "CRYPTO";

int dshl_build_canonical(const char *device_id, uint64_t seq, int64_t timestamp,
                         const char *command, const char *canonical_params,
                         char *out, size_t out_len)
{
    if (!device_id || !command || !canonical_params || !out) {
        return -1;
    }
    int n = snprintf(out, out_len, "%s|%llu|%lld|%s|%s",
                     device_id,
                     (unsigned long long)seq,
                     (long long)timestamp,
                     command,
                     canonical_params);
    if (n < 0 || (size_t)n >= out_len) {
        return -1;
    }
    return n;
}

bool dshl_hmac_hex(const char *key, const char *canonical_msg,
                   char *out_hex, size_t out_hex_len)
{
    if (!key || !canonical_msg || !out_hex || out_hex_len < 65) {
        return false;
    }

    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) {
        return false;
    }

    unsigned char digest[32];
    int ret = mbedtls_md_hmac(info,
                              (const unsigned char *)key, strlen(key),
                              (const unsigned char *)canonical_msg, strlen(canonical_msg),
                              digest);
    if (ret != 0) {
        ESP_LOGE(TAG, "HMAC failed ret=%d", ret);
        return false;
    }

    for (int i = 0; i < 32; i++) {
        snprintf(out_hex + (i * 2), 3, "%02x", digest[i]);
    }
    out_hex[64] = '\0';
    return true;
}

bool dshl_hex_decode(const char *hex, uint8_t *out, size_t out_len)
{
    if (!hex || !out) {
        return false;
    }
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) {
        return false;
    }
    for (size_t i = 0; i < out_len; i++) {
        unsigned int b;
        if (sscanf(hex + (i * 2), "%2x", &b) != 1) {
            return false;
        }
        out[i] = (uint8_t)b;
    }
    return true;
}

bool dshl_const_time_eq(const uint8_t *a, const uint8_t *b, size_t len)
{
    if (!a || !b) {
        return false;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

bool dshl_verify_command(const char *device_id, uint64_t seq, int64_t timestamp,
                         const char *command, const char *canonical_params,
                         const char *signature_hex)
{
    char canonical[384];
    char expected_hex[65];

    if (dshl_build_canonical(device_id, seq, timestamp, command, canonical_params,
                             canonical, sizeof(canonical)) < 0) {
        return false;
    }
    if (!dshl_hmac_hex(DSHL_HMAC_KEY, canonical, expected_hex, sizeof(expected_hex))) {
        return false;
    }
    if (!signature_hex || strlen(signature_hex) != 64) {
        return false;
    }

    uint8_t a[32], b[32];
    if (!dshl_hex_decode(signature_hex, a, 32) ||
        !dshl_hex_decode(expected_hex, b, 32)) {
        return false;
    }
    return dshl_const_time_eq(a, b, 32);
}
