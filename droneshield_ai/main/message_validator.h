/* Message validation: size, JSON, fields, types, device ID, seq, timestamp, signature format. */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "security_logger.h"

#define DSHL_SIG_HEX_LEN 64

typedef struct {
    char device_id[32];
    uint64_t seq;
    int64_t timestamp;
    char command[32];
    char canonical_params[192]; /* canonicalized params string for HMAC */
    char signature_hex[DSHL_SIG_HEX_LEN + 1];
    bool has_params;
    /* raw params object retained for allowlist/range checks */
    char params_json[192];
} dshl_parsed_cmd_t;

typedef enum {
    DSHL_VALIDATE_OK = 0,
    DSHL_VALIDATE_OVERSIZE,
    DSHL_VALIDATE_BAD_JSON,
    DSHL_VALIDATE_MISSING_FIELD,
    DSHL_VALIDATE_BAD_TYPE,
    DSHL_VALIDATE_DEVICE_ID,
    DSHL_VALIDATE_SEQ_RANGE,
    DSHL_VALIDATE_TIMESTAMP,
    DSHL_VALIDATE_SIG_FORMAT,
} dshl_validate_result_t;

/* payload_len is already bounded by DSHL_MAX_PAYLOAD_LEN upstream. */
dshl_validate_result_t dshl_validate_payload(const uint8_t *payload, uint16_t payload_len,
                                             dshl_parsed_cmd_t *out);

/* Canonical params: sorted-key JSON with no whitespace (e.g. "{}" or {"mode":1}). */
bool dshl_canonicalize_params(const char *params_json, char *out, size_t out_len);

const char *dshl_validate_str(dshl_validate_result_t r);
