#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>

#include "esp_log.h"
#include "cJSON.h"
#include "message_validator.h"
#include "app_config.h"
#include "esp_sntp.h"
#include "security_logger.h"

static const char *TAG = "VALIDATOR";

const char *dshl_validate_str(dshl_validate_result_t r)
{
    switch (r) {
    case DSHL_VALIDATE_OK:            return "OK";
    case DSHL_VALIDATE_OVERSIZE:      return "OVERSIZE";
    case DSHL_VALIDATE_BAD_JSON:      return "BAD_JSON";
    case DSHL_VALIDATE_MISSING_FIELD: return "MISSING_FIELD";
    case DSHL_VALIDATE_BAD_TYPE:      return "BAD_TYPE";
    case DSHL_VALIDATE_DEVICE_ID:     return "DEVICE_ID";
    case DSHL_VALIDATE_SEQ_RANGE:     return "SEQ_RANGE";
    case DSHL_VALIDATE_TIMESTAMP:     return "TIMESTAMP";
    case DSHL_VALIDATE_SIG_FORMAT:    return "SIG_FORMAT";
    default:                          return "UNKNOWN";
    }
}

static dshl_reason_t reason_of(dshl_validate_result_t r)
{
    switch (r) {
    case DSHL_VALIDATE_OVERSIZE:      return DSHL_REASON_OVERSIZE;
    case DSHL_VALIDATE_BAD_JSON:      return DSHL_REASON_BAD_JSON;
    case DSHL_VALIDATE_MISSING_FIELD: return DSHL_REASON_MISSING_FIELD;
    case DSHL_VALIDATE_BAD_TYPE:      return DSHL_REASON_BAD_TYPE;
    case DSHL_VALIDATE_DEVICE_ID:     return DSHL_REASON_DEVICE_ID;
    case DSHL_VALIDATE_SEQ_RANGE:     return DSHL_REASON_SEQ_RANGE;
    case DSHL_VALIDATE_TIMESTAMP:     return DSHL_REASON_TIMESTAMP;
    case DSHL_VALIDATE_SIG_FORMAT:    return DSHL_REASON_SIG_FORMAT;
    default:                          return DSHL_REASON_NONE;
    }
}

/* Recursively write canonical JSON: object keys sorted, no whitespace, compact. */
static bool canonical_write(const cJSON *node, char *out, size_t cap, size_t *pos)
{
    if (*pos >= cap) {
        return false;
    }
    if (cJSON_IsObject(node)) {
        if (*pos + 1 >= cap) return false;
        out[(*pos)++] = '{';

        int n = cJSON_GetArraySize((cJSON *)node);
        if (n < 0) return false;
        const cJSON *items[32];
        if (n > 32) return false;
        for (int i = 0; i < n; i++) {
            items[i] = cJSON_GetArrayItem((cJSON *)node, i);
        }
        /* insertion sort by key */
        for (int i = 1; i < n; i++) {
            const cJSON *key = items[i];
            int j = i - 1;
            while (j >= 0) {
                const cJSON *a = items[j];
                const char *ka = a->child ? a->child->valuestring : "";
                const char *kb = key->child ? key->child->valuestring : "";
                if (ka && kb && strcmp(ka, kb) > 0) {
                    items[j + 1] = items[j];
                    j--;
                } else {
                    break;
                }
            }
            items[j + 1] = key;
        }

        for (int i = 0; i < n; i++) {
            if (i > 0) {
                if (*pos >= cap) return false;
                out[(*pos)++] = ',';
            }
            const cJSON *child = items[i];
            const char *k = child->child ? child->child->valuestring : NULL;
            const cJSON *v = child->child ? child->child->next : NULL;
            if (!k || !v) return false;
            int w = snprintf(out + *pos, cap - *pos, "\"%s\":", k);
            if (w < 0 || (size_t)w >= cap - *pos) return false;
            *pos += (size_t)w;
            if (!canonical_write(v, out, cap, pos)) return false;
        }
        if (*pos >= cap) return false;
        out[(*pos)++] = '}';
        out[*pos] = '\0';
        return true;
    }
    if (cJSON_IsString(node) && node->valuestring) {
        int w = snprintf(out + *pos, cap - *pos, "\"%s\"", node->valuestring);
        if (w < 0 || (size_t)w >= cap - *pos) return false;
        *pos += (size_t)w;
        return true;
    }
    if (cJSON_IsNumber(node)) {
        char num[32];
        if (node->valuedouble == (double)(int64_t)node->valuedouble) {
            snprintf(num, sizeof(num), "%lld", (long long)node->valuedouble);
        } else {
            snprintf(num, sizeof(num), "%g", node->valuedouble);
        }
        int w = snprintf(out + *pos, cap - *pos, "%s", num);
        if (w < 0 || (size_t)w >= cap - *pos) return false;
        *pos += (size_t)w;
        return true;
    }
    if (cJSON_IsBool(node)) {
        const char *b = cJSON_IsTrue(node) ? "true" : "false";
        int w = snprintf(out + *pos, cap - *pos, "%s", b);
        if (w < 0 || (size_t)w >= cap - *pos) return false;
        *pos += (size_t)w;
        return true;
    }
    if (cJSON_IsNull(node)) {
        int w = snprintf(out + *pos, cap - *pos, "null");
        if (w < 0 || (size_t)w >= cap - *pos) return false;
        *pos += (size_t)w;
        return true;
    }
    return false;
}

bool dshl_canonicalize_params(const char *params_json, char *out, size_t out_len)
{
    if (!params_json || !out || out_len < 3) {
        return false;
    }
    cJSON *root = cJSON_Parse(params_json);
    if (!root) {
        return false;
    }
    bool ok = false;
    if (cJSON_IsObject(root)) {
        size_t pos = 0;
        out[0] = '\0';
        ok = canonical_write(root, out, out_len, &pos);
    }
    cJSON_Delete(root);
    return ok;
}

static bool is_hex_string(const char *s, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)s[i])) {
            return false;
        }
    }
    return true;
}

dshl_validate_result_t dshl_validate_payload(const uint8_t *payload, uint16_t payload_len,
                                             dshl_parsed_cmd_t *out)
{
    memset(out, 0, sizeof(*out));

    /* 1. Size gate (also enforced upstream; belt and braces). */
    if (payload_len == 0 || payload_len > DSHL_MAX_PAYLOAD_LEN) {
        ESP_LOGW(TAG, "Reject: oversize len=%u", (unsigned)payload_len);
        return DSHL_VALIDATE_OVERSIZE;
    }

    /* 2. Parse JSON safely. */
    cJSON *root = cJSON_ParseWithLength((const char *)payload, payload_len);
    if (!root || !cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return DSHL_VALIDATE_BAD_JSON;
    }

    dshl_validate_result_t result = DSHL_VALIDATE_OK;

    /* 3. Required fields and exact types. */
    const cJSON *j_device = cJSON_GetObjectItemCaseSensitive((cJSON *)root, "device_id");
    const cJSON *j_seq = cJSON_GetObjectItemCaseSensitive((cJSON *)root, "seq");
    const cJSON *j_ts = cJSON_GetObjectItemCaseSensitive((cJSON *)root, "timestamp");
    const cJSON *j_cmd = cJSON_GetObjectItemCaseSensitive((cJSON *)root, "command");
    const cJSON *j_params = cJSON_GetObjectItemCaseSensitive((cJSON *)root, "params");
    const cJSON *j_sig = cJSON_GetObjectItemCaseSensitive((cJSON *)root, "signature");

    if (!cJSON_IsString(j_device) || !j_device->valuestring ||
        !cJSON_IsNumber(j_seq) || !cJSON_IsString(j_cmd) || !j_cmd->valuestring ||
        !cJSON_IsString(j_sig) || !j_sig->valuestring ||
        !cJSON_IsObject(j_params)) {
        result = DSHL_VALIDATE_MISSING_FIELD;
        goto done;
    }

    /* Exact integer types: cJSON stores numbers as double; reject non-integers. */
    if (j_seq->valuedouble != (double)(uint64_t)j_seq->valuedouble ||
        j_seq->valuedouble < 0.0 || j_seq->valuedouble > (double)UINT64_MAX) {
        result = DSHL_VALIDATE_BAD_TYPE;
        goto done;
    }
    if (j_ts && !cJSON_IsNumber(j_ts)) {
        result = DSHL_VALIDATE_BAD_TYPE;
        goto done;
    }

    /* 4. device_id */
    if (strcmp(j_device->valuestring, DSHL_DEVICE_ID) != 0) {
        result = DSHL_VALIDATE_DEVICE_ID;
        goto done;
    }

    /* 5. seq as non-negative integer before casting */
    uint64_t seq = 0;
    if (j_seq->string && j_seq->valuedouble >= 0) {
        /* Prefer string form when present to avoid precision issues; cJSON numbers
         * are doubles, so large seq values must be sent as JSON numbers < 2^53. */
        seq = (uint64_t)j_seq->valuedouble;
        if (j_seq->valuedouble < 0 || seq > 9007199254740991ULL) {
            result = DSHL_VALIDATE_SEQ_RANGE;
            goto done;
        }
    }
    out->seq = seq;

    /* 6. timestamp freshness (only if trustworthy time is available) */
    int64_t ts = 0;
    if (j_ts) {
        if (j_ts->valuedouble != (double)(int64_t)j_ts->valuedouble) {
            result = DSHL_VALIDATE_BAD_TYPE;
            goto done;
        }
        ts = (int64_t)j_ts->valuedouble;
        out->timestamp = ts;

        time_t now = time(NULL);
        if ((int64_t)now >= DSHL_TIME_VALID_EPOCH_S) {
            int64_t age = (int64_t)now - ts;
            if (age < 0) age = -age;
            if (age > DSHL_TIMESTAMP_MAX_AGE_S) {
                ESP_LOGW(TAG, "Reject: timestamp age=%llds", (long long)age);
                result = DSHL_VALIDATE_TIMESTAMP;
                goto done;
            }
        } else {
            dshl_log_event(DSHL_EVT_TIME_NOT_SYNCED, DSHL_REASON_TIMESTAMP, "skip_freshness");
        }
    }

    /* 7. Exactly 64 hexadecimal signature characters */
    size_t sig_len = strlen(j_sig->valuestring);
    if (sig_len != DSHL_SIG_HEX_LEN || !is_hex_string(j_sig->valuestring, sig_len)) {
        result = DSHL_VALIDATE_SIG_FORMAT;
        goto done;
    }
    memcpy(out->signature_hex, j_sig->valuestring, DSHL_SIG_HEX_LEN + 1);

    /* Copy command / params for later stages */
    if (strlen(j_cmd->valuestring) >= sizeof(out->command)) {
        result = DSHL_VALIDATE_BAD_TYPE;
        goto done;
    }
    strlcpy(out->command, j_cmd->valuestring, sizeof(out->command));
    strlcpy(out->device_id, j_device->valuestring, sizeof(out->device_id));

    char *params_printed = cJSON_PrintUnformatted((cJSON *)j_params);
    if (!params_printed) {
        result = DSHL_VALIDATE_BAD_JSON;
        goto done;
    }
    if (strlen(params_printed) >= sizeof(out->params_json)) {
        free(params_printed);
        result = DSHL_VALIDATE_BAD_TYPE;
        goto done;
    }
    strlcpy(out->params_json, params_printed, sizeof(out->params_json));
    free(params_printed);
    out->has_params = true;

    if (!dshl_canonicalize_params(out->params_json, out->canonical_params,
                                  sizeof(out->canonical_params))) {
        result = DSHL_VALIDATE_BAD_JSON;
        goto done;
    }

done:
    cJSON_Delete(root);
    if (result != DSHL_VALIDATE_OK) {
        ESP_LOGW(TAG, "Validation failed: %s", dshl_validate_str(result));
        (void)reason_of(result);
    }
    return result;
}
