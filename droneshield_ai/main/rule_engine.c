#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "cJSON.h"

#include "rule_engine.h"
#include "crypto_security.h"
#include "anti_replay.h"
#include "message_validator.h"
#include "app_config.h"
#include "security_logger.h"

static const char *TAG = "RULES";

bool dshl_command_allowed(const dshl_parsed_cmd_t *cmd)
{
    if (!cmd) {
        return false;
    }

    if (strcmp(cmd->command, DSHL_CMD_STATUS_REQUEST) == 0 ||
        strcmp(cmd->command, DSHL_CMD_PING) == 0 ||
        strcmp(cmd->command, DSHL_CMD_ARM) == 0 ||
        strcmp(cmd->command, DSHL_CMD_DISARM) == 0 ||
        strcmp(cmd->command, DSHL_CMD_SIM_RESET) == 0) {
        /* Parameter validation per command */
        cJSON *params = cJSON_Parse(cmd->params_json);
        if (!params) {
            return false;
        }
        bool ok = true;

        if (strcmp(cmd->command, DSHL_CMD_ARM) == 0 ||
            strcmp(cmd->command, DSHL_CMD_DISARM) == 0 ||
            strcmp(cmd->command, DSHL_CMD_PING) == 0 ||
            strcmp(cmd->command, DSHL_CMD_SIM_RESET) == 0 ||
            strcmp(cmd->command, DSHL_CMD_STATUS_REQUEST) == 0) {
            /* These accept empty params only, or optional "mode" for ARM. */
            const cJSON *mode = cJSON_GetObjectItemCaseSensitive(params, "mode");
            int extra_keys = cJSON_GetArraySize(params) - (mode ? 1 : 0);
            if (extra_keys > 0) {
                ok = false;
            }
            if (mode && strcmp(cmd->command, DSHL_CMD_ARM) == 0) {
                if (!cJSON_IsNumber(mode) ||
                    mode->valuedouble != (double)(int)mode->valuedouble ||
                    (int)mode->valuedouble < 0 ||
                    (int)mode->valuedouble >= DSHL_PARAM_MODE_VALUES) {
                    ok = false;
                }
            } else if (mode) {
                /* mode only valid on ARM */
                ok = false;
            }
        }
        cJSON_Delete(params);
        return ok;
    }
    return false;
}

dshl_rule_result_t dshl_rules_evaluate(const char *topic, uint16_t topic_len,
                                       const uint8_t *payload, uint16_t payload_len,
                                       dshl_parsed_cmd_t *parsed_out)
{
    dshl_rule_result_t r;
    memset(&r, 0, sizeof(r));
    memset(parsed_out, 0, sizeof(*parsed_out));

    /* 1. Topic must be exactly our command topic (no wildcards on our side). */
    r.topic_ok = (topic_len == strlen(DSHL_TOPIC_COMMANDS) &&
                  memcmp(topic, DSHL_TOPIC_COMMANDS, topic_len) == 0);
    if (!r.topic_ok) {
        r.fail_reason = DSHL_REASON_BAD_TOPIC;
        return r;
    }

    /* 2. Structural validation (size, JSON, fields, types, device, seq, ts, sig format). */
    r.validate_result = dshl_validate_payload(payload, payload_len, parsed_out);
    if (r.validate_result != DSHL_VALIDATE_OK) {
        switch (r.validate_result) {
        case DSHL_VALIDATE_OVERSIZE:      r.fail_reason = DSHL_REASON_OVERSIZE; break;
        case DSHL_VALIDATE_BAD_JSON:      r.fail_reason = DSHL_REASON_BAD_JSON; break;
        case DSHL_VALIDATE_MISSING_FIELD: r.fail_reason = DSHL_REASON_MISSING_FIELD; break;
        case DSHL_VALIDATE_BAD_TYPE:      r.fail_reason = DSHL_REASON_BAD_TYPE; break;
        case DSHL_VALIDATE_DEVICE_ID:     r.fail_reason = DSHL_REASON_DEVICE_ID; break;
        case DSHL_VALIDATE_SEQ_RANGE:     r.fail_reason = DSHL_REASON_SEQ_RANGE; break;
        case DSHL_VALIDATE_TIMESTAMP:     r.fail_reason = DSHL_REASON_TIMESTAMP; break;
        case DSHL_VALIDATE_SIG_FORMAT:    r.fail_reason = DSHL_REASON_SIG_FORMAT; break;
        default:                          r.fail_reason = DSHL_REASON_BAD_JSON; break;
        }
        return r;
    }

    /* 3. HMAC verification (after sig format check). */
    r.hmac_ok = dshl_verify_command(parsed_out->device_id, parsed_out->seq,
                                    parsed_out->timestamp, parsed_out->command,
                                    parsed_out->canonical_params,
                                    parsed_out->signature_hex);
    if (!r.hmac_ok) {
        r.fail_reason = DSHL_REASON_HMAC_INVALID;
        ESP_LOGW(TAG, "HMAC invalid: seq=%llu cmd=%s",
                 (unsigned long long)parsed_out->seq, parsed_out->command);
        return r;
    }
    ESP_LOGI(TAG, "HMAC valid");

    /* 4. Anti-replay: reject if not strictly newer than last accepted.
     * Persistence happens only on final ACCEPT (decision_manager) - fail closed. */
    if (parsed_out->seq <= dshl_antireplay_last_seq()) {
        ESP_LOGW(TAG, "Replay detected: seq=%llu last=%llu",
                 (unsigned long long)parsed_out->seq,
                 (unsigned long long)dshl_antireplay_last_seq());
        r.fail_reason = DSHL_REASON_REPLAY;
        return r;
    }
    r.replay_ok = true;

    /* 5. Command allowlist + parameter ranges. */
    r.command_ok = dshl_command_allowed(parsed_out);
    r.params_ok = r.command_ok;
    if (!r.command_ok) {
        r.fail_reason = DSHL_REASON_UNKNOWN_COMMAND;
        ESP_LOGW(TAG, "Command not allowed: %s", parsed_out->command);
        return r;
    }

    r.fail_reason = DSHL_REASON_OK;
    return r;
}
