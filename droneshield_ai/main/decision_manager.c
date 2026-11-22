#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "cJSON.h"

#include "decision_manager.h"
#include "rule_engine.h"
#include "ai_model.h"
#include "anti_replay.h"
#include "feature_extractor.h"
#include "security_logger.h"
#include "uart_gateway.h"
#include "app_config.h"

static const char *TAG = "DECISION";

static int s_tokens = DSHL_RATE_LIMIT_BURST;
static int64_t s_last_refill_ms;

bool dshl_rate_limit_allow(void)
{
    int64_t now = esp_timer_get_time() / 1000;
    if (now - s_last_refill_ms >= DSHL_RATE_LIMIT_REFILL_MS) {
        int elapsed = (int)((now - s_last_refill_ms) / DSHL_RATE_LIMIT_REFILL_MS);
        s_tokens += elapsed;
        if (s_tokens > DSHL_RATE_LIMIT_BURST) {
            s_tokens = DSHL_RATE_LIMIT_BURST;
        }
        s_last_refill_ms = now;
    }
    if (s_tokens <= 0) {
        return false;
    }
    s_tokens--;
    return true;
}

static void log_and_publish(dshl_outcome_t *out, uint64_t seq, const char *command,
                            const char *stage, int payload_len)
{
    dshl_log_decision(out->decision, out->reason, stage, seq, command, payload_len);
    const char *event = "DECISION";
    if (out->decision == DSHL_DECISION_QUARANTINE) {
        event = "QUARANTINE";
    }
    dshl_publish_event(event, out->reason, seq, command, (int32_t)out->ai_label);
}

dshl_outcome_t dshl_decide_mqtt(const char *topic, uint16_t topic_len,
                                const uint8_t *payload, uint16_t payload_len)
{
    dshl_outcome_t out;
    memset(&out, 0, sizeof(out));
    out.decision = DSHL_DECISION_REJECT;
    out.reason = DSHL_REASON_NONE;
    out.forward = false;
    out.ai_label = DSHL_AI_NORMAL;

    bool bad_json = false;
    bool unknown_cmd = false;
    uint16_t pay_len = payload_len;

    /* quad pass-through: no signature, forward raw payload to UART. */
    if (topic && topic_len >= 4 && strncmp(topic, "quad/", 5) == 0) {
        dshl_log_event(DSHL_EVT_MQTT_MSG_RECEIVED, DSHL_REASON_NONE, "quad_raw");
        if (dshl_uart_forward_raw(topic, payload, payload_len) == ESP_OK) {
            dshl_log_event(DSHL_EVT_UART_FORWARDED, DSHL_REASON_OK, "quad_raw");
        } else {
            dshl_log_event(DSHL_EVT_UART_FORWARDED, DSHL_REASON_UART_MALFORMED, "tx_fail");
        }
        out.decision = DSHL_DECISION_ACCEPT;
        out.reason = DSHL_REASON_OK;
        out.forward = true;
        return out;
    }
    if (!dshl_rate_limit_allow()) {
        out.decision = DSHL_DECISION_RATE_LIMIT;
        out.reason = DSHL_REASON_RATE_LIMIT;
        dshl_log_event(DSHL_EVT_RATE_LIMITED, DSHL_REASON_RATE_LIMIT, "token_bucket");
        dshl_features_on_mqtt_msg(pay_len, false, false, false);
        log_and_publish(&out, 0, NULL, "rate_limit", pay_len);
        return out;
    }

    /* Duplicate detection for features: parse seq cheaply later; feed raw first. */
    dshl_parsed_cmd_t parsed;
    dshl_rule_result_t rules = dshl_rules_evaluate(topic, topic_len,
                                                   payload, payload_len, &parsed);

    /* Feature updates (behavioral, does not affect rule outcome). */
    bool invalid_json = (rules.validate_result == DSHL_VALIDATE_BAD_JSON ||
                         rules.validate_result == DSHL_VALIDATE_MISSING_FIELD ||
                         rules.validate_result == DSHL_VALIDATE_BAD_TYPE);
    bool duplicate_seq = (rules.fail_reason == DSHL_REASON_REPLAY);
    unknown_cmd = (rules.fail_reason == DSHL_REASON_UNKNOWN_COMMAND);
    if (!rules.topic_ok) {
        dshl_features_on_unknown_topic();
    }
    dshl_features_on_mqtt_msg(pay_len, duplicate_seq, invalid_json, unknown_cmd);
    bad_json = invalid_json;

    /* Rules are authoritative: any failure -> REJECT (or RATE_LIMIT for limit). */
    if (rules.fail_reason != DSHL_REASON_OK) {
        out.decision = DSHL_DECISION_REJECT;
        out.reason = rules.fail_reason;
        log_and_publish(&out, parsed.seq, parsed.command, "rules", pay_len);
        return out;
    }

    /* Rules passed: run local AI on behavioral features. */
    dshl_feature_vector_t fv;
    dshl_features_snapshot(&fv);
    out.ai_label = dshl_ai_predict(&fv);
    if (out.ai_label == DSHL_AI_ANOMALY) {
        out.decision = DSHL_DECISION_QUARANTINE;
        out.reason = DSHL_REASON_AI_ANOMALY;
        dshl_log_event(DSHL_EVT_AI_FLAG, DSHL_REASON_AI_ANOMALY, "tree");
        log_and_publish(&out, parsed.seq, parsed.command, "ai", pay_len);
        /* Do not commit sequence for quarantined messages. */
        return out;
    }

    /* Final ACCEPT: persist anti-replay state (fail closed). */
    if (!dshl_antireplay_check_and_commit(parsed.seq)) {
        out.decision = DSHL_DECISION_REJECT;
        out.reason = DSHL_REASON_NVS_FAIL;
        log_and_publish(&out, parsed.seq, parsed.command, "nvs", pay_len);
        return out;
    }

    out.decision = DSHL_DECISION_ACCEPT;
    out.reason = DSHL_REASON_OK;
    out.forward = true;
    log_and_publish(&out, parsed.seq, parsed.command, "final", pay_len);

    /* Forward only accepted commands to the UART/simulator gateway. */
    if (dshl_uart_forward_command(&parsed) == ESP_OK) {
        dshl_log_event(DSHL_EVT_UART_FORWARDED, DSHL_REASON_OK, parsed.command);
    } else {
        dshl_log_event(DSHL_EVT_UART_FORWARDED, DSHL_REASON_UART_MALFORMED, "tx_fail");
    }

    (void)bad_json;
    (void)TAG;
    return out;
}
