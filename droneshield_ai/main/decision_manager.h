/* Combines rule engine (authoritative) with AI anomaly flag. */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "rule_engine.h"
#include "security_logger.h"
#include "feature_extractor.h"
#include "ai_model.h"

typedef struct {
    dshl_decision_t decision;
    dshl_reason_t reason;
    bool forward;              /* true only for ACCEPT */
    dshl_ai_label_t ai_label;
} dshl_outcome_t;

/* Full decision pipeline for one received MQTT message. */
dshl_outcome_t dshl_decide_mqtt(const char *topic, uint16_t topic_len,
                                const uint8_t *payload, uint16_t payload_len);

/* Token-bucket rate limit; returns false when limited. */
bool dshl_rate_limit_allow(void);
