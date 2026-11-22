/* Deterministic rule engine: authoritative security checks. AI never overrides these. */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "message_validator.h"
#include "security_logger.h"

typedef struct {
    dshl_validate_result_t validate_result;
    bool topic_ok;
    bool hmac_ok;
    bool replay_ok;       /* true if sequence is new AND persisted */
    bool command_ok;
    bool params_ok;
    dshl_reason_t fail_reason;
} dshl_rule_result_t;

/* Run all deterministic checks in the specified order.
 * Anti-replay commits only after HMAC succeeds (replay check runs after HMAC). */
dshl_rule_result_t dshl_rules_evaluate(const char *topic, uint16_t topic_len,
                                       const uint8_t *payload, uint16_t payload_len,
                                       dshl_parsed_cmd_t *parsed_out);

/* Allowlist + parameter range checks for an already validated parse. */
bool dshl_command_allowed(const dshl_parsed_cmd_t *cmd);
