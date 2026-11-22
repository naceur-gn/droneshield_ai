/* Structured security event logging: event IDs + reason codes, never secrets. */
#pragma once

#include <stdint.h>
#include "esp_err.h"

typedef enum {
    DSHL_EVT_WIFI_CONNECTED = 100,
    DSHL_EVT_WIFI_DISCONNECTED = 101,
    DSHL_EVT_WIFI_RECONNECT_ATTEMPT = 102,
    DSHL_EVT_WIFI_RECONNECTED = 103,
    DSHL_EVT_MQTT_CONNECTED = 200,
    DSHL_EVT_MQTT_DISCONNECTED = 201,
    DSHL_EVT_MQTT_RECONNECT_ATTEMPT = 202,
    DSHL_EVT_MQTT_MSG_RECEIVED = 203,
    DSHL_EVT_MQTT_SUBSCRIBE_OK = 204,
    DSHL_EVT_MQTT_PUBLISH_DENIED = 205,
    DSHL_EVT_QUEUE_DROPPED = 300,
    DSHL_EVT_QUEUE_FLUSHED_STALE = 301,
    DSHL_EVT_RATE_LIMITED = 302,
    DSHL_EVT_DECISION = 400,
    DSHL_EVT_AI_FLAG = 401,
    DSHL_EVT_UART_FORWARDED = 500,
    DSHL_EVT_UART_FRAME_ERROR = 501,
    DSHL_EVT_UART_REJECTED = 502,
    DSHL_EVT_NVS_ERROR = 600,
    DSHL_EVT_TIME_NOT_SYNCED = 601,
    DSHL_EVT_STARTUP = 900,
} dshl_event_id_t;

typedef enum {
    DSHL_REASON_NONE = 0,
    DSHL_REASON_OK = 1,
    DSHL_REASON_OVERSIZE = 2,
    DSHL_REASON_BAD_JSON = 3,
    DSHL_REASON_MISSING_FIELD = 4,
    DSHL_REASON_BAD_TYPE = 5,
    DSHL_REASON_DEVICE_ID = 6,
    DSHL_REASON_SEQ_RANGE = 7,
    DSHL_REASON_TIMESTAMP = 8,
    DSHL_REASON_SIG_FORMAT = 9,
    DSHL_REASON_HMAC_INVALID = 10,
    DSHL_REASON_REPLAY = 11,
    DSHL_REASON_UNKNOWN_COMMAND = 12,
    DSHL_REASON_BAD_PARAMS = 13,
    DSHL_REASON_RATE_LIMIT = 14,
    DSHL_REASON_AI_ANOMALY = 15,
    DSHL_REASON_BAD_TOPIC = 16,
    DSHL_REASON_QUEUE_FULL = 17,
    DSHL_REASON_NVS_FAIL = 18,
    DSHL_REASON_STALE_FLUSH = 19,
    DSHL_REASON_UART_MALFORMED = 20,
    DSHL_REASON_UART_OVERSIZE = 21,
    DSHL_REASON_UART_BAD_TAG = 22,
    DSHL_REASON_UART_REPLAY = 23,
    DSHL_REASON_UART_UNKNOWN_TYPE = 24,
} dshl_reason_t;

typedef enum {
    DSHL_DECISION_ACCEPT = 0,
    DSHL_DECISION_REJECT = 1,
    DSHL_DECISION_RATE_LIMIT = 2,
    DSHL_DECISION_QUARANTINE = 3,
} dshl_decision_t;

const char *dshl_reason_str(dshl_reason_t reason);
const char *dshl_decision_str(dshl_decision_t decision);

void dshl_log_event(dshl_event_id_t id, dshl_reason_t reason, const char *detail);

/* Decision log line: [DECISION] ... with reason + payload length, never secrets. */
void dshl_log_decision(dshl_decision_t decision, dshl_reason_t reason,
                       const char *stage, uint64_t seq, const char *command,
                       int payload_len);

/* Publishes a JSON event to the events topic (no secrets). Safe after MQTT is up;
 * drops silently if MQTT is not connected. */
void dshl_publish_event(const char *event, dshl_reason_t reason, uint64_t seq,
                        const char *command, int32_t extra);
