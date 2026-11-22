/* Rolling-window behavioral feature extraction for the AI model. */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#define DSHL_FEATURE_COUNT 11

typedef struct {
    float features[DSHL_FEATURE_COUNT]; /* order matches model/exported_model.h */
} dshl_feature_vector_t;

esp_err_t dshl_features_init(void);

/* Feed events into the rolling 5-second window. */
void dshl_features_on_mqtt_msg(uint16_t payload_len, bool duplicate_seq,
                               bool invalid_json, bool unknown_command);
void dshl_features_on_unknown_topic(void);
void dshl_features_on_wifi_event(void);      /* disconnect */
void dshl_features_on_mqtt_reconnect(void);
void dshl_features_on_uart_error(uint32_t bytes, bool frame_error);

/* Snapshot current window into features (resets the window). */
void dshl_features_snapshot(dshl_feature_vector_t *out);

/* Copy feature names (for logs/dataset). */
extern const char *const DSHL_FEATURE_NAMES[DSHL_FEATURE_COUNT];
