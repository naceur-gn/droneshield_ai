#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_timer.h"
#include "esp_log.h"

#include "feature_extractor.h"
#include "app_config.h"

static const char *TAG = "FEATURES";

const char *const DSHL_FEATURE_NAMES[DSHL_FEATURE_COUNT] = {
    "mqtt_msg_count",
    "avg_payload_len",
    "max_payload_len",
    "duplicate_count",
    "invalid_json_count",
    "unknown_topic_count",
    "invalid_command_count",
    "wifi_disconnect_count",
    "mqtt_reconnect_count",
    "uart_frame_error_count",
    "uart_bytes_per_second",
};

typedef struct {
    int64_t window_start_ms;
    int mqtt_msg_count;
    int payload_len_sum;
    int max_payload_len;
    int duplicate_count;
    int invalid_json_count;
    int unknown_topic_count;
    int invalid_command_count;
    int wifi_disconnect_count;
    int mqtt_reconnect_count;
    int uart_frame_error_count;
    int uart_bytes;
} window_state_t;

static window_state_t s_win;
static SemaphoreHandle_t s_lock;

static void rotate_if_expired(int64_t now_ms)
{
    if (now_ms - s_win.window_start_ms >= DSHL_FEATURE_WINDOW_MS) {
        memset(&s_win, 0, sizeof(s_win));
        s_win.window_start_ms = now_ms;
    }
}

esp_err_t dshl_features_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    if (!s_lock) {
        return ESP_ERR_NO_MEM;
    }
    memset(&s_win, 0, sizeof(s_win));
    s_win.window_start_ms = esp_timer_get_time() / 1000;
    ESP_LOGI(TAG, "Feature window=%dms features=%d", DSHL_FEATURE_WINDOW_MS, DSHL_FEATURE_COUNT);
    return ESP_OK;
}

void dshl_features_on_mqtt_msg(uint16_t payload_len, bool duplicate_seq,
                               bool invalid_json, bool unknown_command)
{
    if (!s_lock) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    rotate_if_expired(esp_timer_get_time() / 1000);
    s_win.mqtt_msg_count++;
    s_win.payload_len_sum += payload_len;
    if (payload_len > s_win.max_payload_len) {
        s_win.max_payload_len = payload_len;
    }
    if (duplicate_seq) s_win.duplicate_count++;
    if (invalid_json) s_win.invalid_json_count++;
    if (unknown_command) s_win.invalid_command_count++;
    xSemaphoreGive(s_lock);
}

void dshl_features_on_unknown_topic(void)
{
    if (!s_lock) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    rotate_if_expired(esp_timer_get_time() / 1000);
    s_win.unknown_topic_count++;
    xSemaphoreGive(s_lock);
}

void dshl_features_on_wifi_event(void)
{
    if (!s_lock) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    rotate_if_expired(esp_timer_get_time() / 1000);
    s_win.wifi_disconnect_count++;
    xSemaphoreGive(s_lock);
}

void dshl_features_on_mqtt_reconnect(void)
{
    if (!s_lock) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    rotate_if_expired(esp_timer_get_time() / 1000);
    s_win.mqtt_reconnect_count++;
    xSemaphoreGive(s_lock);
}

void dshl_features_on_uart_error(uint32_t bytes, bool frame_error)
{
    if (!s_lock) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    rotate_if_expired(esp_timer_get_time() / 1000);
    s_win.uart_bytes += (int)bytes;
    if (frame_error) {
        s_win.uart_frame_error_count++;
    }
    xSemaphoreGive(s_lock);
}

void dshl_features_snapshot(dshl_feature_vector_t *out)
{
    if (!out || !s_lock) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    rotate_if_expired(esp_timer_get_time() / 1000);

    float window_s = (float)DSHL_FEATURE_WINDOW_MS / 1000.0f;
    out->features[0] = (float)s_win.mqtt_msg_count;
    out->features[1] = s_win.mqtt_msg_count > 0
                       ? (float)s_win.payload_len_sum / (float)s_win.mqtt_msg_count
                       : 0.0f;
    out->features[2] = (float)s_win.max_payload_len;
    out->features[3] = (float)s_win.duplicate_count;
    out->features[4] = (float)s_win.invalid_json_count;
    out->features[5] = (float)s_win.unknown_topic_count;
    out->features[6] = (float)s_win.invalid_command_count;
    out->features[7] = (float)s_win.wifi_disconnect_count;
    out->features[8] = (float)s_win.mqtt_reconnect_count;
    out->features[9] = (float)s_win.uart_frame_error_count;
    out->features[10] = (float)s_win.uart_bytes / window_s;

    /* Reset window after snapshot so each decision uses a fresh interval. */
    memset(&s_win, 0, sizeof(s_win));
    s_win.window_start_ms = esp_timer_get_time() / 1000;
    xSemaphoreGive(s_lock);
}
