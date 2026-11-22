/* DroneShield AI - entry point.
 * Receive -> validate -> detect -> decide -> forward accepted messages only. */

#include <string.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_timer.h"

#include "app_config.h"
#include "security_logger.h"
#include "wifi_manager.h"
#include "mqtt_manager.h"
#include "anti_replay.h"
#include "feature_extractor.h"
#include "decision_manager.h"
#include "uart_gateway.h"
#include "ai_model.h"
#include "rule_engine.h"

static const char *TAG = "MAIN";

static void on_wifi_connected(bool connected)
{
    (void)connected;
    /* Start MQTT only when Wi-Fi is up (and only once). */
    static bool mqtt_started;
    if (!mqtt_started) {
        esp_err_t err = dshl_mqtt_start();
        if (err == ESP_OK) {
            mqtt_started = true;
            ESP_LOGI(TAG, "MQTT started after Wi-Fi connect");
        } else {
            ESP_LOGE(TAG, "MQTT start failed: %s", esp_err_to_name(err));
        }
    }
}

static void on_wifi_disconnected(bool connected)
{
    (void)connected;
    dshl_features_on_wifi_event();
    /* MQTT client auto-reconnects; queued commands are flushed on reconnect. */
}

/* Processing task: pop bounded queue messages and run the security pipeline.
 * Never runs in the MQTT callback context. */
static void processing_task(void *arg)
{
    (void)arg;
    QueueHandle_t q = dshl_mqtt_rx_queue();
    dshl_mqtt_msg_t msg;

    ESP_LOGI(TAG, "Processing task online (tree nodes=%d)", dshl_ai_tree_node_count());

    for (;;) {
        if (xQueueReceive(q, &msg, pdMS_TO_TICKS(500)) != pdTRUE) {
            continue;
        }
        if (msg.stale_flush) {
            dshl_log_event(DSHL_EVT_QUEUE_FLUSHED_STALE, DSHL_REASON_STALE_FLUSH, "task");
            continue;
        }

        dshl_outcome_t out = dshl_decide_mqtt(msg.topic, msg.topic_len,
                                              msg.payload, msg.payload_len);
        (void)out;
    }
}

void app_main(void)
{
    dshl_log_event(DSHL_EVT_STARTUP, DSHL_REASON_NONE, "droneshield_ai " DSHL_FW_VERSION);
    ESP_LOGI(TAG, "DroneShield AI %s device=%s", DSHL_FW_VERSION, DSHL_DEVICE_ID);

    /* NVS first: anti-replay fails closed without it. */
    esp_err_t err = dshl_antireplay_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Anti-replay init failed - refusing to run insecurely");
        return;
    }
    ESP_LOGI(TAG, "Anti-replay ready last_seq=%" PRIu64, dshl_antireplay_last_seq());

    if (dshl_features_init() != ESP_OK) {
        ESP_LOGE(TAG, "Feature extractor init failed");
        return;
    }

    if (dshl_uart_init() != ESP_OK) {
        ESP_LOGE(TAG, "UART gateway init failed");
        return;
    }

    if (dshl_mqtt_init() != ESP_OK) {
        ESP_LOGE(TAG, "MQTT init failed");
        return;
    }

    err = dshl_wifi_init(on_wifi_connected, on_wifi_disconnected);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Wi-Fi init failed");
        return;
    }

    if (xTaskCreate(processing_task, "dshl_proc", 8192, NULL, 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create processing task");
        return;
    }

    err = dshl_wifi_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Wi-Fi start failed: %s", esp_err_to_name(err));
        return;
    }

    ESP_LOGI(TAG, "Pipeline: mqtt_rx -> validate -> rules -> ai -> decision -> uart");
    ESP_LOGI(TAG, "Subscribing only to %s", DSHL_TOPIC_COMMANDS);
}
