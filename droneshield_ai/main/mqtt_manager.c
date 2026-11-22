#include <string.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_crt_bundle.h"
#include "mqtt_client.h"
#include "esp_timer.h"

#include "mqtt_manager.h"
#include "security_logger.h"
#include "wifi_manager.h"
#include "app_config.h"

static const char *TAG = "MQTT";

#define MQTT_CONNECTED_BIT BIT0

static esp_mqtt_client_handle_t s_client;
static QueueHandle_t s_rx_queue;
static EventGroupHandle_t s_events;
static bool s_connected;
static int s_reconnect_count;
static bool s_started;

/* Keep the receive callback short: copy bounded payload into the queue, return. */
static void mqtt_event_handler(void *arg, esp_event_base_t base,
                               int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t evt = (esp_mqtt_event_handle_t)event_data;

    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        s_connected = true;
        s_reconnect_count++;
        xEventGroupSetBits(s_events, MQTT_CONNECTED_BIT);
        dshl_log_event(DSHL_EVT_MQTT_CONNECTED, DSHL_REASON_NONE, "tls_ok");

        /* Flush stale queued messages so reconnects never execute old commands. */
        dshl_mqtt_flush_stale();

        int msg_id = esp_mqtt_client_subscribe(s_client, DSHL_TOPIC_COMMANDS, 1);
        if (msg_id >= 0) {
            dshl_log_event(DSHL_EVT_MQTT_SUBSCRIBE_OK, DSHL_REASON_NONE, DSHL_TOPIC_COMMANDS);
        }
        break;

    case MQTT_EVENT_DISCONNECTED:
        s_connected = false;
        xEventGroupClearBits(s_events, MQTT_CONNECTED_BIT);
        dshl_log_event(DSHL_EVT_MQTT_DISCONNECTED, DSHL_REASON_NONE, "disconnected");
        break;

    case MQTT_EVENT_DATA: {
        dshl_log_event(DSHL_EVT_MQTT_MSG_RECEIVED, DSHL_REASON_NONE, "rx");

        if (evt->topic_len >= (int)sizeof(((dshl_mqtt_msg_t *)0)->topic)) {
            return;
        }
        if (evt->data_len > DSHL_MAX_PAYLOAD_LEN) {
            /* Oversize: drop before queueing; validator would reject anyway. */
            dshl_log_event(DSHL_EVT_QUEUE_DROPPED, DSHL_REASON_OVERSIZE, "mqtt");
            return;
        }
        if (!s_rx_queue) {
            return;
        }

        dshl_mqtt_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        memcpy(msg.topic, evt->topic, evt->topic_len);
        msg.topic_len = (uint16_t)evt->topic_len;
        msg.payload_len = (uint16_t)evt->data_len;
        memcpy(msg.payload, evt->data, evt->data_len);
        msg.recv_ms = (uint32_t)(esp_timer_get_time() / 1000);

        if (xQueueSend(s_rx_queue, &msg, 0) != pdTRUE) {
            dshl_log_event(DSHL_EVT_QUEUE_DROPPED, DSHL_REASON_QUEUE_FULL, "mqtt_rx");
        }
        break;
    }

    case MQTT_EVENT_ERROR:
        if (evt->error_handle) {
            ESP_LOGE(TAG, "MQTT error type=%d (tls=%d, transport=%d)",
                     evt->error_handle->error_type,
                     evt->error_handle->esp_tls_last_esp_err,
                     evt->error_handle->esp_transport_sock_errno);
        }
        dshl_log_event(DSHL_EVT_MQTT_DISCONNECTED, DSHL_REASON_NONE, "error");
        break;

    default:
        break;
    }
}

esp_err_t dshl_mqtt_init(void)
{
    s_rx_queue = xQueueCreate(DSHL_MQTT_RX_QUEUE_LEN, sizeof(dshl_mqtt_msg_t));
    s_events = xEventGroupCreate();
    if (!s_rx_queue || !s_events) {
        return ESP_ERR_NO_MEM;
    }

    esp_mqtt_client_config_t cfg = {
        .broker.address.hostname = DSHL_MQTT_HOST,
        .broker.address.port = DSHL_MQTT_PORT,
        .broker.address.transport = MQTT_TRANSPORT_OVER_SSL,
        .broker.verification.crt_bundle_attach = esp_crt_bundle_attach,
        .credentials.username = DSHL_MQTT_USERNAME,
        .credentials.authentication.password = DSHL_MQTT_PASSWORD,
        .credentials.client_id = DSHL_MQTT_CLIENT_ID,
        .session.disable_keepalive = false,
        .network.disable_auto_reconnect = false,
        .network.reconnect_timeout_ms = 5000,
        .network.timeout_ms = 10000,
        .buffer.size = 1024,
    };

    s_client = esp_mqtt_client_init(&cfg);
    if (!s_client) {
        return ESP_FAIL;
    }
    ESP_ERROR_CHECK(esp_mqtt_client_register_event(s_client, ESP_EVENT_ANY_ID,
                                                    mqtt_event_handler, NULL));
    return ESP_OK;
}

esp_err_t dshl_mqtt_start(void)
{
    if (!s_client) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!dshl_wifi_is_connected()) {
        ESP_LOGE(TAG, "Refusing MQTT start: Wi-Fi not connected");
        return ESP_ERR_INVALID_STATE;
    }
    s_started = true;
    return esp_mqtt_client_start(s_client);
}

bool dshl_mqtt_is_connected(void)
{
    return s_connected;
}

QueueHandle_t dshl_mqtt_rx_queue(void)
{
    return s_rx_queue;
}

void dshl_mqtt_flush_stale(void)
{
    if (!s_rx_queue) {
        return;
    }
    dshl_mqtt_msg_t msg;
    int flushed = 0;
    while (xQueueReceive(s_rx_queue, &msg, 0) == pdTRUE) {
        flushed++;
    }
    if (flushed > 0) {
        ESP_LOGW(TAG, "Flushed %d stale queued message(s) after reconnect", flushed);
        dshl_log_event(DSHL_EVT_QUEUE_FLUSHED_STALE, DSHL_REASON_STALE_FLUSH, "mqtt");
    }
}

bool dshl_mqtt_publish(const char *topic, const char *payload, int qos)
{
    if (!s_client || !s_connected || !topic || !payload) {
        return false;
    }
    int ret = esp_mqtt_client_publish(s_client, topic, payload, 0, qos, 0);
    return ret >= 0;
}

int dshl_mqtt_reconnect_count(void)
{
    return s_reconnect_count;
}

bool dshl_mqtt_started(void)
{
    return s_started;
}
