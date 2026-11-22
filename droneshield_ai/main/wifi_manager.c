#include <string.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_sntp.h"

#include "wifi_manager.h"
#include "security_logger.h"
#include "app_config.h"

static const char *TAG = "WIFI";

#define WIFI_CONNECTED_BIT BIT0

static EventGroupHandle_t s_wifi_events;
static bool s_connected;
static uint32_t s_backoff_ms = DSHL_WIFI_BACKOFF_MIN_MS;
static int s_reconnect_total;
static int64_t s_last_connected_ms = -1;
static int64_t s_disconnect_times[16];
static int s_disconnect_idx;
static dshl_wifi_event_cb_t s_on_connected;
static dshl_wifi_event_cb_t s_on_disconnected;
static bool s_reconnect_task_running;

static void wifi_backoff_task(void *param)
{
    (void)param;
    for (;;) {
        dshl_log_event(DSHL_EVT_WIFI_RECONNECT_ATTEMPT, DSHL_REASON_NONE, "backoff");
        vTaskDelay(pdMS_TO_TICKS(s_backoff_ms));
        if (s_backoff_ms < DSHL_WIFI_BACKOFF_MAX_MS) {
            s_backoff_ms *= 2;
            if (s_backoff_ms > DSHL_WIFI_BACKOFF_MAX_MS) {
                s_backoff_ms = DSHL_WIFI_BACKOFF_MAX_MS;
            }
        }
        if (!s_connected) {
            esp_wifi_connect();
        }
        /* Wait for outcome before allowing another attempt. */
        for (int i = 0; i < 40 && !s_connected; i++) {
            vTaskDelay(pdMS_TO_TICKS(250));
        }
        if (s_connected) {
            s_reconnect_task_running = false;
            vTaskDelete(NULL);
        }
    }
}

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t event_id, void *event_data)
{
    if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *evt = (wifi_event_sta_disconnected_t *)event_data;
        s_connected = false;
        xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT);

        s_disconnect_times[s_disconnect_idx++ % 16] = esp_timer_get_time() / 1000;
        dshl_log_event(DSHL_EVT_WIFI_DISCONNECTED, DSHL_REASON_NONE,
                       evt ? "sta_disconnected" : "disconnected");
        if (s_on_disconnected) {
            s_on_disconnected(false);
        }

        /* Invalid credentials never start MQTT; log and stop retrying aggressively. */
        if (evt && (evt->reason == WIFI_REASON_AUTH_FAIL ||
                    evt->reason == WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT ||
                    evt->reason == WIFI_REASON_HANDSHAKE_TIMEOUT)) {
            ESP_LOGE(TAG, "Auth failure (reason=%d) - check credentials, MQTT stays down", evt->reason);
            return;
        }

        if (!s_reconnect_task_running) {
            s_reconnect_task_running = true;
            xTaskCreate(wifi_backoff_task, "wifi_backoff", 4096, NULL, 5, NULL);
        }
    } else if (base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        bool first = !s_connected;
        s_connected = true;
        s_backoff_ms = DSHL_WIFI_BACKOFF_MIN_MS;
        s_last_connected_ms = esp_timer_get_time() / 1000;
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
        if (first && s_reconnect_total > 0) {
            dshl_log_event(DSHL_EVT_WIFI_RECONNECTED, DSHL_REASON_NONE, "got_ip");
        } else {
            dshl_log_event(DSHL_EVT_WIFI_CONNECTED, DSHL_REASON_NONE, "got_ip");
        }
        s_reconnect_total++;

        /* Best-effort SNTP sync so timestamp freshness checks become active. */
        if (!esp_sntp_enabled()) {
            esp_sntp_set_sync_interval(60000);
            esp_sntp_init();
        }
        if (s_on_connected) {
            s_on_connected(true);
        }
    }
}

static int count_disconnects_in_window(int64_t window_ms)
{
    int64_t now = esp_timer_get_time() / 1000;
    int count = 0;
    for (int i = 0; i < 16; i++) {
        if (s_disconnect_times[i] > 0 && (now - s_disconnect_times[i]) <= window_ms) {
            count++;
        }
    }
    return count;
}

esp_err_t dshl_wifi_init(dshl_wifi_event_cb_t on_connected, dshl_wifi_event_cb_t on_disconnected)
{
    s_on_connected = on_connected;
    s_on_disconnected = on_disconnected;
    s_wifi_events = xEventGroupCreate();
    if (!s_wifi_events) {
        return ESP_ERR_NO_MEM;
    }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler, NULL, NULL));

    wifi_config_t wifi_cfg = {0};
    strlcpy((char *)wifi_cfg.sta.ssid, DSHL_WIFI_SSID, sizeof(wifi_cfg.sta.ssid));
    strlcpy((char *)wifi_cfg.sta.password, DSHL_WIFI_PASSWORD, sizeof(wifi_cfg.sta.password));
    wifi_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_cfg.sta.pmf_cfg.capable = true;
    wifi_cfg.sta.pmf_cfg.required = false;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));

    dshl_log_event(DSHL_EVT_STARTUP, DSHL_REASON_NONE, "wifi_init");
    return ESP_OK;
}

esp_err_t dshl_wifi_start(void)
{
    return esp_wifi_start();
}

bool dshl_wifi_is_connected(void)
{
    return s_connected;
}

int dshl_wifi_disconnect_count_60s(void)
{
    return count_disconnects_in_window(60000);
}

int dshl_wifi_reconnect_count_total(void)
{
    return s_reconnect_total;
}

int64_t dshl_wifi_last_connected_ms(void)
{
    return s_last_connected_ms;
}
