/* Wi-Fi connection management: events, bounded backoff, reconnect. */
#pragma once

#include <stdbool.h>
#include "esp_err.h"

typedef void (*dshl_wifi_event_cb_t)(bool connected);

esp_err_t dshl_wifi_init(dshl_wifi_event_cb_t on_connected, dshl_wifi_event_cb_t on_disconnected);
esp_err_t dshl_wifi_start(void);
bool dshl_wifi_is_connected(void);

/* Rolling counters for feature extraction */
int dshl_wifi_disconnect_count_60s(void);
int dshl_wifi_reconnect_count_total(void);
int64_t dshl_wifi_last_connected_ms(void);   /* -1 if never connected */
