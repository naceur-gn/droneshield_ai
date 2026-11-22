/* MQTT/TLS client: short receive callback, bounded queue, decision publishing. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "app_config.h"

typedef struct {
    char topic[64];
    uint16_t topic_len;
    uint8_t payload[DSHL_MAX_PAYLOAD_LEN];
    uint16_t payload_len;
    uint32_t recv_ms;      /* esp_timer ms when received */
    uint8_t stale_flush;   /* set when flushed due to reconnect (not executed) */
} dshl_mqtt_msg_t;

esp_err_t dshl_mqtt_init(void);
esp_err_t dshl_mqtt_start(void);
bool dshl_mqtt_is_connected(void);

/* Processing task pops from this queue. */
QueueHandle_t dshl_mqtt_rx_queue(void);

/* Drop any queued messages without executing (call after reconnect). */
void dshl_mqtt_flush_stale(void);

/* Publish to an exact topic (QoS0). Returns false if not connected. */
bool dshl_mqtt_publish(const char *topic, const char *payload, int qos);

int dshl_mqtt_reconnect_count(void);
