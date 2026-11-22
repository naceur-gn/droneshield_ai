/* DroneShield AI - application configuration and secrets loading. */
#pragma once

#include <stdint.h>

/* Include local secrets if present; otherwise fall back to committed placeholders. */
#if defined(__has_include)
#  if __has_include("secrets.h")
#    include "secrets.h"
#  else
#    include "secrets.h.example"
#  endif
#else
#  include "secrets.h.example"
#endif

/* Device identity */
#define DSHL_DEVICE_ID          "device_01"
#define DSHL_FW_VERSION         "0.1.0"

/* MQTT topics (subscribe only to our own command topic) */
#define DSHL_TOPIC_COMMANDS     "droneshield/" DSHL_DEVICE_ID "/commands"
#define DSHL_TOPIC_STATUS       "droneshield/" DSHL_DEVICE_ID "/status"
#define DSHL_TOPIC_EVENTS       "droneshield/" DSHL_DEVICE_ID "/events"

/* Payload / queue limits (checked before JSON parsing) */
#define DSHL_MAX_PAYLOAD_LEN    512
#define DSHL_QUEUE_DEPTH        8
#define DSHL_MQTT_RX_QUEUE_LEN  DSHL_QUEUE_DEPTH

/* Freshness window for signed timestamps (seconds); skipped until time is synced */
#define DSHL_TIMESTAMP_MAX_AGE_S      300
#define DSHL_TIME_VALID_EPOCH_S       1600000000LL

/* Rate limiting: token bucket over the processing path */
#define DSHL_RATE_LIMIT_BURST         10
#define DSHL_RATE_LIMIT_REFILL_MS     1000

/* Wi-Fi reconnect backoff (bounded exponential) */
#define DSHL_WIFI_BACKOFF_MIN_MS      1000
#define DSHL_WIFI_BACKOFF_MAX_MS      32000

/* Rolling feature window */
#define DSHL_FEATURE_WINDOW_MS        5000

/* UART simulator link (UART1; UART0 remains the debug console) */
#define DSHL_UART_NUM                 1
#define DSHL_UART_BAUD                115200
#define DSHL_UART_RX_PIN              18
#define DSHL_UART_TX_PIN              17
#define DSHL_UART_MAX_PAYLOAD         256
#define DSHL_UART_TAG_LEN             16

/* UART frame layout:
 *  magic(2)=0xAA55 | ver(1) | type(1) | seq(4 BE) | len(2 BE) | payload[len] | tag(16)
 *  tag = HMAC-SHA256(DSHL_UART_KEY, bytes before tag)[0..15]
 */
#define DSHL_UART_MAGIC0              0xAA
#define DSHL_UART_MAGIC1              0x55
#define DSHL_UART_VERSION             0x01
#define DSHL_UART_HEADER_LEN          10
#define DSHL_UART_FRAME_OVERHEAD      (DSHL_UART_HEADER_LEN + DSHL_UART_TAG_LEN)

#define DSHL_UART_TYPE_COMMAND        0x01
#define DSHL_UART_TYPE_ACK            0x02
#define DSHL_UART_TYPE_EVENT          0x03

/* Command allowlist */
#define DSHL_CMD_STATUS_REQUEST   "STATUS_REQUEST"
#define DSHL_CMD_PING             "PING"
#define DSHL_CMD_ARM              "ARM"
#define DSHL_CMD_DISARM           "DISARM"
#define DSHL_CMD_SIM_RESET        "SIM_RESET"

/* Parameter limits for allowlisted commands */
#define DSHL_PARAM_MODE_VALUES    2          /* 0 = stabilized, 1 = acro */
