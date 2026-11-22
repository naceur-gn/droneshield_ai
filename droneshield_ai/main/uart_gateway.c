#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "driver/uart.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/md.h"

#include "uart_gateway.h"
#include "crypto_security.h"
#include "feature_extractor.h"
#include "security_logger.h"
#include "anti_replay.h"
#include "app_config.h"

static const char *TAG = "UART_GW";

#define RX_BUF_SIZE 1024
#define TX_BUF_SIZE 1024

static bool s_ready;
static uint8_t s_rx_buf[RX_BUF_SIZE];
static uint64_t s_last_rx_seq;
static bool s_have_rx_seq;

/* tag = HMAC_SHA256(DSHL_UART_KEY, frame_bytes_before_tag)[0..15] */
static bool uart_compute_tag(const uint8_t *data, size_t len_without_tag, uint8_t tag[DSHL_UART_TAG_LEN])
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) {
        return false;
    }
    unsigned char digest[32];
    int ret = mbedtls_md_hmac(info,
                              (const unsigned char *)DSHL_UART_KEY, strlen(DSHL_UART_KEY),
                              data, len_without_tag, digest);
    if (ret != 0) {
        return false;
    }
    memcpy(tag, digest, DSHL_UART_TAG_LEN);
    return true;
}

static void handle_frame(const uint8_t *frame, size_t frame_len)
{
    /* frame: magic(2) ver(1) type(1) seq(4) len(2) payload tag(16) */
    if (frame_len < DSHL_UART_FRAME_OVERHEAD + 2) {
        dshl_features_on_uart_error((uint32_t)frame_len, true);
        dshl_log_event(DSHL_EVT_UART_FRAME_ERROR, DSHL_REASON_UART_MALFORMED, "short");
        return;
    }
    if (frame[0] != DSHL_UART_MAGIC0 || frame[1] != DSHL_UART_MAGIC1) {
        dshl_features_on_uart_error((uint32_t)frame_len, true);
        dshl_log_event(DSHL_EVT_UART_FRAME_ERROR, DSHL_REASON_UART_MALFORMED, "magic");
        return;
    }
    if (frame[2] != DSHL_UART_VERSION) {
        dshl_features_on_uart_error((uint32_t)frame_len, true);
        dshl_log_event(DSHL_EVT_UART_FRAME_ERROR, DSHL_REASON_UART_MALFORMED, "version");
        return;
    }
    uint8_t type = frame[3];
    uint32_t seq = ((uint32_t)frame[4] << 24) | ((uint32_t)frame[5] << 16) |
                   ((uint32_t)frame[6] << 8) | (uint32_t)frame[7];
    uint16_t plen = ((uint16_t)frame[8] << 8) | (uint16_t)frame[9];

    if (plen > DSHL_UART_MAX_PAYLOAD) {
        dshl_features_on_uart_error((uint32_t)frame_len, true);
        dshl_log_event(DSHL_EVT_UART_FRAME_ERROR, DSHL_REASON_UART_OVERSIZE, "len");
        return;
    }
    if (frame_len != (size_t)DSHL_UART_HEADER_LEN + plen + DSHL_UART_TAG_LEN) {
        dshl_features_on_uart_error((uint32_t)frame_len, true);
        dshl_log_event(DSHL_EVT_UART_FRAME_ERROR, DSHL_REASON_UART_MALFORMED, "length_mismatch");
        return;
    }

    /* Authenticate tag over header+payload. */
    uint8_t expected[DSHL_UART_TAG_LEN];
    if (!uart_compute_tag(frame, DSHL_UART_HEADER_LEN + plen, expected) ||
        !dshl_const_time_eq(expected, frame + DSHL_UART_HEADER_LEN + plen, DSHL_UART_TAG_LEN)) {
        dshl_features_on_uart_error((uint32_t)frame_len, true);
        dshl_log_event(DSHL_EVT_UART_REJECTED, DSHL_REASON_UART_BAD_TAG, "hmac");
        ESP_LOGW(TAG, "UART frame rejected: bad tag type=%u seq=%lu", type, (unsigned long)seq);
        return;
    }

    if (type != DSHL_UART_TYPE_COMMAND && type != DSHL_UART_TYPE_EVENT) {
        dshl_features_on_uart_error((uint32_t)frame_len, true);
        dshl_log_event(DSHL_EVT_UART_REJECTED, DSHL_REASON_UART_UNKNOWN_TYPE, "type");
        return;
    }

    /* Anti-replay on UART sequence (persistent). */
    if (s_have_rx_seq && seq <= (uint32_t)s_last_rx_seq) {
        dshl_features_on_uart_error((uint32_t)frame_len, true);
        dshl_log_event(DSHL_EVT_UART_REJECTED, DSHL_REASON_UART_REPLAY, "seq");
        ESP_LOGW(TAG, "UART replay: seq=%lu last=%llu", (unsigned long)seq,
                 (unsigned long long)s_last_rx_seq);
        return;
    }

    /* Valid authenticated frame: update replay state. */
    if (seq > (uint32_t)s_last_rx_seq) {
        s_last_rx_seq = seq;
        s_have_rx_seq = true;
    }

    dshl_features_on_uart_error((uint32_t)frame_len, false);
    ESP_LOGI(TAG, "UART authenticated frame type=%u seq=%lu len=%u",
             type, (unsigned long)seq, (unsigned)plen);

    /* Payload of type COMMAND is a JSON command; run through full pipeline
     * as if it came from MQTT (reuse rules by wrapping in a pseudo-topic).
     * For milestone 1 we only log acceptance of the UART control frame. */
    if (type == DSHL_UART_TYPE_COMMAND && plen > 0) {
        char payload_str[DSHL_UART_MAX_PAYLOAD + 1];
        memcpy(payload_str, frame + DSHL_UART_HEADER_LEN, plen);
        payload_str[plen] = '\0';
        ESP_LOGI(TAG, "UART command payload accepted for simulator (len=%u)", (unsigned)plen);
        /* Do not echo payload if it could contain sensitive data in future. */
        (void)payload_str;
    }
}

void dshl_uart_on_rx_bytes(const uint8_t *data, int len)
{
    if (!data || len <= 0) {
        return;
    }
    dshl_features_on_uart_error((uint32_t)len, false);

    /* Strict framing: scan for magic, validate length, authenticate. */
    int i = 0;
    while (i < len) {
        if (data[i] != DSHL_UART_MAGIC0) {
            i++;
            continue;
        }
        if (i + 1 >= len) {
            break;
        }
        if (data[i + 1] != DSHL_UART_MAGIC1) {
            i++;
            continue;
        }
        /* Need full header to know total length */
        if (i + DSHL_UART_HEADER_LEN > len) {
            break;
        }
        uint16_t plen = ((uint16_t)data[i + 8] << 8) | (uint16_t)data[i + 9];
        if (plen > DSHL_UART_MAX_PAYLOAD) {
            dshl_features_on_uart_error(1, true);
            dshl_log_event(DSHL_EVT_UART_FRAME_ERROR, DSHL_REASON_UART_OVERSIZE, "scan");
            i += 2;
            continue;
        }
        size_t total = (size_t)DSHL_UART_HEADER_LEN + plen + DSHL_UART_TAG_LEN;
        if (i + (int)total > len) {
            /* Incomplete frame: wait for more data (simple single-buffer model). */
            break;
        }
        handle_frame(data + i, total);
        i += (int)total;
    }
}

static void uart_rx_task(void *arg)
{
    (void)arg;
    for (;;) {
        int n = uart_read_bytes(DSHL_UART_NUM, s_rx_buf, sizeof(s_rx_buf),
                                pdMS_TO_TICKS(100));
        if (n > 0) {
            dshl_uart_on_rx_bytes(s_rx_buf, n);
        }
    }
}

esp_err_t dshl_uart_init(void)
{
    uart_config_t cfg = {
        .baud_rate = DSHL_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    esp_err_t err = uart_driver_install(DSHL_UART_NUM, RX_BUF_SIZE, TX_BUF_SIZE, 0, NULL, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "uart_driver_install failed: %s", esp_err_to_name(err));
        return err;
    }
    err = uart_param_config(DSHL_UART_NUM, &cfg);
    if (err != ESP_OK) {
        return err;
    }
    err = uart_set_pin(DSHL_UART_NUM, DSHL_UART_TX_PIN, DSHL_UART_RX_PIN,
                       UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (err != ESP_OK) {
        return err;
    }

    if (xTaskCreate(uart_rx_task, "uart_rx", 4096, NULL, 6, NULL) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }

    s_ready = true;
    ESP_LOGI(TAG, "UART gateway ready uart=%d tx=%d rx=%d baud=%d",
             DSHL_UART_NUM, DSHL_UART_TX_PIN, DSHL_UART_RX_PIN, DSHL_UART_BAUD);
    return ESP_OK;
}

esp_err_t dshl_uart_forward_command(const dshl_parsed_cmd_t *cmd)
{
    if (!s_ready || !cmd) {
        return ESP_ERR_INVALID_STATE;
    }

    /* Frame payload: compact JSON {"command":...,"params":...,"seq":...} */
    char body[DSHL_UART_MAX_PAYLOAD];
    int n = snprintf(body, sizeof(body),
                     "{\"command\":\"%s\",\"params\":%s,\"seq\":%llu}",
                     cmd->command,
                     cmd->has_params ? cmd->params_json : "{}",
                     (unsigned long long)cmd->seq);
    if (n < 0 || n >= (int)sizeof(body)) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t frame[DSHL_UART_HEADER_LEN + DSHL_UART_MAX_PAYLOAD + DSHL_UART_TAG_LEN];
    frame[0] = DSHL_UART_MAGIC0;
    frame[1] = DSHL_UART_MAGIC1;
    frame[2] = DSHL_UART_VERSION;
    frame[3] = DSHL_UART_TYPE_COMMAND;
    uint32_t seq = (uint32_t)(cmd->seq & 0xFFFFFFFFu);
    frame[4] = (uint8_t)(seq >> 24);
    frame[5] = (uint8_t)(seq >> 16);
    frame[6] = (uint8_t)(seq >> 8);
    frame[7] = (uint8_t)(seq);
    frame[8] = (uint8_t)((n >> 8) & 0xFF);
    frame[9] = (uint8_t)(n & 0xFF);
    memcpy(frame + DSHL_UART_HEADER_LEN, body, (size_t)n);

    uint8_t tag[DSHL_UART_TAG_LEN];
    if (!uart_compute_tag(frame, DSHL_UART_HEADER_LEN + (size_t)n, tag)) {
        return ESP_FAIL;
    }
    memcpy(frame + DSHL_UART_HEADER_LEN + n, tag, DSHL_UART_TAG_LEN);

    int total = DSHL_UART_HEADER_LEN + n + DSHL_UART_TAG_LEN;
    int written = uart_write_bytes(DSHL_UART_NUM, frame, total);
    if (written != total) {
        return ESP_FAIL;
    }
    return ESP_OK;
}
