/* UART security gateway: authenticated frames, strict parser, forward accepted cmds. */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "message_validator.h"

esp_err_t dshl_uart_init(void);

/* Send an accepted MQTT command to the simulator over authenticated UART frame. */
esp_err_t dshl_uart_forward_command(const dshl_parsed_cmd_t *cmd);

/* Test hook: process raw RX bytes (also used by the UART task). */
void dshl_uart_on_rx_bytes(const uint8_t *data, int len);
