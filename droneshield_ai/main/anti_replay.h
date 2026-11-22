/* Persistent anti-replay sequence state in NVS. Fail closed on NVS errors. */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

esp_err_t dshl_antireplay_init(void);

/* Returns true if seq is strictly newer than persisted last_seq (and updates it).
 * Returns false for replay or on NVS failure (fail closed: caller must reject). */
bool dshl_antireplay_check_and_commit(uint64_t seq);

uint64_t dshl_antireplay_last_seq(void);
