#include <string.h>

#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_err.h"

#include "anti_replay.h"
#include "security_logger.h"

static const char *TAG = "ANTIREPLAY";

#define NVS_NS "dshl"
#define NVS_KEY_LAST_SEQ "last_seq"

static uint64_t s_last_seq;
static bool s_ready;

esp_err_t dshl_antireplay_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_flash_init failed: %s", esp_err_to_name(err));
        dshl_log_event(DSHL_EVT_NVS_ERROR, DSHL_REASON_NVS_FAIL, "init");
        return err;
    }

    nvs_handle_t handle;
    err = nvs_open(NVS_NS, NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        s_last_seq = 0;
        s_ready = true;
        return ESP_OK;
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(err));
        dshl_log_event(DSHL_EVT_NVS_ERROR, DSHL_REASON_NVS_FAIL, "open");
        return err;
    }
    err = nvs_get_u64(handle, NVS_KEY_LAST_SEQ, &s_last_seq);
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(handle);
        dshl_log_event(DSHL_EVT_NVS_ERROR, DSHL_REASON_NVS_FAIL, "get");
        return err;
    }
    nvs_close(handle);
    s_ready = true;
    ESP_LOGI(TAG, "Loaded last_seq=%llu", (unsigned long long)s_last_seq);
    return ESP_OK;
}

bool dshl_antireplay_check_and_commit(uint64_t seq)
{
    if (!s_ready) {
        /* Fail closed: cannot trust replay state. */
        dshl_log_event(DSHL_EVT_NVS_ERROR, DSHL_REASON_NVS_FAIL, "not_ready");
        return false;
    }
    if (seq <= s_last_seq) {
        ESP_LOGW(TAG, "Replay detected: seq=%llu last=%llu",
                 (unsigned long long)seq, (unsigned long long)s_last_seq);
        return false;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        dshl_log_event(DSHL_EVT_NVS_ERROR, DSHL_REASON_NVS_FAIL, "rw_open");
        return false;
    }
    err = nvs_set_u64(handle, NVS_KEY_LAST_SEQ, seq);
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    if (err != ESP_OK) {
        /* Fail closed: do not accept a sequence we cannot persist. */
        dshl_log_event(DSHL_EVT_NVS_ERROR, DSHL_REASON_NVS_FAIL, "commit");
        return false;
    }

    s_last_seq = seq;
    return true;
}

uint64_t dshl_antireplay_last_seq(void)
{
    return s_last_seq;
}
