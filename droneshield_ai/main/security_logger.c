#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_sntp.h"
#include "cJSON.h"

#include "security_logger.h"
#include "app_config.h"
#include "mqtt_manager.h"

static const char *TAG = "SECURITY";

const char *dshl_reason_str(dshl_reason_t reason)
{
    switch (reason) {
    case DSHL_REASON_NONE:            return "NONE";
    case DSHL_REASON_OK:              return "OK";
    case DSHL_REASON_OVERSIZE:        return "OVERSIZE";
    case DSHL_REASON_BAD_JSON:        return "BAD_JSON";
    case DSHL_REASON_MISSING_FIELD:   return "MISSING_FIELD";
    case DSHL_REASON_BAD_TYPE:        return "BAD_TYPE";
    case DSHL_REASON_DEVICE_ID:       return "DEVICE_ID";
    case DSHL_REASON_SEQ_RANGE:       return "SEQ_RANGE";
    case DSHL_REASON_TIMESTAMP:       return "TIMESTAMP";
    case DSHL_REASON_SIG_FORMAT:      return "SIG_FORMAT";
    case DSHL_REASON_HMAC_INVALID:    return "HMAC_INVALID";
    case DSHL_REASON_REPLAY:          return "REPLAY";
    case DSHL_REASON_UNKNOWN_COMMAND: return "UNKNOWN_COMMAND";
    case DSHL_REASON_BAD_PARAMS:      return "BAD_PARAMS";
    case DSHL_REASON_RATE_LIMIT:      return "RATE_LIMIT";
    case DSHL_REASON_AI_ANOMALY:      return "AI_ANOMALY";
    case DSHL_REASON_BAD_TOPIC:       return "BAD_TOPIC";
    case DSHL_REASON_QUEUE_FULL:      return "QUEUE_FULL";
    case DSHL_REASON_NVS_FAIL:        return "NVS_FAIL";
    case DSHL_REASON_STALE_FLUSH:     return "STALE_FLUSH";
    case DSHL_REASON_UART_MALFORMED:  return "UART_MALFORMED";
    case DSHL_REASON_UART_OVERSIZE:   return "UART_OVERSIZE";
    case DSHL_REASON_UART_BAD_TAG:    return "UART_BAD_TAG";
    case DSHL_REASON_UART_REPLAY:     return "UART_REPLAY";
    case DSHL_REASON_UART_UNKNOWN_TYPE: return "UART_UNKNOWN_TYPE";
    default:                          return "UNKNOWN";
    }
}

const char *dshl_decision_str(dshl_decision_t decision)
{
    switch (decision) {
    case DSHL_DECISION_ACCEPT:      return "ACCEPT";
    case DSHL_DECISION_REJECT:      return "REJECT";
    case DSHL_DECISION_RATE_LIMIT:  return "RATE_LIMIT";
    case DSHL_DECISION_QUARANTINE:  return "QUARANTINE";
    default:                        return "UNKNOWN";
    }
}

void dshl_log_event(dshl_event_id_t id, dshl_reason_t reason, const char *detail)
{
    ESP_LOGI(TAG, "[EVENT] id=%d reason=%s detail=%s",
             (int)id, dshl_reason_str(reason), detail ? detail : "-");
}

void dshl_log_decision(dshl_decision_t decision, dshl_reason_t reason,
                       const char *stage, uint64_t seq, const char *command,
                       int payload_len)
{
    ESP_LOGI(TAG, "[DECISION] %s stage=%s reason=%s seq=%" PRIu64 " cmd=%s len=%d",
             dshl_decision_str(decision), stage ? stage : "-",
             dshl_reason_str(reason), seq, command ? command : "-", payload_len);
}

void dshl_publish_event(const char *event, dshl_reason_t reason, uint64_t seq,
                        const char *command, int32_t extra)
{
    if (!dshl_mqtt_is_connected()) {
        return;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return;
    }
    cJSON_AddStringToObject(root, "event", event ? event : "EVENT");
    cJSON_AddStringToObject(root, "reason", dshl_reason_str(reason));
    cJSON_AddNumberToObject(root, "seq", (double)seq);
    if (command && command[0]) {
        cJSON_AddStringToObject(root, "command", command);
    }
    if (extra != INT32_MIN) {
        cJSON_AddNumberToObject(root, "extra", extra);
    }
    cJSON_AddNumberToObject(root, "ts", (double)time(NULL));

    char *printed = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!printed) {
        return;
    }
    dshl_mqtt_publish(DSHL_TOPIC_EVENTS, printed, 0);
    free(printed);
}
