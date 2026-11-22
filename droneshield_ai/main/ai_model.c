#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"

#include "ai_model.h"
#include "exported_model.h"

static const char *TAG = "AI";

dshl_ai_label_t dshl_ai_predict(const dshl_feature_vector_t *features)
{
    if (!features || DSHL_AI_TREE_LEN <= 0) {
        return DSHL_AI_NORMAL;
    }

    int64_t t0 = esp_timer_get_time();
    int node = 0;
    int guard = 0;

    while (node >= 0 && node < DSHL_AI_TREE_LEN && guard++ < DSHL_AI_TREE_MAX_DEPTH * 4) {
        const dshl_ai_node_t *n = &DSHL_AI_TREE[node];
        if (n->feature < 0 || n->feature >= DSHL_FEATURE_COUNT) {
            /* Corrupt node: fail to normal (rules are authoritative anyway). */
            break;
        }
        float v = features->features[n->feature];
        if (v <= n->threshold) {
            node = n->left;
        } else {
            node = n->right;
        }
    }

    /* Leaf nodes encode label in `left` (0 = normal, 1 = anomaly). */
    int label = DSHL_AI_NORMAL;
    if (node >= 0 && node < DSHL_AI_TREE_LEN && DSHL_AI_TREE[node].feature < 0) {
        label = DSHL_AI_TREE[node].left;
    }

    int64_t dt_us = esp_timer_get_time() - t0;
    if (dt_us > 500) {
        ESP_LOGW(TAG, "Inference slow: %lld us", (long long)dt_us);
    }

    return label == 0 ? DSHL_AI_NORMAL : DSHL_AI_ANOMALY;
}

int dshl_ai_tree_node_count(void)
{
    return DSHL_AI_TREE_LEN;
}
