/* Local shallow decision-tree inference. Never overrides rule-based rejection. */
#pragma once

#include <stdbool.h>
#include "feature_extractor.h"

typedef enum {
    DSHL_AI_NORMAL = 0,
    DSHL_AI_ANOMALY = 1,
} dshl_ai_label_t;

/* Run inference on the current feature vector. */
dshl_ai_label_t dshl_ai_predict(const dshl_feature_vector_t *features);

/* Model metadata (from exported tree). */
int dshl_ai_tree_node_count(void);
