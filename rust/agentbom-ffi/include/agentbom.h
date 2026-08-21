#ifndef AGENTBOM_H
#define AGENTBOM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

typedef struct AgentBOMEngine AgentBOMEngine;

AgentBOMEngine* agentbom_engine_new(void);
void agentbom_engine_free(AgentBOMEngine* engine);

int agentbom_engine_add_node(
    AgentBOMEngine* engine,
    const char* id,
    const char* kind,
    const char* name
);

int agentbom_engine_add_edge(
    AgentBOMEngine* engine,
    const char* source,
    const char* kind,
    const char* target
);

char* agentbom_engine_snapshot_hash(const AgentBOMEngine* engine);
char* agentbom_engine_export_json(const AgentBOMEngine* engine);
void agentbom_string_free(char* value);

#ifdef __cplusplus
}
#endif

#endif
