#ifndef AGENTBOM_H
#define AGENTBOM_H
#ifdef __cplusplus
extern "C" {
#endif

typedef struct AgentBOMEngine AgentBOMEngine;
AgentBOMEngine* agentbom_engine_new(void);
void agentbom_engine_free(AgentBOMEngine* engine);
int agentbom_engine_add_node(AgentBOMEngine* engine, const char* id, const char* kind, const char* name);
int agentbom_engine_add_node_json(AgentBOMEngine* engine, const char* id, const char* kind, const char* name, const char* properties_json);
int agentbom_engine_add_edge(AgentBOMEngine* engine, const char* source, const char* kind, const char* target);
int agentbom_engine_add_edge_json(AgentBOMEngine* engine, const char* source, const char* kind, const char* target, const char* properties_json);
char* agentbom_engine_snapshot_hash(const AgentBOMEngine* engine);
char* agentbom_engine_policy_findings(const AgentBOMEngine* engine, unsigned long max_depth);
char* agentbom_engine_attack_paths(const AgentBOMEngine* engine, unsigned long max_depth);
char* agentbom_engine_blast_radius(const AgentBOMEngine* engine, unsigned long max_depth);
char* agentbom_engine_drift(const AgentBOMEngine* engine, const char* baseline_json);
char* agentbom_engine_export_json(const AgentBOMEngine* engine);
void agentbom_string_free(char* value);

#ifdef __cplusplus
}
#endif
#endif
