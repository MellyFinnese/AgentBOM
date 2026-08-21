use crate::authorization::{AuthorizationModel, Effect, Permission};
use serde::Deserialize;

fn strings(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(a) => a.iter().filter_map(|v| v.as_str().map(ToOwned::to_owned)).collect(),
        _ => vec!["*".into()],
    }
}

fn principal(value: Option<&serde_json::Value>) -> String {
    let Some(v) = value else { return "*".into() };
    if let Some(s) = v.as_str() { return s.into(); }
    if let Some(obj) = v.as_object() {
        return obj.values().next().and_then(|x| strings(x).into_iter().next()).unwrap_or_else(|| "*".into());
    }
    "*".into()
}

#[derive(Debug, Deserialize)]
pub struct AwsPolicy { #[serde(default)] pub statements: Vec<AwsStatement> }
#[derive(Debug, Deserialize)]
pub struct AwsStatement {
    #[serde(default)] pub sid: Option<String>,
    pub effect: String,
    pub principal: Option<serde_json::Value>,
    pub action: serde_json::Value,
    pub resource: serde_json::Value,
    #[serde(default)] pub condition: serde_json::Value,
}

pub fn parse_aws_iam(payload: &str) -> Result<AuthorizationModel, String> {
    let policy = serde_json::from_str::<AwsPolicy>(payload).map_err(|e| format!("aws-iam policy JSON: {e}"))?;
    let mut permissions = Vec::new();
    for (i, stmt) in policy.statements.into_iter().enumerate() {
        for action in strings(&stmt.action) {
            for resource in strings(&stmt.resource) {
                let permission_id = stmt.sid.clone().unwrap_or_else(|| format!("aws-statement-{i}-{action}-{resource}"));
                permissions.push(Permission {
                    id: permission_id,
                    principal: principal(stmt.principal.as_ref()),
                    action: action.clone(),
                    resource,
                    effect: if stmt.effect.eq_ignore_ascii_case("deny") { Effect::Deny } else { Effect::Allow },
                    conditions: stmt.condition.clone(),
                    provider: Some("aws-iam".into()),
                });
            }
        }
    }
    Ok(AuthorizationModel { permissions })
}

#[derive(Debug, Deserialize)] pub struct GcpBinding { pub role: String, #[serde(default)] pub members: Vec<String>, #[serde(default)] pub condition: Option<serde_json::Value> }
#[derive(Debug, Deserialize)] pub struct GcpPolicy { #[serde(default)] pub bindings: Vec<GcpBinding> }
pub fn parse_gcp_iam(payload: &str) -> Result<AuthorizationModel, String> {
    let policy = serde_json::from_str::<GcpPolicy>(payload).map_err(|e| format!("gcp-iam policy JSON: {e}"))?;
    let mut permissions = Vec::new();
    for (i, binding) in policy.bindings.into_iter().enumerate() {
        for member in binding.members {
            permissions.push(Permission { id: format!("gcp-binding-{i}-{member}"), principal: member, action: binding.role.clone(), resource: "*".into(), effect: Effect::Allow, conditions: binding.condition.clone().unwrap_or_else(|| serde_json::json!({})), provider: Some("gcp-iam".into()) });
        }
    }
    Ok(AuthorizationModel { permissions })
}

#[derive(Debug, Deserialize)] pub struct AzureRoleAssignment { pub principal_id: String, pub role_definition: String, #[serde(default)] pub scope: Option<String> }
pub fn parse_azure_rbac(payload: &str) -> Result<AuthorizationModel, String> {
    let items = serde_json::from_str::<Vec<AzureRoleAssignment>>(payload).map_err(|e| format!("azure-rbac policy JSON: {e}"))?;
    Ok(AuthorizationModel { permissions: items.into_iter().enumerate().map(|(i, a)| Permission { id: format!("azure-assignment-{i}"), principal: a.principal_id, action: a.role_definition, resource: a.scope.unwrap_or_else(|| "*".into()), effect: Effect::Allow, conditions: serde_json::json!({}), provider: Some("azure-rbac".into()) }).collect() })
}

#[derive(Debug, Deserialize)] pub struct K8sRule { #[serde(default)] pub api_groups: Vec<String>, #[serde(default)] pub resources: Vec<String>, #[serde(default)] pub verbs: Vec<String> }
#[derive(Debug, Deserialize)] pub struct K8sRole { #[serde(default)] pub rules: Vec<K8sRule> }
#[derive(Debug, Deserialize)] pub struct K8sBinding { pub subject: String, pub role: K8sRole }
pub fn parse_kubernetes_rbac(payload: &str) -> Result<AuthorizationModel, String> {
    let items = serde_json::from_str::<Vec<K8sBinding>>(payload).map_err(|e| format!("kubernetes-rbac policy JSON: {e}"))?;
    let mut permissions = Vec::new();
    for (i, binding) in items.into_iter().enumerate() {
        for rule in binding.role.rules {
            for verb in &rule.verbs {
                for resource in &rule.resources {
                    permissions.push(Permission { id: format!("k8s-{i}-{verb}-{resource}"), principal: binding.subject.clone(), action: verb.clone(), resource: resource.clone(), effect: Effect::Allow, conditions: serde_json::json!({"api_groups": rule.api_groups}), provider: Some("kubernetes-rbac".into()) });
                }
            }
        }
    }
    Ok(AuthorizationModel { permissions })
}

#[derive(Debug, Deserialize)] pub struct OAuthGrant { pub principal: String, #[serde(default)] pub scopes: Vec<String>, #[serde(default)] pub audience: Option<String> }
pub fn parse_oauth_scopes(payload: &str) -> Result<AuthorizationModel, String> {
    let items = serde_json::from_str::<Vec<OAuthGrant>>(payload).map_err(|e| format!("oauth policy JSON: {e}"))?;
    let mut permissions = Vec::new();
    for (i, grant) in items.into_iter().enumerate() {
        for scope in grant.scopes {
            permissions.push(Permission { id: format!("oauth-{i}-{scope}"), principal: grant.principal.clone(), action: scope, resource: grant.audience.clone().unwrap_or_else(|| "*".into()), effect: Effect::Allow, conditions: serde_json::json!({}), provider: Some("oauth".into()) });
        }
    }
    Ok(AuthorizationModel { permissions })
}

#[derive(Debug, Deserialize)] pub struct McpGrant { pub principal: String, pub tool: String, #[serde(default)] pub capability: Option<String>, #[serde(default)] pub resource: Option<String>, #[serde(default)] pub effect: Option<String> }
pub fn parse_mcp_auth(payload: &str) -> Result<AuthorizationModel, String> {
    let items = serde_json::from_str::<Vec<McpGrant>>(payload).map_err(|e| format!("mcp policy JSON: {e}"))?;
    Ok(AuthorizationModel { permissions: items.into_iter().enumerate().map(|(i, g)| Permission { id: format!("mcp-{i}"), principal: g.principal, action: g.capability.unwrap_or(g.tool), resource: g.resource.unwrap_or_else(|| "*".into()), effect: if g.effect.as_deref().is_some_and(|e| e.eq_ignore_ascii_case("deny")) { Effect::Deny } else { Effect::Allow }, conditions: serde_json::json!({}), provider: Some("mcp".into()) }).collect() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_expands_actions_and_resources() {
        let model = parse_aws_iam(r#"{"statements":[{"effect":"Allow","principal":"agent","action":["read","write"],"resource":["prod-a","prod-b"]}]}"#).unwrap();
        assert_eq!(model.permissions.len(), 4);
        assert!(model.permissions.iter().all(|p| p.provider.as_deref() == Some("aws-iam")));
    }

    #[test]
    fn kubernetes_expands_verbs_and_resources() {
        let model = parse_kubernetes_rbac(r#"[{"subject":"agent","role":{"rules":[{"api_groups":["apps"],"resources":["deployments","pods"],"verbs":["get","list"]}]}}]"#).unwrap();
        assert_eq!(model.permissions.len(), 4);
        assert!(model.permissions.iter().all(|p| p.provider.as_deref() == Some("kubernetes-rbac")));
    }
}
