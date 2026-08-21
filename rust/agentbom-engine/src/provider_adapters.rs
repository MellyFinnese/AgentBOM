use crate::authorization::{AuthorizationModel, Effect, Permission};
use serde::Deserialize;

fn parse_permissions<T: for<'de> Deserialize<'de>, F: Fn(T, usize) -> Vec<Permission>>(
    payload: &str,
    provider: &str,
    decode: F,
) -> Result<AuthorizationModel, String> {
    let value = serde_json::from_str::<T>(payload).map_err(|e| format!("{provider} policy JSON: {e}"))?;
    Ok(AuthorizationModel { permissions: decode(value, 0) })
}

#[derive(Debug, Deserialize)]
pub struct AwsPolicy { #[serde(default)] pub statements: Vec<AwsStatement> }
#[derive(Debug, Deserialize)] pub struct AwsStatement {
    #[serde(default)] pub sid: Option<String>,
    pub effect: String,
    pub principal: Option<serde_json::Value>,
    pub action: serde_json::Value,
    pub resource: serde_json::Value,
    #[serde(default)] pub condition: serde_json::Value,
}

fn strings(value: &serde_json::Value) -> Vec<String> {
    match value { serde_json::Value::String(s) => vec![s.clone()], serde_json::Value::Array(a) => a.iter().filter_map(|v| v.as_str().map(ToOwned::to_owned)).collect(), _ => vec!["*".into()] }
}
fn principal(value: Option<&serde_json::Value>) -> String {
    let Some(v)=value else { return "*".into() };
    if let Some(s)=v.as_str() { return s.into(); }
    if let Some(obj)=v.as_object() { return obj.values().next().and_then(|x| strings(x).into_iter().next()).unwrap_or_else(|| "*".into()); }
    "*".into()
}

pub fn parse_aws_iam(payload: &str) -> Result<AuthorizationModel, String> {
    parse_permissions::<AwsPolicy, _>(payload, "aws-iam", |policy, _| {
        let mut out=Vec::new();
        for (i, stmt) in policy.statements.into_iter().enumerate() {
            for action in strings(&stmt.action) { for resource in strings(&stmt.resource) { out.push(Permission { id: stmt.sid.clone().unwrap_or_else(|| format!("aws-statement-{i}")), principal: principal(stmt.principal.as_ref()), action: action.clone(), resource: resource.clone(), effect: if stmt.effect.eq_ignore_ascii_case("deny") { Effect::Deny } else { Effect::Allow }, conditions: stmt.condition.clone() }); }}
        }
        out
    })
}

#[derive(Debug, Deserialize)]
pub struct GcpBinding { pub role: String, #[serde(default)] pub members: Vec<String>, #[serde(default)] pub condition: Option<serde_json::Value> }
#[derive(Debug, Deserialize)] pub struct GcpPolicy { #[serde(default)] pub bindings: Vec<GcpBinding> }
pub fn parse_gcp_iam(payload: &str) -> Result<AuthorizationModel, String> {
    parse_permissions::<GcpPolicy, _>(payload, "gcp-iam", |policy, _| {
        policy.bindings.into_iter().enumerate().flat_map(|(i,b)| b.members.into_iter().map(move |m| Permission { id: format!("gcp-binding-{i}"), principal: m, action: b.role.clone(), resource: "*".into(), effect: Effect::Allow, conditions: b.condition.clone().unwrap_or_else(|| serde_json::json!({})) })).collect()
    })
}

#[derive(Debug, Deserialize)]
pub struct AzureRoleAssignment { pub principal_id: String, pub role_definition: String, #[serde(default)] pub scope: Option<String> }
pub fn parse_azure_rbac(payload: &str) -> Result<AuthorizationModel, String> {
    let items=serde_json::from_str::<Vec<AzureRoleAssignment>>(payload).map_err(|e| format!("azure-rbac policy JSON: {e}"))?;
    Ok(AuthorizationModel { permissions: items.into_iter().enumerate().map(|(i,a)| Permission { id: format!("azure-assignment-{i}"), principal: a.principal_id, action: a.role_definition, resource: a.scope.unwrap_or_else(|| "*".into()), effect: Effect::Allow, conditions: serde_json::json!({}) }).collect() })
}

#[derive(Debug, Deserialize)]
pub struct K8sRule { #[serde(default)] pub api_groups: Vec<String>, #[serde(default)] pub resources: Vec<String>, #[serde(default)] pub verbs: Vec<String> }
#[derive(Debug, Deserialize)] pub struct K8sRole { #[serde(default)] pub rules: Vec<K8sRule> }
#[derive(Debug, Deserialize)] pub struct K8sBinding { pub subject: String, pub role: K8sRole }
pub fn parse_kubernetes_rbac(payload: &str) -> Result<AuthorizationModel, String> {
    let items=serde_json::from_str::<Vec<K8sBinding>>(payload).map_err(|e| format!("kubernetes-rbac policy JSON: {e}"))?;
    let mut out=Vec::new();
    for (i,b) in items.into_iter().enumerate() { for rule in b.role.rules { for verb in rule.verbs { for resource in rule.resources.clone() { out.push(Permission { id: format!("k8s-{i}"), principal: b.subject.clone(), action: verb.clone(), resource: resource.clone(), effect: Effect::Allow, conditions: serde_json::json!({"api_groups": rule.api_groups}) }); }}}}
    Ok(AuthorizationModel { permissions: out })
}

#[derive(Debug, Deserialize)] pub struct OAuthGrant { pub principal: String, #[serde(default)] pub scopes: Vec<String>, #[serde(default)] pub audience: Option<String> }
pub fn parse_oauth_scopes(payload: &str) -> Result<AuthorizationModel, String> {
    let items=serde_json::from_str::<Vec<OAuthGrant>>(payload).map_err(|e| format!("oauth policy JSON: {e}"))?;
    Ok(AuthorizationModel { permissions: items.into_iter().enumerate().flat_map(|(i,g)| g.scopes.into_iter().map(move |scope| Permission { id: format!("oauth-{i}"), principal: g.principal.clone(), action: scope, resource: g.audience.clone().unwrap_or_else(|| "*".into()), effect: Effect::Allow, conditions: serde_json::json!({}) })).collect() })
}

#[derive(Debug, Deserialize)] pub struct McpGrant { pub principal: String, pub tool: String, #[serde(default)] pub capability: Option<String>, #[serde(default)] pub resource: Option<String>, #[serde(default)] pub effect: Option<String> }
pub fn parse_mcp_auth(payload: &str) -> Result<AuthorizationModel, String> {
    let items=serde_json::from_str::<Vec<McpGrant>>(payload).map_err(|e| format!("mcp policy JSON: {e}"))?;
    Ok(AuthorizationModel { permissions: items.into_iter().enumerate().map(|(i,g)| Permission { id: format!("mcp-{i}"), principal: g.principal, action: g.capability.unwrap_or(g.tool), resource: g.resource.unwrap_or_else(|| "*".into()), effect: if g.effect.as_deref().is_some_and(|e| e.eq_ignore_ascii_case("deny")) { Effect::Deny } else { Effect::Allow }, conditions: serde_json::json!({}) }).collect() })
}
