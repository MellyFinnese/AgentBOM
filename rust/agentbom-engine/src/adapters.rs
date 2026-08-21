use crate::authorization::{AuthorizationModel, Effect, Permission};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct GenericGrant {
    id: Option<String>,
    principal: String,
    action: String,
    resource: String,
    effect: Option<String>,
    conditions: Option<serde_json::Value>,
}

pub trait AuthorizationAdapter {
    fn provider(&self) -> &'static str;
    fn parse_json(&self, payload: &str) -> Result<AuthorizationModel, String>;
}

#[derive(Debug, Clone, Copy)]
pub struct JsonPolicyAdapter { provider: &'static str }
impl JsonPolicyAdapter { pub const fn new(provider: &'static str) -> Self { Self { provider } } }
impl AuthorizationAdapter for JsonPolicyAdapter {
    fn provider(&self) -> &'static str { self.provider }
    fn parse_json(&self, payload: &str) -> Result<AuthorizationModel, String> {
        let grants: Vec<GenericGrant> = serde_json::from_str(payload).map_err(|e| format!("{} policy JSON: {e}", self.provider))?;
        let permissions = grants.into_iter().enumerate().map(|(i, grant)| Permission {
            id: grant.id.unwrap_or_else(|| format!("{}-grant-{}", self.provider, i + 1)),
            principal: grant.principal,
            action: grant.action,
            resource: grant.resource,
            effect: match grant.effect.as_deref().unwrap_or("allow").to_ascii_lowercase().as_str() {
                "deny" => Effect::Deny,
                _ => Effect::Allow,
            },
            conditions: grant.conditions.unwrap_or_else(|| serde_json::json!({})),
            provider: Some(self.provider.into()),
        }).collect();
        Ok(AuthorizationModel { permissions })
    }
}

pub const AWS_IAM: JsonPolicyAdapter = JsonPolicyAdapter::new("aws-iam");
pub const GCP_IAM: JsonPolicyAdapter = JsonPolicyAdapter::new("gcp-iam");
pub const AZURE_RBAC: JsonPolicyAdapter = JsonPolicyAdapter::new("azure-rbac");
pub const KUBERNETES_RBAC: JsonPolicyAdapter = JsonPolicyAdapter::new("kubernetes-rbac");
pub const OAUTH_SCOPES: JsonPolicyAdapter = JsonPolicyAdapter::new("oauth");
pub const MCP_AUTH: JsonPolicyAdapter = JsonPolicyAdapter::new("mcp");
