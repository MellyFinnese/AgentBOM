use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Permission {
    pub principal: String,
    pub action: String,
    pub resource: String,
    #[serde(default)]
    pub effect: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub conditions: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuthorizationModel {
    pub permissions: Vec<Permission>,
}

impl AuthorizationModel {
    pub fn from_json(payload: &str) -> Result<Self, String> {
        serde_json::from_str(payload).map_err(|e| e.to_string())
    }

    pub fn effective_permissions<'a>(&'a self, principal: &str) -> impl Iterator<Item = &'a Permission> {
        self.permissions.iter().filter(move |p| {
            p.principal == principal && p.effect.to_lowercase() != "deny"
        })
    }

    pub fn wildcard_count(&self) -> usize {
        self.permissions.iter().filter(|p| {
            p.action == "*" || p.resource == "*" || p.action == "*:*" || p.resource == "*:*"
        }).count()
    }
}
