use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Effect { Allow, Deny }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Permission {
    pub id: String,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub effect: Effect,
    #[serde(default)]
    pub conditions: serde_json::Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthorizationModel {
    pub permissions: Vec<Permission>,
}

impl AuthorizationModel {
    pub fn add(&mut self, permission: Permission) { self.permissions.push(permission); }

    pub fn effective(&self, principal: &str, action: &str, resource: &str) -> Vec<&Permission> {
        self.permissions.iter().filter(|p| p.principal == principal
            && matches_pattern(&p.action, action)
            && matches_pattern(&p.resource, resource)).collect()
    }

    pub fn is_allowed(&self, principal: &str, action: &str, resource: &str) -> bool {
        let matches = self.effective(principal, action, resource);
        let denied = matches.iter().any(|p| p.effect == Effect::Deny);
        let allowed = matches.iter().any(|p| p.effect == Effect::Allow);
        allowed && !denied
    }
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
    pattern == "*" || pattern.eq_ignore_ascii_case(value)
}
