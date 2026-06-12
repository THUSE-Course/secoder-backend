use serde::Deserialize;

pub const DEFAULT_JWT_TTL: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub service: Endpoint,
    pub metrics: Endpoint,
    pub database: String,
    pub jwt: Jwt,
    pub rbac: Rbac,
    pub webhook: Webhook,
}

#[derive(Clone, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            service: Endpoint {
                host: "::".to_string(),
                port: 8080,
            },
            metrics: Endpoint {
                host: "::".to_string(),
                port: 9090,
            },
            database: "/srv/secoder.db".to_string(),
            jwt: Jwt::default(),
            rbac: Rbac::default(),
            webhook: Webhook::default(),
        }
    }
}

#[derive(Clone, Deserialize, Default)]
#[serde(default)]
pub struct Webhook {
    pub url: String,
}

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct Jwt {
    pub ttl: u64,
}

impl Default for Jwt {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_JWT_TTL,
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct Rbac {
    pub account: String,
    pub group: String,
    pub user: String,
    pub label: String,
    pub clusterrole: String,
    pub root_clusterrole: String,
}

impl Default for Rbac {
    fn default() -> Self {
        Self {
            account: "default".to_string(),
            group: "g-".to_string(),
            user: "u-".to_string(),
            label: "secoder".to_string(),
            clusterrole: "secoder".to_string(),
            root_clusterrole: "cluster-admin".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, DEFAULT_JWT_TTL};

    #[test]
    fn jwt_ttl_defaults_to_seven_days() {
        assert_eq!(Config::default().jwt.ttl, DEFAULT_JWT_TTL);
    }

    #[test]
    fn jwt_ttl_can_be_overridden_from_config() {
        let config: Config =
            serde_json::from_str(r#"{"jwt":{"ttl":42}}"#).unwrap();
        assert_eq!(config.jwt.ttl, 42);
    }
}
