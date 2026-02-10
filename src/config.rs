use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub service: Endpoint,
    pub metrics: Endpoint,
    pub database: String,
    pub jwt: Jwt,
    pub rbac: Rbac,
    pub user: String,
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
            user: "/srv/users.json".to_string(),
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
        Self { ttl: 3600 }
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
}

impl Default for Rbac {
    fn default() -> Self {
        Self {
            account: "default".to_string(),
            group: "g-".to_string(),
            user: "u-".to_string(),
            label: "secoder".to_string(),
            clusterrole: "secoder".to_string(),
        }
    }
}
