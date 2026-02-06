use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub metrics_host: Option<String>,
    pub metrics_port: Option<u16>,
    pub database: String,
    pub jwt: Jwt,
    pub rbac: Rbac,
    pub user: String,
    pub admin: String,
    pub password: String,
    pub frontend: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: "::".to_string(),
            port: 8080,
            metrics_host: None,
            metrics_port: None,
            database: "/srv/secoder.db".to_string(),
            jwt: Jwt::default(),
            rbac: Rbac::default(),
            user: "users.json".to_string(),
            admin: "admin".to_string(),
            password: "change-me".to_string(),
            frontend: String::new(),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct Jwt {
    pub secret: String,
    pub ttl: u64,
}

impl Default for Jwt {
    fn default() -> Self {
        Self {
            secret: "change-me".to_string(),
            ttl: 3600,
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct Rbac {
    pub account: String,
    pub group: String,
    pub user: String,
}

impl Default for Rbac {
    fn default() -> Self {
        Self {
            account: "default".to_string(),
            group: "g-".to_string(),
            user: "u-".to_string(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::Config;

    #[test]
    fn parse() {
        let raw = r#"{"database":"s.db"}"#;
        let config: Config = serde_json::from_str(raw).unwrap();
        assert_eq!(config.host, "::");
        assert_eq!(config.port, 8080);
        assert!(config.metrics_host.is_none());
        assert!(config.metrics_port.is_none());
        assert_eq!(config.database, "s.db");
        assert_eq!(config.jwt.secret, "change-me");
        assert_eq!(config.rbac.account, "default");
        assert_eq!(config.rbac.group, "g-");
        assert_eq!(config.rbac.user, "u-");
        assert_eq!(config.user, "users.json");
        assert_eq!(config.admin, "admin");
        assert_eq!(config.password, "change-me");
    }
}
