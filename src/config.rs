use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct KubernetesConfig {
    pub user_ns_prefix: String,
    pub group_ns_prefix: String,
    pub cluster_role: String,
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        Self {
            user_ns_prefix: "u-".to_string(),
            group_ns_prefix: "g-".to_string(),
            cluster_role: "admin".to_string(),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct OAuthProviderConfig {
    pub enabled: bool,
    #[allow(dead_code)]
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub code_ttl_secs: u64,
    pub token_ttl_secs: u64,
}

impl Default for OAuthProviderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uris: Vec::new(),
            code_ttl_secs: 600,
            token_ttl_secs: 3600,
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub metrics_host: Option<String>,
    pub metrics_port: Option<u16>,
    pub database: String,
    pub jwt: String,
    pub user: String,
    pub oauth: OAuthProviderConfig,
    pub kubernetes: KubernetesConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: "::".to_string(),
            port: 8080,
            metrics_host: None,
            metrics_port: None,
            database: "/srv/secoder.db".to_string(),
            jwt: "change-me".to_string(),
            user: "users.json".to_string(),
            oauth: OAuthProviderConfig::default(),
            kubernetes: KubernetesConfig::default(),
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
        assert_eq!(config.jwt, "change-me");
        assert_eq!(config.user, "users.json");
    }
}
