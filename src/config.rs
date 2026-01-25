use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Clone, Deserialize)]
pub struct KubernetesConfig {
    #[serde(default)]
    pub user_ns_prefix: String,
    #[serde(default)]
    pub group_ns_prefix: String,
    #[serde(default)]
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
pub struct OAuthProviderConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub code_ttl_secs: u64,
    #[serde(default)]
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
pub struct Config {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub database_path: String,
    #[serde(default)]
    pub jwt_secret: String,
    #[serde(default)]
    pub oauth: OAuthProviderConfig,
    #[serde(default)]
    pub kubernetes: KubernetesConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: "::".to_string(),
            port: 8080,
            database_path: "secoder.db".to_string(),
            jwt_secret: "change-me".to_string(),
            oauth: OAuthProviderConfig::default(),
            kubernetes: KubernetesConfig::default(),
        }
    }
}

impl Config {
    pub fn from_path(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path).with_context(|| {
            format!("failed to read config: {}", path.display())
        })?;
        let config: Config =
            serde_json::from_str(&contents).with_context(|| {
                format!("failed to parse config: {}", path.display())
            })?;
        Ok(config)
    }

    pub fn load_or_default(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::from_path(path)
        } else {
            Ok(Self::default())
        }
    }

    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
