use std::time::Duration;

use anyhow::Result;
use k8s_openapi::api::{
    core::v1::{Namespace, Secret},
    rbac::v1::{ClusterRoleBinding, RoleRef, Subject},
};
use kube::{
    Api, Client, Error as KubeError,
    api::{ObjectMeta, Patch, PatchParams, PostParams},
};
use serde_json::json;

use super::config::Rbac;

pub async fn user_ns(client: &Client, id: &str, rbac: &Rbac) -> Result<()> {
    let namespace = user_namespace(id, rbac);
    let label_value = format!("{}{}", rbac.user, id);
    ensure_namespace(client, &namespace, &label_value, rbac).await
}

pub async fn user_service_account_token(
    client: &Client,
    user_id: &str,
    rbac: &Rbac,
) -> Result<String> {
    let namespace = user_namespace(user_id, rbac);
    ensure_cluster_role_binding(client, user_id, rbac).await?;
    let secrets: Api<Secret> = Api::namespaced(client.clone(), &namespace);
    let secret_name = service_account_token_secret_name(rbac);

    if let Some(token) = get_secret_token(&secrets, &secret_name).await? {
        return Ok(token);
    }

    ensure_service_account_token_secret(&secrets, &secret_name, rbac).await?;

    const TOKEN_RETRIES: usize = 5;
    for _ in 0..TOKEN_RETRIES {
        if let Some(token) = get_secret_token(&secrets, &secret_name).await? {
            return Ok(token);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    Err(anyhow::anyhow!(
        "service account token not available in secret {}",
        secret_name
    ))
}

pub async fn update_group_tenant_label(
    client: &Client,
    group_code_name: &str,
    rbac: &Rbac,
    member_ids: &[String],
) -> Result<()> {
    let namespace =
        sanitize_k8s_name(&format!("{}{}", rbac.group, group_code_name));
    let label_value = member_ids
        .iter()
        .map(|s| format!("{}{s}", rbac.user))
        .collect::<Vec<String>>()
        .join(".");
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let patch = json!({
        "metadata": {
            "labels": {
                &rbac.label: label_value
            }
        }
    });
    match namespaces
        .patch(&namespace, &PatchParams::default(), &Patch::Merge(&patch))
        .await
    {
        Ok(_) => Ok(()),
        Err(err) if is_not_found(&err) => {
            ensure_namespace(client, &namespace, &label_value, rbac).await
        }
        Err(err) => Err(err.into()),
    }
}

fn user_namespace(user_id: &str, rbac: &Rbac) -> String {
    sanitize_k8s_name(&format!("{}{}", rbac.user, user_id))
}

fn service_account_token_secret_name(rbac: &Rbac) -> String {
    sanitize_k8s_name(&format!("{}-token", rbac.account))
}

async fn get_secret_token(
    secrets: &Api<Secret>,
    name: &str,
) -> Result<Option<String>> {
    match secrets.get(name).await {
        Ok(secret) => {
            let data = secret.data.unwrap_or_default();
            if let Some(token) = data.get("token") {
                let token = String::from_utf8(token.0.clone())?;
                Ok(Some(token))
            } else {
                Ok(None)
            }
        }
        Err(err) if is_not_found(&err) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

async fn ensure_service_account_token_secret(
    secrets: &Api<Secret>,
    name: &str,
    rbac: &Rbac,
) -> Result<()> {
    let mut annotations = std::collections::BTreeMap::new();
    annotations.insert(
        "kubernetes.io/service-account.name".to_string(),
        rbac.account.clone(),
    );
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            annotations: Some(annotations),
            ..Default::default()
        },
        type_: Some("kubernetes.io/service-account-token".to_string()),
        ..Default::default()
    };
    match secrets.create(&PostParams::default(), &secret).await {
        Ok(_) => Ok(()),
        Err(err) if is_already_exists(&err) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

async fn ensure_namespace(
    client: &Client,
    name: &str,
    tenant_label: &str,
    rbac: &Rbac,
) -> Result<()> {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert(rbac.label.clone(), tenant_label.to_string());
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let namespace = Namespace {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        ..Default::default()
    };
    match namespaces.create(&PostParams::default(), &namespace).await {
        Ok(_) => Ok(()),
        Err(err) if is_already_exists(&err) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

async fn ensure_cluster_role_binding(
    client: &Client,
    user_id: &str,
    rbac: &Rbac,
) -> Result<()> {
    let name = sanitize_k8s_name(&format!("secoder-{}{}", rbac.user, user_id));
    let namespace = user_namespace(user_id, rbac);
    let bindings: Api<ClusterRoleBinding> = Api::all(client.clone());
    let binding = ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some(name.clone()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: rbac.clusterrole.clone(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: rbac.account.clone(),
            namespace: Some(namespace),
            ..Default::default()
        }]),
    };
    match bindings.create(&PostParams::default(), &binding).await {
        Ok(_) => Ok(()),
        Err(err) if is_already_exists(&err) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn is_already_exists(err: &KubeError) -> bool {
    matches!(err, KubeError::Api(api) if api.code == 409)
}

fn is_not_found(err: &KubeError) -> bool {
    matches!(err, KubeError::Api(api) if api.code == 404)
}

pub fn sanitize_k8s_name(name: &str) -> String {
    let mut sanitized = String::with_capacity(name.len());
    for ch in name.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() || ch == '-' {
            sanitized.push(ch);
        } else {
            sanitized.push('-');
        }
    }
    let trimmed = sanitized.trim_matches('-');
    let mut result = if trimmed.is_empty() {
        "ns".to_string()
    } else {
        trimmed.to_string()
    };
    if result.len() > 63 {
        result.truncate(63);
        while result.ends_with('-') {
            result.pop();
        }
        if result.is_empty() {
            result = "default".to_string();
        }
    }
    result
}
