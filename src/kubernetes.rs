use anyhow::Result;
use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::api::rbac::v1::{RoleBinding, RoleRef, Subject};
use kube::api::{ObjectMeta, PostParams};
use kube::{Api, Client, Error as KubeError};

use super::config::KubernetesConfig;

pub async fn user_ns(
    config: &KubernetesConfig,
    student_id: &str,
) -> Result<()> {
    if should_skip_k8s() {
        return Ok(());
    }
    let namespace =
        sanitize_k8s_name(&format!("{}{}", config.user_ns_prefix, student_id));
    let binding_name = sanitize_k8s_name(&format!("rb-{}", student_id));
    let client = Client::try_default().await?;
    ensure_namespace(&client, &namespace).await?;
    ensure_user_rolebinding(
        &client,
        &namespace,
        &binding_name,
        student_id,
        &config.cluster_role,
    )
    .await?;
    Ok(())
}

pub async fn group_ns(
    config: &KubernetesConfig,
    group_code: &str,
    leader_id: &str,
) -> Result<()> {
    if should_skip_k8s() {
        return Ok(());
    }
    let namespace =
        sanitize_k8s_name(&format!("{}{}", config.group_ns_prefix, group_code));
    let binding_name = sanitize_k8s_name(&format!("rb-{}", leader_id));
    let client = Client::try_default().await?;
    ensure_namespace(&client, &namespace).await?;
    ensure_user_rolebinding(
        &client,
        &namespace,
        &binding_name,
        leader_id,
        &config.cluster_role,
    )
    .await?;
    Ok(())
}

pub async fn group_acl(
    config: &KubernetesConfig,
    group_code: &str,
    student_id: &str,
) -> Result<()> {
    if should_skip_k8s() {
        return Ok(());
    }
    let namespace =
        sanitize_k8s_name(&format!("{}{}", config.group_ns_prefix, group_code));
    let binding_name = sanitize_k8s_name(&format!("rb-{}", student_id));
    let client = Client::try_default().await?;
    ensure_namespace(&client, &namespace).await?;
    ensure_user_rolebinding(
        &client,
        &namespace,
        &binding_name,
        student_id,
        &config.cluster_role,
    )
    .await?;
    Ok(())
}

async fn ensure_namespace(client: &Client, name: &str) -> Result<()> {
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let namespace = Namespace {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
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

async fn ensure_user_rolebinding(
    client: &Client,
    namespace: &str,
    binding_name: &str,
    user_name: &str,
    cluster_role: &str,
) -> Result<()> {
    let bindings: Api<RoleBinding> = Api::namespaced(client.clone(), namespace);
    let binding = RoleBinding {
        metadata: ObjectMeta {
            name: Some(binding_name.to_string()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: cluster_role.to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "User".to_string(),
            api_group: Some("rbac.authorization.k8s.io".to_string()),
            name: user_name.to_string(),
            namespace: None,
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

fn should_skip_k8s() -> bool {
    std::env::var_os("SECODER_SKIP_K8S").is_some()
}

fn sanitize_k8s_name(name: &str) -> String {
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
            result = "ns".to_string();
        }
    }
    result
}
