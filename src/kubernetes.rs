use std::time::Duration;

use anyhow::Result;
use k8s_openapi::api::{
    authentication::v1::{
        BoundObjectReference, TokenRequest, TokenRequestSpec,
    },
    core::v1::{Namespace, Secret},
    rbac::v1::{ClusterRoleBinding, RoleRef, Subject},
};
use kube::{
    Api, Client, Error as KubeError, ResourceExt,
    api::{
        DeleteParams, ListParams, ObjectMeta, Patch, PatchParams, PostParams,
    },
};
use serde_json::json;
use uuid::Uuid;

use super::config::Rbac;

const RBAC_TOKEN_EXPIRATION_SECONDS: i64 = 180 * 24 * 60 * 60;
const RBAC_TOKEN_AUDIENCE: &str =
    "https://kubernetes.default.svc.cluster.local";
const TOKEN_OWNER_LABEL: &str = "secoder/token-owner";
const TOKEN_CURRENT_LABEL: &str = "secoder/token-current";
const LEGACY_TOKEN_SECRET_NAME: &str = "default-token";

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
    let service_accounts: Api<k8s_openapi::api::core::v1::ServiceAccount> =
        Api::namespaced(client.clone(), &namespace);

    let secret = ensure_current_token_anchor(&secrets, user_id).await?;
    create_bound_token(&service_accounts, &secret, rbac).await
}

pub async fn rotate_user_service_account_token(
    client: &Client,
    user_id: &str,
    rbac: &Rbac,
) -> Result<String> {
    let namespace = user_namespace(user_id, rbac);
    user_ns(client, user_id, rbac).await?;
    ensure_cluster_role_binding(client, user_id, rbac).await?;
    let secrets: Api<Secret> = Api::namespaced(client.clone(), &namespace);
    let service_accounts: Api<k8s_openapi::api::core::v1::ServiceAccount> =
        Api::namespaced(client.clone(), &namespace);

    let new_secret = create_token_anchor(&secrets, user_id, true).await?;
    let token =
        create_bound_token(&service_accounts, &new_secret, rbac).await?;
    delete_old_token_anchors(&secrets, user_id, &new_secret.name_any()).await?;
    Ok(token)
}

pub async fn revoke_user_kubernetes_access(
    client: &Client,
    user_id: &str,
    rbac: &Rbac,
) -> Result<()> {
    let namespace = user_namespace(user_id, rbac);
    let secrets: Api<Secret> = Api::namespaced(client.clone(), &namespace);
    delete_token_anchors(&secrets, user_id).await?;
    delete_secret_if_exists(&secrets, LEGACY_TOKEN_SECRET_NAME).await?;

    let binding_name =
        sanitize_k8s_name(&format!("secoder-{}{}", rbac.user, user_id));
    let bindings: Api<ClusterRoleBinding> = Api::all(client.clone());
    match bindings
        .delete(&binding_name, &DeleteParams::default())
        .await
    {
        Ok(_) => {}
        Err(err) if is_not_found(&err) => {}
        Err(err) => return Err(err.into()),
    }
    Ok(())
}

pub async fn revoke_all_legacy_service_account_tokens(
    client: &Client,
    rbac: &Rbac,
) -> Result<()> {
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let rows = namespaces
        .list(&ListParams::default().labels(&rbac.label))
        .await?;
    for namespace in rows {
        let Some(name) = namespace.metadata.name else {
            continue;
        };
        if !name.starts_with(&rbac.user) {
            continue;
        }
        let secrets: Api<Secret> = Api::namespaced(client.clone(), &name);
        delete_secret_if_exists(&secrets, LEGACY_TOKEN_SECRET_NAME).await?;
    }
    Ok(())
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

async fn ensure_current_token_anchor(
    secrets: &Api<Secret>,
    user_id: &str,
) -> Result<Secret> {
    let anchors = list_token_anchors(secrets, user_id).await?;
    if let Some(secret) = anchors.into_iter().find(|secret| {
        secret
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(TOKEN_CURRENT_LABEL))
            .map(|value| value == "true")
            .unwrap_or(false)
    }) {
        return Ok(secret);
    }
    create_token_anchor(secrets, user_id, true).await
}

async fn create_token_anchor(
    secrets: &Api<Secret>,
    user_id: &str,
    current: bool,
) -> Result<Secret> {
    let name = token_anchor_name();
    let mut labels = std::collections::BTreeMap::new();
    labels.insert(TOKEN_OWNER_LABEL.to_string(), token_owner_label(user_id));
    labels.insert(TOKEN_CURRENT_LABEL.to_string(), current.to_string());
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(name),
            labels: Some(labels),
            ..Default::default()
        },
        type_: Some("Opaque".to_string()),
        ..Default::default()
    };
    Ok(secrets.create(&PostParams::default(), &secret).await?)
}

async fn create_bound_token(
    service_accounts: &Api<k8s_openapi::api::core::v1::ServiceAccount>,
    secret: &Secret,
    rbac: &Rbac,
) -> Result<String> {
    let name = secret.name_any();
    let Some(uid) = secret.metadata.uid.clone() else {
        return Err(anyhow::anyhow!("token anchor secret has no uid"));
    };
    let request = TokenRequest {
        metadata: Default::default(),
        spec: Some(TokenRequestSpec {
            audiences: Some(vec![RBAC_TOKEN_AUDIENCE.to_string()]),
            bound_object_ref: Some(BoundObjectReference {
                api_version: Some("v1".to_string()),
                kind: Some("Secret".to_string()),
                name: Some(name),
                uid: Some(uid),
            }),
            expiration_seconds: Some(RBAC_TOKEN_EXPIRATION_SECONDS),
        }),
        status: None,
    };
    let response = service_accounts
        .create_token_request(&rbac.account, &PostParams::default(), &request)
        .await?;
    response
        .status
        .and_then(|status| status.token)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| anyhow::anyhow!("token request returned no token"))
}

async fn list_token_anchors(
    secrets: &Api<Secret>,
    user_id: &str,
) -> Result<Vec<Secret>> {
    let selector =
        format!("{TOKEN_OWNER_LABEL}={}", token_owner_label(user_id));
    Ok(secrets
        .list(&ListParams::default().labels(&selector))
        .await?
        .items)
}

async fn delete_old_token_anchors(
    secrets: &Api<Secret>,
    user_id: &str,
    keep_name: &str,
) -> Result<()> {
    for secret in list_token_anchors(secrets, user_id).await? {
        let name = secret.name_any();
        if name != keep_name {
            delete_secret_if_exists(secrets, &name).await?;
        }
    }
    Ok(())
}

async fn delete_token_anchors(
    secrets: &Api<Secret>,
    user_id: &str,
) -> Result<()> {
    for secret in list_token_anchors(secrets, user_id).await? {
        delete_secret_if_exists(secrets, &secret.name_any()).await?;
    }
    Ok(())
}

async fn delete_secret_if_exists(
    secrets: &Api<Secret>,
    name: &str,
) -> Result<()> {
    match secrets.delete(name, &DeleteParams::default()).await {
        Ok(_) => Ok(()),
        Err(err) if is_not_found(&err) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn token_anchor_name() -> String {
    format!("secoder-{}", Uuid::new_v4().simple())
}

fn token_owner_label(user_id: &str) -> String {
    sanitize_k8s_name(user_id)
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
    let role_name = cluster_role_for_user(user_id, rbac).to_string();
    let bindings: Api<ClusterRoleBinding> = Api::all(client.clone());
    let binding =
        user_cluster_role_binding(&name, &namespace, &role_name, rbac);

    match bindings.get(&name).await {
        Ok(existing) if cluster_role_binding_matches(&existing, &binding) => {
            return Ok(());
        }
        Ok(_) => {
            bindings.delete(&name, &DeleteParams::default()).await?;
        }
        Err(err) if is_not_found(&err) => {}
        Err(err) => return Err(err.into()),
    }

    create_cluster_role_binding(&bindings, &binding).await
}

fn cluster_role_for_user<'a>(user_id: &str, rbac: &'a Rbac) -> &'a str {
    if user_id == "root" {
        &rbac.root_clusterrole
    } else {
        &rbac.clusterrole
    }
}

fn user_cluster_role_binding(
    name: &str,
    namespace: &str,
    role_name: &str,
    rbac: &Rbac,
) -> ClusterRoleBinding {
    ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: Some("rbac.authorization.k8s.io".to_string()),
            kind: "ClusterRole".to_string(),
            name: role_name.to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: rbac.account.clone(),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        }]),
    }
}

fn cluster_role_binding_matches(
    existing: &ClusterRoleBinding,
    desired: &ClusterRoleBinding,
) -> bool {
    existing.role_ref == desired.role_ref
        && existing.subjects == desired.subjects
}

async fn create_cluster_role_binding(
    bindings: &Api<ClusterRoleBinding>,
    binding: &ClusterRoleBinding,
) -> Result<()> {
    const CREATE_RETRIES: usize = 5;
    for attempt in 0..CREATE_RETRIES {
        match bindings.create(&PostParams::default(), binding).await {
            Ok(_) => return Ok(()),
            Err(err)
                if is_already_exists(&err) && attempt + 1 < CREATE_RETRIES =>
            {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(err) => return Err(err.into()),
        }
    }
    Err(anyhow::anyhow!(
        "cluster role binding still exists after delete retry"
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rbac() -> Rbac {
        Rbac {
            clusterrole: "secoder-user-view".to_string(),
            root_clusterrole: "cluster-admin".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn root_uses_root_cluster_role() {
        let rbac = rbac();
        assert_eq!(cluster_role_for_user("root", &rbac), "cluster-admin");
    }

    #[test]
    fn non_root_uses_default_cluster_role() {
        let rbac = rbac();
        assert_eq!(cluster_role_for_user("alice", &rbac), "secoder-user-view");
    }

    #[test]
    fn custom_root_cluster_role_is_honored() {
        let mut rbac = rbac();
        rbac.root_clusterrole = "custom-root-role".to_string();
        assert_eq!(cluster_role_for_user("root", &rbac), "custom-root-role");
    }

    #[test]
    fn binding_match_checks_role_ref_and_subjects() {
        let rbac = rbac();
        let desired = user_cluster_role_binding(
            "secoder-u-root",
            "u-root",
            "cluster-admin",
            &rbac,
        );
        let same = user_cluster_role_binding(
            "secoder-u-root",
            "u-root",
            "cluster-admin",
            &rbac,
        );
        let different_role = user_cluster_role_binding(
            "secoder-u-root",
            "u-root",
            "secoder-user-view",
            &rbac,
        );
        assert!(cluster_role_binding_matches(&same, &desired));
        assert!(!cluster_role_binding_matches(&different_role, &desired));
    }

    #[test]
    fn token_anchor_name_uses_secoder_prefix() {
        let name = token_anchor_name();
        assert!(name.starts_with("secoder-"));
        assert!(name.len() <= 63);
        assert_eq!(sanitize_k8s_name(&name), name);
    }

    #[test]
    fn token_owner_label_is_selector_safe() {
        assert_eq!(token_owner_label("Alice@Example"), "alice-example");
    }
}
