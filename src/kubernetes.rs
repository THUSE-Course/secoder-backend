use anyhow::Result;
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{ObjectMeta, PostParams};
use kube::{Api, Client, Error as KubeError};

pub async fn user_ns(student_id: &str) -> Result<()> {
    if should_skip_k8s() {
        return Ok(());
    }
    let namespace = sanitize_k8s_name(&format!("u-{}", student_id));
    let label_value = format!("u-{}", student_id);
    let client = Client::try_default().await?;
    ensure_namespace(&client, &namespace, &label_value).await?;
    Ok(())
}

pub async fn group_ns(group_code: &str) -> Result<()> {
    if should_skip_k8s() {
        return Ok(());
    }
    let namespace = sanitize_k8s_name(&format!("g-{}", group_code));
    let label_value = format!("g-{}", group_code);
    let client = Client::try_default().await?;
    ensure_namespace(&client, &namespace, &label_value).await?;
    Ok(())
}

async fn ensure_namespace(
    client: &Client,
    name: &str,
    tenant_label: &str,
) -> Result<()> {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert(
        "toolkit.fluxcd.io/tenant".to_string(),
        tenant_label.to_string(),
    );
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
