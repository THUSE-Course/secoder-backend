use super::*;

use crate::kubernetes::{
    rotate_user_service_account_token, user_ns, user_service_account_token,
};

pub async fn get_token(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<String, AppError> {
    super::ensure_not_readonly(&state.db).await?;
    user_ns(&state.kube, &claims.id, &state.config.rbac).await?;
    let token =
        user_service_account_token(&state.kube, &claims.id, &state.config.rbac)
            .await?;
    Ok(token)
}

pub async fn rotate_token(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<String, AppError> {
    super::ensure_not_readonly(&state.db).await?;
    let token = rotate_user_service_account_token(
        &state.kube,
        &claims.id,
        &state.config.rbac,
    )
    .await?;
    Ok(token)
}
