use super::*;

use crate::kubernetes::{user_ns, user_service_account_token};

pub async fn get_token(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<String, AppError> {
    user_ns(&state.kube, &claims.id, &state.config.rbac).await?;
    let token =
        user_service_account_token(&state.kube, &claims.id, &state.config.rbac)
            .await?;
    Ok(token)
}
