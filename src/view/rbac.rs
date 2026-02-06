use super::*;

use crate::kubernetes::user_service_account_token;

pub async fn get_token(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<String, AppError> {
    let token =
        user_service_account_token(&claims.id, &state.config.rbac).await?;
    Ok(token)
}
