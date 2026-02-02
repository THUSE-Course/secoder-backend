use super::*;

pub(super) async fn health_check() -> Json<serde_json::Value> {
    ok_status()
}
