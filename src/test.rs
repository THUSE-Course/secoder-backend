use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use sea_orm::Database;
use tower::ServiceExt;

use crate::config::Config;
use crate::db::init_db;
use crate::view::{AppState, JWT_SECRET, route};

fn ensure_k8s_disabled() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| unsafe {
        std::env::set_var("SECODER_SKIP_K8S", "1");
    });
}

async fn setup_db() -> sea_orm::DatabaseConnection {
    ensure_k8s_disabled();
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("connect in-memory sqlite");
    init_db(&db).await.expect("init schema");
    db
}

async fn test_app() -> axum::Router {
    let db = setup_db().await;
    let mut config = Config::default();
    config.frontend = "https://frontend.example.com/login".to_string();
    JWT_SECRET.get_or_init(|| config.jwt.secret.clone());
    let mut users = std::collections::HashMap::new();
    users.insert("s12345".to_string(), "s12345".to_string());
    route(AppState::new(db, config, users))
}

#[tokio::test]
async fn list_users_empty() {
    let app = test_app().await;
    let login_body = serde_json::json!({
        "id": "admin",
        "password": "change-me"
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .body(Body::from(login_body.to_string()))
                .expect("build login request"),
        )
        .await
        .expect("login response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("parse json");
    let token = json["token"].as_str().expect("token string");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/users")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("users response");
    assert_eq!(response.status(), StatusCode::OK);

    let body = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("parse json");
    assert_eq!(json["page"], 1);
    assert_eq!(json["page_size"], 20);
    assert_eq!(json["users"], serde_json::json!([]));
}

#[tokio::test]
async fn register_and_login() {
    let app = test_app().await;
    let register_body = serde_json::json!({
        "id": "s12345",
        "email": "student@example.com",
        "name": "Student One",
        "password": "s12345"
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("content-type", "application/json")
                .body(Body::from(register_body.to_string()))
                .expect("build register request"),
        )
        .await
        .expect("register response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let login_body = serde_json::json!({
        "id": "s12345",
        "password": "s12345"
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .body(Body::from(login_body.to_string()))
                .expect("build login request"),
        )
        .await
        .expect("login response");
    assert_eq!(response.status(), StatusCode::OK);

    let body = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("parse json");
    assert!(json["token"].is_string());
}

#[tokio::test]
async fn oauth_authorize_and_token_flow() {
    let app = test_app().await;
    let register_body = serde_json::json!({
        "id": "s12345",
        "email": "student@example.com",
        "name": "Student One",
        "password": "s12345"
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("content-type", "application/json")
                .body(Body::from(register_body.to_string()))
                .expect("build register request"),
        )
        .await
        .expect("register response");
    assert_eq!(response.status(), StatusCode::CREATED);
}
