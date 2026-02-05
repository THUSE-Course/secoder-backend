use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use sea_orm::Database;
use tower::ServiceExt;

use crate::config::Config;
use crate::db::init_db;
use crate::view::{AppState, JWT_SECRET, JWT_TTL, build_app};

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
    config.oauth.client_id = "gitlab-client".to_string();
    config.oauth.client_secret = "gitlab-secret".to_string();
    config.oauth.redirect_uri =
        "https://example.com/oauth/callback".to_string();
    config.frontend = "https://frontend.example.com/login".to_string();
    JWT_SECRET.set(config.jwt.clone()).unwrap();
    JWT_TTL.set(config.oauth.token_ttl_secs).unwrap();
    let mut users = std::collections::HashMap::new();
    users.insert("s12345".to_string(), "s12345".to_string());
    build_app(AppState::new(db, config, users))
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
    assert_eq!(response.status(), StatusCode::OK);

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
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth2/v1/authorize?response_type=code&client_id=gitlab-client&redirect_uri=https%3A%2F%2Fexample.com%2Foauth%2Fcallback&state=xyz&scope=read_user")
                .body(Body::empty())
                .expect("build authorize get request"),
        )
        .await
        .expect("authorize get response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .expect("redirect location");
    let location = location.to_str().expect("location string");
    let url = url::Url::parse(location).expect("authorize redirect url");
    assert_eq!(
        url.origin().ascii_serialization(),
        "https://frontend.example.com"
    );
    assert_eq!(url.path(), "/login");
    let txn = url
        .query_pairs()
        .find_map(|(k, v)| {
            if k == "txn" {
                Some(v.into_owned())
            } else {
                None
            }
        })
        .expect("txn query param");

    let form_body = format!("txn={}&id=s12345&password=s12345", txn);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/v1/authorize")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form_body))
                .expect("build authorize post request"),
        )
        .await
        .expect("authorize post response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .expect("redirect location");
    let location = location.to_str().expect("location string");
    assert_eq!(location, format!("/txn/{}", txn));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(location)
                .body(Body::empty())
                .expect("build txn request"),
        )
        .await
        .expect("txn response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .expect("redirect location");
    let location = location.to_str().expect("location string");
    assert!(location.starts_with("https://example.com/oauth/callback?"));
    let code = location
        .split("code=")
        .nth(1)
        .and_then(|value| value.split('&').next())
        .expect("oauth code");

    let token_body = serde_json::json!({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://example.com/oauth/callback",
        "client_id": "gitlab-client",
        "client_secret": "gitlab-secret"
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/v1/token")
                .header("content-type", "application/json")
                .body(Body::from(token_body.to_string()))
                .expect("build token request"),
        )
        .await
        .expect("token response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("parse json");
    assert!(json["access_token"].is_string());
    assert_eq!(json["token_type"], "Bearer");
    assert!(json["expires_in"].is_number());
}
