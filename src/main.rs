use anyhow::{Context, Result};
use clap::Parser;
use sea_orm::Database;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{Level, event, instrument};
use tracing_subscriber::EnvFilter;

mod config;
mod db;
mod entity;
mod error;
mod kubernetes;
mod metrics;
mod security;
#[cfg(test)]
mod test;
mod view;

use config::Config;
use db::init_db;
use view::{AppState, build_app, build_metrics_app};

#[derive(serde::Deserialize)]
struct PredefinedUser {
    id: String,
    passwd: String,
}

#[derive(Parser, Debug)]
#[command(name = "secoder")]
struct Args {
    #[arg(short, long, default_value = "/etc/config.json")]
    config: String,
}

#[instrument]
#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("secoder=info,warn"));
    let subscriber = tracing_subscriber::fmt()
        .compact()
        .with_file(true)
        .with_line_number(false)
        .with_thread_ids(false)
        .with_target(true)
        .with_env_filter(filter)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();
    let config_path = std::path::Path::new(args.config.as_str());
    let config = load_config(config_path)?;
    event!(Level::INFO, "loaded configuration from {:?}", config_path);

    let database_url = format!("sqlite://{}?mode=rwc", &config.database);
    let conn = Database::connect(&database_url).await?;
    event!(Level::INFO, "found database at {}", &config.database);
    init_db(&conn).await?;

    let predefined_users = load_predefined_users(&config.user)?;
    let state = AppState::new(conn, config.clone(), predefined_users);
    let app = build_app(state.clone());

    let metrics_host = config
        .metrics_host
        .clone()
        .unwrap_or_else(|| "::".to_string());
    let metrics_port = config.metrics_port.unwrap_or(9090);
    let metrics_listener =
        tokio::net::TcpListener::bind((metrics_host.as_str(), metrics_port))
            .await?;
    event!(
        Level::INFO,
        "serving metrics on host {} port {}",
        metrics_host,
        metrics_port
    );
    let metrics_app = build_metrics_app(state.clone());

    let listener =
        tokio::net::TcpListener::bind((config.host.as_str(), config.port))
            .await?;
    event!(
        Level::INFO,
        "listening on host {} port {}",
        config.host,
        config.port
    );
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let shutdown_signal_task = {
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            let _ = shutdown_tx.send(());
        })
    };

    let mut metrics_shutdown = shutdown_tx.subscribe();
    let metrics_server = axum::serve(metrics_listener, metrics_app)
        .with_graceful_shutdown(async move {
            let _ = metrics_shutdown.recv().await;
        });

    let mut app_shutdown = shutdown_tx.subscribe();
    let app_server =
        axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = app_shutdown.recv().await;
        });

    let _ = tokio::join!(metrics_server, app_server, shutdown_signal_task);
    Ok(())
}

fn load_config(path: &std::path::Path) -> Result<Config> {
    if path.exists() {
        let contents = std::fs::read_to_string(path).with_context(|| {
            format!("failed to read config: {}", path.display())
        })?;
        let config: Config =
            serde_json::from_str(&contents).with_context(|| {
                format!("failed to parse config: {}", path.display())
            })?;
        Ok(config)
    } else {
        Ok(Config::default())
    }
}

fn load_predefined_users(
    path: &str,
) -> Result<std::collections::HashMap<String, String>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read users file: {}", path))?;
    let users: Vec<PredefinedUser> = serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse users file: {}", path))?;
    let mut map = std::collections::HashMap::new();
    for user in users {
        if map.insert(user.id.clone(), user.passwd).is_some() {
            return Err(anyhow::anyhow!(
                "duplicate user id in users file: {}",
                user.id
            ));
        }
    }
    Ok(map)
}

async fn shutdown_signal() {
    let mut sigint =
        signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut sigterm =
        signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
         _ = sigint.recv() => {},
         _ = sigterm.recv() => {},
    }
    tracing::event!(tracing::Level::INFO, "gracefully shutting down");
}
