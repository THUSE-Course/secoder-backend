use anyhow::Result;
use clap::Parser;
use sea_orm::Database;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{Level, event, instrument};

mod config;
mod db;
mod entity;
mod error;
mod kubernetes;
mod view;
#[cfg(test)]
mod test;

use crate::config::Config;
use crate::db::init_db;
use crate::view::{AppState, build_app};

#[derive(Parser, Debug)]
#[command(name = "secoder")]
struct Args {
    #[arg(short, long, default_value = "/etc/config.json")]
    config: String,
}

#[instrument]
#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .compact()
        .with_file(true)
        .with_line_number(false)
        .with_thread_ids(false)
        .with_target(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();
    let config_path = std::path::Path::new(args.config.as_str());
    let config = Config::load_or_default(config_path)?;
    event!(Level::INFO, "loaded configuration from {:?}", config_path);

    let database_url = format!("sqlite://{}?mode=rwc", &config.database);
    let conn = Database::connect(&database_url).await?;
    event!(Level::INFO, "found database at {}", &config.database);
    init_db(&conn).await?;

    let state = AppState::new(conn, config.clone());
    let app = build_app(state);

    let listener = tokio::net::TcpListener::bind(config.bind_address()).await?;
    event!(Level::INFO, "listening on {}", config.bind_address());
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
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
