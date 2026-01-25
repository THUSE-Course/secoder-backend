use anyhow::Result;
use clap::Parser;
use rusqlite::Connection;
use std::sync::{Arc, Mutex};
use tokio::signal::unix::{SignalKind, signal};
use tracing::{Level, event, instrument};

pub mod config;
pub mod db;
pub mod error;
pub mod kubernetes;
pub mod view;

use config::Config;
use db::init_db;
use view::{AppState, build_app};

#[derive(Parser, Debug)]
#[command(name = "secoder")]
struct Args {
    #[arg(short, long, default_value = "config.json")]
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
    event!(Level::INFO, "loading configuration from {:?}", config_path);
    let config = Config::load_or_default(config_path)?;

    let conn = Connection::open(&config.database_path)?;
    init_db(&conn)?;

    let state = AppState {
        db: Arc::new(Mutex::new(conn)),
        config: config.clone(),
        oauth_store: Arc::new(Mutex::new(Default::default())),
    };
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
