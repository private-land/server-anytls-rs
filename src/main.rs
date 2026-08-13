mod acl;
mod business;
mod config;
mod config_auto;
mod logger;
mod net;

use logger::log;

use anyhow::Result;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::business::{
    AnyTlsAuthenticator, AnyTlsStatsCollector, AnyTlsUserManager, ApiManager, BackgroundTasks,
    PanelConfig, PanelStatsCollector, TaskConfig,
};
use panel_core::PanelApi;
use server_anytls_rs::{ConnectionManager, OutboundRouter, StatsCollector};

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = config::CliArgs::parse_args();
    cli.validate()?;

    logger::init_logger(&cli.log_mode);

    log::info!(
        api = %cli.api,
        node = cli.node,
        "Starting AnyTLS server"
    );

    // Create panel config (v0.1.6: uses data_dir instead of state_file_path)
    let panel_config = PanelConfig {
        api: cli.api.clone(),
        token: cli.token.clone(),
        node_id: cli.node,
        node_type: panel_core::NodeType::AnyTls,
        api_timeout: cli.api_timeout.as_secs(),
        debug: cli.log_mode == "debug",
        data_dir: cli.data_dir.clone(),
        ip_version: cli.panel_ip_version,
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };

    let api_manager = Arc::new(ApiManager::new(panel_config)?);

    let user_manager = Arc::new(AnyTlsUserManager::new(business::sha256_key));

    // Fetch config from panel
    let node_config = api_manager.fetch_config().await?;
    let remote_config = config::parse_anytls_config(node_config)?;

    // Initialize node
    api_manager.initialize(remote_config.server_port).await?;
    log::info!("Node initialized");

    // Fetch initial users
    let users = api_manager.fetch_users().await?;
    if let Some(users) = users {
        user_manager.init(&users);
    }

    // Build TLS config
    let tls_config = build_tls_config(&cli.cert_file, &cli.key_file)?;

    // Build router (ACL or direct)
    let router: Arc<dyn OutboundRouter> = if let Some(ref acl_path) = cli.acl_conf_file {
        let acl_config = acl::load_acl_config(acl_path).await?;
        let engine = acl::AclEngine::new(
            acl_config,
            Some(cli.data_dir.as_path()),
            cli.refresh_geodata,
        )
        .await?;
        Arc::new(acl::AclRouter::with_block_private_ip(
            engine,
            cli.block_private_ip,
        ))
    } else if cli.block_private_ip {
        // No ACL config but still need private IP blocking
        let engine = acl::AclEngine::new_default()?;
        Arc::new(acl::AclRouter::with_block_private_ip(engine, true))
    } else {
        Arc::new(server_anytls_rs::DirectRouter)
    };

    // Build server
    let authenticator = Arc::new(AnyTlsAuthenticator(Arc::clone(&user_manager)));
    let stats_collector = Arc::new(PanelStatsCollector::new());
    let anytls_stats = Arc::new(AnyTlsStatsCollector(Arc::clone(&stats_collector)));
    let connection_manager = ConnectionManager::new();

    let resolved_max = config_auto::resolve(cli.max_connections);
    if let Some(bd) = resolved_max.auto {
        log::info!(
            value = resolved_max.value,
            cpus = resolved_max.cpus,
            total_mem_kb = resolved_max.total_mem_kb,
            nofile_soft = resolved_max.nofile_soft,
            cpu_cap = bd.cpu_cap,
            mem_cap = bd.mem_cap,
            fd_cap = bd.fd_cap,
            limiting = bd.limiting.as_str(),
            "max_connections=auto resolved"
        );
    } else {
        // Same fields for Fixed too — operators reach for these numbers when
        // an explicit value turns out wrong (e.g. OOM at 10000).
        log::info!(
            value = resolved_max.value,
            cpus = resolved_max.cpus,
            total_mem_kb = resolved_max.total_mem_kb,
            nofile_soft = resolved_max.nofile_soft,
            "max_connections=fixed"
        );
    }

    let mut builder = server_anytls_rs::Server::builder()
        .authenticator(authenticator)
        .stats(anytls_stats as Arc<dyn StatsCollector>)
        .router(router)
        .tls_config(tls_config)
        .connection_manager(connection_manager.clone())
        .max_connections(resolved_max.value)
        .write_buf_size(cli.write_buf_size)
        .stream_channel_capacity(cli.stream_channel_capacity);

    if let Some(ref rules) = remote_config.padding_rules
        && !rules.is_empty()
    {
        builder = builder.padding_scheme(rules.as_str());
    }

    let server = Arc::new(builder.build()?);

    // Start background tasks with user kick callback
    let task_config = TaskConfig::new(
        cli.fetch_users_interval,
        cli.report_traffics_interval,
        cli.heartbeat_interval,
    );
    let conn_mgr_for_kick = connection_manager.clone();
    let on_diff = Arc::new(move |diff: panel_core::UserDiff| {
        for uid in diff.removed_ids.iter().chain(diff.uuid_changed_ids.iter()) {
            let kicked = conn_mgr_for_kick.kick_user(*uid);
            if kicked > 0 {
                log::info!(user_id = uid, kicked, "Kicked user connections");
            }
        }
    });
    let background_tasks = BackgroundTasks::new(
        task_config,
        Arc::clone(&api_manager),
        Arc::clone(&user_manager),
        Arc::clone(&stats_collector),
    )
    .on_user_diff(on_diff);
    let background_handle = background_tasks.start();

    // Bind listener (dual-stack: IPv4 + IPv6)
    let listener = net::bind_dual_stack(remote_config.server_port)?;
    let addr = listener.local_addr()?;
    log::info!(addr = %addr, "Listening");

    // Shutdown handler
    let cancel_token = CancellationToken::new();
    let cancel_clone = cancel_token.clone();
    let api_for_shutdown = Arc::clone(&api_manager);
    let shutdown_handle = tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigint = signal(SignalKind::interrupt()).expect("Failed to setup SIGINT");
            let mut sigterm = signal(SignalKind::terminate()).expect("Failed to setup SIGTERM");
            tokio::select! {
                _ = sigint.recv() => log::info!("SIGINT received, shutting down..."),
                _ = sigterm.recv() => log::info!("SIGTERM received, shutting down..."),
                _ = cancel_clone.cancelled() => {}
            }
        }
        #[cfg(not(unix))]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => log::info!("Shutdown signal received..."),
                _ = cancel_clone.cancelled() => {}
            }
        }
        cancel_clone.cancel();
        api_for_shutdown
    });

    // Run server
    let server_result = server.run(listener, cancel_token.clone()).await;
    cancel_token.cancel();

    // Graceful shutdown
    log::info!("Server stopped, performing graceful shutdown...");

    // Cancel all active connections and wait for them to drain
    let active = connection_manager.connection_count();
    if active > 0 {
        log::info!(active, "Draining active connections");
        connection_manager
            .shutdown_drain(std::time::Duration::from_secs(5))
            .await;
        let remaining = connection_manager.connection_count();
        if remaining > 0 {
            log::warn!(remaining, "Drain timeout, forcing shutdown");
        } else {
            log::info!("All connections drained");
        }
    }

    if let Ok(api_for_shutdown) = shutdown_handle.await {
        log::info!("Unregistering node...");
        if let Err(e) = api_for_shutdown.unregister().await {
            log::warn!(error = %e, "Failed to unregister node");
        } else {
            log::info!("Node unregistered successfully");
        }
        background_handle.shutdown().await;
    }

    log::info!("Shutdown complete");
    server_result.map_err(Into::into)
}

fn build_tls_config(cert_file: &str, key_file: &str) -> Result<rustls::ServerConfig> {
    use rustls_pemfile::{certs, private_key};
    use std::io::BufReader;

    let cert_data = std::fs::read(cert_file)?;
    let key_data = std::fs::read(key_file)?;

    let certs: Vec<_> =
        certs(&mut BufReader::new(&cert_data[..])).collect::<std::result::Result<Vec<_>, _>>()?;
    let key = private_key(&mut BufReader::new(&key_data[..]))?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_file))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(config)
}
