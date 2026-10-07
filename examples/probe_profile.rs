//! Local endpoint for reproducing TLS records and native-client compatibility.
//! Uses an explicitly supplied certificate and does not contact the panel.

use std::sync::Arc;

use clap::Parser;
use server_anytls_rs::{Server, SinglePasswordAuth};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    cert: String,
    #[arg(long)]
    key: String,
    #[arg(long, default_value = "127.0.0.1:19401")]
    listen: String,
    #[arg(long)]
    password: String,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    reference_profile: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut cert = std::io::BufReader::new(std::fs::File::open(args.cert)?);
    let certs = rustls_pemfile::certs(&mut cert).collect::<std::io::Result<Vec<_>>>()?;
    let mut key = std::io::BufReader::new(std::fs::File::open(args.key)?);
    let key = rustls_pemfile::private_key(&mut key)?
        .ok_or_else(|| anyhow::anyhow!("missing private key"))?;
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
    let server = Arc::new(
        Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new(&args.password)))
            .auth_probe_resistance(args.reference_profile)
            .tls_config(tls)
            .build()?,
    );
    let listener = TcpListener::bind(args.listen).await?;
    let stop = CancellationToken::new();
    let signal = stop.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        signal.cancel();
    });
    server.run(listener, stop).await?;
    Ok(())
}
