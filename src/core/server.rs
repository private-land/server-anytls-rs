use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::core::connection::ConnectionManager;

use crate::core::hooks::{Authenticator, NoopStatsCollector, OutboundRouter, StatsCollector};
use crate::core::padding::{DEFAULT_SCHEME, PaddingFactory};
use crate::core::session::{
    DEFAULT_STREAM_CHANNEL_CAPACITY, DEFAULT_WRITE_BUF_SIZE, SessionConfig,
};

/// Enable TCP keepalive on a connection to match Go's default
/// behavior (SO_KEEPALIVE + 30s interval). Without this, dead connections
/// hang for 30s–2min during TCP retransmission timeout before being detected.
pub(crate) fn set_tcp_keepalive(stream: &tokio::net::TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_keepalive(true);
    // TCP_KEEPIDLE=30s (when to start probes), TCP_KEEPINTVL=10s (probe interval).
    // Without setting interval, OS defaults apply (75s on Linux/macOS),
    // making dead-connection detection take 30 + 75*9 = 705s instead of 30 + 10*9 = 120s.
    let _ = sock.set_tcp_keepalive(
        &socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(30))
            .with_interval(Duration::from_secs(10)),
    );
}

// ---------------------------------------------------------------------------
// ServerConfig
// ---------------------------------------------------------------------------

pub struct ServerConfig {
    pub max_connections: usize,
    pub max_streams_per_session: usize,
    pub tcp_connect_timeout: Duration,
    pub handshake_timeout: Duration,
    /// BufWriter buffer size for the TLS write half (bytes).
    pub write_buf_size: usize,
    /// Operator switch for server-side downlink padding ("补包").
    ///
    /// Enabled by default but only takes effect for peers that announce
    /// protocol v2, so legacy clients see byte-identical output. See
    /// [`crate::core::downlink_padding`].
    pub downlink_padding: bool,
    /// Per-stream data channel capacity (number of buffered messages).
    pub stream_channel_capacity: usize,
    /// Maximum time a relay (`copy_bidirectional`) may be idle (no bytes
    /// transferred in either direction) before it is forcibly terminated.
    /// Prevents zombie connections when outbound targets become unresponsive.
    pub relay_idle_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_connections: 10000,
            max_streams_per_session: 256,
            tcp_connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(10),
            write_buf_size: DEFAULT_WRITE_BUF_SIZE,
            downlink_padding: true,
            stream_channel_capacity: DEFAULT_STREAM_CHANNEL_CAPACITY,
            relay_idle_timeout: Duration::from_secs(60),
        }
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

pub struct Server {
    pub(crate) authenticator: Arc<dyn Authenticator>,
    pub(crate) stats: Arc<dyn StatsCollector>,
    pub(crate) router: Arc<dyn OutboundRouter>,
    pub(crate) tls_config: Option<Arc<rustls::ServerConfig>>,
    pub(crate) padding: PaddingFactory,
    pub(crate) config: ServerConfig,
    pub(crate) semaphore: Arc<Semaphore>,
    pub(crate) connection_manager: ConnectionManager,
}

impl Server {
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    pub fn connection_manager(&self) -> &ConnectionManager {
        &self.connection_manager
    }

    pub fn session_config(&self) -> SessionConfig {
        SessionConfig {
            max_streams: self.config.max_streams_per_session,
            write_buf_size: self.config.write_buf_size,
            downlink_padding: self.config.downlink_padding,
            stream_channel_capacity: self.config.stream_channel_capacity,
            ..SessionConfig::default()
        }
    }

    pub async fn run(
        self: &Arc<Self>,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> crate::error::Result<()> {
        tracing::info!("anytls server started");
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!("shutdown signal received");
                    break;
                }
                result = listener.accept() => {
                    let (tcp_stream, peer_addr) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("accept error: {e}");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                    };
                    let _ = tcp_stream.set_nodelay(true);
                    set_tcp_keepalive(&tcp_stream);

                    // Acquire connection permit before spawning — blocks accept
                    // loop when max_connections is reached, queuing new connections
                    // in the kernel TCP backlog instead of exceeding the limit.
                    // Race against shutdown so we remain responsive to cancellation.
                    let permit = tokio::select! {
                        _ = shutdown.cancelled() => break,
                        permit = self.semaphore.clone().acquire_owned() => {
                            match permit {
                                Ok(p) => p,
                                Err(_) => break,
                            }
                        }
                    };

                    let server = self.clone();
                    tokio::spawn(async move {
                        tracing::debug!("new connection from {}", peer_addr);
                        if let Err(e) = crate::handler::handle_connection(server, tcp_stream, peer_addr).await {
                            tracing::debug!("connection from {} ended: {}", peer_addr, e);
                        }
                        drop(permit);
                    });
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ServerBuilder
// ---------------------------------------------------------------------------

pub struct ServerBuilder {
    authenticator: Option<Arc<dyn Authenticator>>,
    stats: Option<Arc<dyn StatsCollector>>,
    router: Option<Arc<dyn OutboundRouter>>,
    tls_config: Option<rustls::ServerConfig>,
    padding_scheme: Option<String>,
    connection_manager: Option<ConnectionManager>,
    max_connections: usize,
    max_streams_per_session: usize,
    tcp_connect_timeout: Duration,
    handshake_timeout: Duration,
    write_buf_size: usize,
    downlink_padding: bool,
    stream_channel_capacity: usize,
    relay_idle_timeout: Duration,
}

impl ServerBuilder {
    fn new() -> Self {
        let defaults = ServerConfig::default();
        Self {
            authenticator: None,
            stats: None,
            router: None,
            tls_config: None,
            padding_scheme: None,
            connection_manager: None,
            max_connections: defaults.max_connections,
            max_streams_per_session: defaults.max_streams_per_session,
            tcp_connect_timeout: defaults.tcp_connect_timeout,
            handshake_timeout: defaults.handshake_timeout,
            write_buf_size: defaults.write_buf_size,
            downlink_padding: defaults.downlink_padding,
            stream_channel_capacity: defaults.stream_channel_capacity,
            relay_idle_timeout: defaults.relay_idle_timeout,
        }
    }

    pub fn authenticator(mut self, auth: Arc<dyn Authenticator>) -> Self {
        self.authenticator = Some(auth);
        self
    }

    pub fn stats(mut self, stats: Arc<dyn StatsCollector>) -> Self {
        self.stats = Some(stats);
        self
    }

    pub fn router(mut self, router: Arc<dyn OutboundRouter>) -> Self {
        self.router = Some(router);
        self
    }

    pub fn tls_config(mut self, tls: rustls::ServerConfig) -> Self {
        self.tls_config = Some(tls);
        self
    }

    pub fn connection_manager(mut self, cm: ConnectionManager) -> Self {
        self.connection_manager = Some(cm);
        self
    }

    pub fn padding_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.padding_scheme = Some(scheme.into());
        self
    }

    pub fn max_connections(mut self, n: usize) -> Self {
        self.max_connections = n;
        self
    }

    pub fn max_streams_per_session(mut self, n: usize) -> Self {
        self.max_streams_per_session = n;
        self
    }

    pub fn tcp_connect_timeout(mut self, d: Duration) -> Self {
        self.tcp_connect_timeout = d;
        self
    }

    pub fn handshake_timeout(mut self, d: Duration) -> Self {
        self.handshake_timeout = d;
        self
    }

    pub fn write_buf_size(mut self, n: usize) -> Self {
        self.write_buf_size = n;
        self
    }

    pub fn downlink_padding(mut self, enabled: bool) -> Self {
        self.downlink_padding = enabled;
        self
    }

    pub fn stream_channel_capacity(mut self, n: usize) -> Self {
        self.stream_channel_capacity = n;
        self
    }

    pub fn relay_idle_timeout(mut self, d: Duration) -> Self {
        self.relay_idle_timeout = d;
        self
    }

    pub fn build(self) -> anyhow::Result<Server> {
        let authenticator = self
            .authenticator
            .ok_or_else(|| anyhow::anyhow!("authenticator is required"))?;

        let stats: Arc<dyn StatsCollector> =
            self.stats.unwrap_or_else(|| Arc::new(NoopStatsCollector));

        let router: Arc<dyn OutboundRouter> = self
            .router
            .unwrap_or_else(|| Arc::new(crate::core::hooks::DirectRouter));

        let scheme = self.padding_scheme.as_deref().unwrap_or(DEFAULT_SCHEME);
        let padding = PaddingFactory::new(scheme)
            .map_err(|e| anyhow::anyhow!("invalid padding scheme: {e}"))?;

        let config = ServerConfig {
            max_connections: self.max_connections,
            max_streams_per_session: self.max_streams_per_session,
            tcp_connect_timeout: self.tcp_connect_timeout,
            handshake_timeout: self.handshake_timeout,
            write_buf_size: self.write_buf_size,
            downlink_padding: self.downlink_padding,
            stream_channel_capacity: self.stream_channel_capacity,
            relay_idle_timeout: self.relay_idle_timeout,
        };

        let semaphore = Arc::new(Semaphore::new(config.max_connections));

        let tls_config = self.tls_config.map(|mut tls| {
            // Enable session tickets for TLS resumption — avoids a full
            // handshake on reconnect, reducing latency by 1-RTT.
            match rustls::crypto::aws_lc_rs::Ticketer::new() {
                Ok(ticketer) => tls.ticketer = ticketer,
                Err(e) => tracing::warn!("failed to create TLS session ticketer: {e}"),
            }
            Arc::new(tls)
        });

        let connection_manager = self.connection_manager.unwrap_or_default();

        Ok(Server {
            authenticator,
            stats,
            router,
            tls_config,
            padding,
            config,
            semaphore,
            connection_manager,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::hooks::*;

    #[test]
    fn test_server_builder_defaults() {
        let server = Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new("test")))
            .build()
            .unwrap();
        assert_eq!(server.config.max_connections, 10000);
        assert_eq!(server.config.max_streams_per_session, 256);
        assert_eq!(server.config.handshake_timeout, Duration::from_secs(10));
        assert_eq!(server.config.relay_idle_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_server_builder_custom_config() {
        let server = Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new("test")))
            .max_connections(500)
            .max_streams_per_session(64)
            .tcp_connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        assert_eq!(server.config.max_connections, 500);
        assert_eq!(server.config.max_streams_per_session, 64);
        assert_eq!(
            server.config.tcp_connect_timeout,
            std::time::Duration::from_secs(10)
        );
    }

    #[test]
    #[should_panic(expected = "authenticator is required")]
    fn test_server_builder_missing_auth() {
        Server::builder().build().unwrap();
    }

    #[test]
    fn test_server_builder_with_custom_hooks() {
        let server = Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new("pw")))
            .stats(Arc::new(NoopStatsCollector))
            .router(Arc::new(DirectRouter))
            .build()
            .unwrap();
        let _ = server;
    }

    #[test]
    fn test_session_config() {
        let server = Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new("test")))
            .max_streams_per_session(128)
            .build()
            .unwrap();
        let sc = server.session_config();
        assert_eq!(sc.max_streams, 128);
    }

    /// Verify that `set_tcp_keepalive` enables SO_KEEPALIVE on a socket.
    #[tokio::test]
    async fn test_accepted_connection_has_tcp_keepalive() {
        use tokio::net::TcpStream;

        let test_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let test_addr = test_listener.local_addr().unwrap();

        let client_handle =
            tokio::spawn(async move { TcpStream::connect(test_addr).await.unwrap() });

        let (accepted, _peer) = test_listener.accept().await.unwrap();

        let _ = accepted.set_nodelay(true);
        set_tcp_keepalive(&accepted);

        let sock = socket2::SockRef::from(&accepted);
        let keepalive = sock.keepalive().unwrap();

        drop(client_handle);

        assert!(
            keepalive,
            "TCP keepalive should be enabled on accepted connections"
        );
    }

    /// RED: set_tcp_keepalive should configure keepalive interval (TCP_KEEPINTVL),
    /// not just the idle time (TCP_KEEPIDLE). Without setting interval, Linux
    /// defaults to 75s between probes × 9 retries = 675s to detect a dead
    /// connection. With a 10s interval the detection time drops to ~120s.
    #[tokio::test]
    async fn test_tcp_keepalive_sets_interval() {
        use tokio::net::TcpStream;

        let test_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let test_addr = test_listener.local_addr().unwrap();

        let client_handle =
            tokio::spawn(async move { TcpStream::connect(test_addr).await.unwrap() });

        let (accepted, _peer) = test_listener.accept().await.unwrap();
        set_tcp_keepalive(&accepted);

        let sock = socket2::SockRef::from(&accepted);

        drop(client_handle);

        // keepalive_interval() returns the TCP_KEEPINTVL value.
        // If set_tcp_keepalive properly configured it, it should be ≤ 30s.
        // RED: Currently only TCP_KEEPIDLE is set; interval is OS default
        // (75s on Linux, 75s on macOS), so this assertion fails.
        let interval = sock.tcp_keepalive_interval().expect(
            "keepalive_interval() should be readable — if this fails, \
             TCP_KEEPINTVL was never set",
        );
        assert!(
            interval <= Duration::from_secs(30),
            "TCP keepalive interval should be ≤ 30s for fast dead-connection \
             detection, but got {interval:?}. set_tcp_keepalive only sets \
             TCP_KEEPIDLE, not TCP_KEEPINTVL — dead connections take 675s+ \
             to detect with OS defaults."
        );
    }
}
