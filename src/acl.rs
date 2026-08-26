//! ACL (Access Control List) Engine integration
//!
//! Provides rule-based traffic routing with support for:
//! - Direct connections
//! - SOCKS5 proxy
//! - HTTP/HTTPS proxy
//! - Reject (block) connections
//!
//! Configuration format (YAML):
//! ```yaml
//! outbounds:
//!   - name: warp
//!     type: socks5
//!     socks5:
//!       addr: 127.0.0.1:40000
//!   - name: http-proxy
//!     type: http
//!     http:
//!       addr: 127.0.0.1:8080
//! acl:
//!   inline:
//!     - reject(all, udp/443)
//!     - warp(suffix:google.com)
//!     - direct(all)
//! ```

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// Re-export types from acl-engine-rs
pub use acl_engine_rs::{
    HostInfo, Protocol,
    geo::{AutoGeoLoader, GeoIpFormat, GeoSiteFormat, NilGeoLoader},
    outbound::{
        Addr, AsyncOutbound, AsyncTcpConn, AsyncUdpConn, Direct, DirectMode, DirectOptions, Http,
        Reject, Socks5,
    },
};

use crate::logger::log;

/// ACL configuration loaded from YAML file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclConfig {
    /// List of outbound configurations
    #[serde(default)]
    pub outbounds: Vec<OutboundEntry>,

    /// ACL rules configuration
    #[serde(default)]
    pub acl: AclRules,
}

/// ACL rules section
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AclRules {
    /// Inline rules (list of rule strings)
    #[serde(default)]
    pub inline: Vec<String>,
}

/// Outbound entry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundEntry {
    /// Outbound name (used in rules)
    pub name: String,

    /// Outbound type: "direct", "socks5", "http", "reject"
    #[serde(rename = "type")]
    pub outbound_type: String,

    /// SOCKS5 configuration (when type = "socks5")
    #[serde(default)]
    pub socks5: Option<Socks5Config>,

    /// HTTP proxy configuration (when type = "http")
    #[serde(default)]
    pub http: Option<HttpConfig>,

    /// Direct configuration (when type = "direct")
    #[serde(default)]
    pub direct: Option<DirectConfig>,
}

/// SOCKS5 outbound configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Config {
    /// SOCKS5 server address (host:port)
    pub addr: String,

    /// Optional username for authentication
    #[serde(default)]
    pub username: Option<String>,

    /// Optional password for authentication
    #[serde(default)]
    pub password: Option<String>,

    /// Whether to allow UDP through this proxy (default: true)
    #[serde(default = "default_allow_udp")]
    pub allow_udp: bool,
}

fn default_allow_udp() -> bool {
    true
}

/// HTTP proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    /// HTTP proxy server address (host:port or full URL)
    pub addr: String,

    /// Optional username for basic authentication
    #[serde(default)]
    pub username: Option<String>,

    /// Optional password for basic authentication
    #[serde(default)]
    pub password: Option<String>,

    /// Use HTTPS for proxy connection
    #[serde(default)]
    pub https: bool,
}

/// Direct outbound configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectConfig {
    /// IP mode: "auto", "4", "6", "prefer4", "prefer6"
    #[serde(default = "default_ip_mode")]
    pub mode: String,

    /// Bind outgoing connections to a specific local IPv4 address
    #[serde(rename = "bindIPv4", default)]
    pub bind_ipv4: Option<String>,

    /// Bind outgoing connections to a specific local IPv6 address
    #[serde(rename = "bindIPv6", default)]
    pub bind_ipv6: Option<String>,

    /// Bind outgoing connections to a specific network device (Linux only, SO_BINDTODEVICE)
    /// Mutually exclusive with bindIPv4/bindIPv6
    #[serde(rename = "bindDevice", default)]
    pub bind_device: Option<String>,

    /// Enable TCP Fast Open for outgoing connections (Linux/macOS)
    #[serde(rename = "fastOpen", default)]
    pub fast_open: bool,

    /// Enable TCP_NODELAY (disable Nagle's algorithm). Default: true.
    #[serde(rename = "tcpNoDelay", default = "default_tcp_nodelay")]
    pub tcp_nodelay: bool,

    /// TCP keepalive interval in seconds. 0 = disable. Default: 60.
    #[serde(rename = "tcpKeepAlive", default = "default_tcp_keepalive_secs")]
    pub tcp_keepalive_secs: u64,

    /// Connect timeout in seconds for this outbound. 0 = use the built-in
    /// default (10s). Intended to fail faster than the server's global
    /// `tcp_connect_timeout`: the effective connect timeout is the smaller of
    /// the two (the connect path also wraps the dial in `tcp_connect_timeout`),
    /// so a value larger than `tcp_connect_timeout` has no additional effect.
    #[serde(rename = "connectTimeout", default)]
    pub connect_timeout_secs: u64,
}

fn default_ip_mode() -> String {
    "auto".to_string()
}

fn default_tcp_nodelay() -> bool {
    true
}

fn default_tcp_keepalive_secs() -> u64 {
    60
}

impl Default for DirectConfig {
    fn default() -> Self {
        Self {
            mode: default_ip_mode(),
            bind_ipv4: None,
            bind_ipv6: None,
            bind_device: None,
            fast_open: false,
            tcp_nodelay: default_tcp_nodelay(),
            tcp_keepalive_secs: default_tcp_keepalive_secs(),
            connect_timeout_secs: 0,
        }
    }
}

/// Outbound handler wrapper
#[derive(Clone)]
pub enum OutboundHandler {
    /// Direct connection. `custom_dial` is true when the outbound sets any
    /// dialing option a bare `connect_target()` cannot apply — bindIPv4/bindIPv6/
    /// bindDevice, a non-`auto` IP mode, TCP Fast Open, a non-default TCP_NODELAY,
    /// a non-default keepalive, or a non-default connect timeout — so the router
    /// routes such handlers through their own dialer (`inner`).
    Direct {
        inner: Arc<Direct>,
        custom_dial: bool,
    },
    /// SOCKS5 proxy
    Socks5 { inner: Arc<Socks5>, allow_udp: bool },
    /// HTTP proxy
    Http(Arc<Http>),
    /// Reject connection
    Reject(Arc<Reject>),
}

impl std::fmt::Debug for OutboundHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundHandler::Direct { .. } => write!(f, "Direct"),
            OutboundHandler::Socks5 { allow_udp, .. } => write!(f, "Socks5(udp={})", allow_udp),
            OutboundHandler::Http(_) => write!(f, "Http"),
            OutboundHandler::Reject(_) => write!(f, "Reject"),
        }
    }
}

impl OutboundHandler {
    /// Create OutboundHandler from configuration entry
    pub fn from_entry(entry: &OutboundEntry) -> Result<Self> {
        match entry.outbound_type.as_str() {
            "direct" => {
                let config = entry.direct.as_ref();
                let mode = config.map(|d| d.mode.as_str()).unwrap_or("auto");

                let direct_mode = match mode {
                    "auto" => DirectMode::Auto,
                    "4" | "only4" => DirectMode::Only4,
                    "6" | "only6" => DirectMode::Only6,
                    "prefer4" | "46" => DirectMode::Prefer46,
                    "prefer6" | "64" => DirectMode::Prefer64,
                    _ => {
                        return Err(anyhow!(
                            "Invalid direct mode '{}' for outbound '{}', \
                             valid values: auto, 4, only4, 6, only6, prefer4, 46, prefer6, 64",
                            mode,
                            entry.name
                        ));
                    }
                };

                let bind_ip4 = config
                    .and_then(|d| d.bind_ipv4.as_deref())
                    .map(|s| {
                        s.parse::<std::net::Ipv4Addr>()
                            .map_err(|e| anyhow!("Invalid bindIPv4 '{}': {}", s, e))
                    })
                    .transpose()?;
                let bind_ip6 = config
                    .and_then(|d| d.bind_ipv6.as_deref())
                    .map(|s| {
                        s.parse::<std::net::Ipv6Addr>()
                            .map_err(|e| anyhow!("Invalid bindIPv6 '{}': {}", s, e))
                    })
                    .transpose()?;
                let bind_device = config.and_then(|d| d.bind_device.clone());
                let fast_open = config.is_some_and(|d| d.fast_open);
                let tcp_nodelay = config
                    .map(|d| d.tcp_nodelay)
                    .unwrap_or_else(default_tcp_nodelay);
                let tcp_keepalive_secs = config
                    .map(|d| d.tcp_keepalive_secs)
                    .unwrap_or_else(default_tcp_keepalive_secs);
                let tcp_keepalive = if tcp_keepalive_secs > 0 {
                    Some(std::time::Duration::from_secs(tcp_keepalive_secs))
                } else {
                    None
                };
                let connect_timeout_secs = config.map(|d| d.connect_timeout_secs).unwrap_or(0);
                let connect_timeout = if connect_timeout_secs > 0 {
                    Some(std::time::Duration::from_secs(connect_timeout_secs))
                } else {
                    None
                };

                // Validate bind IPs at startup by trying to bind a test socket
                if let Some(ip) = bind_ip4 {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(|e| anyhow!("Failed to create test socket: {}", e))?;
                    let bind_addr: std::net::SocketAddr =
                        std::net::SocketAddr::new(std::net::IpAddr::V4(ip), 0);
                    socket.bind(&bind_addr.into()).map_err(|e| {
                        anyhow!(
                            "FATAL: outbound '{}' bindIPv4 {} failed: {}",
                            entry.name,
                            ip,
                            e
                        )
                    })?;
                }
                if let Some(ip) = bind_ip6 {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV6,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(|e| anyhow!("Failed to create test socket: {}", e))?;
                    let bind_addr: std::net::SocketAddr =
                        std::net::SocketAddr::new(std::net::IpAddr::V6(ip), 0);
                    socket.bind(&bind_addr.into()).map_err(|e| {
                        anyhow!(
                            "FATAL: outbound '{}' bindIPv6 {} failed: {}",
                            entry.name,
                            ip,
                            e
                        )
                    })?;
                }

                // Validate bindDevice at startup
                #[cfg(target_os = "linux")]
                if let Some(ref device) = bind_device {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(|e| anyhow!("Failed to create test socket: {}", e))?;
                    socket.bind_device(Some(device.as_bytes())).map_err(|e| {
                        anyhow!(
                            "FATAL: outbound '{}' bindDevice '{}' failed: {}",
                            entry.name,
                            device,
                            e
                        )
                    })?;
                }
                #[cfg(not(target_os = "linux"))]
                if let Some(ref device) = bind_device {
                    return Err(anyhow!(
                        "FATAL: outbound '{}' bindDevice '{}' is only supported on Linux",
                        entry.name,
                        device
                    ));
                }

                // Options that a bare connect_target() cannot apply; when any is
                // set, the router must dial through this handler instead.
                // connect_target() always forces TCP_NODELAY on and applies its
                // own fixed keepalive, and never enables TFO, so those diverge
                // from any non-default configuration here.
                let custom_dial = bind_ip4.is_some()
                    || bind_ip6.is_some()
                    || bind_device.is_some()
                    || direct_mode != DirectMode::Auto
                    || fast_open
                    || !tcp_nodelay
                    || tcp_keepalive_secs != default_tcp_keepalive_secs()
                    || connect_timeout.is_some();

                let opts = DirectOptions {
                    mode: direct_mode,
                    bind_ip4,
                    bind_ip6,
                    bind_device,
                    fast_open,
                    timeout: connect_timeout,
                    tcp_nodelay,
                    tcp_keepalive,
                };
                let direct = Direct::with_options(opts)
                    .map_err(|e| anyhow!("Invalid direct outbound '{}': {}", entry.name, e))?;

                // Log the direct outbound configuration
                let mut parts = vec![format!("mode={}", mode)];
                if let Some(ip) = bind_ip4 {
                    parts.push(format!("bindIPv4={}", ip));
                }
                if let Some(ip) = bind_ip6 {
                    parts.push(format!("bindIPv6={}", ip));
                }
                if let Some(ref dev) = config.and_then(|d| d.bind_device.as_ref()) {
                    parts.push(format!("bindDevice={}", dev));
                }
                if fast_open {
                    parts.push("fastOpen=true".to_string());
                }
                if !tcp_nodelay {
                    parts.push("tcpNoDelay=false".to_string());
                }
                if let Some(ka) = tcp_keepalive {
                    if ka.as_secs() != 60 {
                        parts.push(format!("tcpKeepAlive={}s", ka.as_secs()));
                    }
                } else {
                    parts.push("tcpKeepAlive=off".to_string());
                }
                if let Some(ct) = connect_timeout {
                    parts.push(format!("connectTimeout={}s", ct.as_secs()));
                }
                log::info!(
                    outbound = %entry.name,
                    "Direct outbound configured: {}",
                    parts.join(", ")
                );

                Ok(OutboundHandler::Direct {
                    inner: Arc::new(direct),
                    custom_dial,
                })
            }
            "socks5" => {
                let config = entry.socks5.as_ref().ok_or_else(|| {
                    anyhow!("socks5 config required for outbound '{}'", entry.name)
                })?;

                let socks5 = if let (Some(username), Some(password)) =
                    (&config.username, &config.password)
                {
                    Socks5::with_auth(&config.addr, username, password)
                        .map_err(|e| anyhow!("Invalid socks5 outbound '{}': {}", entry.name, e))?
                } else {
                    Socks5::new(&config.addr)
                };

                Ok(OutboundHandler::Socks5 {
                    inner: Arc::new(socks5),
                    allow_udp: config.allow_udp,
                })
            }
            "http" => {
                let config = entry
                    .http
                    .as_ref()
                    .ok_or_else(|| anyhow!("http config required for outbound '{}'", entry.name))?;

                let mut http = if config.https {
                    Http::try_new(&config.addr, true)
                        .map_err(|e| anyhow!("Invalid http outbound '{}': {}", entry.name, e))?
                } else {
                    Http::new(&config.addr)
                };

                if let (Some(username), Some(password)) = (&config.username, &config.password) {
                    http = http.with_auth(username, password);
                }

                Ok(OutboundHandler::Http(Arc::new(http)))
            }
            "reject" => Ok(OutboundHandler::Reject(Arc::new(Reject::new()))),
            unknown => Err(anyhow!(
                "Unknown outbound type '{}' for outbound '{}'",
                unknown,
                entry.name
            )),
        }
    }

    /// Check if this handler rejects connections
    #[allow(dead_code)]
    pub fn is_reject(&self) -> bool {
        matches!(self, OutboundHandler::Reject(_))
    }

    /// Check if this handler routes through a proxy (SOCKS5 or HTTP)
    #[allow(dead_code)]
    pub fn is_proxy(&self) -> bool {
        matches!(
            self,
            OutboundHandler::Socks5 { .. } | OutboundHandler::Http(_)
        )
    }

    /// For a `direct` outbound carrying custom dialing options, return the
    /// dialer to route through so those options are applied; otherwise `None`.
    /// Plain direct outbounds return `None` and keep using `connect_target()`.
    fn custom_dialer(self: &Arc<Self>) -> Option<Arc<dyn AsyncOutbound>> {
        match self.as_ref() {
            OutboundHandler::Direct {
                custom_dial: true, ..
            } => Some(self.clone() as Arc<dyn AsyncOutbound>),
            _ => None,
        }
    }

    /// Check if this handler allows UDP
    #[allow(dead_code)]
    pub fn allows_udp(&self) -> bool {
        match self {
            OutboundHandler::Direct { .. } => true,
            OutboundHandler::Socks5 { allow_udp, .. } => *allow_udp,
            OutboundHandler::Http(_) => false, // HTTP proxy doesn't support UDP
            OutboundHandler::Reject(_) => false,
        }
    }
}

#[async_trait]
impl AsyncOutbound for OutboundHandler {
    async fn dial_tcp(&self, addr: &mut Addr) -> acl_engine_rs::Result<Box<dyn AsyncTcpConn>> {
        match self {
            OutboundHandler::Direct { inner, .. } => inner.dial_tcp(addr).await,
            OutboundHandler::Socks5 { inner, .. } => inner.dial_tcp(addr).await,
            OutboundHandler::Http(h) => h.dial_tcp(addr).await,
            OutboundHandler::Reject(r) => r.dial_tcp(addr).await,
        }
    }

    async fn dial_udp(&self, addr: &mut Addr) -> acl_engine_rs::Result<Box<dyn AsyncUdpConn>> {
        match self {
            OutboundHandler::Direct { inner, .. } => inner.dial_udp(addr).await,
            OutboundHandler::Socks5 { inner, .. } => inner.dial_udp(addr).await,
            OutboundHandler::Http(h) => h.dial_udp(addr).await,
            OutboundHandler::Reject(r) => r.dial_udp(addr).await,
        }
    }
}

/// ACL Engine for rule-based traffic routing
pub struct AclEngine {
    /// Compiled rule set
    compiled: acl_engine_rs::CompiledRuleSet<Arc<OutboundHandler>>,
    /// Keep outbounds map for reference
    #[allow(dead_code)]
    outbounds: HashMap<String, Arc<OutboundHandler>>,
}

impl AclEngine {
    /// Create a new ACL engine from configuration
    ///
    /// # Arguments
    /// * `config` - ACL configuration
    /// * `data_dir` - Optional data directory for geo data files
    /// * `refresh_geodata` - If true, force refresh geo data files on startup
    pub async fn new(
        config: AclConfig,
        data_dir: Option<&Path>,
        refresh_geodata: bool,
    ) -> Result<Self> {
        // Step 1: Parse outbounds into handler map
        let mut outbounds: HashMap<String, Arc<OutboundHandler>> = HashMap::new();

        for entry in &config.outbounds {
            let handler = OutboundHandler::from_entry(entry)?;
            log::info!(
                outbound = %entry.name,
                outbound_type = %entry.outbound_type,
                "Loaded outbound"
            );
            outbounds.insert(entry.name.clone(), Arc::new(handler));
        }

        // Step 2: Ensure default outbounds exist
        outbounds
            .entry("reject".to_string())
            .or_insert_with(|| Arc::new(OutboundHandler::Reject(Arc::new(Reject::new()))));
        outbounds.entry("direct".to_string()).or_insert_with(|| {
            Arc::new(OutboundHandler::Direct {
                inner: Arc::new(Direct::new()),
                custom_dial: false,
            })
        });

        // Step 3: Get rules or use default
        let rules = if config.acl.inline.is_empty() {
            vec!["direct(all)".to_string()]
        } else {
            config.acl.inline.clone()
        };

        // Step 4: Parse rules text
        let rules_text = rules.join("\n");
        let text_rules = acl_engine_rs::parse_rules(&rules_text)
            .map_err(|e| anyhow!("Failed to parse ACL rules: {}", e))?;

        // Step 5: Create geo loader
        let mut geo_loader = if let Some(dir) = data_dir {
            AutoGeoLoader::new()
                .with_data_dir(dir)
                .with_geoip(GeoIpFormat::Mmdb)
                .with_geosite(GeoSiteFormat::Sing)
        } else {
            AutoGeoLoader::new()
                .with_geoip(GeoIpFormat::Mmdb)
                .with_geosite(GeoSiteFormat::Sing)
        };

        // Force refresh geodata if requested
        if refresh_geodata {
            use std::time::Duration;
            geo_loader = geo_loader.with_update_interval(Duration::ZERO);
            log::info!("Geo data refresh requested, will download latest files");
        }

        // Step 6: Compile rules
        let compiled = acl_engine_rs::compile(
            &text_rules,
            &outbounds,
            NonZeroUsize::new(4096).unwrap(),
            &geo_loader,
        )
        .map_err(|e| anyhow!("Failed to compile ACL rules: {}", e))?;

        log::info!(
            outbounds = outbounds.len(),
            rules = compiled.rule_count(),
            "ACL engine initialized"
        );

        Ok(Self {
            compiled,
            outbounds,
        })
    }

    /// Create a default ACL engine (direct all traffic)
    #[allow(dead_code)]
    pub fn new_default() -> Result<Self> {
        let mut outbounds: HashMap<String, Arc<OutboundHandler>> = HashMap::new();
        outbounds.insert(
            "direct".to_string(),
            Arc::new(OutboundHandler::Direct {
                inner: Arc::new(Direct::new()),
                custom_dial: false,
            }),
        );
        outbounds.insert(
            "reject".to_string(),
            Arc::new(OutboundHandler::Reject(Arc::new(Reject::new()))),
        );

        let text_rules = acl_engine_rs::parse_rules("direct(all)")
            .map_err(|e| anyhow!("Failed to parse default rules: {}", e))?;

        let compiled = acl_engine_rs::compile(
            &text_rules,
            &outbounds,
            NonZeroUsize::new(1024).unwrap(),
            &NilGeoLoader,
        )
        .map_err(|e| anyhow!("Failed to compile default rules: {}", e))?;

        Ok(Self {
            compiled,
            outbounds,
        })
    }

    /// Match a host against ACL rules and return the appropriate outbound handler
    pub fn match_host(
        &self,
        host: &str,
        port: u16,
        protocol: Protocol,
    ) -> Option<Arc<OutboundHandler>> {
        // Create HostInfo from host string
        let host_info = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            HostInfo::from_ip(ip)
        } else {
            HostInfo::from_name(host)
        };

        match self.compiled.match_host(&host_info, protocol, port) {
            Some(result) => Some(result.outbound.clone()),
            None => {
                // No match, return default direct
                self.outbounds.get("direct").cloned()
            }
        }
    }

    /// Get the number of compiled rules
    #[allow(dead_code)]
    pub fn rule_count(&self) -> usize {
        self.compiled.rule_count()
    }
}

/// Load ACL configuration from YAML file
pub async fn load_acl_config(path: &Path) -> Result<AclConfig> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| anyhow!("Failed to read ACL config file '{}': {}", path.display(), e))?;

    let config: AclConfig = serde_yaml::from_str(&content).map_err(|e| {
        anyhow!(
            "Failed to parse ACL config file '{}': {}",
            path.display(),
            e
        )
    })?;

    Ok(config)
}

// ---------------------------------------------------------------------------
// Private IP helpers
// ---------------------------------------------------------------------------

fn is_private_ipv4(ip: &[u8; 4]) -> bool {
    matches!(
        ip,
        [10, ..] | [172, 16..=31, ..] | [192, 168, ..] | [127, ..] | [0, 0, 0, 0] | [169, 254, ..]
    )
}

fn is_private_ipv6(ip: &[u8; 16]) -> bool {
    // ::1 (loopback)
    if ip == &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
        return true;
    }
    // :: (unspecified)
    if ip == &[0u8; 16] {
        return true;
    }
    // fc00::/7 (ULA)
    if ip[0] & 0xfe == 0xfc {
        return true;
    }
    // fe80::/10 (link-local)
    if ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80 {
        return true;
    }
    // ::ffff:0:0/96 (IPv4-mapped) - check embedded IPv4
    if ip[..10] == [0u8; 10] && ip[10] == 0xff && ip[11] == 0xff {
        return is_private_ipv4(&[ip[12], ip[13], ip[14], ip[15]]);
    }
    false
}

// ---------------------------------------------------------------------------
// AclRouter
// ---------------------------------------------------------------------------

/// ACL Router adapter implementing server_anytls_rs::OutboundRouter
///
/// This adapter wraps the ACL engine and implements the OutboundRouter trait
/// for integration with the core proxy layer.
pub struct AclRouter {
    engine: AclEngine,
    /// Block connections to private/loopback IP addresses (SSRF protection)
    block_private_ip: bool,
    /// DNS resolution cache (LRU eviction, per-entry TTL, singleflight,
    /// 2s query timeout). Backed by `dns_cache_rs::DnsCache` — defaults
    /// match the previous hand-rolled constants (TTL 120s, negative 15s,
    /// capacity 4096).
    dns_cache: dns_cache_rs::DnsCache,
}

impl AclRouter {
    /// Create a new ACL router with custom private IP blocking setting.
    ///
    /// Uses `DnsCache::new()` defaults: 120s positive TTL, 15s negative TTL,
    /// 4096-entry LRU cap, 2s per-query timeout, host normalization on.
    pub fn with_block_private_ip(engine: AclEngine, block_private_ip: bool) -> Self {
        Self {
            engine,
            block_private_ip,
            dns_cache: dns_cache_rs::DnsCache::new(),
        }
    }

    /// Test-only constructor — accepts a pre-built `DnsCache` so tests can
    /// inject a `MockResolver`. Not visible in non-test builds.
    #[cfg(test)]
    fn with_dns_cache(
        engine: AclEngine,
        block_private_ip: bool,
        dns_cache: dns_cache_rs::DnsCache,
    ) -> Self {
        Self {
            engine,
            block_private_ip,
            dns_cache,
        }
    }

    /// Resolve a domain via the DNS cache. Returns `None` for any failure
    /// mode (NotFound / Timeout / Other) so the caller's existing
    /// fail-closed branch (`block_private_ip` + unresolvable domain →
    /// Reject) keeps working unchanged.
    ///
    /// The returned `SocketAddr`s carry `port == 0`; downstream
    /// `outbound::connect_target` overrides the port via `set_port` using
    /// the original target's port. This contract avoids storing a port
    /// per cache entry.
    async fn resolve_domain(&self, host: &str) -> Option<Arc<[std::net::SocketAddr]>> {
        match self.dns_cache.resolve(host).await {
            Ok(ips) => Some(
                ips.iter()
                    .map(|ip| std::net::SocketAddr::new(*ip, 0))
                    .collect::<Vec<_>>()
                    .into(),
            ),
            Err(_) => None,
        }
    }
}

impl AclRouter {
    /// Shared routing logic parameterized by protocol.
    ///
    /// ACL matching runs **before** DNS resolution so that proxied domains
    /// (SOCKS5/HTTP) never trigger a server-side DNS lookup. This avoids
    /// unnecessary latency and prevents false rejections when the server
    /// cannot resolve the domain but a downstream proxy can.
    async fn route_with_protocol(
        &self,
        addr: &server_anytls_rs::Address,
        protocol: Protocol,
    ) -> server_anytls_rs::OutboundType {
        use server_anytls_rs::{Address, OutboundType};

        // Fast-reject private IP literals (no DNS needed).
        match addr {
            Address::IPv4(ip, _) if self.block_private_ip && is_private_ipv4(ip) => {
                log::debug!(target = %addr, "Blocked private IPv4 address");
                return OutboundType::Reject;
            }
            Address::IPv6(ip, _) if self.block_private_ip && is_private_ipv6(ip) => {
                log::debug!(target = %addr, "Blocked private IPv6 address");
                return OutboundType::Reject;
            }
            _ => {}
        }

        // ACL match first — no DNS involved, pure string matching.
        let host = addr.host_str();
        let port = addr.port();
        let acl_result = self.engine.match_host(&host, port, protocol);

        // Proxy / Reject: return immediately, no DNS needed on our side.
        // A `direct` handler with custom dialing options is captured here and
        // attached to the Direct decision *after* the SSRF check below, so its
        // options are applied while still honoring private-IP blocking.
        let mut dialer: Option<Arc<dyn AsyncOutbound>> = None;
        if let Some(handler) = acl_result {
            if handler.is_proxy() {
                return OutboundType::Proxy(handler);
            }
            if handler.is_reject() {
                return OutboundType::Reject;
            }
            dialer = handler.custom_dialer();
        }

        // Direct route — resolve DNS for domain addresses so connect_target()
        // can reuse the result and we can enforce private-IP blocking.
        let mut resolved_addrs: Option<Arc<[std::net::SocketAddr]>> = None;

        if let Address::Domain(domain, _) = addr {
            if let Some(addrs) = self.resolve_domain(domain).await {
                if self.block_private_ip {
                    for resolved in addrs.iter() {
                        match resolved.ip() {
                            std::net::IpAddr::V4(ip) => {
                                let octets = ip.octets();
                                if is_private_ipv4(&octets) {
                                    log::debug!(target = %addr, resolved = %ip, "Blocked domain resolving to private IPv4");
                                    return OutboundType::Reject;
                                }
                            }
                            std::net::IpAddr::V6(ip) => {
                                let octets = ip.octets();
                                if is_private_ipv6(&octets) {
                                    log::debug!(target = %addr, resolved = %ip, "Blocked domain resolving to private IPv6");
                                    return OutboundType::Reject;
                                }
                            }
                        }
                    }
                }
                resolved_addrs = Some(addrs);
            } else if self.block_private_ip {
                log::debug!(target = %addr, "Blocked domain with unresolvable DNS (fail-closed)");
                return OutboundType::Reject;
            }
        }

        // `dialer` is Some for a custom-dial direct outbound: the connect path
        // dials through it, feeding it `resolved` so its bind/mode/TCP options
        // apply without re-resolving (the SSRF check above has already run on
        // exactly those IPs). Plain direct keeps the connect_target() path.
        OutboundType::Direct {
            resolved: resolved_addrs,
            dialer,
        }
    }
}

#[async_trait]
impl server_anytls_rs::OutboundRouter for AclRouter {
    async fn route(&self, addr: &server_anytls_rs::Address) -> server_anytls_rs::OutboundType {
        self.route_with_protocol(addr, Protocol::TCP).await
    }

    async fn route_udp(&self, addr: &server_anytls_rs::Address) -> server_anytls_rs::OutboundType {
        self.route_with_protocol(addr, Protocol::UDP).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_acl_config() {
        let yaml = r#"
outbounds:
  - name: warp
    type: socks5
    socks5:
      addr: 127.0.0.1:40000
      allow_udp: true
  - name: http-proxy
    type: http
    http:
      addr: 127.0.0.1:8080
      https: false
acl:
  inline:
    - reject(all, udp/443)
    - warp(suffix:google.com)
    - direct(all)
"#;

        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.outbounds.len(), 2);
        assert_eq!(config.outbounds[0].name, "warp");
        assert_eq!(config.outbounds[0].outbound_type, "socks5");
        assert_eq!(config.acl.inline.len(), 3);
    }

    #[test]
    fn test_outbound_handler_from_entry_direct() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                mode: "auto".to_string(),
                ..Default::default()
            }),
        };

        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(matches!(handler, OutboundHandler::Direct { .. }));
        assert!(handler.allows_udp());
        assert!(!handler.is_reject());
    }

    #[test]
    fn test_outbound_handler_from_entry_socks5() {
        let entry = OutboundEntry {
            name: "proxy".to_string(),
            outbound_type: "socks5".to_string(),
            socks5: Some(Socks5Config {
                addr: "127.0.0.1:1080".to_string(),
                username: None,
                password: None,
                allow_udp: true,
            }),
            http: None,
            direct: None,
        };

        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(matches!(handler, OutboundHandler::Socks5 { .. }));
        assert!(handler.allows_udp());
    }

    #[test]
    fn test_outbound_handler_from_entry_http() {
        let entry = OutboundEntry {
            name: "http".to_string(),
            outbound_type: "http".to_string(),
            socks5: None,
            http: Some(HttpConfig {
                addr: "127.0.0.1:8080".to_string(),
                username: None,
                password: None,
                https: false,
            }),
            direct: None,
        };

        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(matches!(handler, OutboundHandler::Http(_)));
        assert!(!handler.allows_udp()); // HTTP doesn't support UDP
    }

    #[test]
    fn test_outbound_handler_from_entry_reject() {
        let entry = OutboundEntry {
            name: "block".to_string(),
            outbound_type: "reject".to_string(),
            socks5: None,
            http: None,
            direct: None,
        };

        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(matches!(handler, OutboundHandler::Reject(_)));
        assert!(handler.is_reject());
        assert!(!handler.allows_udp());
    }

    #[tokio::test]
    async fn test_acl_engine_default() {
        let engine = AclEngine::new_default().unwrap();
        assert_eq!(engine.rule_count(), 1);

        // Should match everything to direct
        let handler = engine.match_host("example.com", 80, Protocol::TCP);
        assert!(handler.is_some());
        assert!(!handler.unwrap().is_reject());
    }

    #[test]
    fn test_parse_empty_config() {
        let yaml = r#"
outbounds: []
acl:
  inline: []
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.outbounds.is_empty());
        assert!(config.acl.inline.is_empty());
    }

    #[test]
    fn test_parse_config_with_auth() {
        let yaml = r#"
outbounds:
  - name: auth-proxy
    type: socks5
    socks5:
      addr: 127.0.0.1:1080
      username: user
      password: pass
      allow_udp: true
  - name: http-auth
    type: http
    http:
      addr: 127.0.0.1:8080
      username: admin
      password: secret
      https: true
acl:
  inline:
    - auth-proxy(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.outbounds.len(), 2);

        let socks5 = &config.outbounds[0];
        assert_eq!(
            socks5.socks5.as_ref().unwrap().username,
            Some("user".to_string())
        );
        assert_eq!(
            socks5.socks5.as_ref().unwrap().password,
            Some("pass".to_string())
        );

        let http = &config.outbounds[1];
        assert!(http.http.as_ref().unwrap().https);
    }

    #[test]
    fn test_outbound_handler_socks5_no_udp() {
        let entry = OutboundEntry {
            name: "no-udp-proxy".to_string(),
            outbound_type: "socks5".to_string(),
            socks5: Some(Socks5Config {
                addr: "127.0.0.1:1080".to_string(),
                username: None,
                password: None,
                allow_udp: false,
            }),
            http: None,
            direct: None,
        };

        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(!handler.allows_udp());
    }

    #[test]
    fn test_outbound_handler_direct_modes() {
        // Test various direct modes
        let modes = vec![
            ("auto", DirectMode::Auto),
            ("4", DirectMode::Only4),
            ("only4", DirectMode::Only4),
            ("6", DirectMode::Only6),
            ("only6", DirectMode::Only6),
            ("prefer4", DirectMode::Prefer46),
            ("46", DirectMode::Prefer46),
            ("prefer6", DirectMode::Prefer64),
            ("64", DirectMode::Prefer64),
        ];

        for (mode_str, _expected_mode) in modes {
            let entry = OutboundEntry {
                name: "direct".to_string(),
                outbound_type: "direct".to_string(),
                socks5: None,
                http: None,
                direct: Some(DirectConfig {
                    mode: mode_str.to_string(),
                    ..Default::default()
                }),
            };

            let handler = OutboundHandler::from_entry(&entry).unwrap();
            assert!(matches!(handler, OutboundHandler::Direct { .. }));
        }
    }

    #[test]
    fn test_direct_invalid_mode_rejected() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                mode: "invalid_mode".to_string(),
                ..Default::default()
            }),
        };
        let err = OutboundHandler::from_entry(&entry).unwrap_err();
        assert!(
            err.to_string().contains("Invalid direct mode"),
            "Expected mode validation error, got: {}",
            err
        );
    }

    #[test]
    fn test_direct_invalid_bind_ipv4_rejected() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_ipv4: Some("not-an-ip".to_string()),
                ..Default::default()
            }),
        };
        let err = OutboundHandler::from_entry(&entry).unwrap_err();
        assert!(
            err.to_string().contains("Invalid bindIPv4"),
            "Expected IPv4 parse error, got: {}",
            err
        );
    }

    #[test]
    fn test_direct_invalid_bind_ipv6_rejected() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_ipv6: Some("not-an-ipv6".to_string()),
                ..Default::default()
            }),
        };
        let err = OutboundHandler::from_entry(&entry).unwrap_err();
        assert!(
            err.to_string().contains("Invalid bindIPv6"),
            "Expected IPv6 parse error, got: {}",
            err
        );
    }

    #[test]
    fn test_direct_bind_device_exclusive_with_bind_ip() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_ipv4: Some("127.0.0.1".to_string()),
                bind_device: Some("eth0".to_string()),
                ..Default::default()
            }),
        };
        // Must fail: either mutual exclusion (Linux) or platform not supported (non-Linux)
        let err = OutboundHandler::from_entry(&entry).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mutually exclusive")
                || msg.contains("bind_device")
                || msg.contains("only supported on Linux"),
            "Expected device-related error, got: {}",
            msg
        );
    }

    #[test]
    fn test_direct_bind_ipv4_unreachable_rejected() {
        // Use an IP that cannot exist on any local interface
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_ipv4: Some("198.51.100.1".to_string()), // TEST-NET-2, never local
                ..Default::default()
            }),
        };
        let err = OutboundHandler::from_entry(&entry).unwrap_err();
        assert!(
            err.to_string().contains("FATAL") && err.to_string().contains("bindIPv4"),
            "Expected startup bind validation error, got: {}",
            err
        );
    }

    #[test]
    fn test_direct_bind_ipv4_loopback_ok() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_ipv4: Some("127.0.0.1".to_string()),
                ..Default::default()
            }),
        };
        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(matches!(handler, OutboundHandler::Direct { .. }));
    }

    #[test]
    fn test_direct_bind_ipv6_unreachable_rejected() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_ipv6: Some("2001:db8::1".to_string()), // Documentation prefix, never local
                ..Default::default()
            }),
        };
        let err = OutboundHandler::from_entry(&entry).unwrap_err();
        assert!(
            err.to_string().contains("FATAL") && err.to_string().contains("bindIPv6"),
            "Expected startup bind validation error, got: {}",
            err
        );
    }

    #[test]
    fn test_direct_bind_ipv6_loopback_ok() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_ipv6: Some("::1".to_string()),
                ..Default::default()
            }),
        };
        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(matches!(handler, OutboundHandler::Direct { .. }));
    }

    #[test]
    fn test_direct_bind_device_exclusive_with_bind_ipv6() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_ipv6: Some("::1".to_string()),
                bind_device: Some("eth0".to_string()),
                ..Default::default()
            }),
        };
        // Must fail: either mutual exclusion (Linux) or platform not supported (non-Linux)
        let err = OutboundHandler::from_entry(&entry).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mutually exclusive")
                || msg.contains("bind_device")
                || msg.contains("only supported on Linux"),
            "Expected device-related error, got: {}",
            msg
        );
    }

    #[test]
    fn test_direct_bind_device_rejected_on_non_linux() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_device: Some("lo0".to_string()),
                ..Default::default()
            }),
        };
        if cfg!(target_os = "linux") {
            // On Linux: may succeed or fail depending on permissions/device,
            // but should not fail with "only supported on Linux"
            let result = OutboundHandler::from_entry(&entry);
            if let Err(ref e) = result {
                assert!(
                    !e.to_string().contains("only supported on Linux"),
                    "Should not get platform error on Linux, got: {}",
                    e
                );
            }
        } else {
            // On non-Linux: should fail with platform error
            let err = OutboundHandler::from_entry(&entry).unwrap_err();
            assert!(
                err.to_string().contains("only supported on Linux"),
                "Expected platform error, got: {}",
                err
            );
        }
    }

    #[test]
    fn test_direct_with_fast_open() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                fast_open: true,
                ..Default::default()
            }),
        };
        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(matches!(handler, OutboundHandler::Direct { .. }));
    }

    // -----------------------------------------------------------------
    // custom-dial routing: a `direct` outbound with options that
    // connect_target() cannot apply (bind/mode/fastOpen/nodelay/keepalive/
    // connectTimeout) must be dialed through the handler, surfaced as
    // `Direct { dialer: Some(_) }`. Ported from server-mieru-rs.
    // -----------------------------------------------------------------
    mod dialer_routing {
        use super::super::*;
        use server_anytls_rs::{Address, OutboundRouter, OutboundType};

        /// Build an `AclEngine` whose only rule (`bound(all)`) routes every host
        /// to a single custom `direct` outbound built from `direct`.
        async fn engine_with_bound_direct(direct: DirectConfig) -> AclEngine {
            let config = AclConfig {
                outbounds: vec![OutboundEntry {
                    name: "bound".to_string(),
                    outbound_type: "direct".to_string(),
                    socks5: None,
                    http: None,
                    direct: Some(direct),
                }],
                acl: AclRules {
                    inline: vec!["bound(all)".to_string()],
                },
            };
            AclEngine::new(config, None, false)
                .await
                .expect("engine builds")
        }

        /// A `direct` outbound with `bindIPv4` must be dialed through the handler
        /// so the bind is applied — surfaced as `Direct { dialer: Some(_) }`.
        /// Before the fix the router dropped the Direct handler and returned a
        /// plain `Direct { dialer: None }`, routing to `connect_target()` which
        /// knows nothing about bind/mode, so the bind was silently lost.
        #[tokio::test]
        async fn custom_bind_direct_carries_dialer() {
            let engine = engine_with_bound_direct(DirectConfig {
                bind_ipv4: Some("127.0.0.1".to_string()),
                ..Default::default()
            })
            .await;
            let router = AclRouter::with_block_private_ip(engine, true);

            // IP literal: no DNS involved, isolates the routing decision.
            let result = router.route(&Address::IPv4([1, 2, 3, 4], 443)).await;

            match result {
                OutboundType::Direct {
                    dialer: Some(_), ..
                } => {}
                other => panic!("custom-bind direct must carry a dialer, got {other:?}"),
            }
        }

        /// `fastOpen`/`tcpNoDelay`/`mode` are also options `connect_target()`
        /// cannot honor, so a direct outbound setting any of them (even with no
        /// bind) must route through the handler.
        #[tokio::test]
        async fn direct_with_non_default_tcp_options_carries_dialer() {
            for direct in [
                DirectConfig {
                    fast_open: true,
                    ..Default::default()
                },
                DirectConfig {
                    tcp_nodelay: false,
                    ..Default::default()
                },
                DirectConfig {
                    mode: "4".to_string(),
                    ..Default::default()
                },
            ] {
                let label = format!("{direct:?}");
                let engine = engine_with_bound_direct(direct).await;
                let router = AclRouter::with_block_private_ip(engine, true);
                let result = router.route(&Address::IPv4([1, 2, 3, 4], 443)).await;
                assert!(
                    matches!(
                        result,
                        OutboundType::Direct {
                            dialer: Some(_),
                            ..
                        }
                    ),
                    "config {label} must carry a dialer, got {result:?}"
                );
            }
        }

        /// Guard: a plain `direct` outbound (all defaults) must keep using the
        /// `connect_target()` path — `Direct { dialer: None }`. Because
        /// `match_host` falls back to the `direct` handler for unmatched traffic,
        /// rerouting *all* Direct handlers through the dialer would change the
        /// default path for every connection.
        #[tokio::test]
        async fn plain_direct_carries_no_dialer() {
            let engine = AclEngine::new_default().expect("default engine builds");
            let router = AclRouter::with_block_private_ip(engine, true);

            let result = router.route(&Address::IPv4([1, 2, 3, 4], 443)).await;

            assert!(
                matches!(result, OutboundType::Direct { dialer: None, .. }),
                "plain direct must stay on the connect_target path, got {result:?}"
            );
        }

        /// A custom-dial direct outbound targeting a domain must hand the handler
        /// the router's already-SSRF-checked IPs (`resolved`) so the handler
        /// binds without re-resolving — otherwise a rebinding domain could
        /// connect to an unchecked, private IP (SSRF). The decision must carry
        /// BOTH the dialer AND the checked resolution.
        #[tokio::test]
        async fn custom_dial_direct_domain_carries_checked_ips() {
            use std::net::{IpAddr, Ipv4Addr};
            let public_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
            let mock = Arc::new(dns_cache_rs::MockResolver::new());
            mock.set("target.test", Ok(vec![public_ip]));
            let cache = dns_cache_rs::DnsCache::builder()
                .resolver_arc(mock)
                .query_timeout(Some(std::time::Duration::from_millis(100)))
                .build()
                .expect("cache builds");
            let engine = engine_with_bound_direct(DirectConfig {
                bind_ipv4: Some("127.0.0.1".to_string()),
                ..Default::default()
            })
            .await;
            let router = AclRouter::with_dns_cache(engine, true, cache);

            let result = router
                .route(&Address::Domain("target.test".to_string(), 443))
                .await;

            match result {
                OutboundType::Direct {
                    resolved: Some(addrs),
                    dialer: Some(_),
                } => {
                    assert_eq!(addrs.len(), 1);
                    assert_eq!(addrs[0].ip(), public_ip, "handler must get checked IP");
                }
                other => panic!("expected Direct with checked IPs and a dialer, got {other:?}"),
            }
        }

        /// A non-default connect timeout is a dialing option the bare
        /// connect_target() path cannot apply, so it must route through the
        /// outbound's own dialer.
        #[tokio::test]
        async fn direct_with_custom_connect_timeout_carries_dialer() {
            let engine = engine_with_bound_direct(DirectConfig {
                connect_timeout_secs: 5,
                ..Default::default()
            })
            .await;
            let router = AclRouter::with_block_private_ip(engine, true);
            let result = router.route(&Address::IPv4([1, 2, 3, 4], 443)).await;
            assert!(
                matches!(
                    result,
                    OutboundType::Direct {
                        dialer: Some(_),
                        ..
                    }
                ),
                "custom connectTimeout must carry a dialer, got {result:?}"
            );
        }

        /// The SSRF guard must still reject a custom-dial direct outbound whose
        /// domain resolves to a private IP — the private-IP block runs before
        /// the dialer is attached.
        #[tokio::test]
        async fn custom_dial_direct_rejects_private_resolution() {
            use std::net::{IpAddr, Ipv4Addr};
            let mock = Arc::new(dns_cache_rs::MockResolver::new());
            mock.set(
                "evil.test",
                Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]),
            );
            let cache = dns_cache_rs::DnsCache::builder()
                .resolver_arc(mock)
                .query_timeout(Some(std::time::Duration::from_millis(100)))
                .build()
                .expect("cache builds");
            let engine = engine_with_bound_direct(DirectConfig {
                bind_ipv4: Some("127.0.0.1".to_string()),
                ..Default::default()
            })
            .await;
            let router = AclRouter::with_dns_cache(engine, true, cache);

            let result = router
                .route(&Address::Domain("evil.test".to_string(), 443))
                .await;

            assert!(matches!(result, OutboundType::Reject), "got {result:?}");
        }
    }

    #[test]
    fn test_direct_config_yaml_camel_case() {
        let yaml = r#"
outbounds:
  - name: direct
    type: direct
    direct:
      mode: "4"
      bindIPv4: "127.0.0.1"
      fastOpen: true
acl:
  inline:
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let direct_cfg = config.outbounds[0].direct.as_ref().unwrap();
        assert_eq!(direct_cfg.mode, "4");
        assert_eq!(direct_cfg.bind_ipv4.as_deref(), Some("127.0.0.1"));
        assert!(direct_cfg.fast_open);
        assert!(direct_cfg.bind_ipv6.is_none());
        assert!(direct_cfg.bind_device.is_none());
    }

    #[test]
    fn test_direct_config_yaml_all_options() {
        let yaml = r#"
outbounds:
  - name: direct
    type: direct
    direct:
      mode: prefer4
      bindIPv4: "10.0.0.1"
      bindIPv6: "::1"
      fastOpen: false
acl:
  inline:
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let direct_cfg = config.outbounds[0].direct.as_ref().unwrap();
        assert_eq!(direct_cfg.mode, "prefer4");
        assert_eq!(direct_cfg.bind_ipv4.as_deref(), Some("10.0.0.1"));
        assert_eq!(direct_cfg.bind_ipv6.as_deref(), Some("::1"));
        assert!(!direct_cfg.fast_open);
    }

    #[test]
    fn test_direct_config_yaml_connect_timeout() {
        let yaml = r#"
outbounds:
  - name: direct
    type: direct
    direct:
      connectTimeout: 5
acl:
  inline:
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let direct_cfg = config.outbounds[0].direct.as_ref().unwrap();
        assert_eq!(direct_cfg.connect_timeout_secs, 5);
    }

    #[test]
    fn test_direct_config_default_values() {
        // Minimal YAML: only mode should default to "auto", rest None/false
        let yaml = r#"
outbounds:
  - name: direct
    type: direct
    direct: {}
acl:
  inline:
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let direct_cfg = config.outbounds[0].direct.as_ref().unwrap();
        assert_eq!(direct_cfg.mode, "auto");
        assert!(direct_cfg.bind_ipv4.is_none());
        assert!(direct_cfg.bind_ipv6.is_none());
        assert!(direct_cfg.bind_device.is_none());
        assert!(!direct_cfg.fast_open);
    }

    #[test]
    fn test_outbound_handler_unknown_type() {
        let entry = OutboundEntry {
            name: "unknown".to_string(),
            outbound_type: "unknown_type".to_string(),
            socks5: None,
            http: None,
            direct: None,
        };

        let result = OutboundHandler::from_entry(&entry);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unknown outbound type")
        );
    }

    #[test]
    fn test_outbound_handler_missing_socks5_config() {
        let entry = OutboundEntry {
            name: "bad-socks5".to_string(),
            outbound_type: "socks5".to_string(),
            socks5: None, // Missing required config
            http: None,
            direct: None,
        };

        let result = OutboundHandler::from_entry(&entry);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("socks5 config required")
        );
    }

    #[test]
    fn test_outbound_handler_missing_http_config() {
        let entry = OutboundEntry {
            name: "bad-http".to_string(),
            outbound_type: "http".to_string(),
            socks5: None,
            http: None, // Missing required config
            direct: None,
        };

        let result = OutboundHandler::from_entry(&entry);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("http config required")
        );
    }

    #[test]
    fn test_outbound_handler_debug_format() {
        let direct = OutboundHandler::Direct {
            inner: Arc::new(Direct::new()),
            custom_dial: false,
        };
        assert_eq!(format!("{:?}", direct), "Direct");

        let reject = OutboundHandler::Reject(Arc::new(Reject::new()));
        assert_eq!(format!("{:?}", reject), "Reject");

        let socks5 = OutboundHandler::Socks5 {
            inner: Arc::new(Socks5::new("127.0.0.1:1080")),
            allow_udp: true,
        };
        assert_eq!(format!("{:?}", socks5), "Socks5(udp=true)");

        let http = OutboundHandler::Http(Arc::new(Http::new("127.0.0.1:8080")));
        assert_eq!(format!("{:?}", http), "Http");
    }

    #[tokio::test]
    async fn test_acl_engine_with_multiple_outbounds() {
        let yaml = r#"
outbounds:
  - name: proxy1
    type: socks5
    socks5:
      addr: 127.0.0.1:1080
  - name: proxy2
    type: http
    http:
      addr: 127.0.0.1:8080
acl:
  inline:
    - proxy1(suffix:example.com)
    - proxy2(suffix:test.org)
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let engine = AclEngine::new(config, None, false).await.unwrap();

        assert_eq!(engine.rule_count(), 3);
    }

    #[tokio::test]
    async fn test_acl_engine_match_ip_addresses() {
        let engine = AclEngine::new_default().unwrap();

        // Test IPv4
        let handler = engine.match_host("192.168.1.1", 80, Protocol::TCP);
        assert!(handler.is_some());

        // Test IPv6
        let handler = engine.match_host("::1", 80, Protocol::TCP);
        assert!(handler.is_some());
    }

    #[tokio::test]
    async fn test_acl_engine_reject_rule() {
        let yaml = r#"
outbounds: []
acl:
  inline:
    - reject(suffix:blocked.com)
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let engine = AclEngine::new(config, None, false).await.unwrap();

        // Test blocked domain
        let handler = engine.match_host("www.blocked.com", 443, Protocol::TCP);
        assert!(handler.is_some());
        assert!(handler.unwrap().is_reject());

        // Test allowed domain
        let handler = engine.match_host("example.com", 80, Protocol::TCP);
        assert!(handler.is_some());
        assert!(!handler.unwrap().is_reject());
    }

    #[tokio::test]
    async fn test_acl_engine_protocol_specific_rules() {
        let yaml = r#"
outbounds: []
acl:
  inline:
    - reject(all, udp/443)
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let engine = AclEngine::new(config, None, false).await.unwrap();

        // UDP on port 443 should be rejected
        let handler = engine.match_host("example.com", 443, Protocol::UDP);
        assert!(handler.is_some());
        assert!(handler.unwrap().is_reject());

        // TCP on port 443 should be allowed (direct)
        let handler = engine.match_host("example.com", 443, Protocol::TCP);
        assert!(handler.is_some());
        assert!(!handler.unwrap().is_reject());

        // UDP on other ports should be allowed
        let handler = engine.match_host("example.com", 80, Protocol::UDP);
        assert!(handler.is_some());
        assert!(!handler.unwrap().is_reject());
    }

    #[tokio::test]
    async fn test_acl_engine_port_specific_rules() {
        let yaml = r#"
outbounds:
  - name: warp
    type: socks5
    socks5:
      addr: 127.0.0.1:40000
acl:
  inline:
    - warp(all, tcp/22)
    - warp(all, tcp/25)
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let engine = AclEngine::new(config, None, false).await.unwrap();

        // Port 22 should match warp (socks5)
        let handler = engine.match_host("any.host.com", 22, Protocol::TCP);
        assert!(handler.is_some());
        assert!(matches!(*handler.unwrap(), OutboundHandler::Socks5 { .. }));

        // Port 25 should match warp (socks5)
        let handler = engine.match_host("any.host.com", 25, Protocol::TCP);
        assert!(handler.is_some());
        assert!(matches!(*handler.unwrap(), OutboundHandler::Socks5 { .. }));

        // Port 80 should be direct
        let handler = engine.match_host("any.host.com", 80, Protocol::TCP);
        assert!(handler.is_some());
        assert!(matches!(*handler.unwrap(), OutboundHandler::Direct { .. }));
    }

    #[tokio::test]
    async fn test_load_acl_config_from_file() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
        writeln!(
            file,
            r#"
outbounds:
  - name: test
    type: direct
acl:
  inline:
    - test(all)
"#
        )
        .unwrap();

        let config = load_acl_config(file.path()).await.unwrap();
        assert_eq!(config.outbounds.len(), 1);
        assert_eq!(config.outbounds[0].name, "test");
    }

    #[tokio::test]
    async fn test_load_acl_config_invalid_yaml() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
        writeln!(file, "this is not valid yaml: {{{{").unwrap();

        let result = load_acl_config(file.path()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_load_acl_config_file_not_found() {
        use std::path::Path;
        let result = load_acl_config(Path::new("/nonexistent/path/config.yaml")).await;
        assert!(result.is_err());
    }

    // Integration test with real acl-o.yaml file
    #[tokio::test]
    async fn test_real_acl_config_file() {
        use std::path::Path;

        let acl_path = Path::new("acl-o.yaml");
        if !acl_path.exists() {
            println!("Skipping test: acl-o.yaml not found");
            return;
        }

        // Load and parse the real config
        let config = load_acl_config(acl_path).await.unwrap();

        // Verify basic structure
        assert!(
            !config.outbounds.is_empty(),
            "Should have at least one outbound"
        );
        assert!(!config.acl.inline.is_empty(), "Should have ACL rules");

        // Verify warp outbound exists and is socks5 type
        let warp_outbound = config.outbounds.iter().find(|o| o.name == "warp");
        assert!(warp_outbound.is_some(), "Should have 'warp' outbound");
        assert_eq!(warp_outbound.unwrap().outbound_type, "socks5");

        // Create engine (without geo data, will skip geosite rules)
        // Note: This may fail if geosite rules are required and data_dir is not provided
        // For a full test with geosite, provide data_dir with actual geo files
        let engine_result = AclEngine::new(config, None, false).await;

        // If engine creation succeeds, test some rules
        if let Ok(engine) = engine_result {
            println!("ACL engine created with {} rules", engine.rule_count());

            // Test reject rule: udp/443 should be rejected
            let handler = engine.match_host("any.com", 443, Protocol::UDP);
            if let Some(h) = handler {
                assert!(h.is_reject(), "UDP/443 should be rejected");
            }

            // Test port-based rule: tcp/22 should go through warp
            let handler = engine.match_host("any.com", 22, Protocol::TCP);
            if let Some(h) = handler {
                assert!(
                    matches!(*h, OutboundHandler::Socks5 { .. }),
                    "TCP/22 should use warp (socks5)"
                );
            }

            // Test suffix rule: google.com should go through warp
            let handler = engine.match_host("www.google.com", 443, Protocol::TCP);
            if let Some(h) = handler {
                assert!(
                    matches!(*h, OutboundHandler::Socks5 { .. }),
                    "google.com should use warp"
                );
            }

            // Test default rule: random domain should be direct
            let handler = engine.match_host("random-unknown-site.xyz", 80, Protocol::TCP);
            if let Some(h) = handler {
                assert!(
                    matches!(*h, OutboundHandler::Direct { .. }),
                    "Unknown domain should be direct"
                );
            }
        } else {
            println!(
                "Note: ACL engine creation failed (likely due to missing geo data): {:?}",
                engine_result.err()
            );
        }
    }

    // Test with real geo data (requires data directory)
    #[tokio::test]
    async fn test_real_acl_with_geo_data() {
        use std::path::Path;

        let acl_path = Path::new("acl-o.yaml");
        let data_dir = Path::new("data"); // Standard data directory

        if !acl_path.exists() {
            println!("Skipping test: acl-o.yaml not found");
            return;
        }

        if !data_dir.exists() {
            println!("Skipping full geo test: data directory not found");
            return;
        }

        let config = load_acl_config(acl_path).await.unwrap();
        let engine = AclEngine::new(config, Some(data_dir), false).await;

        match engine {
            Ok(engine) => {
                println!(
                    "ACL engine created with geo data, {} rules",
                    engine.rule_count()
                );

                // Test geosite:openai rule (if data is available)
                let handler = engine.match_host("chat.openai.com", 443, Protocol::TCP);
                if let Some(h) = handler {
                    println!("openai.com matched: {:?}", h);
                }

                // Test geosite:google-deepmind rule
                let handler = engine.match_host("deepmind.google.com", 443, Protocol::TCP);
                if let Some(h) = handler {
                    println!("deepmind.google.com matched: {:?}", h);
                }
            }
            Err(e) => {
                println!("ACL engine with geo data failed: {}", e);
            }
        }
    }

    #[test]
    fn test_default_ip_mode() {
        assert_eq!(default_ip_mode(), "auto");
    }

    #[test]
    fn test_acl_rules_default() {
        let rules = AclRules::default();
        assert!(rules.inline.is_empty());
    }

    #[test]
    fn test_direct_config_default_mode() {
        let yaml = r#"
outbounds:
  - name: d
    type: direct
acl:
  inline: []
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        // direct config is None, should use default "auto" mode
        assert!(config.outbounds[0].direct.is_none());
    }

    #[test]
    fn test_acl_router_blocks_private_ip_by_default() {
        let engine = AclEngine::new_default().unwrap();
        let router = AclRouter::with_block_private_ip(engine, true);
        assert!(router.block_private_ip);
    }

    #[test]
    fn test_acl_router_with_custom_block_setting() {
        let engine = AclEngine::new_default().unwrap();
        let router = AclRouter::with_block_private_ip(engine, false);
        assert!(!router.block_private_ip);
    }

    #[tokio::test]
    async fn test_acl_router_rejects_private_ipv4() {
        use server_anytls_rs::{Address, OutboundRouter, OutboundType};

        let engine = AclEngine::new_default().unwrap();
        let router = AclRouter::with_block_private_ip(engine, true);

        // Test loopback
        let addr = Address::IPv4([127, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));

        // Test private Class A
        let addr = Address::IPv4([10, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));

        // Test private Class C
        let addr = Address::IPv4([192, 168, 1, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));

        // Test public IP should not be rejected
        let addr = Address::IPv4([8, 8, 8, 8], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Direct { .. }));
    }

    #[tokio::test]
    async fn test_acl_router_rejects_private_ipv6() {
        use server_anytls_rs::{Address, OutboundRouter, OutboundType};

        let engine = AclEngine::new_default().unwrap();
        let router = AclRouter::with_block_private_ip(engine, true);

        // Test loopback ::1
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));

        // Test ULA (fd00::1)
        let addr = Address::IPv6([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));
    }

    #[tokio::test]
    async fn test_acl_router_allows_private_when_disabled() {
        use server_anytls_rs::{Address, OutboundRouter, OutboundType};

        let engine = AclEngine::new_default().unwrap();
        let router = AclRouter::with_block_private_ip(engine, false);

        // Private IP should be allowed when blocking is disabled
        let addr = Address::IPv4([127, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Direct { .. }));
    }

    // ---------------------------------------------------------------------------
    // Private IP helper tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_is_private_ipv4_loopback() {
        assert!(is_private_ipv4(&[127, 0, 0, 1]));
        assert!(is_private_ipv4(&[127, 255, 255, 255]));
    }

    #[test]
    fn test_is_private_ipv4_class_a() {
        assert!(is_private_ipv4(&[10, 0, 0, 0]));
        assert!(is_private_ipv4(&[10, 255, 255, 255]));
    }

    #[test]
    fn test_is_private_ipv4_class_b() {
        assert!(is_private_ipv4(&[172, 16, 0, 0]));
        assert!(is_private_ipv4(&[172, 31, 255, 255]));
        assert!(!is_private_ipv4(&[172, 15, 0, 0]));
        assert!(!is_private_ipv4(&[172, 32, 0, 0]));
    }

    #[test]
    fn test_is_private_ipv4_class_c() {
        assert!(is_private_ipv4(&[192, 168, 0, 0]));
        assert!(is_private_ipv4(&[192, 168, 255, 255]));
    }

    #[test]
    fn test_is_private_ipv4_link_local() {
        assert!(is_private_ipv4(&[169, 254, 0, 1]));
        assert!(is_private_ipv4(&[169, 254, 255, 255]));
    }

    #[test]
    fn test_is_private_ipv4_unspecified() {
        assert!(is_private_ipv4(&[0, 0, 0, 0]));
    }

    #[test]
    fn test_is_private_ipv4_public() {
        assert!(!is_private_ipv4(&[8, 8, 8, 8]));
        assert!(!is_private_ipv4(&[1, 1, 1, 1]));
        assert!(!is_private_ipv4(&[203, 0, 113, 1]));
    }

    #[test]
    fn test_is_private_ipv6_loopback() {
        assert!(is_private_ipv6(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]));
    }

    #[test]
    fn test_is_private_ipv6_unspecified() {
        assert!(is_private_ipv6(&[0u8; 16]));
    }

    #[test]
    fn test_is_private_ipv6_ula() {
        // fc00::/7
        assert!(is_private_ipv6(&[
            0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]));
        assert!(is_private_ipv6(&[
            0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]));
    }

    #[test]
    fn test_is_private_ipv6_link_local() {
        // fe80::/10
        assert!(is_private_ipv6(&[
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]));
        assert!(is_private_ipv6(&[
            0xfe, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]));
    }

    #[test]
    fn test_is_private_ipv6_ipv4_mapped_private() {
        // ::ffff:127.0.0.1
        assert!(is_private_ipv6(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1
        ]));
        // ::ffff:10.0.0.1
        assert!(is_private_ipv6(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1
        ]));
        // ::ffff:192.168.1.1
        assert!(is_private_ipv6(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1
        ]));
    }

    #[test]
    fn test_is_private_ipv6_ipv4_mapped_public() {
        // ::ffff:8.8.8.8
        assert!(!is_private_ipv6(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8
        ]));
    }

    #[test]
    fn test_is_private_ipv6_public() {
        // 2001:db8::1 (documentation)
        assert!(!is_private_ipv6(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]));
        // 2606:4700::1 (Cloudflare)
        assert!(!is_private_ipv6(&[
            0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]));
    }

    /// ACL should return Proxy(handler) for domains matching a socks5 outbound rule,
    /// not Direct. This is the bug: socks5/http handlers were mapped to Direct.
    #[tokio::test]
    async fn test_acl_router_returns_proxy_for_socks5_rule() {
        use server_anytls_rs::{Address, OutboundRouter, OutboundType};

        // Build an engine with a socks5 outbound + rule routing example.com through it
        let config = AclConfig {
            outbounds: vec![OutboundEntry {
                name: "warp".to_string(),
                outbound_type: "socks5".to_string(),
                socks5: Some(Socks5Config {
                    addr: "127.0.0.1:40000".to_string(),
                    username: None,
                    password: None,
                    allow_udp: true,
                }),
                http: None,
                direct: None,
            }],
            acl: AclRules {
                inline: vec!["warp(example.com)".to_string(), "direct(all)".to_string()],
            },
        };

        let engine = AclEngine::new(config, None, false).await.unwrap();
        let router = AclRouter::with_block_private_ip(engine, false);

        // example.com should be routed through the socks5 proxy, not direct
        let addr = Address::Domain("example.com".to_string(), 443);
        let result = router.route(&addr).await;
        assert!(
            matches!(result, OutboundType::Proxy(_)),
            "expected Proxy for socks5-routed domain, got {:?}",
            result
        );

        // other domains should still be direct
        let addr = Address::Domain("other.com".to_string(), 80);
        let result = router.route(&addr).await;
        assert!(
            matches!(result, OutboundType::Direct { .. }),
            "expected Direct for unmatched domain, got {:?}",
            result
        );
    }

    /// Build a `MockResolver`-backed `DnsCache` that returns
    /// `Err(DnsError::NotFound)` for every host in `not_found_hosts`,
    /// and `Ok` for any host pre-configured via the returned mock handle.
    ///
    /// `query_timeout(None)` disables the 2s default to keep tests
    /// independent of wall-clock latency.
    fn mock_dns_cache(
        not_found_hosts: &[&str],
    ) -> (
        dns_cache_rs::DnsCache,
        std::sync::Arc<dns_cache_rs::MockResolver>,
    ) {
        let mock = std::sync::Arc::new(dns_cache_rs::MockResolver::new());
        for host in not_found_hosts {
            mock.set(
                host,
                Err(dns_cache_rs::DnsError::NotFound((*host).to_string())),
            );
        }
        let cache = dns_cache_rs::DnsCache::builder()
            .resolver_arc(mock.clone())
            .query_timeout(None)
            .build()
            .expect("default-ish DnsCache config must build");
        (cache, mock)
    }

    /// Build an `AclRouter` whose DNS cache returns NotFound for
    /// `simulated-dns-fail.test` (used by the legacy fail-closed tests).
    fn make_router_with_dns_failure(block_private_ip: bool) -> AclRouter {
        let engine = AclEngine::new_default().unwrap();
        let (cache, _mock) = mock_dns_cache(&["simulated-dns-fail.test"]);
        AclRouter::with_dns_cache(engine, block_private_ip, cache)
    }

    /// DNS resolution returning NotFound should be treated as failure
    /// (the public `resolve_domain` collapses every error variant to None).
    #[tokio::test]
    async fn test_resolve_domain_empty_result_returns_none() {
        let router = make_router_with_dns_failure(true);
        let result = router.resolve_domain("simulated-dns-fail.test").await;
        assert!(result.is_none(), "NotFound DNS result should return None");
    }

    /// When block_private_ip is enabled and DNS resolution fails,
    /// the router must reject (fail-closed) to prevent SSRF bypass.
    #[tokio::test]
    async fn test_acl_router_rejects_domain_on_dns_failure_when_blocking() {
        use server_anytls_rs::{Address, OutboundRouter, OutboundType};

        let router = make_router_with_dns_failure(true);
        let addr = Address::Domain("simulated-dns-fail.test".to_string(), 80);
        let result = router.route(&addr).await;
        assert!(
            matches!(result, OutboundType::Reject),
            "expected Reject when DNS fails with block_private_ip=true, got {:?}",
            result
        );
    }

    /// When block_private_ip is disabled, DNS failure should NOT reject.
    #[tokio::test]
    async fn test_acl_router_allows_domain_on_dns_failure_when_not_blocking() {
        use server_anytls_rs::{Address, OutboundRouter, OutboundType};

        let router = make_router_with_dns_failure(false);
        let addr = Address::Domain("simulated-dns-fail.test".to_string(), 80);
        let result = router.route(&addr).await;
        assert!(
            matches!(result, OutboundType::Direct { .. }),
            "expected Direct when DNS fails with block_private_ip=false, got {:?}",
            result
        );
    }

    // -----------------------------------------------------------------------
    // DNS cache improvement tests
    // -----------------------------------------------------------------------

    /// Negative cache: a cached `NotFound` should cause `resolve_domain`
    /// to return None on subsequent lookups without re-invoking the
    /// resolver.
    #[tokio::test]
    async fn test_negative_cache_returns_none_on_hit() {
        let engine = AclEngine::new_default().unwrap();
        let (cache, mock) = mock_dns_cache(&["cached-negative.test"]);
        let router = AclRouter::with_dns_cache(engine, false, cache);

        // First call: miss → resolver invoked once → cached negatively.
        let r1 = router.resolve_domain("cached-negative.test").await;
        assert!(r1.is_none(), "first call should return None (NotFound)");

        // Second call: negative cache hit → resolver NOT invoked again.
        let r2 = router.resolve_domain("cached-negative.test").await;
        assert!(r2.is_none(), "second call should also return None");

        assert_eq!(
            mock.call_count("cached-negative.test"),
            1,
            "negative cache should suppress the second resolver call",
        );
    }

    /// Singleflight: concurrent `resolve_domain` calls for the same host
    /// must coalesce into a single resolver invocation.
    #[tokio::test]
    async fn test_singleflight_coalesces_concurrent_lookups() {
        use std::net::{IpAddr, Ipv4Addr};
        use std::time::Duration;

        let engine = AclEngine::new_default().unwrap();
        let mock = std::sync::Arc::new(dns_cache_rs::MockResolver::new());
        mock.set("same.test", Ok(vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]));
        // Slow the resolver so that 50 concurrent callers genuinely
        // overlap inside the singleflight critical section.
        mock.set_delay(Some(Duration::from_millis(50)));

        let cache = dns_cache_rs::DnsCache::builder()
            .resolver_arc(mock.clone())
            .query_timeout(None)
            .build()
            .expect("build cache");
        let router = Arc::new(AclRouter::with_dns_cache(engine, false, cache));

        let mut handles = Vec::new();
        for _ in 0..50 {
            let r = Arc::clone(&router);
            handles.push(tokio::spawn(
                async move { r.resolve_domain("same.test").await },
            ));
        }

        for h in handles {
            let result = h.await.unwrap();
            assert!(
                result.is_some(),
                "every waiter should get the cached result"
            );
        }

        assert_eq!(
            mock.call_count("same.test"),
            1,
            "singleflight should issue exactly one resolver call",
        );
    }

    /// Cache should respect the maximum capacity and not grow unbounded.
    /// Uses a small `capacity(2)` so we can verify the bound quickly without
    /// inserting thousands of entries.
    #[tokio::test]
    async fn test_cache_respects_max_capacity() {
        use std::net::{IpAddr, Ipv4Addr};

        let engine = AclEngine::new_default().unwrap();
        let mock = std::sync::Arc::new(dns_cache_rs::MockResolver::new());
        for i in 0..10u8 {
            mock.set(
                &format!("h{i}.test"),
                Ok(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, i))]),
            );
        }
        let cache = dns_cache_rs::DnsCache::builder()
            .resolver_arc(mock)
            .capacity(2)
            .query_timeout(None)
            .build()
            .expect("build cache");
        let router = AclRouter::with_dns_cache(engine, false, cache);

        for i in 0..10u8 {
            let _ = router.resolve_domain(&format!("h{i}.test")).await;
        }

        // moka eviction is eventually-consistent; nudge maintenance with
        // a no-op invalidate so entry_count() reflects post-eviction state
        // without a sleep.
        router
            .dns_cache
            .invalidate("__sentinel_for_maintenance__")
            .await;

        let count = router.dns_cache.entry_count();
        assert!(
            count <= 8, // capacity 2 + small slack for moka small-N overshoot
            "entry_count {} should be near capacity 2 (eviction broken?)",
            count,
        );
    }

    /// RED test: route_udp() must use Protocol::UDP so that
    /// `reject(all, udp/443)` actually blocks UDP traffic.
    #[tokio::test]
    async fn test_acl_router_route_udp_rejects_udp_443() {
        use server_anytls_rs::{Address, OutboundRouter, OutboundType};

        let yaml = r#"
outbounds: []
acl:
  inline:
    - reject(all, udp/443)
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let engine = AclEngine::new(config, None, false).await.unwrap();
        let router = AclRouter::with_block_private_ip(engine, false);

        // UDP on port 443 must be rejected
        let addr = Address::Domain("s.youtube.com".to_string(), 443);
        let result = router.route_udp(&addr).await;
        assert!(
            matches!(result, OutboundType::Reject),
            "expected Reject for UDP/443, got {:?}",
            result
        );

        // TCP on port 443 should still be direct (route, not route_udp)
        let result = router.route(&addr).await;
        assert!(
            matches!(result, OutboundType::Direct { .. }),
            "expected Direct for TCP/443, got {:?}",
            result
        );
    }

    /// Verify every rule in acl.yaml against TCP and UDP routing.
    #[tokio::test]
    async fn test_all_acl_yaml_rules() {
        // Replicate acl.yaml inline rules (without geosite, which needs geo data)
        let yaml = r#"
outbounds:
  - name: warp
    type: socks5
    socks5:
      addr: 127.0.0.1:40000
acl:
  inline:
    - reject(all, udp/443)
    - warp(all, tcp/22)
    - warp(all, tcp/25)
    - warp(all, tcp/465)
    - warp(all, tcp/587)
    - warp(all, tcp/993)
    - warp(all, tcp/995)
    - warp(all, tcp/3389)
    - warp(www.google.com)
    - warp(suffix:ping0.cc)
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let engine = AclEngine::new(config, None, false).await.unwrap();

        let is_warp = |h: &OutboundHandler| matches!(h, OutboundHandler::Socks5 { .. });
        let is_direct = |h: &OutboundHandler| matches!(h, OutboundHandler::Direct { .. });

        let tcp = Protocol::TCP;
        let udp = Protocol::UDP;

        // ---- Rule 1: reject(all, udp/443) ----
        let h = engine.match_host("any.com", 443, udp).unwrap();
        assert!(h.is_reject(), "udp/443 should reject, got {:?}", h);

        let h = engine.match_host("any.com", 443, tcp).unwrap();
        assert!(!h.is_reject(), "tcp/443 should NOT reject, got {:?}", h);

        let h = engine.match_host("any.com", 80, udp).unwrap();
        assert!(!h.is_reject(), "udp/80 should NOT reject, got {:?}", h);

        // ---- Rule 2-8: warp(all, tcp/<port>) ----
        let warp_ports = [22, 25, 465, 587, 993, 995, 3389];
        for port in warp_ports {
            let h = engine.match_host("random.com", port, tcp).unwrap();
            assert!(is_warp(&h), "tcp/{} should warp, got {:?}", port, h);

            // Same port via UDP should NOT match tcp/ rule → falls to direct(all)
            let h = engine.match_host("random.com", port, udp).unwrap();
            assert!(
                is_direct(&h),
                "udp/{} should direct (tcp-only rule), got {:?}",
                port,
                h
            );
        }

        // ---- Rule 9: warp(www.google.com) — exact domain, any protocol ----
        let h = engine.match_host("www.google.com", 443, tcp).unwrap();
        assert!(
            is_warp(&h),
            "www.google.com tcp/443 should warp, got {:?}",
            h
        );

        let h = engine.match_host("www.google.com", 80, tcp).unwrap();
        assert!(
            is_warp(&h),
            "www.google.com tcp/80 should warp, got {:?}",
            h
        );

        // !! UDP/443 被 reject(all, udp/443) 优先拦截，不会走到 warp(www.google.com)
        let h = engine.match_host("www.google.com", 443, udp).unwrap();
        assert!(
            h.is_reject(),
            "www.google.com udp/443 hit reject first, got {:?}",
            h
        );

        // UDP non-443 可以正常走到 warp(www.google.com)
        let h = engine.match_host("www.google.com", 80, udp).unwrap();
        assert!(
            is_warp(&h),
            "www.google.com udp/80 should warp, got {:?}",
            h
        );

        // subdomain should NOT match exact domain rule
        let h = engine.match_host("mail.google.com", 443, tcp).unwrap();
        assert!(is_direct(&h), "mail.google.com should direct, got {:?}", h);

        // ---- Rule 10: warp(suffix:ping0.cc) ----
        let h = engine.match_host("ping0.cc", 443, tcp).unwrap();
        assert!(is_warp(&h), "ping0.cc tcp/443 should warp, got {:?}", h);

        let h = engine.match_host("www.ping0.cc", 80, tcp).unwrap();
        assert!(is_warp(&h), "www.ping0.cc tcp/80 should warp, got {:?}", h);

        // !! UDP/443 同样被 reject(all, udp/443) 优先拦截
        let h = engine.match_host("ping0.cc", 443, udp).unwrap();
        assert!(
            h.is_reject(),
            "ping0.cc udp/443 hit reject first, got {:?}",
            h
        );

        // UDP non-443 可以正常走到 warp(suffix:ping0.cc)
        let h = engine.match_host("ping0.cc", 80, udp).unwrap();
        assert!(is_warp(&h), "ping0.cc udp/80 should warp, got {:?}", h);

        // ---- Rule 11: direct(all) — fallback ----
        let h = engine.match_host("unknown.xyz", 80, tcp).unwrap();
        assert!(is_direct(&h), "unknown tcp should direct, got {:?}", h);

        let h = engine.match_host("unknown.xyz", 80, udp).unwrap();
        assert!(is_direct(&h), "unknown udp should direct, got {:?}", h);
    }

    /// Proxied domains must NOT trigger DNS resolution. When a domain
    /// matches a proxy rule (e.g. `warp(suffix:google.com)`), the router
    /// should return Proxy immediately — even if DNS resolution would fail.
    #[tokio::test]
    async fn test_proxied_domain_skips_dns_resolution() {
        use server_anytls_rs::{Address, OutboundRouter, OutboundType};

        let config = AclConfig {
            outbounds: vec![OutboundEntry {
                name: "warp".to_string(),
                outbound_type: "socks5".to_string(),
                socks5: Some(Socks5Config {
                    addr: "127.0.0.1:40000".to_string(),
                    username: None,
                    password: None,
                    allow_udp: true,
                }),
                http: None,
                direct: None,
            }],
            acl: AclRules {
                inline: vec![
                    "warp(suffix:google.com)".to_string(),
                    "direct(all)".to_string(),
                ],
            },
        };

        let engine = AclEngine::new(config, None, false).await.unwrap();
        // block_private_ip=true: DNS failure would cause rejection if DNS
        // is attempted before ACL matching.
        // Simulate a server that cannot resolve Google DNS via the mock resolver.
        let (cache, mock) = mock_dns_cache(&["www.google.com"]);
        let router = AclRouter::with_dns_cache(engine, true, cache);

        // Even though DNS "fails", the domain matches warp(suffix:google.com)
        // so it should be routed through the proxy — NOT rejected.
        let addr = Address::Domain("www.google.com".to_string(), 443);
        let result = router.route(&addr).await;
        assert!(
            matches!(result, OutboundType::Proxy(_)),
            "proxied domain with DNS failure should route through proxy, got {:?}",
            result
        );
        // Pin the "skips DNS" property: ACL match must short-circuit
        // before resolve_domain runs. Without this assert, the test name's
        // claim is unverified — a regression that resolves DNS first and
        // happens to still return Proxy would silently pass.
        assert_eq!(
            mock.call_count("www.google.com"),
            0,
            "ACL match must short-circuit before DNS resolution",
        );
    }

    /// Transient resolver errors (`DnsError::Other`) must NOT be cached;
    /// the next call should re-invoke the resolver. This is a behavior
    /// improvement over the previous moka-based implementation, which
    /// folded all errors into an empty Arc and cached them for 15 s.
    #[tokio::test]
    async fn test_transient_error_not_cached() {
        use std::sync::Arc;

        let engine = AclEngine::new_default().unwrap();
        let mock = Arc::new(dns_cache_rs::MockResolver::new());
        mock.set(
            "broken.test",
            Err(dns_cache_rs::DnsError::Other(Arc::new(
                std::io::Error::other("simulated transient resolver error"),
            ))),
        );

        let cache = dns_cache_rs::DnsCache::builder()
            .resolver_arc(mock.clone())
            .query_timeout(None)
            .build()
            .expect("build cache");
        let router = AclRouter::with_dns_cache(engine, false, cache);

        let _ = router.resolve_domain("broken.test").await;
        let _ = router.resolve_domain("broken.test").await;

        assert_eq!(
            mock.call_count("broken.test"),
            2,
            "Other errors must not be cached (would be 1 if cached)",
        );
    }

    /// A resolver that hangs longer than the configured query_timeout
    /// must produce `None` from `resolve_domain` (the `Timeout` error
    /// variant is collapsed to None alongside NotFound and Other).
    /// The timeout itself is enforced by the dns-cache-rs library.
    #[tokio::test]
    async fn test_query_timeout_yields_none_in_router_path() {
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        let engine = AclEngine::new_default().unwrap();
        let mock = Arc::new(dns_cache_rs::MockResolver::new());
        // Resolver would take 5s if it ran to completion.
        mock.set_delay(Some(Duration::from_secs(5)));
        // Even though we configure a hit, the delay should trip the timeout first.
        mock.set(
            "slow.test",
            Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                1, 1, 1, 1,
            ))]),
        );

        let cache = dns_cache_rs::DnsCache::builder()
            .resolver_arc(mock)
            .query_timeout(Some(Duration::from_millis(100)))
            .build()
            .expect("build cache");
        let router = AclRouter::with_dns_cache(engine, false, cache);

        let start = Instant::now();
        let result = router.resolve_domain("slow.test").await;
        let elapsed = start.elapsed();

        assert!(
            result.is_none(),
            "Timeout must collapse to None, got {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "should bail in ~100ms, took {elapsed:?}"
        );
    }

    /// End-to-end fail-closed: when `block_private_ip=true`, a domain whose
    /// resolution times out must be Rejected (same code path as NotFound).
    #[tokio::test]
    async fn test_acl_router_rejects_on_dns_timeout_when_blocking() {
        use server_anytls_rs::{Address, OutboundRouter, OutboundType};
        use std::sync::Arc;
        use std::time::Duration;

        let engine = AclEngine::new_default().unwrap();
        let mock = Arc::new(dns_cache_rs::MockResolver::new());
        // 5s delay >> 100ms timeout: the 100ms query_timeout fires first,
        // so the resolver never returns. We exercise the Timeout branch
        // (not NotFound) on the way to Reject.
        mock.set_delay(Some(Duration::from_secs(5)));
        let cache = dns_cache_rs::DnsCache::builder()
            .resolver_arc(mock)
            .query_timeout(Some(Duration::from_millis(100)))
            .build()
            .expect("build cache");
        let router = AclRouter::with_dns_cache(engine, true, cache);

        let addr = Address::Domain("hangs.test".to_string(), 443);
        let result = router.route(&addr).await;
        assert!(
            matches!(result, OutboundType::Reject),
            "expected Reject on DNS timeout with block_private_ip=true, got {result:?}",
        );
    }

    /// Host normalization (lowercase + trailing-dot strip, library default)
    /// must cause `Example.COM`, `example.com.`, and `example.com` to share
    /// a single cache entry — verified by the resolver call_count being 1.
    #[tokio::test]
    async fn test_host_normalization_shares_cache_slot() {
        use std::sync::Arc;

        let engine = AclEngine::new_default().unwrap();
        let mock = Arc::new(dns_cache_rs::MockResolver::new());
        mock.set(
            "example.com",
            Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                1, 1, 1, 1,
            ))]),
        );
        let cache = dns_cache_rs::DnsCache::builder()
            .resolver_arc(mock.clone())
            .query_timeout(None)
            .build()
            .expect("build cache");
        let router = AclRouter::with_dns_cache(engine, false, cache);

        let _ = router.resolve_domain("Example.COM").await;
        let _ = router.resolve_domain("example.com.").await;
        let _ = router.resolve_domain("example.com").await;

        assert_eq!(
            mock.call_count("example.com"),
            1,
            "normalized variants must share one cache slot",
        );
    }

    /// Contract test: `resolve_domain` returns `SocketAddr`s with port 0.
    /// Downstream `outbound::connect_target` overrides the port via
    /// `set_port(target.port())`. Pinning this contract prevents an
    /// accidental change to a non-zero default that would silently
    /// mis-route traffic.
    #[tokio::test]
    async fn test_resolve_domain_returns_socketaddr_with_zero_port() {
        use std::net::{IpAddr, Ipv4Addr};
        use std::sync::Arc;

        let engine = AclEngine::new_default().unwrap();
        let mock = Arc::new(dns_cache_rs::MockResolver::new());
        mock.set(
            "ip.test",
            Ok(vec![
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            ]),
        );
        let cache = dns_cache_rs::DnsCache::builder()
            .resolver_arc(mock)
            .query_timeout(None)
            .build()
            .expect("build cache");
        let router = AclRouter::with_dns_cache(engine, false, cache);

        let addrs = router
            .resolve_domain("ip.test")
            .await
            .expect("resolver returned Ok");
        assert_eq!(addrs.len(), 2);
        for sa in addrs.iter() {
            assert_eq!(sa.port(), 0, "resolve_domain must emit port=0");
        }
        // Pin IP values + order so a regression in the IpAddr→SocketAddr
        // conversion (wrong index, missed entry, etc.) fails loudly.
        assert_eq!(addrs[0].ip(), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(addrs[1].ip(), IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)));
    }

    /// Guard against silent upstream changes to dns-cache-rs defaults.
    /// The previous hand-rolled constants were 120s/15s/4096; the library
    /// defaults must continue to match so production behavior stays stable.
    #[test]
    fn test_dns_cache_default_constants_match_previous_implementation() {
        use std::time::Duration;
        assert_eq!(
            dns_cache_rs::defaults::TTL,
            Duration::from_secs(120),
            "positive TTL drifted from prior 120s value",
        );
        assert_eq!(
            dns_cache_rs::defaults::NEGATIVE_TTL,
            Duration::from_secs(15),
            "negative TTL drifted from prior 15s value",
        );
        assert_eq!(
            dns_cache_rs::defaults::CAPACITY,
            4096,
            "capacity drifted from prior 4096 value",
        );
        assert_eq!(
            dns_cache_rs::defaults::QUERY_TIMEOUT,
            Duration::from_secs(2),
            "query_timeout drifted from the 2s baseline relied on by the \
             fail-closed-on-timeout test and the spec §5 behavior matrix",
        );
    }
}
