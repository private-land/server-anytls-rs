use anyhow::{Result, anyhow};
use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;

use crate::business::IpVersion;
use crate::config_auto::MaxConnections;

fn parse_duration(s: &str) -> Result<Duration, String> {
    if let Ok(d) = humantime::parse_duration(s) {
        return Ok(d);
    }
    s.parse::<u64>().map(Duration::from_secs).map_err(|_| {
        format!(
            "Invalid duration '{}'. Use formats like '60s', '2m', '1h' or plain seconds",
            s
        )
    })
}

fn parse_ip_version(s: &str) -> Result<IpVersion, String> {
    match s.to_lowercase().as_str() {
        "v4" | "ipv4" | "4" => Ok(IpVersion::V4),
        "v6" | "ipv6" | "6" => Ok(IpVersion::V6),
        "auto" | "dual" => Ok(IpVersion::Auto),
        other => Err(format!(
            "Invalid IP version '{}'. Use 'v4', 'v6', or 'auto'",
            other
        )),
    }
}

const DEFAULT_DATA_DIR: &str = "/var/lib/anytls-agent-node";

#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    about = "AnyTLS Server Agent with gRPC Panel Integration"
)]
#[command(rename_all = "snake_case")]
pub struct CliArgs {
    /// gRPC server host (e.g., "127.0.0.1")
    #[arg(
        long = "server_host",
        env = "X_PANDA_ANYTLS_SERVER_HOST",
        default_value = "127.0.0.1"
    )]
    pub server_host: String,

    /// gRPC server port (e.g., 8082)
    #[arg(long = "port", env = "X_PANDA_ANYTLS_PORT", default_value_t = 8082)]
    pub port: u16,

    /// Node ID from the panel (required)
    #[arg(long, env = "X_PANDA_ANYTLS_NODE")]
    pub node: u32,

    #[arg(
        long,
        env = "X_PANDA_ANYTLS_CERT_FILE",
        default_value = "/root/.cert/server.crt"
    )]
    pub cert_file: String,

    #[arg(
        long,
        env = "X_PANDA_ANYTLS_KEY_FILE",
        default_value = "/root/.cert/server.key"
    )]
    pub key_file: String,

    #[arg(long, env = "X_PANDA_ANYTLS_FETCH_USERS_INTERVAL", default_value = "60s", value_parser = parse_duration)]
    pub fetch_users_interval: Duration,

    #[arg(long, env = "X_PANDA_ANYTLS_REPORT_TRAFFICS_INTERVAL", default_value = "80s", value_parser = parse_duration)]
    pub report_traffics_interval: Duration,

    #[arg(long, env = "X_PANDA_ANYTLS_HEARTBEAT_INTERVAL", default_value = "180s", value_parser = parse_duration)]
    pub heartbeat_interval: Duration,

    #[arg(long = "api_timeout", env = "X_PANDA_ANYTLS_API_TIMEOUT", default_value = "15s", value_parser = parse_duration)]
    pub api_timeout: Duration,

    /// TLS server name (SNI) for panel connection (defaults to --server_host)
    #[arg(
        long = "server_name",
        env = "X_PANDA_ANYTLS_SERVER_NAME",
        value_name = "NAME"
    )]
    pub server_name: Option<String>,

    /// CA certificate path for panel TLS (omit for system trust store)
    #[arg(long = "ca_file", env = "X_PANDA_ANYTLS_CA_FILE", value_name = "PATH")]
    pub ca_file: Option<String>,

    #[arg(long, env = "X_PANDA_ANYTLS_LOG_MODE", default_value = "error")]
    pub log_mode: String,

    #[arg(long, env = "X_PANDA_ANYTLS_DATA_DIR", default_value = DEFAULT_DATA_DIR)]
    pub data_dir: PathBuf,

    #[arg(long, env = "X_PANDA_ANYTLS_ACL_CONF_FILE")]
    pub acl_conf_file: Option<PathBuf>,

    #[arg(long, env = "X_PANDA_ANYTLS_BLOCK_PRIVATE_IP", default_value_t = true)]
    pub block_private_ip: bool,

    #[arg(long, env = "X_PANDA_ANYTLS_REFRESH_GEODATA", default_value_t = false)]
    pub refresh_geodata: bool,

    /// IP version preference for panel API connections (v4, v6, auto)
    #[arg(long, env = "X_PANDA_ANYTLS_PANEL_IP_VERSION", default_value = "v4",
           value_parser = parse_ip_version, help_heading = "Network")]
    pub panel_ip_version: IpVersion,

    // --- Performance tuning ---
    /// Maximum number of concurrent connections. Use 'auto' to derive a
    /// sensible cap from CPU cores, total RAM, and the file-descriptor limit.
    #[arg(
        long,
        env = "X_PANDA_ANYTLS_MAX_CONNECTIONS",
        default_value = "auto",
        help_heading = "Performance"
    )]
    pub max_connections: MaxConnections,

    /// BufWriter buffer size for the TLS write half (bytes).
    #[arg(long, env = "X_PANDA_ANYTLS_WRITE_BUF_SIZE", default_value_t = 32 * 1024, help_heading = "Performance")]
    pub write_buf_size: usize,

    /// Server-side downlink padding ("补包"): shape downlink record sizes so
    /// the TLS record-length sequence carries no TLS-in-TLS signature.
    ///
    /// Only applies to clients announcing protocol v2; legacy clients are
    /// byte-for-byte unaffected. Disable to fall back to the unshaped write
    /// path (useful as a control when measuring block rates).
    #[arg(
        long,
        env = "X_PANDA_ANYTLS_DOWNLINK_PADDING",
        default_value_t = true,
        help_heading = "Performance"
    )]
    pub downlink_padding: bool,

    /// Per-stream data channel capacity (number of buffered messages).
    #[arg(
        long,
        env = "X_PANDA_ANYTLS_STREAM_CHANNEL_CAPACITY",
        default_value_t = 128,
        help_heading = "Performance"
    )]
    pub stream_channel_capacity: usize,
}

impl CliArgs {
    pub fn parse_args() -> Self {
        Self::parse()
    }

    pub fn validate(&self) -> Result<()> {
        if self.server_host.is_empty() {
            return Err(anyhow!("gRPC server host is required"));
        }
        if self.node == 0 {
            return Err(anyhow!("Node ID must be a positive integer"));
        }
        if self.cert_file.is_empty() {
            return Err(anyhow!("TLS certificate file path is required"));
        }
        if self.key_file.is_empty() {
            return Err(anyhow!("TLS private key file path is required"));
        }
        if self.fetch_users_interval.is_zero() {
            return Err(anyhow!("fetch_users_interval must be greater than 0"));
        }
        if self.report_traffics_interval.is_zero() {
            return Err(anyhow!("report_traffics_interval must be greater than 0"));
        }
        if self.heartbeat_interval.is_zero() {
            return Err(anyhow!("heartbeat_interval must be greater than 0"));
        }
        if let Some(ref path) = self.acl_conf_file {
            if !path.exists() {
                return Err(anyhow!("ACL config file not found: {}", path.display()));
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !ext.eq_ignore_ascii_case("yaml") && !ext.eq_ignore_ascii_case("yml") {
                return Err(anyhow!(
                    "Invalid ACL config file format: expected .yaml or .yml"
                ));
            }
        }
        Ok(())
    }
}

/// AnyTLS node configuration from panel JSON
#[derive(Debug, Clone, Deserialize)]
pub struct AnyTlsConfig {
    pub server_port: u16,
    #[serde(default)]
    pub padding_rules: Option<String>,
}

pub fn parse_anytls_config(node_config: panel_core::NodeConfigEnum) -> Result<AnyTlsConfig> {
    match node_config {
        panel_core::NodeConfigEnum::AnyTls(json) => {
            serde_json::from_str(&json).map_err(|e| anyhow!("Failed to parse AnyTlsConfig: {}", e))
        }
        other => Err(anyhow!(
            "Expected AnyTls config, got {:?}",
            std::mem::discriminant(&other)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_cli_args() -> CliArgs {
        CliArgs {
            server_host: "127.0.0.1".to_string(),
            port: 8082,
            node: 1,
            cert_file: "/path/to/cert.pem".to_string(),
            key_file: "/path/to/key.pem".to_string(),
            fetch_users_interval: Duration::from_secs(60),
            report_traffics_interval: Duration::from_secs(80),
            heartbeat_interval: Duration::from_secs(180),
            api_timeout: Duration::from_secs(15),
            log_mode: "error".to_string(),
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            acl_conf_file: None,
            block_private_ip: true,
            max_connections: MaxConnections::Auto,
            refresh_geodata: false,
            panel_ip_version: IpVersion::V4,
            server_name: None,
            ca_file: None,
            write_buf_size: 32 * 1024,
            downlink_padding: true,
            stream_channel_capacity: 128,
        }
    }

    #[test]
    fn test_cli_args_defaults() {
        let cli = create_test_cli_args();
        assert_eq!(cli.server_host, "127.0.0.1");
        assert_eq!(cli.port, 8082);
        assert_eq!(cli.fetch_users_interval, Duration::from_secs(60));
        assert_eq!(cli.report_traffics_interval, Duration::from_secs(80));
        assert_eq!(cli.heartbeat_interval, Duration::from_secs(180));
        assert_eq!(cli.api_timeout, Duration::from_secs(15));
        assert_eq!(cli.log_mode, "error");
        assert!(cli.server_name.is_none());
        assert!(cli.ca_file.is_none());
    }

    #[test]
    fn test_cli_args_validate_success() {
        let cli = create_test_cli_args();
        assert!(cli.validate().is_ok());
    }

    #[test]
    fn test_cli_args_validate_empty_server_host() {
        let mut cli = create_test_cli_args();
        cli.server_host = "".to_string();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_invalid_node_id() {
        let mut cli = create_test_cli_args();
        cli.node = 0;
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_zero_interval() {
        let mut cli = create_test_cli_args();
        cli.fetch_users_interval = Duration::ZERO;
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_empty_cert() {
        let mut cli = create_test_cli_args();
        cli.cert_file = "".to_string();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_empty_key() {
        let mut cli = create_test_cli_args();
        cli.key_file = "".to_string();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_with_server_name() {
        let mut cli = create_test_cli_args();
        cli.server_name = Some("panel.example.com".to_string());
        assert!(cli.validate().is_ok());
        assert_eq!(cli.server_name.unwrap(), "panel.example.com");
    }

    #[test]
    fn test_cli_args_with_ca_file() {
        let mut cli = create_test_cli_args();
        cli.ca_file = Some("/path/to/ca.crt".to_string());
        assert!(cli.validate().is_ok());
        assert_eq!(cli.ca_file.unwrap(), "/path/to/ca.crt");
    }

    #[test]
    fn test_default_data_dir_value() {
        assert_eq!(DEFAULT_DATA_DIR, "/var/lib/anytls-agent-node");
    }

    #[test]
    fn test_parse_duration_humantime() {
        assert_eq!(parse_duration("60s").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_duration_plain_seconds() {
        assert_eq!(parse_duration("60").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("120").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("invalid").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn test_parse_anytls_config() {
        let json = r#"{"server_port": 443}"#;
        let config = parse_anytls_config(panel_core::NodeConfigEnum::AnyTls(json.to_string()));
        assert!(config.is_ok());
        assert_eq!(config.unwrap().server_port, 443);
    }

    #[test]
    fn test_parse_anytls_config_with_padding_rules_string() {
        // Real panel response: padding_rules is a string with \r\n separators, not an array
        let json = r#"{"server_port":4430,"padding_rules":"stop=5\r\n0=30-30\r\n1=100-300\r\n2=300-500,c,500-1000,c,500-1000,c,500-1000\r\n3=500-1000\r\n4=500-1000"}"#;
        let config =
            parse_anytls_config(panel_core::NodeConfigEnum::AnyTls(json.to_string())).unwrap();
        assert_eq!(config.server_port, 4430);
        let rules = config.padding_rules.unwrap();
        assert!(rules.contains("stop=5"));
        assert!(rules.contains("0=30-30"));
    }

    #[test]
    fn test_parse_anytls_config_wrong_type() {
        let json = r#"{"server_port": 443}"#;
        let config = parse_anytls_config(panel_core::NodeConfigEnum::Trojan(json.to_string()));
        assert!(config.is_err());
    }

    #[test]
    fn test_cli_args_performance_defaults() {
        let cli = create_test_cli_args();
        assert_eq!(cli.write_buf_size, 32 * 1024);
        assert!(cli.downlink_padding);
        assert_eq!(cli.stream_channel_capacity, 128);
    }

    #[test]
    fn test_parse_ip_version_valid() {
        for (input, expected) in [
            ("v4", IpVersion::V4),
            ("ipv4", IpVersion::V4),
            ("4", IpVersion::V4),
            ("V4", IpVersion::V4),
            ("v6", IpVersion::V6),
            ("ipv6", IpVersion::V6),
            ("6", IpVersion::V6),
            ("auto", IpVersion::Auto),
            ("dual", IpVersion::Auto),
        ] {
            assert_eq!(
                parse_ip_version(input).unwrap(),
                expected,
                "input: {}",
                input
            );
        }
    }

    #[test]
    fn test_parse_ip_version_invalid() {
        for input in ["", "v5", "invalid", "ip4"] {
            assert!(parse_ip_version(input).is_err(), "input: {}", input);
        }
    }
}
