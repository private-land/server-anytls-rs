# server-anytls-rs

A high-performance [AnyTLS](https://github.com/anytls/anytls-go) proxy server implementation in Rust.

## Features

- Multiplexed TLS connections with virtual stream support
- SHA-256 password authentication with constant-time comparison
- Per-user traffic statistics and reporting
- Optional ACL-based traffic routing
- Connection management with user kick-off and graceful shutdown
- Dynamic padding scheme support
- Panel integration via Connect-RPC over QUIC/HTTP3
- Server-side keepalive to prevent NAT idle connection drops
- jemalloc allocator for optimized memory performance

## Build

```bash
cargo build --release
```

## Usage

```bash
server-anytls-agent \
  --server_host 10.0.0.1 \
  --port 8082 \
  --node <node-id> \
  --cert_file /path/to/server.crt \
  --key_file /path/to/server.key
```

All arguments support environment variables with `X_PANDA_ANYTLS_` prefix.

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--server_host` | `127.0.0.1` | Panel Connect-RPC server host |
| `--port` | `8082` | Panel Connect-RPC server port |
| `--node` | (required) | Node ID |
| `--cert_file` | `/root/.cert/server.crt` | TLS certificate path |
| `--key_file` | `/root/.cert/server.key` | TLS private key path |
| `--server_name` | same as `server_host` | TLS SNI for panel connection |
| `--ca_file` | (none) | CA certificate path for panel TLS (omit for system trust store) |
| `--fetch_users_interval` | `60s` | User list refresh interval |
| `--report_traffics_interval` | `80s` | Traffic stats reporting interval |
| `--heartbeat_interval` | `180s` | Heartbeat interval |
| `--keepalive_interval` | `30s` | Server-side keepalive interval (`0s` to disable) |
| `--api_timeout` | `15s` | API call timeout |
| `--log_mode` | `error` | Log level (`error`, `info`, `debug`) |
| `--data_dir` | `/var/lib/anytls-agent-node` | Data directory |
| `--acl_conf_file` | (none) | ACL rules YAML file |
| `--block_private_ip` | `true` | Block private IP connections |
| `--max_connections` | `auto` | Global connection limit. `auto` derives a cap from `min(cpu_throughput, ram_budget, fd_limit)`; pass a positive integer to override. |
| `--write_buf_size` | `32768` | BufWriter buffer size for the TLS write half, in bytes. |
| `--stream_channel_capacity` | `128` | Per-stream data channel capacity (number of buffered messages). |
| `--downlink_padding` | `true` | Server-side downlink shaping for protocol v1/v2. v2 uses a bounded session-level early window, then normal bulk buffering; controls retain a 10-byte Waste suffix. v1 retains split/head-fill shaping. Set `false` for an unshaped control. |
| `--downlink_burst_padding` | `true` | v2: substantial fill during the first 8 non-empty flush attempts, capped at 8 KiB per outer session. v1: at most 3 seconds / 8 records / 2 KiB after outbound success. Requires `--downlink_padding true`. Set `false` to disable substantial v2 early fill while retaining its small control suffix, or retain only v1 split/head-fill. |
| `--auth_probe_resistance` | `true` | Silently reject malformed initial TLS input and close failed/incomplete authentication at a shared 5-second deadline after TLS handshake completion. Successful authentication proceeds immediately. Set `false` to retain the original handshake/authentication path. |
| `--refresh_geodata` | `false` | Force refresh ACL geodata |

Authentication probe resistance is enabled by default. Disable it with
`--auth_probe_resistance false` (also `--auth-probe-resistance=false`) or
`X_PANDA_ANYTLS_AUTH_PROBE_RESISTANCE=false`. After a successful TLS handshake,
incomplete or rejected authentication closes at the same five-second deadline;
later input cannot extend it. A peer that disconnects releases the connection
early. Valid authentication proceeds immediately, including coalesced Settings.
Malformed initial input, including plaintext HTTP, is silently rejected before
accepting a ClientHello. Subsequent TLS negotiation retains rustls's normal
error handling. The TLS handshake retains its separate bounded timeout. With
the option disabled, TLS handshake and authentication use the original shared
timeout, failed password checks close immediately, and TLS parse alerts are
unchanged. This option does not modify padding or establish censorship resistance.

Early downlink padding is enabled by default. Disable it with
`--downlink_burst_padding false` or
`X_PANDA_ANYTLS_DOWNLINK_BURST_PADDING=false`. The client's padding scheme and
MD5 do not change. For v2, Settings, heartbeat replies, SynAck, data and FIN
share one non-renewable window: the first eight non-empty plaintext flush
attempts target 500–1000 bytes. The window does not expire with time, and new
streams or repeated Settings cannot replenish it. After the window, bulk data
uses normal buffering and TLS fragmentation; control frames keep only the
10-byte Waste suffix. That suffix is accounted separately from the 8 KiB
substantial-padding limit. It adds 10 bytes per control frame for the life of
the session; ordinary data writes have no permanent suffix.

The v2 policy follows observed reference-server behavior, rather than a known
copy of its internal algorithm. Plaintext flushes are not necessarily individual
TLS records. v1 retains its existing per-stream early window and continuous
split/head-fill policy. These policies do not deliberately delay writes or
remove directional/timing correlations, and do not establish censorship resistance.

Session-close debug logs report total shaping bytes and padding cost; measure
latency, overhead, and IP survival on a canary before enabling it across a fleet.
`cargo test --test tls_in_tls_padding -- --nocapture` runs a local HTTPS HEAD/204
flow through two real TLS layers and compares encrypted outer record lengths
with this option enabled and disabled. The fixture models a short response; it
does not reproduce Gstatic's exact certificates, tickets, or response headers.

## Benchmark: Rust vs Go

Tested on macOS Darwin 24.6.0 (MacBook Pro), using [anytls-go](https://github.com/anytls/anytls-go) client v0.0.12 as SOCKS5 proxy, with a mock panel API and Go HTTP target server on localhost.

### Throughput (RPS)

| Concurrency | Go | Rust | Delta |
|-------------|--------|----------|-------|
| c=1 | 11,066 | 10,729 | -3% |
| c=50 | 63,132 | 61,897 | -2% |
| c=100 | 64,783 | 64,344 | -1% |
| c=200 | 64,853 | 63,732 | -2% |
| c=500 | 61,613 | 62,003 | +1% |

> RPS roughly equal — bottlenecked by the shared anytls-go client.

### Tail Latency (p99)

| Concurrency | Go p99 | Rust p99 | Improvement |
|-------------|--------|----------|-------------|
| c=50 | 2.02ms | 1.55ms | **1.3x better** |
| c=100 | 5.24ms | 3.06ms | **1.7x better** |
| c=200 | 12.39ms | 7.38ms | **1.7x better** |
| c=500 | 24.4ms | 17.8ms | **1.4x better** |

### Bandwidth (large payload transfer)

| Payload | Go | Rust | Delta |
|---------|-----------|-----------|-------|
| 10KB c=50 | 497 MB/s | 535 MB/s | **+7.6%** |
| 1MB c=20 | 2,832 MB/s | 3,393 MB/s | **+19.8%** |
| 10MB c=10 | 2,847 MB/s | 2,915 MB/s | **+2.4%** |

### Resource Usage (under sustained load)

| Metric | Go | Rust | Notes |
|--------|---------|---------|-------|
| Avg CPU | 240.7% | 203.1% | **Rust 16% less CPU** |
| Avg RSS | 122.6 MB | 163.8 MB | Go 33% less memory (jemalloc preallocation) |

### Key Takeaways

- **p99 latency 1.3-1.7x lower** — no GC pauses, more predictable under load
- **Large transfer throughput up to 20% higher** — zero-copy IO advantage
- **16% less CPU** for same workload
- Go uses less memory due to jemalloc's arena preallocation in Rust build

Full results: see `benchmarks/` directory or run `~/code/test/anytls-bench/deep_bench.sh`.

## License

MIT
