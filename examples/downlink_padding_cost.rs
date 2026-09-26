//! One-off measurement harness for the downlink shaper's traffic cost.
//!
//! Drives the production `WriteState` (the exact type the session puts behind
//! its write half) against a `Sink` that records the payload size of every
//! `poll_write`. `WriteState` wraps a `BufWriter`, and each `flush()` becomes
//! one TLS record, so the recorded sizes *are* the downlink record-length
//! sequence the middlebox sees.
//!
//! Traffic model mirrors the production call sites:
//!   * session start -> `write_settings_response`: one coalesced buffer, one
//!     `write_all`, one `flush` (session.rs)
//!   * per connection -> `write_frame(SynAck)` with an EMPTY payload, under its
//!     own lock, ending in its own `flush`
//!   * connection body -> the writer task: up to `MAX_BATCH_SIZE` commands
//!     written under the lock, ONE `flush` per batch
//!
//! Run: `cargo run --release --example downlink_padding_cost`

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use server_anytls_rs::core::downlink_padding::WriteState;
use server_anytls_rs::core::frame::{Command, HEADER_SIZE};
use tokio::io::AsyncWrite;

const CAP: usize = 32 * 1024;

/// `MAX_BATCH_SIZE` in `src/core/session.rs`: how many WriteCommands the writer
/// task drains before it flushes one record.
const MAX_BATCH_SIZE: usize = 64;

/// TLS 1.3 record framing added to every emitted record: 5-byte record header,
/// 1-byte inner content type, 16-byte AEAD tag. The numbers below are plaintext
/// payload; this is what the middlebox actually counts on the wire.
const TLS_RECORD_OVERHEAD: usize = 22;

#[derive(Clone, Default)]
struct Sink {
    records: Arc<Mutex<Vec<usize>>>,
}

impl Sink {
    fn sizes(&self) -> Vec<usize> {
        self.records.lock().unwrap().clone()
    }
}

impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.records.lock().unwrap().push(buf.len());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn frame(cmd: Command, stream: u32, payload: usize) -> Vec<u8> {
    let mut b = Vec::with_capacity(HEADER_SIZE + payload);
    b.push(cmd as u8);
    b.extend_from_slice(&stream.to_be_bytes());
    b.extend_from_slice(&(payload as u16).to_be_bytes());
    b.resize(HEADER_SIZE + payload, 0);
    b
}

/// `write_settings_response`: one coalesced buffer, one write, one flush — and
/// the burst head that arms the shaper.
async fn session_head(ws: &mut WriteState<Sink>) {
    if ws.shaper().is_configured() {
        ws.shaper_mut().enable();
    }
    ws.shaper_mut().mark_burst_head();
    ws.write_all(&frame(Command::UpdatePaddingScheme, 0, 14))
        .await
        .unwrap();
    ws.write_all(&frame(Command::ServerSettings, 0, 3))
        .await
        .unwrap();
    ws.flush().await.unwrap();
}

/// One proxied connection: the empty `SynAck` head under its own lock, then
/// `chunks` body frames delivered by the writer task in batches of
/// `MAX_BATCH_SIZE`, with the `Fin` riding in the final batch.
async fn proxied_connection(ws: &mut WriteState<Sink>, stream: u32, chunk: usize, chunks: usize) {
    // write_frame(SynAck, &[]) — its own lock, its own flush.
    ws.shaper_mut().mark_burst_head();
    ws.write_all(&frame(Command::SynAck, stream, 0))
        .await
        .unwrap();
    ws.flush().await.unwrap();

    let mut remaining = chunks;
    while remaining > 0 {
        let batch = remaining.min(MAX_BATCH_SIZE);
        for _ in 0..batch {
            ws.write_all(&frame(Command::Psh, stream, chunk))
                .await
                .unwrap();
        }
        if batch == remaining {
            // write_cmd_frame: the FIN rides in the same batch as the last PSH.
            ws.write_all(&frame(Command::Fin, stream, 0)).await.unwrap();
        }
        ws.flush().await.unwrap();
        remaining -= batch;
    }
}

struct Scenario {
    name: &'static str,
    connections: u32,
    chunk: usize,
    chunks: usize,
}

struct Measured {
    /// Payload the tunnel carried, excluding padding.
    real: u64,
    /// Payload that was padding.
    padded: u64,
    records: usize,
    /// What the middlebox sees: plaintext handed to TLS (padding and frame
    /// headers included) plus TLS record framing.
    wire: u64,
}

fn drive(scenario: &Scenario, configured: bool) -> (Measured, Vec<usize>) {
    let sink = Sink::default();
    let mut ws = WriteState::new(sink.clone(), CAP, configured);
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    rt.block_on(async {
        session_head(&mut ws).await;
        for stream in 1..=scenario.connections {
            proxied_connection(&mut ws, stream, scenario.chunk, scenario.chunks).await;
        }
    });

    let stats = ws.shaper().counters().snapshot();
    let sizes = sink.sizes();
    let records = sizes.len();
    // `sizes` is plaintext; adding record framing gives the wire cost the
    // middlebox (and the Lightsail egress meter) actually sees.
    let wire =
        sizes.iter().map(|n| *n as u64).sum::<u64>() + TLS_RECORD_OVERHEAD as u64 * records as u64;
    (
        Measured {
            real: stats.real_bytes(),
            padded: stats.padded,
            records,
            wire,
        },
        sizes,
    )
}

fn main() {
    let scenarios = [
        Scenario {
            name: "chat/API   40 conns x 4 x 256B",
            connections: 40,
            chunk: 256,
            chunks: 4,
        },
        Scenario {
            name: "web page    60 conns x 2 x 2KB",
            connections: 60,
            chunk: 2 * 1024,
            chunks: 2,
        },
        Scenario {
            name: "photo/app   20 conns x 8 x 16KB",
            connections: 20,
            chunk: 16 * 1024,
            chunks: 8,
        },
        Scenario {
            name: "video       1 conn  x 256 x 16KB",
            connections: 1,
            chunk: 16 * 1024,
            chunks: 256,
        },
    ];

    println!(
        "{:<32} {:>11} {:>10} {:>11} {:>11} {:>9}",
        "scenario", "real", "padding", "wire off", "wire on", "overhead"
    );
    for s in &scenarios {
        let (off, _) = drive(s, false);
        let (on, _) = drive(s, true);
        let ratio = (on.wire as f64 / off.wire as f64 - 1.0) * 100.0;
        println!(
            "{:<32} {:>11} {:>10} {:>11} {:>11} {:>8.2}%",
            s.name, on.real, on.padded, off.wire, on.wire, ratio
        );
    }

    println!("\n-- cost decomposition (shaped runs) --");
    for s in &scenarios {
        let (off, _) = drive(s, false);
        let (on, _) = drive(s, true);
        let framing = TLS_RECORD_OVERHEAD as u64 * (on.records as u64 - off.records as u64);
        let per_conn = on.padded as f64 / s.connections as f64;
        println!(
            "{:<32} padding {:>8} B ({:>5.2}%)  extra TLS framing {:>8} B ({:>5.2}%)  \
             records {:>5}->{:<5}  padding/conn {:>6.0} B",
            s.name,
            on.padded,
            100.0 * on.padded as f64 / off.wire as f64,
            framing,
            100.0 * framing as f64 / off.wire as f64,
            off.records,
            on.records,
            per_conn,
        );
    }

    println!("\n-- downlink record-length sequence (the middlebox-visible shape) --");
    for s in &scenarios {
        let (_, sizes_off) = drive(s, false);
        let (_, sizes_on) = drive(s, true);
        let show = |v: &[usize]| {
            let mut parts: Vec<String> = v.iter().take(32).map(|n| n.to_string()).collect();
            if v.len() > 32 {
                parts.push(format!("... ({} total)", v.len()));
            }
            parts.join(" ")
        };
        println!("\n[{}]", s.name);
        println!("  padding off: {}", show(&sizes_off));
        println!("  padding on : {}", show(&sizes_on));
    }
}
