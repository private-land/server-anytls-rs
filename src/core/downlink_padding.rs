//! Server-side downlink padding ("补包").
//!
//! # Why this exists
//!
//! A proxied TLS connection carries a *second* TLS handshake inside the outer
//! one. The wall only sees the outer records, and their plaintext length
//! sequence is what gives the tunnel away. The observed shape of an unshaped
//! anytls session is:
//!
//! ```text
//! 27 754 281 53 | 27 24 165 | 4761 5520 24      (outer TLS record lengths)
//!    ^ handshake     ^ control    ^ data burst
//! ```
//!
//! Two properties of that sequence are the signature:
//!
//! 1. a handful of tiny records (24–165 B) carries the per-connection control
//!    frames, including a small `SynAck` for every v2 proxied connection,
//! 2. the records that follow mirror the *inner* TLS records one-for-one, so
//!    the outer lengths match the inner handshake/`16 KiB` record lengths.
//!
//! The reference implementation only pads the client→server direction; the
//! protocol itself explicitly allows either side to pad — "any party receiving
//! `cmdWaste` must read it out completely and discard it silently" — so a
//! server-originated downlink padding frame is legal for unmodified clients.
//!
//! # How the shaping works
//!
//! A `BufWriter` flush hands a bounded plaintext write to TLS. Actual TLS
//! record sizes also depend on the TLS writer and must be measured on the
//! encrypted stream. Shaping decides how many bytes go into each flush:
//!
//! * **split** — a record larger than [`SPLIT_MAX`] is cut into several records
//!   of a randomised size inside `[SPLIT_MIN, SPLIT_MAX]`. Each cut costs an
//!   outer-record header (~21 B) and one AEAD encryption pass, so at the
//!   ~1.8 KB average the overhead is ≈1 % of bytes and the session emits
//!   ~9× more records than it would at 16 KiB — the byte cost is negligible,
//!   the per-record cost is small but not zero.
//! * **fill** — the first record of a *burst* (the session head, and the head of
//!   each proxied connection's downlink, which starts at `SynAck`) is padded up
//!   into `[HEAD_MIN, HEAD_MAX]` with a `Waste` frame. This is the only place
//!   real bytes are spent, and the only place they are needed: the band's floor
//!   lifts a 7-byte `SynAck` to a record size that reads like a handshake
//!   fragment.
//!
//! The split/head-fill policy alone leaves data tails and other control frames
//! unpadded, preserving some short inner-handshake/HTTP-response lengths. The
//! early-window policy, enabled by default by the server, fills tails after
//! successful `SynAck`, bounded by time, record count, and additional bytes.
//! Larger tails also get random extra bytes to change burst totals. It neither
//! delays writes deliberately nor removes directional/timing correlations.
//!
//! Two further properties keep the shaping from becoming a signature of its own:
//!
//! * the target size is drawn per record, so a session's record sizes have
//!   natural variance instead of sitting in a tight constant band — a "split
//!   everything at exactly 1400" scheme is itself learnable, and
//! * the fill band is deliberately *narrower and lower* than the split band. A
//!   head is paid once per proxied connection, so it is the expensive lever;
//!   it only has to stop being tiny, not match the bulk band.
//!
//! # Compatibility
//!
//! Shaping is gated twice. The operator flag ([`DownlinkShaper::new`]'s first
//! argument) decides whether the feature exists at all, and [`DownlinkShaper::enable`]
//! is only called once the peer has announced protocol v2 — which is exactly the
//! announcement that says "I understand `ServerSettings`, and I will silently
//! discard `Waste`". A legacy peer never sends it, so `enable()` is never called
//! and the downlink is byte-for-byte what it was before this module existed.
//!
//! Nothing here touches the padding *scheme* string or its md5, so no client is
//! asked to re-handshake, and the shaper allocates nothing per record — just
//! one small counter struct per session — so the connection budget in
//! `config_auto` keeps its meaning.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::time::Instant;

use crate::core::frame::{Command, FrameHeader, HEADER_SIZE};

/// Smallest plaintext size a burst-head record is filled up to.
///
/// 320 B is where a record stops looking like a control marker and starts
/// looking like the tail of a TLS handshake flight (a certificate fragment).
pub const HEAD_MIN: usize = 320;

/// Largest plaintext size a burst-head record is allowed to have.
///
/// Deliberately modest, and below [`SPLIT_MAX`]: a head is filled once per
/// proxied connection, so it is the expensive lever and only has to stop being
/// tiny. The 4.4× spread over [`HEAD_MIN`] keeps heads from forming a
/// recognisable constant size.
pub const HEAD_MAX: usize = 1400;

/// Smallest plaintext size a bulk record is cut down to.
pub const SPLIT_MIN: usize = 1024;

/// Largest plaintext size a bulk record is allowed to have.
///
/// Far below the 16 KiB TLS record limit on purpose: full-size outer records
/// are what the wall expects to see when the inner TLS stream sends full-size
/// records, and keeping every record under the band top breaks that
/// correspondence.
pub const SPLIT_MAX: usize = 2560;

/// Additional padding budget for one early downlink window, excluding the
/// existing Settings/SynAck head fill and TLS framing overhead.
pub const BURST_PADDING_BUDGET: usize = 2048;
const BURST_RECORD_LIMIT: usize = 8;
const BURST_DURATION: Duration = Duration::from_secs(3);
const BURST_HEAD_MAX: usize = 768;

/// A `Waste` frame is `HEADER_SIZE` bytes of header plus a payload; the
/// smallest useful one is a bare header.
const MIN_WASTE_FRAME: usize = HEADER_SIZE;

/// Process-wide seed source, so two sessions never draw the same sequence.
static SESSION_SEQ: AtomicU64 = AtomicU64::new(0);

/// Per-session shaping counters, shared so the session owner can report the
/// overhead without taking the write lock.
#[derive(Debug, Default)]
pub struct ShapingCounters {
    records: AtomicU64,
    bytes: AtomicU64,
    padded: AtomicU64,
}

/// Snapshot of [`ShapingCounters`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShapingStats {
    /// Number of TLS records emitted while shaping was active.
    pub records: u64,
    /// Total plaintext bytes emitted, including padding.
    pub bytes: u64,
    /// Plaintext bytes that were padding, i.e. the cost of the feature.
    pub padded: u64,
}

impl ShapingStats {
    /// Payload bytes the tunnel actually carried (total minus padding).
    pub fn real_bytes(&self) -> u64 {
        self.bytes.saturating_sub(self.padded)
    }

    /// Padding as a fraction of the tunnel's own payload (`0.0` when empty).
    pub fn padding_ratio(&self) -> f64 {
        let real = self.real_bytes();
        if real == 0 {
            return 0.0;
        }
        self.padded as f64 / real as f64
    }
}

impl ShapingCounters {
    pub fn snapshot(&self) -> ShapingStats {
        ShapingStats {
            records: self.records.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            padded: self.padded.load(Ordering::Relaxed),
        }
    }
}

/// Decides the size of each downlink TLS record.
///
/// Holds no buffers: it only tracks how many plaintext bytes are in the record
/// currently being built and what size the next one should aim for.
pub struct DownlinkShaper {
    /// The operator's flag. Shaping can happen only when this is set.
    configured: bool,
    /// The live switch: `configured` **and** the peer announced v2.
    enabled: bool,
    /// Plaintext bytes already handed to the writer for the current record.
    pending: usize,
    /// Plaintext size the current record aims for.
    target: usize,
    /// The record being built starts a burst, so it may be filled up to the
    /// band floor with a `Waste` frame.
    head: bool,
    head_min: usize,
    head_max: usize,
    split_min: usize,
    split_max: usize,
    rng: u64,
    counters: Arc<ShapingCounters>,
    burst_configured: bool,
    burst_deadline: Option<Instant>,
    burst_budget: usize,
    burst_records: usize,
}

impl DownlinkShaper {
    pub fn new(configured: bool, buf_capacity: usize) -> Self {
        Self::with_seed(configured, buf_capacity, fresh_seed())
    }

    /// Seedable constructor: tests use it to get a reproducible record sequence.
    pub fn with_seed(configured: bool, buf_capacity: usize, rng: u64) -> Self {
        // A record can never be larger than the `BufWriter` capacity: tokio
        // bypasses its buffer (and therefore our flush boundaries) for any
        // single write bigger than the capacity, which would hand the TLS
        // layer one oversized record behind our back.
        let (head_min, head_max) = clamp_band(HEAD_MIN, HEAD_MAX, buf_capacity);
        let (split_min, split_max) = clamp_band(SPLIT_MIN, SPLIT_MAX, buf_capacity);
        let mut shaper = Self {
            configured,
            enabled: false,
            pending: 0,
            target: head_max,
            // The session head is a burst head: the first downlink records are
            // the settings response, which is exactly the tiny-record giveaway.
            head: true,
            head_min,
            head_max,
            split_min,
            split_max,
            rng,
            counters: Arc::new(ShapingCounters::default()),
            burst_configured: false,
            burst_deadline: None,
            burst_budget: 0,
            burst_records: 0,
        };
        shaper.pick_target();
        shaper
    }

    /// Start shaping. Called once the peer has announced protocol v2, under the
    /// same write lock as the first shaped record.
    ///
    /// A no-op when the operator disabled the feature, so an operator switch is
    /// never overridden by a peer's announcement.
    pub fn enable(&mut self) {
        self.enabled = self.configured;
    }

    pub fn is_configured(&self) -> bool {
        self.configured
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Optional early-window padding, still gated by the main flag and v2.
    pub fn configure_burst_padding(&mut self, enabled: bool) {
        self.burst_configured = enabled;
        if !enabled {
            self.burst_deadline = None;
        }
    }

    /// Re-arm only after a successful SynAck has been flushed. Windows belong
    /// to the outer session, so overlapping streams share (rather than add)
    /// this budget. No per-stream allocation or timer task is needed.
    pub fn start_burst_padding(&mut self) {
        if self.enabled && self.burst_configured {
            self.burst_deadline = Some(Instant::now() + BURST_DURATION);
            self.burst_budget = BURST_PADDING_BUDGET;
            self.burst_records = BURST_RECORD_LIMIT;
        }
    }

    fn burst_active(&self) -> bool {
        self.enabled
            && self.burst_configured
            && self.burst_records > 0
            && self.burst_budget >= MIN_WASTE_FRAME
            && self
                .burst_deadline
                .is_some_and(|deadline| Instant::now() < deadline)
    }

    pub fn counters(&self) -> &Arc<ShapingCounters> {
        &self.counters
    }

    /// Plaintext bytes that may be handed to the writer before the current
    /// record must be flushed. `usize::MAX` when shaping is off.
    pub fn write_budget(&self) -> usize {
        if !self.enabled {
            return usize::MAX;
        }
        self.target.saturating_sub(self.pending).max(1)
    }

    /// Account for `n` plaintext bytes just handed to the writer. Returns
    /// `true` when the record reached its target and must be flushed now.
    pub fn account(&mut self, n: usize) -> bool {
        if !self.enabled {
            return false;
        }
        self.pending += n;
        self.pending >= self.target
    }

    pub fn pending(&self) -> usize {
        self.pending
    }

    /// Bytes of padding to append before flushing the current record, so that a
    /// burst head lands inside `[HEAD_MIN, HEAD_MAX]`. `0` means "do not pad".
    ///
    /// The returned count includes the `Waste` frame header. Padding is only
    /// ever appended behind *complete* frames.
    pub fn tail_padding(&self) -> usize {
        if !self.enabled || !self.head || self.pending == 0 || self.pending >= self.head_min {
            return 0;
        }
        let cap = self.head_max.saturating_sub(self.pending);
        if cap < MIN_WASTE_FRAME {
            return 0;
        }
        self.target
            .saturating_sub(self.pending)
            .clamp(MIN_WASTE_FRAME, cap)
    }

    /// Called only at a complete frame boundary. Small records get a random
    /// floor; larger tails get random additional bytes, changing burst totals
    /// as well as record boundaries. Mid-frame split flushes never use this.
    fn padding_for_flush(&mut self) -> usize {
        let head_pad = self.tail_padding();
        if head_pad > 0 || !self.burst_active() || self.pending == 0 {
            return head_pad;
        }
        let capacity = self
            .split_max
            .saturating_sub(self.pending)
            .min(self.burst_budget);
        if capacity < MIN_WASTE_FRAME {
            return 0;
        }
        let wanted = if self.pending < self.head_min {
            self.range(self.head_min, BURST_HEAD_MAX.min(self.head_max)) - self.pending
        } else {
            self.range(32, 256)
        };
        let pad = wanted.clamp(MIN_WASTE_FRAME, capacity);
        // Reserve before any I/O await. A failed/cancelled flush must not
        // spend the same additional-byte budget again on a later retry.
        self.burst_budget -= pad;
        pad
    }

    fn reserve_record_flush(&mut self) {
        if self.pending > 0 {
            // Count attempts conservatively: bytes may have reached the peer
            // even if the underlying flush subsequently fails or is cancelled.
            self.burst_records = self.burst_records.saturating_sub(1);
        }
    }

    /// Mark the next record as a burst head: the session start, or a `SynAck`
    /// (the head of a proxied connection's downlink burst).
    pub fn mark_burst_head(&mut self) {
        if !self.enabled {
            return;
        }
        self.head = true;
        // Mid-record, the size was already drawn; only a fresh record gets to
        // pick from the fill band.
        if self.pending == 0 {
            self.pick_target();
        }
    }

    /// Finish the record that was just flushed. `padded` is how many of its
    /// bytes were padding.
    pub fn record_done(&mut self, padded: usize) {
        if !self.enabled || self.pending == 0 {
            return;
        }
        self.counters.records.fetch_add(1, Ordering::Relaxed);
        self.counters
            .bytes
            .fetch_add(self.pending as u64, Ordering::Relaxed);
        self.counters
            .padded
            .fetch_add(padded as u64, Ordering::Relaxed);
        self.pending = 0;
        self.head = false;
        self.pick_target();
    }

    fn pick_target(&mut self) {
        let (lo, hi) = if self.head {
            (self.head_min, self.head_max)
        } else {
            (self.split_min, self.split_max)
        };
        self.target = self.range(lo, hi);
    }

    /// Uniform in `[lo, hi]`, inclusive.
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        if hi <= lo {
            return lo;
        }
        let span = (hi - lo + 1) as u64;
        lo + (self.next_u64() % span) as usize
    }

    /// splitmix64. Small, allocation-free, and `Send` — `rand`'s `ThreadRng` is
    /// neither storable across an `await` nor shareable across the writer task
    /// and the control-frame paths, and this shaper lives inside a shared lock.
    fn next_u64(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Clamp a band into the `BufWriter` capacity, keeping `lo <= hi`.
fn clamp_band(lo: usize, hi: usize, buf_capacity: usize) -> (usize, usize) {
    let hi = hi.min(buf_capacity.max(1));
    (lo.min(hi), hi)
}

fn fresh_seed() -> u64 {
    let seq = SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut z = nanos ^ seq.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The downlink write half: the `BufWriter` and the shaper behind the *same*
/// mutex.
///
/// They must share one lock. The session writes downlink bytes through two
/// paths — the writer task (data frames) and the direct control-frame writers
/// (`write_frame` / `write_settings_response`, which take the lock themselves) —
/// and a shaper that only saw the data path would leave the session's first
/// records, which *are* control frames, unshaped. That is precisely the tiny
/// record the shaping exists to remove.
pub struct WriteState<W> {
    w: BufWriter<W>,
    shaper: DownlinkShaper,
}

impl<W: AsyncWrite + Unpin> WriteState<W> {
    pub fn new(inner: W, buf_capacity: usize, downlink_padding: bool) -> Self {
        Self {
            w: BufWriter::with_capacity(buf_capacity, inner),
            shaper: DownlinkShaper::new(downlink_padding, buf_capacity),
        }
    }

    pub fn shaper(&self) -> &DownlinkShaper {
        &self.shaper
    }

    pub fn shaper_mut(&mut self) -> &mut DownlinkShaper {
        &mut self.shaper
    }

    /// Write framed bytes, ending the current TLS record whenever it reaches the
    /// shaper's target size.
    ///
    /// Callers hand over whole frames; a cut point can land in the middle of a
    /// frame, which is invisible to the peer because anytls frames are recovered
    /// from a byte stream, not from record boundaries. The lock is held for the
    /// whole call, so no other writer can append behind a half-written frame —
    /// which is also why this path never pads: a record cut here may end
    /// mid-frame, and padding behind a partial frame would desynchronise the
    /// peer's frame parser.
    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut rest = buf;
        while !rest.is_empty() {
            let n = self.shaper.write_budget().min(rest.len());
            self.w.write_all(&rest[..n]).await?;
            rest = &rest[n..];
            if self.shaper.account(n) {
                self.shaper.reserve_record_flush();
                self.w.flush().await?;
                self.shaper.record_done(0);
            }
        }
        Ok(())
    }

    /// If a record is currently being built, flush it so the next frame starts
    /// a fresh record. The buffer may hold a partial frame (split is
    /// frame-transparent), so this never pads — padding behind a partial frame
    /// would desynchronise the peer's parser.
    ///
    /// Control frames call this first so they are never split across records:
    /// a split control frame whose flush then times out leaves half a frame in
    /// the buffer, and the next writer appends behind a truncated header,
    /// corrupting the frame stream from there on.
    pub async fn ensure_record_boundary(&mut self) -> io::Result<()> {
        if self.shaper.pending() > 0 {
            self.shaper.reserve_record_flush();
            self.w.flush().await?;
            self.shaper.record_done(0);
        }
        Ok(())
    }

    /// Write a whole frame in one go, never splitting it across records.
    ///
    /// Control frames use this instead of [`Self::write_all`]: a `write_all`
    /// record cut can land inside the frame, and if the flush after the cut
    /// times out the remainder is a truncated header the next writer appends
    /// behind. Writing the frame atomically means a timed-out flush leaves a
    /// *complete* frame in the buffer. Call [`Self::ensure_record_boundary`]
    /// first so the frame also starts a fresh record.
    pub async fn write_atomic(&mut self, buf: &[u8]) -> io::Result<()> {
        self.w.write_all(buf).await?;
        self.shaper.account(buf.len());
        Ok(())
    }

    /// Flush at a complete frame boundary, applying head fill or the optional
    /// bounded early-window fill. Never call this with a partial frame pending.
    pub async fn flush(&mut self) -> io::Result<()> {
        let pad = self.shaper.padding_for_flush();
        self.shaper.reserve_record_flush();
        if pad > 0 {
            write_waste(&mut self.w, pad).await?;
            self.shaper.account(pad);
        }
        self.w.flush().await?;
        self.shaper.record_done(pad);
        Ok(())
    }
}

/// Append a `Waste` frame of exactly `len` bytes (header + zero payload) to the
/// buffer. The peer reads it out and discards it silently, as the protocol
/// requires.
async fn write_waste<W: AsyncWrite + Unpin>(w: &mut W, len: usize) -> io::Result<()> {
    debug_assert!(len >= HEADER_SIZE);
    // A frame length is a u16, so a single `Waste` frame cannot exceed this.
    debug_assert!(len <= HEADER_SIZE + u16::MAX as usize);
    let mut hdr = [0u8; HEADER_SIZE];
    FrameHeader {
        command: Command::Waste,
        stream_id: 0,
        length: (len - HEADER_SIZE) as u16,
    }
    .encode(&mut hdr);
    w.write_all(&hdr).await?;

    const ZEROS: [u8; 512] = [0u8; 512];
    let mut left = len - HEADER_SIZE;
    while left > 0 {
        let n = left.min(ZEROS.len());
        w.write_all(&ZEROS[..n]).await?;
        left -= n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::pin::Pin;
    use std::rc::Rc;
    use std::task::{Context, Poll};

    /// Test capacity, matching the production default.
    const CAP: usize = 32 * 1024;

    /// A writer that records the plaintext size of every `poll_write` call.
    /// With a `BufWriter` in front, one `poll_write` == one emitted TLS record.
    #[derive(Default, Clone)]
    struct Log {
        records: Rc<RefCell<Vec<usize>>>,
        bytes: Rc<RefCell<Vec<u8>>>,
    }

    impl Log {
        fn sizes(&self) -> Vec<usize> {
            self.records.borrow().clone()
        }
        fn stream(&self) -> Vec<u8> {
            self.bytes.borrow().clone()
        }
    }

    struct Recorder {
        log: Log,
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.log.records.borrow_mut().push(buf.len());
            self.log.bytes.borrow_mut().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// `(write state, record-size log)`, mirroring how the session builds it.
    ///
    /// `configured` is the operator's flag; `enable()` stands in for the peer's
    /// v2 announcement. Only both together produce shaping.
    fn setup(configured: bool) -> (WriteState<Recorder>, Log) {
        let log = Log::default();
        let ws = WriteState::new(Recorder { log: log.clone() }, CAP, configured);
        (ws, log)
    }

    /// A `Recorder`-backed shaper in the state a live v2 session reaches: the
    /// operator flag set and the peer's announcement received.
    fn enabled_setup() -> (WriteState<Recorder>, Log) {
        let (mut ws, log) = setup(true);
        ws.shaper_mut().enable();
        assert!(ws.shaper().is_enabled());
        (ws, log)
    }

    /// A well-formed anytls frame of `payload_len` zero bytes.
    fn frame(command: Command, stream_id: u32, payload_len: usize) -> Vec<u8> {
        let mut hdr = [0u8; HEADER_SIZE];
        FrameHeader {
            command,
            stream_id,
            length: payload_len as u16,
        }
        .encode(&mut hdr);
        let mut buf = Vec::with_capacity(HEADER_SIZE + payload_len);
        buf.extend_from_slice(&hdr);
        buf.resize(HEADER_SIZE + payload_len, 0);
        buf
    }

    /// Walk the plaintext stream as frames; panics on a truncated or
    /// desynchronised stream, which is what padding in the wrong place causes.
    fn parse_frames(bytes: &[u8]) -> Vec<(Command, usize)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            assert!(
                i + HEADER_SIZE <= bytes.len(),
                "trailing {} bytes cannot form a frame header",
                bytes.len() - i
            );
            let mut hdr = [0u8; HEADER_SIZE];
            hdr.copy_from_slice(&bytes[i..i + HEADER_SIZE]);
            let f = FrameHeader::decode(&hdr);
            let len = f.length as usize;
            assert!(
                i + HEADER_SIZE + len <= bytes.len(),
                "frame at {i} claims {len} payload bytes, stream ends at {}",
                bytes.len()
            );
            out.push((f.command, len));
            i += HEADER_SIZE + len;
        }
        out
    }

    /// The record sizes a burst head is allowed to land in.
    fn head_band() -> std::ops::RangeInclusive<usize> {
        HEAD_MIN..=HEAD_MAX
    }

    #[tokio::test]
    async fn test_configured_but_not_enabled_leaves_the_wire_untouched() {
        // The operator said yes, but no v2 settings ever arrived — the only
        // thing that starts shaping. Output must be exactly what it was before
        // this module existed.
        let (mut ws, log) = setup(true);
        assert!(ws.shaper().is_configured());
        assert!(!ws.shaper().is_enabled());

        ws.shaper_mut().mark_burst_head();
        let syn_ack = frame(Command::SynAck, 1, 0);
        ws.write_all(&syn_ack).await.unwrap();
        let data = frame(Command::Psh, 1, 20_000);
        ws.write_all(&data).await.unwrap();
        ws.flush().await.unwrap();

        // One record, carrying the input verbatim: no split, no fill.
        assert_eq!(log.sizes(), vec![syn_ack.len() + data.len()]);
        let mut expected = syn_ack;
        expected.extend_from_slice(&data);
        assert_eq!(log.stream(), expected);
        assert_eq!(ws.shaper().counters().snapshot().records, 0);
    }

    #[tokio::test]
    async fn test_disabled_feature_stays_off_even_when_the_peer_announces_v2() {
        // The operator said no. A peer's v2 announcement must not override it.
        let (mut ws, log) = setup(false);
        ws.shaper_mut().enable();
        assert!(!ws.shaper().is_enabled());

        ws.write_all(&frame(Command::Psh, 1, 20_000)).await.unwrap();
        ws.flush().await.unwrap();

        assert_eq!(log.sizes(), vec![HEADER_SIZE + 20_000]);
        assert_eq!(ws.shaper().counters().snapshot().padded, 0);
    }

    #[tokio::test]
    async fn test_enabled_shaper_splits_large_records_and_reassembles_exactly() {
        let (mut ws, log) = enabled_setup();
        let data = frame(Command::Psh, 7, 64 * 1024);
        ws.write_all(&data).await.unwrap();
        ws.flush().await.unwrap();

        let sizes = log.sizes();
        assert!(
            sizes.len() >= 20,
            "64 KiB must not go out as a few huge records: {sizes:?}"
        );
        for (i, s) in sizes.iter().enumerate() {
            assert!(*s <= SPLIT_MAX, "record {i} of {sizes:?} exceeds SPLIT_MAX");
            assert!(*s > 0);
        }
        assert_eq!(
            sizes.iter().sum::<usize>(),
            data.len(),
            "splitting must neither add nor drop bytes"
        );
        assert_eq!(log.stream(), data, "payload must survive verbatim");
        assert_eq!(ws.shaper().counters().snapshot().padded, 0);
    }

    #[tokio::test]
    async fn test_split_sizes_vary_within_the_band() {
        let (mut ws, log) = enabled_setup();
        let data = frame(Command::Psh, 3, 400 * 1024);
        ws.write_all(&data).await.unwrap();
        ws.flush().await.unwrap();

        let sizes = log.sizes();
        assert!(
            sizes.len() > 100,
            "expected many records, got {}",
            sizes.len()
        );
        let distinct: std::collections::HashSet<_> = sizes.iter().collect();
        assert!(
            distinct.len() > 20,
            "record sizes must vary, not sit in a fixed pattern: {distinct:?}"
        );
        let min = *sizes.iter().min().unwrap();
        let max = *sizes.iter().max().unwrap();
        assert!(
            max >= min * 2,
            "band should be wide enough to look organic: min {min} max {max}"
        );
    }

    #[tokio::test]
    async fn test_burst_head_is_filled_and_padding_is_a_waste_frame() {
        let (mut ws, log) = enabled_setup();
        // Session head, as at connection start: the settings response is small.
        let settings = frame(Command::ServerSettings, 0, 3);
        ws.write_all(&settings).await.unwrap();
        ws.flush().await.unwrap();

        let sizes = log.sizes();
        assert_eq!(sizes.len(), 1);
        assert!(
            head_band().contains(&sizes[0]),
            "head record {} outside the fill band",
            sizes[0]
        );

        // The stream must read back as: the real frame, then one Waste frame
        // filling the rest of the record.
        let frames = parse_frames(&log.stream());
        assert_eq!(frames.len(), 2, "{frames:?}");
        assert_eq!(frames[0].0, Command::ServerSettings);
        assert_eq!(frames[1].0, Command::Waste);
        assert_eq!(
            HEADER_SIZE + frames[0].1 + HEADER_SIZE + frames[1].1,
            sizes[0],
            "padding must sit entirely inside the same record"
        );
        assert_eq!(
            ws.shaper().counters().snapshot().padded,
            (HEADER_SIZE + frames[1].1) as u64
        );
    }

    #[tokio::test]
    async fn test_every_connection_head_is_filled_not_just_the_session() {
        let (mut ws, log) = enabled_setup();
        // Session head first, then two proxied-connection heads.
        ws.write_all(&frame(Command::ServerSettings, 0, 3))
            .await
            .unwrap();
        ws.flush().await.unwrap();

        for stream_id in 1..=2u32 {
            ws.shaper_mut().mark_burst_head();
            let syn_ack = frame(Command::SynAck, stream_id, 0);
            ws.write_all(&syn_ack).await.unwrap();
            ws.flush().await.unwrap();
        }

        let sizes = log.sizes();
        assert_eq!(sizes.len(), 3);
        for (i, s) in sizes.iter().enumerate() {
            assert!(
                head_band().contains(s),
                "burst head {i} record {s} outside the fill band"
            );
        }
        // No 28-byte marker anywhere in the stream: that is the point.
        assert!(sizes.iter().all(|s| *s >= HEAD_MIN));
    }

    #[tokio::test]
    async fn test_data_tail_is_not_padded() {
        let (mut ws, log) = enabled_setup();
        // Burn the session head.
        ws.write_all(&frame(Command::Psh, 1, 8 * 1024))
            .await
            .unwrap();
        ws.flush().await.unwrap();
        let before = log.sizes().len();

        // A small data flush: a real server ends a burst with a partial record,
        // and padding every chatty one-line response would cost real money.
        ws.write_all(&frame(Command::Psh, 1, 40)).await.unwrap();
        ws.flush().await.unwrap();

        let sizes = log.sizes();
        assert_eq!(sizes[before], HEADER_SIZE + 40);
        assert_eq!(ws.shaper().counters().snapshot().padded, 0);
    }

    async fn burst_setup() -> (WriteState<Recorder>, Log) {
        let (mut ws, log) = enabled_setup();
        ws.shaper = DownlinkShaper::with_seed(true, CAP, 42);
        ws.shaper.enable();
        ws.write_all(&frame(Command::ServerSettings, 0, 3))
            .await
            .unwrap();
        ws.flush().await.unwrap();
        ws.shaper_mut().configure_burst_padding(true);
        ws.shaper_mut().start_burst_padding();
        (ws, log)
    }

    #[tokio::test]
    async fn test_burst_padding_bounds_cost_and_restores_small_tails() {
        let (mut ws, log) = burst_setup().await;
        let before = ws.shaper().counters().snapshot().padded;
        let first = log.sizes().len();
        for _ in 0..20 {
            ws.write_all(&frame(Command::Psh, 1, 40)).await.unwrap();
            ws.flush().await.unwrap();
        }
        let sizes = log.sizes();
        assert!(
            sizes[first] >= HEAD_MIN,
            "first small response must be filled"
        );
        assert!(sizes[first + 8..].iter().all(|&n| n == 47));
        let spent = ws.shaper().counters().snapshot().padded - before;
        assert!(
            spent > 0 && spent <= 2048,
            "additional padding spent {spent}"
        );
        assert_eq!(
            parse_frames(&log.stream())
                .iter()
                .filter(|(cmd, _)| *cmd == Command::Psh)
                .count(),
            20
        );
    }

    #[tokio::test]
    async fn test_burst_padding_changes_medium_response_total() {
        let (mut ws, log) = burst_setup().await;
        let first = log.sizes().len();
        ws.write_all(&frame(Command::Psh, 1, 600)).await.unwrap();
        ws.flush().await.unwrap();
        let sizes = log.sizes();
        assert!(
            sizes[first] > 607,
            "splitting alone leaves the burst total unchanged"
        );
        assert!(sizes[first] <= 607 + 256);
        parse_frames(&log.stream());
    }

    #[tokio::test]
    async fn test_burst_record_limit_is_independent_of_byte_budget() {
        let (mut ws, log) = burst_setup().await;
        let first = log.sizes().len();
        for _ in 0..8 {
            ws.write_all(&frame(Command::Psh, 1, 600)).await.unwrap();
            ws.flush().await.unwrap();
        }
        assert!(
            ws.shaper.burst_budget >= 256,
            "fixture must leave enough budget for a ninth fill"
        );
        assert!(log.sizes()[first..].iter().all(|&n| n > 607));
        ws.write_all(&frame(Command::Psh, 1, 600)).await.unwrap();
        ws.flush().await.unwrap();
        assert_eq!(log.sizes()[first + 8], 607);
        parse_frames(&log.stream());
    }

    #[tokio::test]
    async fn test_mid_frame_splits_consume_burst_record_limit() {
        let (mut ws, log) = burst_setup().await;
        ws.write_all(&frame(Command::Psh, 1, 32_000)).await.unwrap();
        ws.flush().await.unwrap();
        let first = log.sizes().len();
        ws.write_all(&frame(Command::Psh, 1, 40)).await.unwrap();
        ws.flush().await.unwrap();
        assert_eq!(log.sizes()[first], 47);
        assert_eq!(
            ws.shaper.burst_budget, 2048,
            "splits must exhaust records without spending fill budget"
        );
        parse_frames(&log.stream());
    }

    #[tokio::test]
    async fn test_burst_padding_expires_and_rearms_for_reused_session() {
        let (mut ws, log) = burst_setup().await;
        tokio::time::sleep(Duration::from_millis(3100)).await;
        let first = log.sizes().len();
        ws.write_all(&frame(Command::Psh, 1, 40)).await.unwrap();
        ws.flush().await.unwrap();
        assert_eq!(log.sizes()[first], 47);
        ws.shaper_mut().start_burst_padding();
        ws.write_all(&frame(Command::Psh, 3, 40)).await.unwrap();
        ws.flush().await.unwrap();
        assert!(log.sizes()[first + 1] >= HEAD_MIN);
    }

    #[tokio::test]
    async fn test_burst_padding_cannot_enable_legacy_or_disabled_shaping() {
        for main_flag in [false, true] {
            let (mut ws, log) = setup(main_flag);
            ws.shaper_mut().configure_burst_padding(true);
            if !main_flag {
                ws.shaper_mut().enable();
            }
            ws.shaper_mut().start_burst_padding();
            ws.write_all(&frame(Command::Psh, 1, 40)).await.unwrap();
            ws.flush().await.unwrap();
            assert_eq!(log.sizes(), vec![47]);
            assert_eq!(ws.shaper().counters().snapshot().padded, 0);
        }
    }

    #[tokio::test]
    async fn test_burst_padding_keeps_split_frames_parseable() {
        let (mut ws, log) = burst_setup().await;
        ws.write_all(&frame(Command::Psh, 1, 6000)).await.unwrap();
        ws.flush().await.unwrap();
        let frames = parse_frames(&log.stream());
        assert!(frames.contains(&(Command::Psh, 6000)));
        assert!(frames.iter().any(|(command, _)| *command == Command::Waste));
        assert!(log.sizes().iter().all(|&n| n <= 2560));
    }

    #[tokio::test]
    async fn test_burst_padding_budget_survives_failed_flush_retries() {
        struct FailingFlush {
            recorder: Recorder,
            fail: bool,
        }
        impl AsyncWrite for FailingFlush {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.recorder).poll_write(cx, buf)
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                if self.fail {
                    Poll::Ready(Err(io::Error::other("flush failed after write")))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let log = Log::default();
        let mut ws = WriteState::new(
            FailingFlush {
                recorder: Recorder { log: log.clone() },
                fail: false,
            },
            CAP,
            true,
        );
        ws.shaper_mut().enable();
        ws.write_all(&frame(Command::ServerSettings, 0, 3))
            .await
            .unwrap();
        ws.flush().await.unwrap();
        let before = log.stream().len();
        let before_records = log.sizes().len();
        ws.shaper_mut().configure_burst_padding(true);
        ws.shaper_mut().start_burst_padding();
        ws.w.get_mut().fail = true;
        ws.write_all(&frame(Command::Psh, 1, 40)).await.unwrap();
        for _ in 0..64 {
            assert!(ws.flush().await.is_err());
        }
        let actual_padding = log.stream().len() - before - 47;
        assert!(
            actual_padding <= 2048,
            "failed flush retries reused the budget: {actual_padding} bytes"
        );
        assert!(
            log.sizes().len() - before_records <= 8,
            "failed flush retries reused the record budget"
        );
        parse_frames(&log.stream());
    }

    #[tokio::test]
    async fn test_interleaved_control_and_data_keep_frames_intact() {
        // The writer task releases the lock between commands, so a control frame
        // can land in the middle of a batch. Appending padding there would
        // corrupt the frame stream; this test fails if it ever does.
        let (mut ws, log) = enabled_setup();
        ws.write_all(&frame(Command::Psh, 1, 30_000)).await.unwrap();

        ws.shaper_mut().mark_burst_head();
        ws.write_all(&frame(Command::SynAck, 2, 0)).await.unwrap();
        ws.flush().await.unwrap();

        ws.write_all(&frame(Command::Psh, 2, 500)).await.unwrap();
        ws.write_all(&frame(Command::Fin, 2, 0)).await.unwrap();
        ws.flush().await.unwrap();

        let frames = parse_frames(&log.stream());
        let real: Vec<_> = frames
            .iter()
            .filter(|(c, _)| *c != Command::Waste)
            .cloned()
            .collect();
        assert_eq!(
            real,
            vec![
                (Command::Psh, 30_000),
                (Command::SynAck, 0),
                (Command::Psh, 500),
                (Command::Fin, 0),
            ]
        );
    }

    #[tokio::test]
    async fn test_padding_cost_is_bounded_in_absolute_bytes() {
        // 101 burst heads (one session head plus 100 proxied connections) over a
        // megabyte of payload — roughly a busy session's shape.
        const HEADS: usize = 100;
        const BULK: usize = 64;
        const BLOCK: usize = 16 * 1024;

        let (mut ws, _log) = enabled_setup();
        ws.write_all(&frame(Command::ServerSettings, 0, 3))
            .await
            .unwrap();
        ws.flush().await.unwrap();

        for stream_id in 1..=HEADS as u32 {
            ws.shaper_mut().mark_burst_head();
            ws.write_all(&frame(Command::SynAck, stream_id, 0))
                .await
                .unwrap();
            ws.flush().await.unwrap();
        }
        for _ in 0..BULK {
            ws.write_all(&frame(Command::Psh, 1, BLOCK)).await.unwrap();
            ws.flush().await.unwrap();
        }

        let stats = ws.shaper().counters().snapshot();
        // Absolute bound on purpose. A bound written in terms of HEAD_MAX (or any
        // other tuning constant) would still pass after the band is widened, so
        // it could not catch the one regression this assertion exists for:
        // 101 fills at an average of ~0.9 KiB is ~90 KiB, and 160 KiB is well
        // clear of it while still failing loudly if fills start averaging 1.6 KiB
        // or more.
        assert!(
            stats.padded <= 160 * 1024,
            "padding overhead too high: {stats:?}"
        );
        assert!(
            stats.padding_ratio() < 0.12,
            "padding must stay a rounding error on real payload: {stats:?}"
        );
        // Every frame pays its own header, including each `Psh`.
        assert_eq!(
            stats.real_bytes(),
            (HEADER_SIZE + 3 + HEADS * HEADER_SIZE + BULK * (HEADER_SIZE + BLOCK)) as u64,
            "counters must not double count the padding as payload"
        );
    }

    #[tokio::test]
    async fn test_head_fill_stays_within_the_narrower_head_band() {
        // The fill band is intentionally cheaper than the split band: heads are
        // paid once per proxied connection, so they must not be filled to the
        // bulk top.
        let (mut ws, log) = enabled_setup();
        for stream_id in 1..=32u32 {
            ws.shaper_mut().mark_burst_head();
            ws.write_all(&frame(Command::SynAck, stream_id, 0))
                .await
                .unwrap();
            ws.flush().await.unwrap();
        }

        let sizes = log.sizes();
        assert_eq!(sizes.len(), 32);
        let max = *sizes.iter().max().unwrap();
        assert!(
            max < SPLIT_MAX,
            "head fill reached the bulk band top ({max} >= {SPLIT_MAX})"
        );
    }

    #[test]
    fn test_band_is_clamped_to_the_buffer_capacity() {
        // A tiny BufWriter would bypass its own buffer for band-sized writes and
        // produce one oversized record behind the shaper's back.
        let s = DownlinkShaper::with_seed(true, 512, 1);
        assert!(s.target <= 512);
        assert!(s.head_max <= 512);
        assert!(s.split_max <= 512);
        assert!(s.head_min <= s.head_max);
        assert!(s.split_min <= s.split_max);
    }

    #[test]
    fn test_a_head_that_is_already_large_is_not_filled() {
        // A burst head whose record already carries more than the band floor has
        // no step left to hide; filling it would be pure cost. Only *small* heads
        // are worth padding.
        let mut s = DownlinkShaper::with_seed(true, CAP, 7);
        s.enable();
        s.mark_burst_head();
        let pending = s.head_min + 100;
        s.account(pending);
        assert_eq!(s.pending(), pending);
        assert_eq!(
            s.tail_padding(),
            0,
            "a head already above the band floor must not be padded"
        );
    }

    /// True when every record boundary falls on a frame boundary.
    ///
    /// `sizes` are the per-record plaintext sizes in emission order, `bytes`
    /// their concatenation (what `Recorder` records). A split control frame
    /// leaves a truncated header at the end of one record; this is the failure
    /// mode that corrupts the peer's frame parser when the flush after the cut
    /// is cancelled.
    fn is_frame_aligned(sizes: &[usize], bytes: &[u8]) -> bool {
        let mut offset = 0;
        for &size in sizes {
            let end = offset + size;
            let mut i = offset;
            while i < end {
                if i + HEADER_SIZE > end {
                    return false; // header truncated at the record boundary
                }
                let mut hdr = [0u8; HEADER_SIZE];
                hdr.copy_from_slice(&bytes[i..i + HEADER_SIZE]);
                let f = FrameHeader::decode(&hdr);
                let frame_end = i + HEADER_SIZE + f.length as usize;
                if frame_end > end {
                    return false; // payload crosses the record boundary
                }
                i = frame_end;
            }
            offset = end;
        }
        offset == bytes.len()
    }

    #[tokio::test]
    async fn test_control_frame_never_straddles_a_record() {
        // Regression: control frames used to go through `write_all`, the data
        // path, which cuts at the shaper's target. A SynAck landing exactly at
        // the budget edge was split into 3+4 bytes across two records — the
        // trailing 4 bytes became a bare tiny record (the very giveaway the
        // feature exists to remove), and a cancelled flush after the cut left a
        // truncated header in the buffer that the next writer appended behind,
        // corrupting the frame stream from there on.
        let (mut ws, log) = enabled_setup();

        // Leave the current record 3 bytes short of its target: exactly one
        // 7-byte SynAck fits before the budget runs dry, so the old path was
        // *guaranteed* to split the frame. The data itself is a non-head frame.
        let target = ws.shaper().target;
        assert!(
            target >= HEADER_SIZE + 3 + HEADER_SIZE,
            "target {target} too small for a split-proof frame"
        );
        ws.write_all(&frame(Command::Psh, 1, target - HEADER_SIZE - 3))
            .await
            .unwrap();
        assert_eq!(ws.shaper().pending(), target - 3);

        // The control-frame sequence: close the pending record first (the
        // buffer now holds only complete frames), then write the SynAck
        // atomically so it starts its own fresh record.
        ws.ensure_record_boundary().await.unwrap();
        ws.shaper_mut().mark_burst_head();
        let syn_ack = frame(Command::SynAck, 7, 0);
        ws.write_atomic(&syn_ack).await.unwrap();
        ws.flush().await.unwrap();

        let sizes = log.sizes();
        let stream = log.stream();
        assert!(
            is_frame_aligned(&sizes, &stream),
            "a record boundary cuts through a frame: records {sizes:?}"
        );

        // The pending data record was flushed whole, and the SynAck started a
        // fresh record that got filled up into the head band — it must not come
        // out as a bare 7-byte tail.
        assert_eq!(sizes.len(), 2, "records: {sizes:?}");
        assert_eq!(sizes[0], target - 3, "data record must flush un-split");
        assert!(
            head_band().contains(&sizes[1]),
            "SynAck record {} outside the fill band",
            sizes[1]
        );

        // And the frame stream reads back exactly: Psh(data), SynAck, then the
        // Waste frame that filled the head.
        let frames = parse_frames(&stream);
        let real: Vec<_> = frames
            .iter()
            .filter(|(c, _)| *c != Command::Waste)
            .cloned()
            .collect();
        assert_eq!(
            real,
            vec![
                (Command::Psh, target - HEADER_SIZE - 3),
                (Command::SynAck, 0),
            ]
        );
    }

    #[test]
    fn test_seeded_shaper_is_reproducible() {
        let mut a = DownlinkShaper::with_seed(true, CAP, 0x1234_5678);
        let mut b = DownlinkShaper::with_seed(true, CAP, 0x1234_5678);
        let mut c = DownlinkShaper::with_seed(true, CAP, 0x8765_4321);
        a.enable();
        b.enable();
        c.enable();

        let mut seq_a = Vec::new();
        let mut seq_b = Vec::new();
        let mut seq_c = Vec::new();
        for _ in 0..4 {
            seq_a.push(a.target);
            seq_b.push(b.target);
            seq_c.push(c.target);
            for s in [&mut a, &mut b, &mut c] {
                s.account(4096);
                s.record_done(0);
            }
        }
        assert_eq!(seq_a, seq_b, "same seed must give the same record sizes");
        assert_ne!(seq_a, seq_c, "different seeds must diverge");
    }
}
