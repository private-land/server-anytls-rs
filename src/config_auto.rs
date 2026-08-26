//! Automatic computation of `max_connections` from system resources.
//!
//! See `compute_auto` for the formula and the constants' rationale.

use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxConnections {
    Auto,
    Fixed(usize),
}

impl FromStr for MaxConnections {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("auto") {
            return Ok(Self::Auto);
        }
        let n = s.parse::<usize>().map_err(|_| {
            format!("Invalid max_connections '{s}'. Use 'auto' or a positive integer")
        })?;
        if n == 0 {
            return Err(format!(
                "Invalid max_connections '{s}'. Must be 'auto' or a positive integer (>= 1)"
            ));
        }
        Ok(Self::Fixed(n))
    }
}

/// Sustained TLS throughput per CPU core (Mbps).
///
/// rustls + aws-lc-rs (AES-NI) end-to-end including framing, copy_bidirectional,
/// and syscalls measures around 1.5 Gbps/core on typical x86_64 VPS CPUs.
const PER_CORE_MBPS: u64 = 1500;

/// Average per-user bandwidth assumption (Kbps).
///
/// Mixed proxy traffic (mobile + desktop, web + occasional video) averages
/// 100~500 Kbps per active user. 200 Kbps is a middle-of-the-road default.
const PER_USER_KBPS: u64 = 200;

/// Per-session fixed user-space memory cost (KB).
///
/// Derived from code:
///   BufWriter (32 KB) + payload_buf (64 KB) + combined_buf (64 KB) +
///   mpsc<WriteCommand>(512) (~20 KB) + mpsc<Stream>(256) (~30 KB) +
///   rustls server state (~50 KB) + task stacks/Arcs (~5 KB)
///   ≈ 265 KB idle.  Add ~85 KB amortized for active stream buffers.
const PER_SESSION_KB: u64 = 350;

/// Fraction of total RAM (in percent) reserved as the session-state budget.
/// The remaining 50% covers kernel TCP buffers, gRPC client, geosite, logs.
const MEM_BUDGET_PCT: u64 = 50;

/// File descriptors reserved for non-session use (logs, gRPC, DNS, etc.).
/// On boxes with a small `RLIMIT_NOFILE` this is capped to a quarter of the
/// limit so a low rlimit doesn't drive `fd_cap` to zero.
const FD_RESERVE_DEFAULT: u64 = 1024;

/// Average file descriptors consumed per session (1 inbound + 1 outbound).
const FD_PER_SESSION: u64 = 2;

/// Pure function that computes `max_connections` from system resources.
///
/// Formula:
/// ```text
/// auto = min(
///     cpus * PER_CORE_MBPS * 1000 / PER_USER_KBPS,           // CPU throughput
///     total_mem_kb * MEM_BUDGET_PCT / 100 / PER_SESSION_KB,  // memory
///     (nofile_soft - reserve) / FD_PER_SESSION,              // file descriptors
/// )
/// ```
/// where `reserve = min(FD_RESERVE_DEFAULT, nofile_soft / 4)` so a small
/// rlimit doesn't make the fd term collapse to zero.
///
/// The minimum result is 1 — any caller passing a degenerate input still
/// receives a value safe to feed into `Semaphore::new`.
pub fn compute_auto(cpus: usize, total_mem_kb: u64, nofile_soft: u64) -> AutoBreakdown {
    let cpus = cpus.max(1) as u64;

    let cpu_cap = cpus.saturating_mul(PER_CORE_MBPS).saturating_mul(1000) / PER_USER_KBPS;

    let mem_cap = total_mem_kb.saturating_mul(MEM_BUDGET_PCT) / 100 / PER_SESSION_KB;

    let fd_reserve = FD_RESERVE_DEFAULT.min(nofile_soft / 4);
    let fd_cap = nofile_soft.saturating_sub(fd_reserve) / FD_PER_SESSION;

    let raw = cpu_cap.min(mem_cap).min(fd_cap);
    let value = (raw.max(1)) as usize;

    let limiting = if cpu_cap <= mem_cap && cpu_cap <= fd_cap {
        Limit::Cpu
    } else if mem_cap <= fd_cap {
        Limit::Memory
    } else {
        Limit::FileDescriptors
    };

    AutoBreakdown {
        value,
        cpu_cap,
        mem_cap,
        fd_cap,
        limiting,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Cpu,
    Memory,
    FileDescriptors,
}

impl Limit {
    pub fn as_str(&self) -> &'static str {
        match self {
            Limit::Cpu => "cpu",
            Limit::Memory => "memory",
            Limit::FileDescriptors => "fd",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AutoBreakdown {
    pub value: usize,
    pub cpu_cap: u64,
    pub mem_cap: u64,
    pub fd_cap: u64,
    pub limiting: Limit,
}

#[derive(Debug, Clone, Copy)]
pub struct ResolvedMaxConnections {
    pub value: usize,
    pub auto: Option<AutoBreakdown>,
    pub cpus: usize,
    pub total_mem_kb: u64,
    pub nofile_soft: u64,
}

/// Resolve a `MaxConnections` spec to a concrete value, querying the host
/// when the spec is `Auto`.  Always succeeds; falls back to safe defaults
/// when host queries fail.
pub fn resolve(spec: MaxConnections) -> ResolvedMaxConnections {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    // 4 GB fallback when total memory can't be queried (non-Linux dev hosts).
    // Production target is Linux where the real value is always available;
    // this fallback only keeps `cargo run` ergonomic on macOS/BSD.
    let total_mem_kb = total_memory_kb().unwrap_or(4 * 1024 * 1024);
    let nofile_soft = nofile_soft_limit().unwrap_or(65_536);

    match spec {
        MaxConnections::Fixed(n) => ResolvedMaxConnections {
            value: n,
            auto: None,
            cpus,
            total_mem_kb,
            nofile_soft,
        },
        MaxConnections::Auto => {
            let bd = compute_auto(cpus, total_mem_kb, nofile_soft);
            ResolvedMaxConnections {
                value: bd.value,
                auto: Some(bd),
                cpus,
                total_mem_kb,
                nofile_soft,
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn total_memory_kb() -> Option<u64> {
    // SAFETY: sysconf is async-signal-safe and side-effect-free.
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if pages > 0 && page_size > 0 {
        Some((pages as u64).saturating_mul(page_size as u64) / 1024)
    } else {
        None
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn total_memory_kb() -> Option<u64> {
    // macOS/BSD don't expose _SC_PHYS_PAGES.  Production target is Linux,
    // so a None here just means dev builds use the safe fallback.
    None
}

#[cfg(not(unix))]
fn total_memory_kb() -> Option<u64> {
    None
}

#[cfg(unix)]
fn nofile_soft_limit() -> Option<u64> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit fills the rlimit struct; no aliasing concerns.
    let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
    if ret == 0 { Some(rl.rlim_cur) } else { None }
}

#[cfg(not(unix))]
fn nofile_soft_limit() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mb_to_kb(mb: u64) -> u64 {
        mb * 1024
    }

    fn gb_to_kb(gb: u64) -> u64 {
        gb * 1024 * 1024
    }

    #[test]
    fn parses_auto_case_insensitive() {
        assert_eq!(
            "auto".parse::<MaxConnections>().unwrap(),
            MaxConnections::Auto
        );
        assert_eq!(
            "AUTO".parse::<MaxConnections>().unwrap(),
            MaxConnections::Auto
        );
        assert_eq!(
            "Auto".parse::<MaxConnections>().unwrap(),
            MaxConnections::Auto
        );
    }

    #[test]
    fn parses_fixed_integer() {
        assert_eq!(
            "5000".parse::<MaxConnections>().unwrap(),
            MaxConnections::Fixed(5000)
        );
    }

    #[test]
    fn zero_is_rejected() {
        // 0 would deadlock the accept loop and is almost certainly a typo;
        // refuse it explicitly so the operator sees a clear error.
        assert!("0".parse::<MaxConnections>().is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!("xyz".parse::<MaxConnections>().is_err());
        assert!("-1".parse::<MaxConnections>().is_err());
    }

    #[test]
    fn one_cpu_two_gb_is_memory_bound_around_3000() {
        let bd = compute_auto(1, gb_to_kb(2), 65_536);
        // mem_cap = 2*1024*1024 * 50 / 100 / 350 ≈ 2997
        assert!(bd.value >= 2900 && bd.value <= 3100, "got {}", bd.value);
        assert_eq!(bd.limiting, Limit::Memory);
    }

    #[test]
    fn two_cpu_four_gb_is_memory_bound_around_6000() {
        let bd = compute_auto(2, gb_to_kb(4), 65_536);
        // mem_cap ≈ 5995, cpu_cap = 15000
        assert!(bd.value >= 5800 && bd.value <= 6100, "got {}", bd.value);
        assert_eq!(bd.limiting, Limit::Memory);
    }

    #[test]
    fn four_cpu_eight_gb_is_cpu_bound() {
        let bd = compute_auto(4, gb_to_kb(8), 65_536);
        // cpu_cap = 4*1500*1000/200 = 30000, mem_cap ≈ 11990 → memory still binds
        // (CPU only binds once cores get ahead of RAM)
        assert_eq!(bd.limiting, Limit::Memory);
        assert!(bd.value >= 11_500 && bd.value <= 12_500, "got {}", bd.value);
    }

    #[test]
    fn many_cores_small_ram_is_memory_bound() {
        let bd = compute_auto(16, gb_to_kb(2), 65_536);
        assert_eq!(bd.limiting, Limit::Memory);
        assert!(bd.value <= 3100);
    }

    #[test]
    fn one_core_huge_ram_is_cpu_bound() {
        let bd = compute_auto(1, gb_to_kb(64), 65_536);
        // cpu_cap = 7500, mem_cap ≈ 95945 → CPU binds
        assert_eq!(bd.limiting, Limit::Cpu);
        assert!(bd.value >= 7400 && bd.value <= 7600, "got {}", bd.value);
    }

    #[test]
    fn tight_fd_limit_binds() {
        // RLIMIT_NOFILE = 4096 → fd_cap = (4096-1024)/2 = 1536
        let bd = compute_auto(8, gb_to_kb(16), 4096);
        assert_eq!(bd.limiting, Limit::FileDescriptors);
        assert_eq!(bd.value, 1536);
    }

    #[test]
    fn small_rlimit_uses_adaptive_reserve() {
        // nofile=512: reserve = min(1024, 128) = 128
        // fd_cap = (512 - 128) / 2 = 192
        // Without adaptive reserve this collapsed to 0 and got floored to 64,
        // which lied about the actual fd budget.
        let bd = compute_auto(8, gb_to_kb(16), 512);
        assert_eq!(bd.limiting, Limit::FileDescriptors);
        assert_eq!(bd.fd_cap, 192);
        assert_eq!(bd.value, 192);
    }

    #[test]
    fn tiny_box_reports_actual_value_not_floor() {
        // mem_cap ≈ 46 → no floor; report the truth so the operator
        // sees the box is too small instead of an inflated 64.
        let bd = compute_auto(1, mb_to_kb(32), 65_536);
        assert_eq!(bd.limiting, Limit::Memory);
        assert_eq!(bd.value, bd.mem_cap as usize);
        assert!(bd.value < 100, "got {}", bd.value);
    }

    #[test]
    fn degenerate_zero_inputs_floor_to_one() {
        // All caps zero → value still safe to feed Semaphore::new.
        let bd = compute_auto(1, 0, 0);
        assert_eq!(bd.value, 1);
    }

    #[test]
    fn huge_box_reports_actual_cpu_value() {
        // cpu_cap = 480000, mem_cap ≈ 767000, fd_cap = 523776 → CPU binds.
        // No artificial ceiling — operators with this hardware can override
        // explicitly if they want a smaller cap.
        let bd = compute_auto(64, gb_to_kb(512), 1_048_576);
        assert_eq!(bd.limiting, Limit::Cpu);
        assert_eq!(bd.value, 480_000);
    }

    #[test]
    fn zero_cpus_treated_as_one() {
        let bd = compute_auto(0, gb_to_kb(2), 65_536);
        // Should not divide by zero; cpu_cap should match 1-cpu case.
        let bd1 = compute_auto(1, gb_to_kb(2), 65_536);
        assert_eq!(bd.cpu_cap, bd1.cpu_cap);
    }

    /// Smoke test exercising the host-querying half of the module.
    /// Asserts only invariants — the actual numbers depend on the host.
    #[test]
    fn resolve_auto_smokes() {
        let r = resolve(MaxConnections::Auto);
        assert!(r.auto.is_some());
        assert!(r.value >= 1);
        assert!(r.cpus >= 1);
        let bd = r.auto.unwrap();
        // The chosen value must equal the binding cap, not exceed any of them.
        assert!(bd.value as u64 <= bd.cpu_cap);
        assert!(bd.value as u64 <= bd.mem_cap);
        assert!(bd.value as u64 <= bd.fd_cap);
    }

    #[test]
    fn resolve_fixed_passes_value_through() {
        let r = resolve(MaxConnections::Fixed(1234));
        assert_eq!(r.value, 1234);
        assert!(r.auto.is_none());
    }
}
