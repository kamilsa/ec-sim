//! Structured event log stream for post-run analysis.
//!
//! Emits machine-parseable `EVENT ...` lines on the dedicated `event` tracing
//! target. Each line is timestamped with the *shared* Shadow virtual clock
//! (`SystemTime` → `CLOCK_REALTIME`), which every host reads from the same
//! simulated source — so subtracting a per-run epoch yields comparable
//! cross-node timing.
//!
//! Line grammar:
//!
//! ```text
//! EVENT kind=<kind> t_ms=<u64> <key>=<value> ...
//! ```
//!
//! Values are bare scalars, `true`/`false`, or the sentinel `NA` for an unset
//! optional. Fields are whitespace-separated; the node id is the host directory
//! name (the log file), never a field.

use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch on the shared (Shadow-simulated) realtime
/// clock.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Lowercase hex of an arbitrary byte slice.
pub fn hex_bytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// Emit one structured event line at the `event` target.
///
/// Usage: `event!("warmup_complete");` or with trailing `key = value` pairs:
/// `event!("run_end", reconstructed = reconstructed);`. The `kind` must be a
/// string literal so the format string is assembled at compile time. Values are
/// formatted with `Display`.
#[macro_export]
macro_rules! event {
    ($kind:literal $(, $key:ident = $val:expr)* $(,)?) => {
        ::tracing::info!(
            target: "event",
            concat!("EVENT kind=", $kind, " t_ms={}" $(, " ", stringify!($key), "={}")*),
            $crate::events::now_ms(),
            $($val),*
        );
    };
}
