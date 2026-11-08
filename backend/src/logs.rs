//! In-memory ring buffer for the last N tracing events.
//!
//! Hooks into `tracing-subscriber` as a custom `Layer` running alongside the
//! standard fmt layer, so logs still print to stdout *and* are queryable via
//! `GET /api/logs`. Capacity is bounded so the buffer can't grow without
//! bound on a long-running panel.
//!
//! There are two rings, not one. xray's access log writes a line per accepted
//! connection into the same stream, and on a busy node that buried every
//! warning within minutes — a real outage was already evicted by the time
//! anyone came to look. Warnings and errors are therefore *also* kept in a
//! ring of their own, which ordinary traffic cannot push anything out of, so
//! `?level=warn` reaches back days instead of minutes.

use chrono::Utc;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, sync::Arc};
use tracing::{Event, Subscriber, field::Visit};
use tracing_subscriber::layer::{Context, Layer};
use ts_rs::TS;

const CAPACITY: usize = 500;
/// Warn + error get their own ring. Same size, but these events are rare,
/// so the same 500 slots cover days rather than the ten-odd minutes the
/// shared ring manages under load.
const PROBLEM_CAPACITY: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/stats.ts")]
pub struct LogEntry {
    /// ISO-8601 UTC timestamp.
    pub timestamp: String,
    /// `trace` | `debug` | `info` | `warn` | `error`.
    pub level: String,
    /// Originating module path (e.g. `<crate>::xray::reload`).
    pub target: String,
    /// Rendered message text.
    pub message: String,
}

/// The two rings behind [`LogBuffer`], under one lock.
#[derive(Default)]
struct Rings {
    /// Everything, newest at the back. What an unfiltered `/api/logs` reads.
    all: VecDeque<LogEntry>,
    /// Warn and error only, so access-log traffic can never evict them.
    problems: VecDeque<LogEntry>,
}

#[derive(Clone, Default)]
pub struct LogBuffer {
    inner: Arc<Mutex<Rings>>,
}

impl LogBuffer {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Rings {
                all: VecDeque::with_capacity(CAPACITY),
                problems: VecDeque::with_capacity(PROBLEM_CAPACITY),
            })),
        }
    }

    pub fn push(&self, entry: LogEntry) {
        let mut guard = self.inner.lock();
        if level_at_least(&entry.level, "warn") {
            if guard.problems.len() >= PROBLEM_CAPACITY {
                guard.problems.pop_front();
            }
            guard.problems.push_back(entry.clone());
        }
        if guard.all.len() >= CAPACITY {
            guard.all.pop_front();
        }
        guard.all.push_back(entry);
    }

    /// Snapshot newest-first, optionally filtered by minimum level and capped
    /// at `limit` entries.
    ///
    /// A filter of `warn` or stricter is served from the problem ring, which
    /// is why it can answer for a window the shared ring has long since
    /// overwritten. Every other filter reads the full ring, so an unfiltered
    /// call still returns events in one true chronological order.
    pub fn snapshot(&self, min_level: Option<&str>, limit: usize) -> Vec<LogEntry> {
        let guard = self.inner.lock();
        let ring = match min_level {
            Some(min) if level_at_least(min, "warn") => &guard.problems,
            _ => &guard.all,
        };
        let entries: Vec<LogEntry> = ring
            .iter()
            .rev()
            .filter(|e| min_level.is_none_or(|min| level_at_least(&e.level, min)))
            .take(limit)
            .cloned()
            .collect();
        // Hand the lock back before returning: `push` runs on every single
        // tracing event, so a reader must not hold this while a caller walks
        // away with the result.
        drop(guard);
        entries
    }
}

/// `info` < `warn` < `error`. Filtering by "warn" returns warn+error; by
/// "error" returns only error. Unknown filters pass everything.
fn level_rank(level: &str) -> u8 {
    match level.to_ascii_lowercase().as_str() {
        "debug" => 1,
        "info" => 2,
        "warn" => 3,
        "error" => 4,
        _ => 0, // trace or unknown
    }
}

fn level_at_least(entry: &str, min: &str) -> bool {
    level_rank(entry) >= level_rank(min)
}

/// Tracing `Layer` that records every event into the shared buffer.
pub struct BufferLayer {
    pub buffer: LogBuffer,
}

impl<S: Subscriber> Layer<S> for BufferLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        self.buffer.push(LogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: metadata.level().to_string().to_lowercase(),
            target: metadata.target().to_string(),
            message: visitor.message,
        });
    }
}

/// Pulls the `message` field out of a tracing event. tracing's API delivers
/// fields one at a time via `Visit::record_*`; the "message" field is the
/// rendered format string.
#[derive(Default)]
struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}").trim_matches('"').to_string();
        }
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(level: &str, message: &str) -> LogEntry {
        LogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: level.to_owned(),
            target: "test".to_owned(),
            message: message.to_owned(),
        }
    }

    /// The reason the second ring exists. xray's access log writes a line per
    /// accepted connection into this same buffer, so on a busy node a warning
    /// was evicted within minutes and every post-mortem arrived to an empty
    /// window. Traffic must not be able to erase the record of a failure.
    #[test]
    fn a_flood_of_traffic_cannot_evict_a_warning() {
        let buf = LogBuffer::new();
        buf.push(entry("warn", "the bridge went away"));
        for i in 0..CAPACITY * 3 {
            buf.push(entry("info", &format!("accepted tcp:example.com:{i}")));
        }

        // The shared ring has long since rolled the warning out...
        assert!(
            buf.snapshot(None, CAPACITY)
                .iter()
                .all(|e| e.level == "info"),
            "the shared ring was expected to roll over"
        );
        // ...but the warning is still answerable.
        let problems = buf.snapshot(Some("warn"), 50);
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].message, "the bridge went away");
    }

    /// Bounded too — a server stuck emitting errors must not grow the buffer
    /// without end just because the entries are interesting.
    #[test]
    fn the_problem_ring_is_bounded_and_drops_its_oldest() {
        let buf = LogBuffer::new();
        for i in 0..PROBLEM_CAPACITY + 10 {
            buf.push(entry("error", &format!("failure {i}")));
        }
        let problems = buf.snapshot(Some("warn"), PROBLEM_CAPACITY * 2);
        assert_eq!(problems.len(), PROBLEM_CAPACITY);
        assert_eq!(
            problems[0].message,
            format!("failure {}", PROBLEM_CAPACITY + 9)
        );
        assert!(
            !problems.iter().any(|e| e.message == "failure 0"),
            "the oldest error should have been dropped"
        );
    }

    /// The unfiltered view is the chronological one: a warning has to appear
    /// in its real position among the traffic, not hoisted out of order.
    #[test]
    fn an_unfiltered_snapshot_stays_newest_first_across_levels() {
        let buf = LogBuffer::new();
        buf.push(entry("info", "first"));
        buf.push(entry("warn", "second"));
        buf.push(entry("info", "third"));
        let all = buf.snapshot(None, 10);
        let messages: Vec<&str> = all.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(messages, ["third", "second", "first"]);
    }

    #[test]
    fn the_error_filter_excludes_warnings() {
        let buf = LogBuffer::new();
        buf.push(entry("warn", "a warning"));
        buf.push(entry("error", "an error"));
        let errors = buf.snapshot(Some("error"), 10);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "an error");
        assert_eq!(buf.snapshot(Some("warn"), 10).len(), 2);
    }

    /// `info` is below the problem ring's threshold, so it must still read the
    /// full buffer — otherwise filtering to info would hide all the info.
    #[test]
    fn the_info_filter_still_reads_the_full_ring() {
        let buf = LogBuffer::new();
        buf.push(entry("info", "chatter"));
        buf.push(entry("warn", "trouble"));
        assert_eq!(buf.snapshot(Some("info"), 10).len(), 2);
    }

    /// Documented behaviour from before the split: an unrecognised filter is
    /// not an error, it just passes everything.
    #[test]
    fn an_unknown_filter_still_passes_everything() {
        let buf = LogBuffer::new();
        buf.push(entry("info", "chatter"));
        buf.push(entry("error", "trouble"));
        assert_eq!(buf.snapshot(Some("nonsense"), 10).len(), 2);
    }

    #[test]
    fn the_limit_is_honoured_on_both_rings() {
        let buf = LogBuffer::new();
        for i in 0..20 {
            buf.push(entry("info", &format!("i{i}")));
            buf.push(entry("warn", &format!("w{i}")));
        }
        assert_eq!(buf.snapshot(None, 5).len(), 5);
        assert_eq!(buf.snapshot(Some("warn"), 5).len(), 5);
    }
}
