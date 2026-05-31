//! In-memory ring buffer for the last N tracing events.
//!
//! Hooks into `tracing-subscriber` as a custom `Layer` running alongside the
//! standard fmt layer, so logs still print to stdout *and* are queryable via
//! `GET /api/logs`. Capacity is bounded so the buffer can't grow without
//! bound on a long-running panel.

use chrono::Utc;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, sync::Arc};
use tracing::{Event, Subscriber, field::Visit};
use tracing_subscriber::layer::{Context, Layer};
use ts_rs::TS;

const CAPACITY: usize = 500;

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

#[derive(Clone, Default)]
pub struct LogBuffer {
    inner: Arc<Mutex<VecDeque<LogEntry>>>,
}

impl LogBuffer {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(CAPACITY))),
        }
    }

    pub fn push(&self, entry: LogEntry) {
        let mut guard = self.inner.lock();
        if guard.len() >= CAPACITY {
            guard.pop_front();
        }
        guard.push_back(entry);
    }

    /// Snapshot newest-first, optionally filtered by minimum level and capped
    /// at `limit` entries.
    pub fn snapshot(&self, min_level: Option<&str>, limit: usize) -> Vec<LogEntry> {
        let guard = self.inner.lock();
        guard
            .iter()
            .rev()
            .filter(|e| min_level.is_none_or(|min| level_at_least(&e.level, min)))
            .take(limit)
            .cloned()
            .collect()
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
