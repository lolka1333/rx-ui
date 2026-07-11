//! Thin gRPC client wrapper around Xray-core's `HandlerService`.
//!
//! The panel keeps **one** lazily-connected client. The connection is
//! created on first call and reused — `tonic::transport::Channel` is `Clone`
//! and internally multiplexes over a single HTTP/2 connection, so cloning
//! the client per request is cheap.
//!
//! Boot ordering note: xray starts listening on its API port (127.0.0.1:62789
//! by default) only after it has parsed its config. Panel startup pushes
//! enabled inbounds via this client right after starting xray, so the first
//! call typically races the API listener. `connect_with_retry` polls every
//! 100ms for up to 5s before giving up — long enough to cover a healthy
//! startup, short enough that a misconfigured xray doesn't deadlock the
//! panel for minutes.
//!
//! Authentication: xray's `HandlerService` is unauthenticated (it relies on the
//! API listener being bound to localhost for security). We follow suit — the
//! panel and xray run on the same host, and the dokodemo-door API inbound is
//! explicitly bound to 127.0.0.1 in `config_gen::build_bootstrap_config`.

use std::time::Duration;

use tokio::sync::Mutex;
use tonic::transport::{Channel, Endpoint};

use prost::Message;

use crate::xray::proto::xray::app::proxyman::command::{
    AddInboundRequest, AddOutboundRequest, AddUserOperation, AlterInboundRequest,
    RemoveInboundRequest, RemoveOutboundRequest, RemoveUserOperation,
    handler_service_client::HandlerServiceClient,
};
use crate::xray::proto::xray::app::stats::command::{
    GetAllOnlineUsersRequest, GetAllOnlineUsersResponse, QueryStatsRequest, QueryStatsResponse,
    stats_service_client::StatsServiceClient,
};
use crate::xray::proto::xray::common::protocol::User;
use crate::xray::proto::xray::common::serial::TypedMessage;
use crate::xray::proto::xray::core::{InboundHandlerConfig, OutboundHandlerConfig};

/// Bare proto-package paths xray expects in `TypedMessage.type` (no
/// `type.googleapis.com/` prefix — xray uses raw package paths since
/// it carries its own type registry instead of leaning on Any URLs).
const TYPE_ADD_USER_OPERATION: &str = "xray.app.proxyman.command.AddUserOperation";
const TYPE_REMOVE_USER_OPERATION: &str = "xray.app.proxyman.command.RemoveUserOperation";

/// Default endpoint matching the API inbound in `build_bootstrap_config`.
pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:62789";

/// gRPC client for `HandlerService`.
///
/// Holds the endpoint URI and a `Mutex<Option<Channel>>` that gets populated
/// on first use. We don't eagerly connect in `new()` because the panel may
/// boot before xray does — letting the first call do the dial means startup
/// ordering doesn't matter.
#[derive(Clone)]
pub struct XrayClient {
    endpoint: String,
    channel: std::sync::Arc<Mutex<Option<Channel>>>,
}

impl XrayClient {
    /// Build a client for `endpoint` (e.g. `http://127.0.0.1:62789`). No
    /// connection attempt happens here.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            channel: std::sync::Arc::new(Mutex::new(None)),
        }
    }

    /// Get a connected `Channel`, dialing on first call.
    ///
    /// The first caller does a bounded-retry dial; subsequent callers fast-
    /// path through the cached channel. If the cached channel later turns
    /// out to be broken (xray restart), the next request through tonic will
    /// fail and our higher-level CRUD handlers translate that into a 503 to
    /// the panel UI — operator can then hit `/api/xray/restart` and re-push.
    async fn channel(&self) -> anyhow::Result<Channel> {
        // Fast path: a previously-dialed channel is cached. Release the
        // lock immediately after the read so concurrent callers don't
        // queue behind us.
        if let Some(c) = self.channel.lock().await.as_ref() {
            return Ok(c.clone());
        }
        // Slow path: dial without holding the lock — `connect_with_retry`
        // can block for up to 5 seconds and we don't want every other
        // gRPC caller to stall behind a single dial. The double-check
        // after re-acquiring handles the race where two callers raced
        // through the fast path before either could store its channel.
        let channel = connect_with_retry(&self.endpoint, Duration::from_secs(5)).await?;
        // Scoped guard so the lock is released the moment we've stored
        // (or lost the race for) the channel — the trailing `Ok(...)`
        // shouldn't keep the mutex held.
        {
            let mut guard = self.channel.lock().await;
            if let Some(existing) = guard.as_ref() {
                return Ok(existing.clone());
            }
            *guard = Some(channel.clone());
        }
        Ok(channel)
    }

    /// Drop the cached channel. Call after restarting xray to force a fresh
    /// dial on the next request.
    pub async fn invalidate(&self) {
        *self.channel.lock().await = None;
    }

    /// Add an inbound handler to a running xray.
    pub async fn add_inbound(&self, inbound: InboundHandlerConfig) -> anyhow::Result<()> {
        let channel = self.channel().await?;
        let mut client = HandlerServiceClient::new(channel);
        client
            .add_inbound(AddInboundRequest {
                inbound: Some(inbound),
            })
            .await
            .map_err(|s| {
                anyhow::anyhow!("xray add_inbound failed: {} {}", s.code(), s.message())
            })?;
        Ok(())
    }

    /// Remove an inbound by tag.
    pub async fn remove_inbound(&self, tag: &str) -> anyhow::Result<()> {
        let channel = self.channel().await?;
        let mut client = HandlerServiceClient::new(channel);
        client
            .remove_inbound(RemoveInboundRequest {
                tag: tag.to_owned(),
            })
            .await
            .map_err(|s| {
                anyhow::anyhow!(
                    "xray remove_inbound({tag}) failed: {} {}",
                    s.code(),
                    s.message()
                )
            })?;
        Ok(())
    }

    /// Add a user to a running inbound's handler. Goes through `AlterInbound`
    /// with an `AddUserOperation` wrapped as `TypedMessage` — xray executes
    /// it against the named inbound's in-memory user list, no restart.
    ///
    /// The `user.email` is xray's identity for that account (must be unique
    /// inside the inbound). `user.account` carries the protocol-specific
    /// secret (VLESS UUID, Trojan password, etc.) — built by the caller via
    /// the protocol layer's `build_user`.
    pub async fn add_user(&self, inbound_tag: &str, user: User) -> anyhow::Result<()> {
        let op = AddUserOperation { user: Some(user) };
        let typed = TypedMessage {
            r#type: TYPE_ADD_USER_OPERATION.to_owned(),
            value: op.encode_to_vec(),
        };
        let channel = self.channel().await?;
        let mut client = HandlerServiceClient::new(channel);
        client
            .alter_inbound(AlterInboundRequest {
                tag: inbound_tag.to_owned(),
                operation: Some(typed),
            })
            .await
            .map_err(|s| {
                anyhow::anyhow!(
                    "xray AlterInbound(AddUser tag={inbound_tag}) failed: {} {}",
                    s.code(),
                    s.message()
                )
            })?;
        Ok(())
    }

    /// Remove a user (by email) from a running inbound's handler.
    pub async fn remove_user(&self, inbound_tag: &str, email: &str) -> anyhow::Result<()> {
        let op = RemoveUserOperation {
            email: email.to_owned(),
        };
        let typed = TypedMessage {
            r#type: TYPE_REMOVE_USER_OPERATION.to_owned(),
            value: op.encode_to_vec(),
        };
        let channel = self.channel().await?;
        let mut client = HandlerServiceClient::new(channel);
        client
            .alter_inbound(AlterInboundRequest {
                tag: inbound_tag.to_owned(),
                operation: Some(typed),
            })
            .await
            .map_err(|s| {
                anyhow::anyhow!(
                    "xray AlterInbound(RemoveUser tag={inbound_tag} email={email}) failed: {} {}",
                    s.code(),
                    s.message()
                )
            })?;
        Ok(())
    }

    /// Add an outbound handler to a running xray (custom egress / relay).
    /// Mirrors `add_inbound` — pushes the `OutboundHandlerConfig` built by
    /// `orchestrator::outbound_to_handler_config`, no restart.
    pub async fn add_outbound(&self, outbound: OutboundHandlerConfig) -> anyhow::Result<()> {
        let channel = self.channel().await?;
        let mut client = HandlerServiceClient::new(channel);
        client
            .add_outbound(AddOutboundRequest {
                outbound: Some(outbound),
            })
            .await
            .map_err(|s| {
                anyhow::anyhow!("xray add_outbound failed: {} {}", s.code(), s.message())
            })?;
        Ok(())
    }

    /// Remove an outbound by tag.
    pub async fn remove_outbound(&self, tag: &str) -> anyhow::Result<()> {
        let channel = self.channel().await?;
        let mut client = HandlerServiceClient::new(channel);
        client
            .remove_outbound(RemoveOutboundRequest {
                tag: tag.to_owned(),
            })
            .await
            .map_err(|s| {
                anyhow::anyhow!(
                    "xray remove_outbound({tag}) failed: {} {}",
                    s.code(),
                    s.message()
                )
            })?;
        Ok(())
    }

    /// Pull every `user>>>*` counter in one RPC. xray's `GetUsersStats`
    /// is unusable here — it returns only users with an active
    /// `online` counter, dropping anyone whose last TCP socket closed
    /// even if their cumulative traffic counters are still ticking.
    /// `QueryStats(pattern="user>>>")` returns the raw counter list
    /// regardless of online state; the poller parses
    /// `user>>>{email}>>>traffic>>>{uplink|downlink}` names into the
    /// snapshot map.
    pub async fn query_user_stats(&self) -> anyhow::Result<QueryStatsResponse> {
        let channel = self.channel().await?;
        let mut client = StatsServiceClient::new(channel);
        let resp = client
            .query_stats(QueryStatsRequest {
                pattern: "user>>>".to_owned(),
                reset: false,
            })
            .await
            .map_err(|s| {
                anyhow::anyhow!("xray query_stats failed: {} {}", s.code(), s.message())
            })?;
        Ok(resp.into_inner())
    }

    /// Pull every `outbound>>>{tag}>>>traffic>>>{uplink|downlink}` counter in
    /// one RPC — per-outbound traffic for the Outbounds page. Session totals
    /// (xray resets them on restart). Enabled by `policy.system.statsOutbound*`
    /// in `config_gen`.
    pub async fn query_outbound_stats(&self) -> anyhow::Result<QueryStatsResponse> {
        let channel = self.channel().await?;
        let mut client = StatsServiceClient::new(channel);
        let resp = client
            .query_stats(QueryStatsRequest {
                pattern: "outbound>>>".to_owned(),
                reset: false,
            })
            .await
            .map_err(|s| {
                anyhow::anyhow!(
                    "xray query_stats (outbound) failed: {} {}",
                    s.code(),
                    s.message()
                )
            })?;
        Ok(resp.into_inner())
    }

    /// Pull every `inbound>>>{tag}>>>traffic>>>{uplink|downlink}` counter in one
    /// RPC — per-inbound traffic for the Inbounds page. Session totals (xray
    /// resets them on restart). Enabled by `policy.system.statsInbound*` in
    /// `config_gen`. Lets the panel show a correct per-inbound split that xray's
    /// per-user (`user>>>`) counters can't provide when a client spans inbounds.
    pub async fn query_inbound_stats(&self) -> anyhow::Result<QueryStatsResponse> {
        let channel = self.channel().await?;
        let mut client = StatsServiceClient::new(channel);
        let resp = client
            .query_stats(QueryStatsRequest {
                pattern: "inbound>>>".to_owned(),
                reset: false,
            })
            .await
            .map_err(|s| {
                anyhow::anyhow!(
                    "xray query_stats (inbound) failed: {} {}",
                    s.code(),
                    s.message()
                )
            })?;
        Ok(resp.into_inner())
    }

    /// Email-list of users with at least one active TCP socket right
    /// now. Cheap (one round-trip, just strings) so it can run on
    /// every poll tick alongside `query_user_stats`.
    pub async fn get_all_online_users(&self) -> anyhow::Result<GetAllOnlineUsersResponse> {
        let channel = self.channel().await?;
        let mut client = StatsServiceClient::new(channel);
        let resp = client
            .get_all_online_users(GetAllOnlineUsersRequest {})
            .await
            .map_err(|s| {
                anyhow::anyhow!(
                    "xray get_all_online_users failed: {} {}",
                    s.code(),
                    s.message()
                )
            })?;
        Ok(resp.into_inner())
    }
}

/// Dial `endpoint` with a 100ms-period retry until `total_timeout` elapses.
async fn connect_with_retry(endpoint: &str, total_timeout: Duration) -> anyhow::Result<Channel> {
    let endpoint = Endpoint::from_shared(endpoint.to_owned())?
        .connect_timeout(Duration::from_millis(500))
        .keep_alive_while_idle(true);

    let deadline = tokio::time::Instant::now() + total_timeout;
    let mut last_err: tonic::transport::Error;
    loop {
        match endpoint.connect().await {
            Ok(c) => return Ok(c),
            Err(e) => {
                last_err = e;
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    Err(anyhow::anyhow!(
        "xray gRPC API at {} not reachable after {:?}: {}",
        endpoint.uri(),
        total_timeout,
        last_err
    ))
}
