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
use crate::xray::proto::xray::app::router::Config as RouterConfig;
use crate::xray::proto::xray::app::router::command::{
    AddRuleRequest, routing_service_client::RoutingServiceClient,
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
const TYPE_ROUTER_CONFIG: &str = "xray.app.router.Config";

/// Default endpoint matching the API inbound in `build_bootstrap_config`.
pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:62789";

/// Why a live routing push failed — the cases need opposite handling.
pub enum RoutingPushError {
    /// The RPC never reached xray (no channel). The live rule set is untouched,
    /// so there is nothing to recover from — restarting would be pure downtime.
    Undelivered(anyhow::Error),
    /// The running xray has no `RoutingService`: it was started from a config
    /// written before the panel began declaring that service. Its rules are
    /// intact, but no push can ever land — retrying is pointless, and only a
    /// restart on a regenerated config makes hot-apply work again.
    Unsupported(anyhow::Error),
    /// xray received the request and refused it. `AddRule(shouldAppend=false)`
    /// clears the rule set BEFORE building the new one, so the live router is
    /// now empty — including the api pin — and needs a restart to recover.
    Rejected(anyhow::Error),
}

impl std::fmt::Display for RoutingPushError {
    /// Every variant carries the same shape of detail — xray's status code and
    /// message — and the caller logs it and hands it to the operator verbatim,
    /// so the variant name would only get in the way.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Undelivered(e) | Self::Unsupported(e) | Self::Rejected(e) => write!(f, "{e}"),
        }
    }
}

impl RoutingPushError {
    /// What this failure means for the live process, as a pure decision so the
    /// table can be tested without an xray. `None` = the live rules are intact,
    /// leave the process alone. `Some((rules_wiped, cause))` = restart, where
    /// `rules_wiped` says whether xray already cleared its rule set (which is
    /// what forces a restart even when the config regen fails) and `cause` is
    /// the operator-facing half.
    ///
    /// Both halves come out of one match so a future variant can't get a
    /// recovery without a reason, or a reason that contradicts its recovery.
    /// Both directions are expensive to get wrong, and both fail silently:
    /// restarting on an undelivered push is downtime for a request that never
    /// left the panel, while NOT restarting after a refusal leaves a router
    /// with no rules at all — api pin included, so the control channel is gone.
    pub const fn recovery(&self) -> Option<(bool, &'static str)> {
        match self {
            Self::Undelivered(_) => None,
            Self::Unsupported(_) => Some((false, "the live xray has no RoutingService")),
            Self::Rejected(_) => {
                Some((true, "xray rejected the rule set, its router is now empty"))
            }
        }
    }
}

/// Which `RoutingPushError` a gRPC status code maps to. Pure, and split from the
/// RPC itself so the classification is testable — an xray that predates
/// `RoutingService` and an xray that is simply unreachable both fail the call,
/// but only one of them can be fixed by retrying.
fn classify_push_code(code: tonic::Code) -> fn(anyhow::Error) -> RoutingPushError {
    match code {
        // The connection itself failed, so the call never reached a handler
        // and the live rules are untouched — restarting would be downtime for
        // nothing.
        tonic::Code::Unavailable => RoutingPushError::Undelivered,
        // xray's commander registers only the services its config lists, so
        // this means the running process was started before we began declaring
        // RoutingService. No retry can help; only a restart on a fresh config.
        tonic::Code::Unimplemented => RoutingPushError::Unsupported,
        // Anything else is ambiguous or an outright refusal, and xray clears
        // the rule set BEFORE building the new one — so assume the router is
        // empty and let the caller restart.
        _ => RoutingPushError::Rejected,
    }
}

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

    /// Atomically replace the live routing-rule set via `RoutingService.AddRule`
    /// with `shouldAppend=false` — the router swaps the whole slice under its
    /// lock, so a rule change applies with NO xray restart and live connections
    /// survive. `config` MUST be the complete ordered set (api pin + system +
    /// custom), since a full-replace wipes whatever was there — a partial set
    /// would sever the control channel or dangle referenced outbounds.
    pub async fn replace_routing_rules(
        &self,
        config: RouterConfig,
    ) -> Result<(), RoutingPushError> {
        let channel = self
            .channel()
            .await
            .map_err(RoutingPushError::Undelivered)?;
        let mut client = RoutingServiceClient::new(channel);
        let sent = client
            .add_rule(AddRuleRequest {
                config: Some(TypedMessage {
                    r#type: TYPE_ROUTER_CONFIG.to_owned(),
                    value: config.encode_to_vec(),
                }),
                should_append: false,
            })
            .await;
        let Err(status) = sent else {
            return Ok(());
        };
        let detail = anyhow::anyhow!(
            "xray add_rule failed: {} {}",
            status.code(),
            status.message()
        );
        let err = classify_push_code(status.code())(detail);
        // Only a dead connection is worth redialling; on the other two the
        // channel is healthy and dropping it would just cost the next call a
        // 5s reconnect.
        if matches!(err, RoutingPushError::Undelivered(_)) {
            self.invalidate().await;
        }
        Err(err)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(code: tonic::Code) -> RoutingPushError {
        classify_push_code(code)(anyhow::anyhow!("test"))
    }

    /// The two codes that mean something specific. Everything else has to fall
    /// to `Rejected`: xray clears its rule set before it builds the new one, so
    /// an unrecognised failure has to be assumed to have emptied the router.
    #[test]
    fn push_codes_map_to_their_recovery() {
        assert!(matches!(
            kind(tonic::Code::Unavailable),
            RoutingPushError::Undelivered(_)
        ));
        assert!(matches!(
            kind(tonic::Code::Unimplemented),
            RoutingPushError::Unsupported(_)
        ));
        for code in [
            tonic::Code::Unknown,
            tonic::Code::Internal,
            tonic::Code::InvalidArgument,
            tonic::Code::Cancelled,
            tonic::Code::DeadlineExceeded,
            tonic::Code::PermissionDenied,
        ] {
            assert!(
                matches!(kind(code), RoutingPushError::Rejected(_)),
                "{code:?} must fail safe to Rejected"
            );
        }
    }

    /// The half that decides whether xray gets restarted. `Rejected` MUST carry
    /// `rules_wiped = true`: that is what makes the recovery restart happen even
    /// when the config regen fails, and without it the panel would keep a live
    /// process whose router has no rules at all — api pin included, so the
    /// control channel would be gone for good. The cause travels with the flag,
    /// so a restart can't end up logged with the wrong explanation.
    #[test]
    fn recovery_matches_what_xray_did_to_the_rules() {
        let e = || anyhow::anyhow!("test");
        assert_eq!(RoutingPushError::Undelivered(e()).recovery(), None);

        let (wiped, cause) = RoutingPushError::Unsupported(e()).recovery().unwrap();
        assert!(
            !wiped,
            "nothing was wiped, so a failed regen must not restart"
        );
        assert!(cause.contains("RoutingService"), "{cause}");

        let (wiped, cause) = RoutingPushError::Rejected(e()).recovery().unwrap();
        assert!(wiped, "a refusal leaves the router empty and MUST restart");
        assert!(cause.contains("rejected"), "{cause}");
    }
}
