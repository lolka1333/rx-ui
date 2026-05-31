//! Hysteria 2 proto building. The protocol-side config is intentionally
//! tiny — `ServerConfig` is just a `repeated User`. Per-user secrets live
//! on `Client.auth`; the operator-facing QUIC knobs (auth, masq, idle)
//! live on the paired `transports::hysteria` block because that's where
//! the upstream listener consumes them.

use crate::models::Client;
use crate::protocols::Protocol;
use crate::xray::proto::xray::common::protocol::User;
use crate::xray::proto::xray::common::serial::TypedMessage;
use crate::xray::proto::xray::proxy::hysteria::ServerConfig as XrayHysteriaServerConfig;
use crate::xray::proto::xray::proxy::hysteria::account::Account as XrayHysteriaAccount;
use prost::Message;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

const TYPE_HYSTERIA_SERVER_CONFIG: &str = "xray.proxy.hysteria.ServerConfig";
const TYPE_HYSTERIA_ACCOUNT: &str = "xray.proxy.hysteria.account.Account";

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/protocol.ts")]
pub struct HysteriaProtocol {}

impl Protocol for HysteriaProtocol {
    fn build_proxy_settings(&self, users: Vec<User>) -> anyhow::Result<TypedMessage> {
        let cfg = XrayHysteriaServerConfig { users };
        Ok(TypedMessage {
            r#type: TYPE_HYSTERIA_SERVER_CONFIG.to_owned(),
            value: cfg.encode_to_vec(),
        })
    }

    fn build_user(&self, client: &Client) -> anyhow::Result<User> {
        let account = XrayHysteriaAccount {
            auth: client.effective_hysteria_auth().to_owned(),
        };
        Ok(User {
            level: 0,
            email: client.email.clone(),
            account: Some(TypedMessage {
                r#type: TYPE_HYSTERIA_ACCOUNT.to_owned(),
                value: account.encode_to_vec(),
            }),
        })
    }
}
