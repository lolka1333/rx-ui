//! Registering a Cloudflare WARP tunnel, so the panel can offer it as an
//! outbound with one click.
//!
//! WARP is ordinary `WireGuard` with one addition: every registration gets a
//! `client_id`, and the three bytes behind it ride in the `reserved` field of
//! each packet so Cloudflare's edge can tell registrations apart. A tunnel
//! built without them connects and then hears nothing back.
//!
//! The flow is the one every WARP client performs — there is no public API
//! contract here, only the endpoints the official app talks to:
//!
//! ```text
//! POST /v0a2158/reg          our public key  -> peer key, endpoint, addresses, client_id
//! PATCH /v0a2158/reg/{id}    warp_enabled=true (registration alone leaves it off)
//! ```
//!
//! Everything network-facing lives in [`register`]; turning a response into an
//! outbound is [`WarpRegistration::into_outbound`], which is pure and tested
//! against a captured response.

use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use crate::models::{MasqueOutbound, WireguardOutbound};

/// The version string in the path travels with the client version header; the
/// two are a pair and the edge rejects a mismatch.
const API_BASE: &str = "https://api.cloudflareclient.com/v0a2158";
const CLIENT_VERSION: &str = "a-6.10-2158";
/// The official app's UA. A generic one is answered with 403.
const USER_AGENT: &str = "okhttp/3.12.1";
/// The revision MASQUE enrolment is known to work on — the one the WARP app
/// that introduced MASQUE speaks (also what `usque` uses). Kept apart from the
/// `WireGuard` pair above, which predates it and is left as it was.
const MASQUE_API_BASE: &str = "https://api.cloudflareclient.com/v0a4471";
const MASQUE_CLIENT_VERSION: &str = "a-6.35-4471";
const MASQUE_USER_AGENT: &str = "WARP for Android";
/// The registration names the edge with port 0; the app dials 443.
const MASQUE_PORT: u16 = 443;

/// WARP's own MTU. The core would default to 1420, which fragments over the
/// tunnel and shows up as connections that open and then stall.
const WARP_MTU: i32 = 1280;

/// What the panel keeps of a registration: enough to build the outbound and
/// nothing else. The account id and token Cloudflare hands back are the keys
/// to that registration — they are used to enable WARP during [`register`] and
/// then dropped, because a panel that never calls the API again has no reason
/// to hold someone else's credentials at rest.
#[derive(Debug, Clone)]
pub struct WarpRegistration {
    pub secret_key: String,
    pub peer_public_key: String,
    pub endpoint: String,
    pub addresses: Vec<String>,
    pub reserved: Vec<u8>,
}

impl WarpRegistration {
    /// The outbound this registration describes.
    pub fn into_outbound(self) -> WireguardOutbound {
        WireguardOutbound {
            secret_key: self.secret_key,
            address: self.addresses,
            peer_public_key: self.peer_public_key,
            endpoint: self.endpoint,
            // The edge offers neither: WARP authenticates by the registration
            // it just handed back, and its peer is an IP, so there is no
            // domain for a strategy to resolve.
            pre_shared_key: String::new(),
            domain_strategy: String::new(),
            // The edge hands out its own resolvers with the registration, but
            // nothing here reads them, and inventing a pair would route the
            // operator's lookups somewhere they did not choose.
            remote_dns: Vec::new(),
            reserved: self.reserved,
            mtu: WARP_MTU,
            // WARP's edge does not need one, and a keepalive on an idle tunnel
            // is traffic the operator did not ask for.
            keep_alive: 0,
            warp: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Wire shapes — only the fields we read.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RegResponse {
    id: String,
    token: String,
    config: RegConfig,
}

#[derive(Debug, Deserialize)]
struct RegConfig {
    client_id: String,
    peers: Vec<RegPeer>,
    interface: RegInterface,
}

#[derive(Debug, Deserialize)]
struct RegPeer {
    public_key: String,
    endpoint: RegEndpoint,
}

#[derive(Debug, Deserialize)]
struct RegEndpoint {
    /// `engage.cloudflareclient.com:2408` — a name, so the edge can move.
    host: Option<String>,
    v4: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegInterface {
    addresses: RegAddresses,
}

#[derive(Debug, Deserialize)]
struct RegAddresses {
    v4: Option<String>,
    v6: Option<String>,
}

/// What the panel keeps of a MASQUE registration — the same rule as for
/// [`WarpRegistration`]: the account id and token are dropped once the device
/// is enrolled and enabled.
#[derive(Debug, Clone)]
pub struct MasqueRegistration {
    /// Our P-256 key, base64 PKCS #8 DER.
    pub private_key: String,
    /// The edge's P-256 key, base64 PKIX DER.
    pub peer_public_key: String,
    /// The edge's address, without a port.
    pub endpoint_host: String,
    pub addresses: Vec<String>,
}

impl MasqueRegistration {
    /// The outbound this registration describes, dialling HTTP/3 or HTTP/2.
    /// Both go to the address the registration names: it is the edge whose
    /// key the registration handed back. Measured — 162.159.198.1, the
    /// address older notes give for HTTP/3, presented a different key to a
    /// device registered on 162.159.198.2 and was refused.
    pub fn into_outbound(self, http2: bool) -> MasqueOutbound {
        MasqueOutbound {
            private_key: self.private_key,
            peer_public_key: self.peer_public_key,
            address: self.addresses,
            endpoint: format!("{}:{MASQUE_PORT}", self.endpoint_host),
            // The app's own SNI; see `WARP_SNI`.
            server_name: String::new(),
            http2,
            // As for WireGuard: the edge's resolvers are not chosen for the
            // operator.
            remote_dns: Vec::new(),
        }
    }
}

/// The first call of a registration: only the handles to the new device.
#[derive(Debug, Deserialize)]
struct NewDevice {
    id: String,
    token: String,
}

/// The answer to MASQUE enrolment: the device as it now stands, with the
/// edge's P-256 key in place of a `WireGuard` one.
#[derive(Debug, Deserialize)]
struct EnrolResponse {
    config: EnrolConfig,
}

#[derive(Debug, Deserialize)]
struct EnrolConfig {
    peers: Vec<EnrolPeer>,
    interface: RegInterface,
}

#[derive(Debug, Deserialize)]
struct EnrolPeer {
    /// PEM `PUBLIC KEY`.
    public_key: String,
    endpoint: EnrolEndpoint,
}

#[derive(Debug, Deserialize)]
struct EnrolEndpoint {
    /// `162.159.198.2:0`.
    v4: Option<String>,
}

/// A license Cloudflare refused. Separate from every other failure because it
/// is the operator's typo, not the panel's problem — the API answers it with a
/// message worth repeating verbatim ("Invalid license").
#[derive(Debug)]
pub struct BadLicense(pub String);

impl std::fmt::Display for BadLicense {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BadLicense {}

/// One revision of Cloudflare's device API: the path prefix, the client
/// version it must travel with (the edge rejects a mismatched pair) and the
/// user agent of the app that speaks it.
struct Api {
    http: reqwest::Client,
    base: &'static str,
    client_version: &'static str,
}

impl Api {
    fn new(
        base: &'static str,
        client_version: &'static str,
        user_agent: &str,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(user_agent)
            // Registration is a few small round trips; a stuck one must not
            // hold the request handler open.
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .context("build http client")?;
        Ok(Self {
            http,
            base,
            client_version,
        })
    }

    /// Send one call and hand back the body of a 2xx answer, or the status and
    /// body of anything else.
    async fn call(&self, req: reqwest::RequestBuilder, what: &str) -> anyhow::Result<String> {
        let resp = req
            .header("CF-Client-Version", self.client_version)
            .send()
            .await
            .with_context(|| format!("cloudflare: {what}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("cloudflare answered {status} to {what}: {}", text.trim());
        }
        Ok(text)
    }

    /// Create a device registered with this `WireGuard` key.
    async fn create(&self, wireguard_public_key: &str) -> anyhow::Result<String> {
        let body = serde_json::json!({
            "key": wireguard_public_key,
            "install_id": "",
            "fcm_token": "",
            "tos": chrono::Utc::now().to_rfc3339(),
            "model": "PC",
            "serial_number": "",
            "locale": "en_US",
        });
        let req = self.http.post(format!("{}/reg", self.base)).json(&body);
        self.call(req, "registration").await
    }

    async fn patch(
        &self,
        id: &str,
        token: &str,
        body: &serde_json::Value,
        what: &str,
    ) -> anyhow::Result<String> {
        let req = self
            .http
            .patch(format!("{}/reg/{id}", self.base))
            .bearer_auth(token)
            .json(body);
        self.call(req, what).await
    }

    /// Registration creates the account with WARP off; without this the tunnel
    /// comes up and carries nothing (MASQUE: the edge answers "access denied").
    async fn enable(&self, id: &str, token: &str) -> anyhow::Result<()> {
        self.patch(
            id,
            token,
            &serde_json::json!({ "warp_enabled": true }),
            "enable warp",
        )
        .await
        .map(drop)
    }

    /// Upgrade the account to WARP+. A refusal is the operator's typo and comes
    /// back as [`BadLicense`], in Cloudflare's own words.
    async fn apply_license(&self, id: &str, token: &str, license: &str) -> anyhow::Result<()> {
        let license = license.trim();
        if license.is_empty() {
            return Ok(());
        }
        let resp = self
            .http
            .put(format!("{}/reg/{id}/account", self.base))
            .header("CF-Client-Version", self.client_version)
            .bearer_auth(token)
            .json(&serde_json::json!({ "license": license }))
            .send()
            .await
            .context("apply warp+ license")?;
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(BadLicense(license_error(&body)).into());
        }
        Ok(())
    }
}

/// Register a fresh WARP tunnel and return everything needed to dial it.
///
/// `secret_key`/`public_key` are ours — generated by the caller so the private
/// half never leaves the panel. A non-empty `license` upgrades the fresh
/// account to WARP+ before the tunnel is handed back; an invalid one fails the
/// whole call rather than quietly returning a free tunnel the operator did not
/// ask for.
pub async fn register(
    secret_key: String,
    public_key: &str,
    license: &str,
) -> anyhow::Result<WarpRegistration> {
    let api = Api::new(API_BASE, CLIENT_VERSION, USER_AGENT)?;
    let text = api.create(public_key).await?;
    let reg: RegResponse =
        serde_json::from_str(&text).context("cloudflare registration response")?;
    api.enable(&reg.id, &reg.token).await?;
    api.apply_license(&reg.id, &reg.token, license).await?;
    build_registration(secret_key, reg)
}

/// Register a WARP device that connects over MASQUE.
///
/// The app's sequence: create the device with a `WireGuard` key (the API has
/// no other way in — the private half is thrown away unused), enrol a P-256
/// key in its place with the MASQUE tunnel type, then switch WARP on. Our key
/// is generated here and its private half never leaves the panel.
pub async fn register_masque(license: &str) -> anyhow::Result<MasqueRegistration> {
    let api = Api::new(MASQUE_API_BASE, MASQUE_CLIENT_VERSION, MASQUE_USER_AGENT)?;
    let throwaway = crate::xray::keygen::generate_wireguard_keypair();
    let device: NewDevice = serde_json::from_str(&api.create(&throwaway.public_key).await?)
        .context("cloudflare registration response")?;

    let keys = crate::xray::masque::generate_keypair()?;
    let enrolled = api
        .patch(
            &device.id,
            &device.token,
            &serde_json::json!({
                "key": keys.public_key,
                "key_type": "secp256r1",
                "tunnel_type": "masque",
            }),
            "MASQUE key enrolment",
        )
        .await?;
    let enrolled: EnrolResponse =
        serde_json::from_str(&enrolled).context("cloudflare enrolment response")?;

    api.enable(&device.id, &device.token).await?;
    api.apply_license(&device.id, &device.token, license)
        .await?;
    build_masque_registration(keys.private_key, enrolled)
}

/// Turn an enrolment answer into the fields an outbound needs. Split out so
/// the mapping is testable without the network.
fn build_masque_registration(
    private_key: String,
    enrolled: EnrolResponse,
) -> anyhow::Result<MasqueRegistration> {
    let peer = enrolled
        .config
        .peers
        .into_iter()
        .next()
        .context("enrolment carried no peer")?;
    // Checked here rather than at save: a key the core cannot read would be a
    // tunnel that registers fine and never connects.
    let peer_public_key = STANDARD.encode(
        crate::xray::masque::public_key_spki(&peer.public_key).context("the edge's public key")?,
    );
    let v4 = peer.endpoint.v4.context("peer carried no v4 endpoint")?;
    // `162.159.198.2:0` — the port says nothing; the app dials 443.
    let endpoint_host = v4
        .rsplit_once(':')
        .map_or(v4.as_str(), |(h, _)| h)
        .to_owned();
    anyhow::ensure!(
        endpoint_host.parse::<std::net::Ipv4Addr>().is_ok(),
        "peer endpoint is not an IPv4 address: {v4}"
    );

    let addresses = enrolled.config.interface.addresses;
    let v4 = addresses.v4.context("enrolment carried no v4 address")?;
    let mut list = vec![format!("{v4}/32")];
    if let Some(v6) = addresses.v6 {
        list.push(format!("{v6}/128"));
    }

    Ok(MasqueRegistration {
        private_key,
        peer_public_key,
        endpoint_host,
        addresses: list,
    })
}

/// Cloudflare's own words for a rejected license — `{"errors":[{"message":
/// "Invalid license"}]}`. Repeating them beats a status code: the operator is
/// looking at the key they just pasted, and "Invalid license" says what to do
/// about it.
fn license_error(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("errors")?
                .get(0)?
                .get("message")?
                .as_str()
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "cloudflare rejected the license".to_owned())
}

/// Turn a registration response into the fields an outbound needs. Split out
/// so the mapping is testable without the network.
fn build_registration(secret_key: String, reg: RegResponse) -> anyhow::Result<WarpRegistration> {
    let peer = reg
        .config
        .peers
        .into_iter()
        .next()
        .context("registration carried no peer")?;
    // Prefer the name: Cloudflare moves the address behind it, and a pinned
    // v4 goes dark when it does.
    let endpoint = peer
        .endpoint
        .host
        .or(peer.endpoint.v4)
        .context("peer carried no endpoint")?;

    let v4 = reg
        .config
        .interface
        .addresses
        .v4
        .context("registration carried no v4 address")?;
    let mut addresses = vec![format!("{v4}/32")];
    if let Some(v6) = reg.config.interface.addresses.v6 {
        addresses.push(format!("{v6}/128"));
    }

    // `client_id` is four base64 characters — the three bytes that go into
    // every packet's reserved field.
    let reserved = STANDARD
        .decode(reg.config.client_id.as_bytes())
        .context("client_id is not base64")?;
    if reserved.len() != 3 {
        bail!("client_id decoded to {} bytes, expected 3", reserved.len());
    }

    Ok(WarpRegistration {
        secret_key,
        peer_public_key: peer.public_key,
        endpoint,
        addresses,
        reserved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A registration response, trimmed to the fields the panel reads, with
    /// the shape Cloudflare actually returns.
    const SAMPLE: &str = r#"{
        "id": "t.00000000-0000-0000-0000-000000000000",
        "token": "00000000-0000-0000-0000-000000000000",
        "config": {
            "client_id": "kGWq",
            "peers": [{
                "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "endpoint": {
                    "v4": "162.159.192.1:2408",
                    "v6": "[2606:4700:d0::a29f:c001]:2408",
                    "host": "engage.cloudflareclient.com:2408"
                }
            }],
            "interface": { "addresses": { "v4": "172.16.0.2", "v6": "2606:4700:110:8a1b::1" } }
        }
    }"#;

    #[test]
    fn a_registration_becomes_a_dialable_tunnel() {
        let reg: RegResponse = serde_json::from_str(SAMPLE).expect("sample parses");
        let ob = build_registration("cGxhY2Vob2xkZXI=".to_owned(), reg)
            .expect("mapping")
            .into_outbound();

        // The name, not the v4 — the address behind it moves.
        assert_eq!(ob.endpoint, "engage.cloudflareclient.com:2408");
        assert_eq!(ob.address, ["172.16.0.2/32", "2606:4700:110:8a1b::1/128"]);
        // Three bytes, and they are what the edge matches on: a tunnel that
        // sends the wrong ones is answered with silence, which is the hardest
        // possible failure to read from the outside.
        assert_eq!(ob.reserved, [144, 101, 170]);
        assert_eq!(ob.mtu, 1280);
        assert!(ob.warp);
    }

    /// Cloudflare has answered with an empty peer list before now; that must
    /// be an error the operator sees, not an outbound with no peer that xray
    /// accepts and quietly drops every packet into.
    #[test]
    fn a_registration_without_a_peer_is_refused() {
        let broken = SAMPLE.replace(r#""peers": [{"#, r#""peers": [], "ignored": [{"#);
        let reg: RegResponse = serde_json::from_str(&broken).expect("sample parses");
        assert!(build_registration(String::new(), reg).is_err());
    }

    /// The edge key Cloudflare hands every MASQUE device (it is the same in
    /// every enrolment answer, and in the core's own example).
    const EDGE_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG\n\
        7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==\n\
        -----END PUBLIC KEY-----\n";

    /// A real enrolment answer (2026-11-14), trimmed to the shape around what
    /// the panel reads; the account block with its license, the ids and the
    /// device key are left out.
    fn enrolment(edge_public_key_pem: &str) -> String {
        serde_json::json!({
            "type": "a",
            "key_type": "secp256r1",
            "tunnel_type": "masque",
            "config": {
                "client_id": "iLC8",
                "peers": [{
                    "public_key": edge_public_key_pem,
                    "endpoint": {
                        "v4": "162.159.198.2:0",
                        "v6": "[2606:4700:103::2]:0",
                        "host": "engage.cloudflareclient.com:2408",
                        "ports": [443, 500, 1701, 4500, 4443, 8443, 8095]
                    }
                }],
                "interface": { "addresses": {
                    "v4": "172.16.0.2",
                    "v6": "2606:4700:110:82f2:cd2d:81ec:edf2:8457"
                } },
                "services": { "http_proxy": "172.16.0.1:2480" }
            },
            "warp_enabled": false,
            "policy": { "tunnel_protocol": "masque" }
        })
        .to_string()
    }

    #[test]
    fn a_masque_enrolment_becomes_a_dialable_tunnel() {
        let enrolled: EnrolResponse = serde_json::from_str(&enrolment(EDGE_PEM)).expect("parses");
        let reg = build_masque_registration("our-key".to_owned(), enrolled).expect("mapping");

        let h3 = reg.clone().into_outbound(false);
        // Port 0 in the answer, 443 on the wire.
        assert_eq!(h3.endpoint, "162.159.198.2:443");
        // PEM in, the single-line base64 DER the form shows out.
        assert_eq!(
            h3.peer_public_key,
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG\
             7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w=="
        );
        assert_eq!(h3.private_key, "our-key");
        assert_eq!(
            h3.address,
            [
                "172.16.0.2/32",
                "2606:4700:110:82f2:cd2d:81ec:edf2:8457/128"
            ]
        );
        assert!(!h3.http2);

        // HTTP/2 goes to the same edge: it is the one whose key we hold.
        let h2 = reg.into_outbound(true);
        assert_eq!(h2.endpoint, "162.159.198.2:443");
        assert!(h2.http2);
    }

    /// The answer to enrolment is where a WireGuard-shaped mistake would show
    /// up: a curve25519 peer key where a P-256 one belongs. That must fail at
    /// registration, not as a tunnel that never connects.
    #[test]
    fn an_enrolment_without_a_p256_peer_key_is_refused() {
        let wireguard_key = enrolment("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=");
        let enrolled: EnrolResponse = serde_json::from_str(&wireguard_key).expect("parses");
        assert!(build_masque_registration(String::new(), enrolled).is_err());

        let no_peer = enrolment(EDGE_PEM).replace("\"peers\":[{", "\"peers\":[],\"ignored\":[{");
        let enrolled: EnrolResponse = serde_json::from_str(&no_peer).expect("parses");
        assert!(build_masque_registration(String::new(), enrolled).is_err());
    }
}
