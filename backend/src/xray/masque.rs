//! Cloudflare WARP over MASQUE: the device keys, and the stream layer the core
//! is handed for a [`MasqueOutbound`].
//!
//! The core's JSON parser does three things for a `masque` outbound that the
//! gRPC path skips, so they happen here instead (`MasqueConfig.Build` and the
//! `parseWarp*` helpers in `infra/conf/transport_method.go`):
//!
//! * whatever encoding the keys arrived in becomes PKCS #8 (private) and PKIX
//!   (public) DER — the runtime reads nothing else;
//! * WARP's host and path are filled in;
//! * XMUX gets one connection, reused for 30–50 minutes, when nothing else was
//!   asked for.

use anyhow::Context as _;
use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _,
    ParsedPublicKey,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::models::MasqueOutbound;
use crate::security::{SecurityConfig, tls::TlsSecurity};
use crate::xray::proto::xray::common::serial::TypedMessage;
use crate::xray::proto::xray::transport::internet::masque::{Config as MasqueConfig, Warp};
use crate::xray::proto::xray::transport::internet::splithttp::{RangeConfig, XmuxConfig};
use crate::xray::proto::xray::transport::internet::{
    SocketConfig, StreamConfig, TransportConfig as XrayTransportConfig,
};

/// What the WARP app sends as SNI, and the name the edge serves the WARP
/// certificate under. Measured: under another name (`www.example.com`) the
/// edge presents a different certificate and the key check refuses it; taking
/// the certificate by name instead (`verifyPeerCertByName`, the core's
/// fronting escape hatch) gets the CONNECT-IP request answered with 400.
pub const WARP_SNI: &str = "consumer-masque.cloudflareclient.com";
/// `WarpHost` / `WarpPath` in `transport/internet/masque/warp.go`.
const WARP_HOST: &str = "cloudflareaccess.com";
const WARP_PATH: &str = "/";
const PROTOCOL_NAME: &str = "masque";
const TYPE_MASQUE_TRANSPORT: &str = "xray.transport.internet.masque.Config";

/// A freshly generated device key: the private half as base64 PKCS #8 DER, the
/// way the outbound stores it, and the public half as base64 PKIX DER, the way
/// Cloudflare's enrolment call wants it.
pub struct MasqueKeypair {
    pub private_key: String,
    pub public_key: String,
}

/// Generate the P-256 key a WARP device authenticates with over MASQUE.
pub fn generate_keypair() -> anyhow::Result<MasqueKeypair> {
    let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)
        .map_err(|_| anyhow::anyhow!("could not generate a P-256 key"))?;
    let pkcs8 = pair
        .to_pkcs8v1()
        .map_err(|_| anyhow::anyhow!("could not encode the P-256 key"))?;
    let spki = pair
        .public_key()
        .as_der()
        .map_err(|_| anyhow::anyhow!("could not encode the P-256 public key"))?;
    Ok(MasqueKeypair {
        private_key: STANDARD.encode(pkcs8.as_ref()),
        public_key: STANDARD.encode(spki.as_ref()),
    })
}

/// A key as an operator might paste it: PEM (first block only, the way Go's
/// `pem.Decode` reads it) or bare base64 DER.
fn decode_key_text(text: &str) -> anyhow::Result<Vec<u8>> {
    let text = text.trim();
    anyhow::ensure!(!text.is_empty(), "empty key");
    let body: String = if text.starts_with("-----BEGIN") {
        let mut lines = text.lines().map(str::trim);
        lines.next();
        let body: String = lines.take_while(|l| !l.starts_with("-----END")).collect();
        anyhow::ensure!(!body.is_empty(), "the PEM block is empty");
        body
    } else {
        text.chars().filter(|c| !c.is_whitespace()).collect()
    };
    STANDARD.decode(body).context("neither PEM nor base64")
}

/// The device's private key as the PKCS #8 DER the core's proto carries.
/// SEC 1 (`EC PRIVATE KEY`) is accepted too and converted, as the core's own
/// parser does; any curve but P-256 is refused.
pub fn private_key_pkcs8(text: &str) -> anyhow::Result<Vec<u8>> {
    let der = decode_key_text(text)?;
    let pair = EcdsaKeyPair::from_private_key_der(&ECDSA_P256_SHA256_ASN1_SIGNING, &der)
        .map_err(|_| anyhow::anyhow!("not a P-256 private key (PKCS #8 or SEC 1)"))?;
    let pkcs8 = pair
        .to_pkcs8v1()
        .map_err(|_| anyhow::anyhow!("could not re-encode the private key"))?;
    Ok(pkcs8.as_ref().to_vec())
}

/// The endpoint's public key as PKIX (`SubjectPublicKeyInfo`) DER. A bare EC
/// point is refused even though it would parse: the core reads this field with
/// `x509.ParsePKIXPublicKey`, which wants the wrapped form.
pub fn public_key_spki(text: &str) -> anyhow::Result<Vec<u8>> {
    let der = decode_key_text(text)?;
    anyhow::ensure!(
        der.first() == Some(&0x30),
        "not a SubjectPublicKeyInfo (PEM `PUBLIC KEY` or its base64 DER)"
    );
    ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &der)
        .map_err(|_| anyhow::anyhow!("not a P-256 public key"))?;
    Ok(der)
}

/// The tunnel's own addresses, as `parseWarpAddress` writes them: each a prefix
/// (a bare address becomes a host prefix), at most one per family.
pub fn tunnel_addresses(list: &[String]) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::with_capacity(list.len());
    let (mut v4, mut v6) = (false, false);
    for raw in list.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let (ip_text, bits) = raw
            .split_once('/')
            .map_or((raw, None), |(a, b)| (a, Some(b)));
        let ip: std::net::IpAddr = ip_text
            .parse()
            .map_err(|_| anyhow::anyhow!("tunnel address is not an IP: {raw}"))?;
        let max: u8 = if ip.is_ipv4() { 32 } else { 128 };
        let bits = match bits {
            None => max,
            Some(b) => b
                .parse::<u8>()
                .ok()
                .filter(|b| *b <= max)
                .ok_or_else(|| anyhow::anyhow!("prefix out of range for the family: {raw}"))?,
        };
        let seen = if ip.is_ipv4() { &mut v4 } else { &mut v6 };
        anyhow::ensure!(
            !*seen,
            "the tunnel takes at most one IPv4 and one IPv6 address"
        );
        *seen = true;
        out.push(format!("{ip}/{bits}"));
    }
    anyhow::ensure!(!out.is_empty(), "the tunnel needs at least one address");
    Ok(out)
}

/// Split `host:port` (`[v6]:port` for an IPv6 literal) into its halves.
pub fn endpoint_parts(endpoint: &str) -> anyhow::Result<(String, u16)> {
    let endpoint = endpoint.trim();
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("endpoint needs a port: {endpoint}"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    anyhow::ensure!(!host.is_empty(), "endpoint has no host: {endpoint}");
    let port: u16 = port
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| anyhow::anyhow!("endpoint port out of range: {endpoint}"))?;
    Ok((host.to_owned(), port))
}

/// The resolvers reached through the tunnel. The core's JSON parser refuses
/// anything but a bare IP here; the gRPC path does not check, so this does.
pub fn remote_dns(list: &[String]) -> anyhow::Result<Vec<String>> {
    list.iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<std::net::IpAddr>()
                .map(|_| s.to_owned())
                .map_err(|_| anyhow::anyhow!("remote DNS must be an IP address: {s}"))
        })
        .collect()
}

/// XMUX as the JSON parser fills it when the config says nothing: one
/// connection, retired after 30–50 minutes.
fn default_xmux() -> XmuxConfig {
    XmuxConfig {
        max_connections: Some(RangeConfig { from: 1, to: 1 }),
        h_max_reusable_secs: Some(RangeConfig {
            from: 1800,
            to: 3000,
        }),
        ..XmuxConfig::default()
    }
}

/// The whole stream layer of a MASQUE outbound: the `masque` transport with the
/// WARP keys, and the TLS it runs over. `socket_settings` carries the outbound's
/// chaining, built by the caller the same way for every protocol.
pub fn stream_config(
    m: &MasqueOutbound,
    socket_settings: Option<SocketConfig>,
) -> anyhow::Result<StreamConfig> {
    let warp = Warp {
        private_key: private_key_pkcs8(&m.private_key).context("private key")?,
        public_key: public_key_spki(&m.peer_public_key).context("peer public key")?,
        address: tunnel_addresses(&m.address)?,
    };
    let transport = MasqueConfig {
        host: WARP_HOST.to_owned(),
        path: WARP_PATH.to_owned(),
        headers: std::collections::HashMap::new(),
        warp: Some(warp),
        xmux: Some(default_xmux()),
    };

    // The core picks HTTP/2 when the ALPN list names `h2` and not `h3`, and
    // sets `h3` itself for HTTP/3. The fingerprint (Chrome, the builder's
    // default) only matters on HTTP/2, where the TLS runs over TCP.
    let server_name = match m.server_name.trim() {
        "" => WARP_SNI,
        name => name,
    };
    let tls = SecurityConfig::Tls(TlsSecurity {
        server_name: Some(server_name.to_owned()),
        alpn: Some(vec![if m.http2 { "h2" } else { "h3" }.to_owned()]),
        ..TlsSecurity::default()
    });
    let security = tls.as_security();

    Ok(StreamConfig {
        socket_settings,
        protocol_name: PROTOCOL_NAME.to_owned(),
        transport_settings: vec![XrayTransportConfig {
            protocol_name: PROTOCOL_NAME.to_owned(),
            settings: Some(TypedMessage {
                r#type: TYPE_MASQUE_TRANSPORT.to_owned(),
                value: prost::Message::encode_to_vec(&transport),
            }),
        }],
        security_type: security.xray_type_url().to_owned(),
        security_settings: security
            .build_client_settings()?
            .map_or_else(Vec::new, |msg| vec![msg]),
        ..StreamConfig::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::proto::xray::transport::internet::tls::Config as TlsConfig;
    use prost::Message as _;

    fn outbound() -> MasqueOutbound {
        let keys = generate_keypair().expect("keygen");
        let peer = generate_keypair().expect("keygen");
        MasqueOutbound {
            private_key: keys.private_key,
            peer_public_key: peer.public_key,
            address: vec![
                "172.16.0.2/32".to_owned(),
                "2606:4700:110:8a36::2/128".to_owned(),
            ],
            endpoint: "162.159.198.1:443".to_owned(),
            server_name: String::new(),
            http2: false,
            remote_dns: Vec::new(),
        }
    }

    /// A generated key is one the core can use: PKCS #8 that round-trips
    /// through the same parser, and a public half that is wrapped PKIX.
    #[test]
    fn a_generated_keypair_is_what_the_core_reads() {
        let keys = generate_keypair().expect("keygen");
        let pkcs8 = private_key_pkcs8(&keys.private_key).expect("private key parses");
        assert_eq!(STANDARD.encode(&pkcs8), keys.private_key, "already PKCS #8");
        let spki = public_key_spki(&keys.public_key).expect("public key parses");
        // P-256 SubjectPublicKeyInfo: 26 bytes of header, then the 65-byte
        // uncompressed point.
        assert_eq!(spki.len(), 91);
        assert_eq!(spki[26], 0x04);
    }

    /// The registration and the WARP app hand keys around as PEM, and the
    /// example in the core's own change used SEC 1 base64. All of them must
    /// arrive as the same PKCS #8 bytes.
    #[test]
    fn keys_are_accepted_in_every_spelling_the_core_accepts() {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("keygen");
        let pkcs8 = pair.to_pkcs8v1().expect("pkcs8").as_ref().to_vec();
        let sec1 = pair.private_key().as_der().expect("sec1").as_ref().to_vec();
        assert_ne!(sec1, pkcs8);

        let from_sec1 = private_key_pkcs8(&STANDARD.encode(&sec1)).expect("SEC 1 base64");
        let pem = format!(
            "-----BEGIN EC PRIVATE KEY-----\n{}\n{}\n-----END EC PRIVATE KEY-----\n",
            &STANDARD.encode(&sec1)[..40],
            &STANDARD.encode(&sec1)[40..]
        );
        let from_pem = private_key_pkcs8(&pem).expect("SEC 1 PEM, wrapped");
        // Same key either way; the encoding may carry the public point or not,
        // so compare through the parser rather than byte for byte.
        for der in [from_sec1, from_pem] {
            let back = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &der)
                .expect("PKCS #8 out");
            assert_eq!(back.public_key().as_ref(), pair.public_key().as_ref());
        }

        let spki = pair.public_key().as_der().expect("spki").as_ref().to_vec();
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            STANDARD.encode(&spki)
        );
        assert_eq!(public_key_spki(&pem).expect("PEM public key"), spki);
    }

    /// Each of these would reach the core and fail only when the tunnel is
    /// dialled — or, for the bare point, be refused by `ParsePKIXPublicKey`.
    #[test]
    fn keys_the_core_cannot_use_are_refused() {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("keygen");
        let p384 = EcdsaKeyPair::generate(&aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1_SIGNING)
            .expect("keygen");
        let p384_pkcs8 = STANDARD.encode(p384.to_pkcs8v1().expect("pkcs8").as_ref());
        let bare_point = STANDARD.encode(pair.public_key().as_ref());

        assert!(private_key_pkcs8("").is_err());
        assert!(private_key_pkcs8("not base64 !").is_err());
        assert!(private_key_pkcs8(&STANDARD.encode(b"junk")).is_err());
        assert!(private_key_pkcs8(&p384_pkcs8).is_err(), "only P-256");
        assert!(
            public_key_spki(&bare_point).is_err(),
            "a bare point is not PKIX"
        );
        let p384_spki = STANDARD.encode(p384.public_key().as_der().expect("spki").as_ref());
        assert!(public_key_spki(&p384_spki).is_err(), "only P-256");
    }

    /// `parseWarpAddress`: a bare address is a host prefix, and each family
    /// appears once at most.
    #[test]
    fn tunnel_addresses_follow_the_cores_rules() {
        assert_eq!(
            tunnel_addresses(&[
                " 172.16.0.2 ".to_owned(),
                String::new(),
                "2606:4700:110:8A36::2/128".to_owned(),
            ])
            .expect("valid"),
            ["172.16.0.2/32", "2606:4700:110:8a36::2/128"]
        );
        for bad in [
            vec![],
            vec!["warp.example.com".to_owned()],
            vec!["172.16.0.2/33".to_owned()],
            vec!["172.16.0.2/32".to_owned(), "172.16.0.3/32".to_owned()],
        ] {
            assert!(tunnel_addresses(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn endpoints_split_into_host_and_port() {
        assert_eq!(
            endpoint_parts("162.159.198.1:443").expect("v4"),
            ("162.159.198.1".to_owned(), 443)
        );
        assert_eq!(
            endpoint_parts("[2606:4700:103::1]:443").expect("v6"),
            ("2606:4700:103::1".to_owned(), 443)
        );
        for bad in ["162.159.198.1", ":443", "162.159.198.1:0", "h:99999"] {
            assert!(endpoint_parts(bad).is_err(), "{bad}");
        }
    }

    fn decode(stream: &StreamConfig) -> (MasqueConfig, TlsConfig) {
        assert_eq!(stream.protocol_name, "masque");
        let settings = stream.transport_settings[0]
            .settings
            .as_ref()
            .expect("transport settings");
        assert_eq!(settings.r#type, "xray.transport.internet.masque.Config");
        let transport = MasqueConfig::decode(settings.value.as_slice()).expect("masque config");
        assert_eq!(stream.security_type, "xray.transport.internet.tls.Config");
        let tls = TlsConfig::decode(stream.security_settings[0].value.as_slice()).expect("tls");
        (transport, tls)
    }

    /// What the JSON parser would have built from the same outbound: keys as
    /// DER, WARP's host and path, one XMUX connection, the app's SNI and HTTP/3.
    #[test]
    fn the_stream_carries_what_the_json_parser_would_have_filled_in() {
        let ob = outbound();
        let (transport, tls) = decode(&stream_config(&ob, None).expect("builds"));

        assert_eq!(transport.host, "cloudflareaccess.com");
        assert_eq!(transport.path, "/");
        let warp = transport.warp.expect("warp block");
        assert_eq!(STANDARD.encode(&warp.private_key), ob.private_key);
        assert_eq!(STANDARD.encode(&warp.public_key), ob.peer_public_key);
        assert_eq!(warp.address, ["172.16.0.2/32", "2606:4700:110:8a36::2/128"]);
        let xmux = transport.xmux.expect("xmux");
        assert_eq!(xmux.max_connections, Some(RangeConfig { from: 1, to: 1 }));
        assert_eq!(xmux.max_concurrency, None);

        assert_eq!(tls.server_name, WARP_SNI);
        assert_eq!(tls.next_protocol, ["h3"]);
        assert_eq!(tls.fingerprint, "chrome");
    }

    /// HTTP/2 is chosen by the ALPN list alone, and an operator's SNI wins.
    #[test]
    fn http2_and_a_custom_sni_reach_the_tls_block() {
        let ob = MasqueOutbound {
            http2: true,
            server_name: " www.example.com ".to_owned(),
            ..outbound()
        };
        let (_, tls) = decode(&stream_config(&ob, None).expect("builds"));
        assert_eq!(tls.next_protocol, ["h2"]);
        assert_eq!(tls.server_name, "www.example.com");
    }

    #[test]
    fn remote_dns_takes_addresses_only() {
        assert_eq!(
            remote_dns(&[
                " 1.1.1.1".to_owned(),
                String::new(),
                "2606:4700:4700::1111".to_owned()
            ])
            .expect("valid"),
            ["1.1.1.1", "2606:4700:4700::1111"]
        );
        assert!(remote_dns(&["dns.google".to_owned()]).is_err());
    }
}
