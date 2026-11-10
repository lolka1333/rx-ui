import { describe, expect, it } from 'vitest';
import { LinkParseError, parseOutboundLink } from './parseLink';

// Links are written the way the backend's builders write them
// (backend/src/xray/share_link.rs): `vless://UUID@HOST:PORT?…#TAG` and
// `hysteria2://AUTH@HOST:PORT/?…#TAG`, every value percent-encoded.

const UUID = '6f2c1e1a-8a0b-4c1e-9a55-0d1f2e3a4b5c';
const q = (params: Record<string, string>) =>
  Object.entries(params)
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join('&');
const vless = (params: Record<string, string>, host = 'de1.example.com', tag = 'vless-in') =>
  `vless://${UUID}@${host}:443?${q(params)}#${encodeURIComponent(tag)}`;
const hy2 = (params: Record<string, string>, auth = 'secret pass', tag = 'hy-in') =>
  `hysteria2://${encodeURIComponent(auth)}@hy.example.com:27500/?${q(params)}#${encodeURIComponent(tag)}`;
const fm = (layers: { tcp?: unknown[]; udp?: unknown[] }) =>
  JSON.stringify({ tcp: layers.tcp ?? [], udp: layers.udp ?? [] });

const errorKey = (link: string) => {
  try {
    parseOutboundLink(link);
  } catch (e) {
    return e instanceof LinkParseError ? e.i18nKey : `not a LinkParseError: ${String(e)}`;
  }
  return 'no error';
};

describe('vless links', () => {
  it('reads a Reality link', () => {
    const out = parseOutboundLink(
      vless({
        type: 'tcp',
        security: 'reality',
        sni: 'www.cloudflare.com',
        pbk: 'PUBKEY',
        sid: 'ab12',
        fp: 'firefox',
        spx: '/probe',
        flow: 'xtls-rprx-vision',
      }),
    );
    expect(out).toMatchObject({
      tag: 'vless-in',
      address: 'de1.example.com',
      port: 443,
      uuid: UUID,
      flow: 'xtls-rprx-vision',
      security: 'reality',
      reality_server_name: 'www.cloudflare.com',
      reality_public_key: 'PUBKEY',
      reality_short_id: 'ab12',
      reality_fingerprint: 'firefox',
      reality_spider_x: '/probe',
      network: 'tcp',
      encryption_mode: 'none',
    });
  });

  it('fills the Reality defaults a link may leave out', () => {
    const out = parseOutboundLink(vless({ security: 'reality', sni: 'a', pbk: 'k', sid: '' }));
    expect(out.reality_fingerprint).toBe('chrome');
    expect(out.reality_spider_x).toBe('/');
  });

  it('reads TLS over WebSocket', () => {
    const out = parseOutboundLink(
      vless({ type: 'ws', security: 'tls', sni: 'cdn.example.com', alpn: 'h2, http/1.1', path: '/ws', host: 'cdn.example.com' }),
    );
    expect(out).toMatchObject({
      security: 'tls',
      tls_server_name: 'cdn.example.com',
      tls_alpn: ['h2', 'http/1.1'],
      tls_fingerprint: 'chrome',
      network: 'ws',
      ws_path: '/ws',
      ws_host: 'cdn.example.com',
    });
  });

  it('reads XHTTP with its extra block', () => {
    const extra = JSON.stringify({
      xPaddingObfsMode: true,
      xPaddingKey: 'k',
      sessionIDPlacement: 'cookie',
      seqKey: 'seq',
      uplinkDataPlacement: 'header',
    });
    const out = parseOutboundLink(
      vless({ type: 'xhttp', security: 'tls', sni: 's', path: '/up', mode: 'packet-up', extra }),
    );
    expect(out).toMatchObject({
      network: 'xhttp',
      xhttp_path: '/up',
      xhttp_mode: 'packet-up',
      xhttp_x_padding_obfs_mode: true,
      xhttp_x_padding_key: 'k',
      xhttp_session_placement: 'cookie',
      xhttp_seq_key: 'seq',
      xhttp_uplink_data_placement: 'header',
    });
  });

  it('accepts the old splithttp name for XHTTP', () => {
    expect(parseOutboundLink(vless({ type: 'splithttp' })).network).toBe('xhttp');
  });

  it('ignores a malformed XHTTP extra instead of failing the whole link', () => {
    const out = parseOutboundLink(vless({ type: 'xhttp', extra: '{not json' }));
    expect(out.network).toBe('xhttp');
    expect(out.xhttp_x_padding_obfs_mode).toBeUndefined();
  });

  it('splits VLESS encryption into mode, xor, padding and key', () => {
    const withPadding = parseOutboundLink(
      vless({ encryption: 'mlkem768x25519plus.xorpub.0rtt.100-200-300.CLIENTKEY' }),
    );
    expect(withPadding).toMatchObject({
      encryption_mode: 'mlkem768x25519plus',
      encryption_xor_mode: 'xorpub',
      encryption_padding: '100-200-300',
      encryption_client_key: 'CLIENTKEY',
    });
    const bare = parseOutboundLink(vless({ encryption: 'mlkem768x25519plus.native.0rtt.KEY' }));
    expect(bare).toMatchObject({ encryption_padding: '', encryption_client_key: 'KEY' });
    expect(parseOutboundLink(vless({ encryption: 'none' })).encryption_mode).toBe('none');
  });

  it('collapses an unknown flow, security or transport to the plain choice', () => {
    const out = parseOutboundLink(vless({ flow: 'xtls-rprx-direct', security: 'xtls', type: 'kcp' }));
    expect(out).toMatchObject({ flow: '', security: 'none', network: 'tcp' });
  });

  it('carries the reverse tunnel tag', () => {
    expect(parseOutboundLink(vless({ reverse: 'tunnel-home' })).reverse_tag).toBe('tunnel-home');
  });

  it('reads a bracketed IPv6 host', () => {
    const out = parseOutboundLink(vless({}, '[2001:db8::1]'));
    expect(out).toMatchObject({ address: '2001:db8::1', port: 443 });
  });

  it('decodes a percent-encoded tag', () => {
    expect(parseOutboundLink(vless({}, 'h.example', 'ру узел #1')).tag).toBe('ру узел #1');
  });

  it('reads each finalmask from fm=', () => {
    const fragment = parseOutboundLink(
      vless({ fm: fm({ tcp: [{ type: 'fragment', settings: { packets: '2-5', lengths: ['10-20'], delays: ['1-2'] } }] }) }),
    );
    expect(fragment).toMatchObject({
      finalmask_kind: 'fragment',
      finalmask_fragment_packets_mode: 'range',
      finalmask_fragment_packets_from: 2,
      finalmask_fragment_packets_to: 5,
      finalmask_fragment_lengths: '10-20',
      finalmask_fragment_delays: '1-2',
    });
    const tlshello = parseOutboundLink(
      vless({ fm: fm({ tcp: [{ type: 'fragment', settings: { packets: 'tlshello', lengths: ['100-200'] } }] }) }),
    );
    expect(tlshello.finalmask_fragment_packets_mode).toBe('tlshello');

    const sudoku = parseOutboundLink(
      vless({ fm: fm({ tcp: [{ type: 'sudoku', settings: { password: 'pw' } }] }) }),
    );
    expect(sudoku).toMatchObject({ finalmask_kind: 'sudoku', finalmask_sudoku_password: 'pw' });

    const xmc = parseOutboundLink(
      vless({
        fm: fm({
          tcp: [
            {
              type: 'xmc',
              settings: {
                hostname: 'mc.example',
                password: 'pw',
                profiles: [{ username: 'u', uuid: 'id', texturesValue: 'tv', texturesSignature: 'ts' }],
              },
            },
          ],
        }),
      }),
    );
    expect(xmc).toMatchObject({
      finalmask_kind: 'xmc',
      finalmask_xmc_hostname: 'mc.example',
      finalmask_xmc_profiles: [
        { username: 'u', uuid: 'id', textures_value: 'tv', textures_signature: 'ts' },
      ],
    });
  });
});

describe('hysteria2 links', () => {
  it('reads auth, pinned certificate and alpn', () => {
    const out = parseOutboundLink(hy2({ sni: 'hy.example.com', pinSHA256: 'ABCDEF', alpn: 'h3' }));
    expect(out).toMatchObject({
      tag: 'hy-in',
      protocol_kind: 'hysteria',
      address: 'hy.example.com',
      port: 27500,
      hysteria_auth: 'secret pass',
      security: 'tls',
      tls_server_name: 'hy.example.com',
      tls_pinned_peer_cert_sha256: ['ABCDEF'],
      tls_alpn: ['h3'],
    });
  });

  it('turns insecure into trust-by-name when nothing is pinned', () => {
    const out = parseOutboundLink(hy2({ insecure: '1' }));
    expect(out.tls_verify_peer_cert_by_name).toEqual(['hy.example.com']);
    expect(out.tls_pinned_peer_cert_sha256).toBeUndefined();
  });

  it('accepts the hy2:// spelling', () => {
    const link = hy2({}).replace('hysteria2://', 'hy2://');
    expect(parseOutboundLink(link).protocol_kind).toBe('hysteria');
  });

  it('reads salamander from the standard obfs params', () => {
    const out = parseOutboundLink(hy2({ obfs: 'salamander', 'obfs-password': 'opw' }));
    expect(out).toMatchObject({ finalmask_kind: 'salamander', finalmask_salamander_password: 'opw' });
  });

  // The backend writes every mask but salamander as `fm=` on hysteria2 links
  // too; these were dropped on paste, leaving an outbound without its mask.
  it('reads noise from fm=', () => {
    const out = parseOutboundLink(
      hy2({ fm: fm({ udp: [{ type: 'noise', settings: { noise: [{ rand: '5-10', delay: '1-2' }] } }] }) }),
    );
    expect(out).toMatchObject({
      finalmask_kind: 'noise',
      finalmask_noise_items: [
        { packet_hex: '', rand_min: 5, rand_max: 10, delay_min: 1, delay_max: 2 },
      ],
    });
  });

  it('reads XICMP from fm=, the client half only', () => {
    const out = parseOutboundLink(
      hy2({ fm: fm({ udp: [{ type: 'xicmp', settings: { ips: ['203.0.113.9'], dgram: true } }] }) }),
    );
    expect(out).toMatchObject({
      finalmask_kind: 'xicmp',
      finalmask_xicmp_server_ips: ['203.0.113.9'],
      finalmask_xicmp_dgram: true,
    });
    expect(out.finalmask_xicmp_allowed_client_ips).toBeUndefined();
  });
});

describe('rejected links', () => {
  it.each([
    ['', 'outbounds.linkErrEmpty'],
    ['vmess://abc', 'outbounds.linkErrScheme'],
    ['trojan://x@h:1', 'outbounds.linkErrScheme'],
    ['https://example.com', 'outbounds.linkErrUnknown'],
    ['vless://de1.example.com:443', 'outbounds.linkErrNoUuid'],
    [`vless://${UUID}@:443`, 'outbounds.linkErrNoHost'],
    [`vless://${UUID}@h.example:0`, 'outbounds.linkErrHostPort'],
    [`vless://${UUID}@h.example:70000`, 'outbounds.linkErrHostPort'],
    [`vless://${UUID}@[2001:db8::1:443`, 'outbounds.linkErrIpv6'],
  ])('%s → %s', (link, key) => {
    expect(errorKey(link)).toBe(key);
  });
});
