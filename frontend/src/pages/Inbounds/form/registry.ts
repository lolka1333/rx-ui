//! Per-protocol declarative metadata + the snap-back guard hook that
//! enforces it. The registry owns rules that drive form layout (allowed
//! transports / securities, defaults, extra tabs, whether the protocol
//! carries a flow concept). The hook below watches the form and resets
//! incompatible field combinations as the operator flips protocol /
//! transport / security — the backend's `validate_layers` mirrors the
//! same rules, so missing a guard here only means a 4xx on save (not
//! corrupted data), but "disabled radio still shows the wrong value"
//! is a bad UX.
//!
//! Adding a new protocol becomes:
//!   1. extend `FormProtocol` (in `./types`) + `ProtocolConfig` (backend ts-rs)
//!   2. add one `PROTOCOL_REGISTRY` entry below
//!   3. drop a tab component if it has its own knobs
//!
//! No `isHysteria` branches scattered around the form code.

import { useEffect } from 'react';
import { Form } from 'antd';
import { useFinalMaskGuard } from '@/api/finalmaskSupport';
import { HysteriaTab } from '../tabs/HysteriaTab';
import { VlessEncryption } from '../tabs/VlessEncryption';
import { WireguardTab } from '../tabs/WireguardTab';
import type {
  FormNetwork,
  FormProtocol,
  FormSecurity,
  FormValues,
  ProtocolDef,
} from './types';

export const PROTOCOL_REGISTRY: Record<FormProtocol, ProtocolDef> = {
  vless: {
    label: 'VLESS',
    allowedTransports: ['tcp', 'ws', 'xhttp'],
    allowedSecurities: ['none', 'tls', 'reality'],
    defaultSecurity: 'reality',
    hasFlow: true,
    MainTabExtras: VlessEncryption,
  },
  hysteria2: {
    label: 'Hysteria 2',
    allowedTransports: ['hysteria'],
    allowedSecurities: ['tls'],
    defaultSecurity: 'tls',
    hasFlow: false,
    extraTabs: [
      { key: 'hysteria', labelKey: 'inbounds.tabHysteria', Component: HysteriaTab },
    ],
    protocolHintKey: 'inbounds.protocolHysteriaHint',
    securityHintKey: 'inbounds.securityTlsRequiredHysteriaHint',
  },
  // WireGuard carries its own crypto and rides UDP directly: no transport to
  // pick, no TLS layer to put under it. Both single-entry lists hide their
  // selectors, which is exactly right — there is nothing to choose.
  wireguard: {
    label: 'WireGuard',
    allowedTransports: ['tcp'],
    allowedSecurities: ['none'],
    defaultSecurity: 'none',
    hasFlow: false,
    extraTabs: [
      { key: 'wireguard', labelKey: 'inbounds.tabWireguard', Component: WireguardTab },
    ],
    protocolHintKey: 'inbounds.protocolWireguardHint',
    securityHintKey: 'inbounds.securityWireguardHint',
    badgeKey: 'inbounds.protocolLegacyBadge',
  },
};

export function useProtocolGuards(form: ReturnType<typeof Form.useForm<FormValues>>[0]) {
  const protocol = Form.useWatch('protocol_kind', form) as FormProtocol | undefined;
  const network = Form.useWatch('network', form) as FormNetwork | undefined;
  const flow = Form.useWatch('vless_flow', form);
  const security = Form.useWatch('security', form) as FormSecurity | undefined;

  useEffect(() => {
    if (!protocol) return;
    const def = PROTOCOL_REGISTRY[protocol];

    // Protocol's allow-list owns the security choice — snap to default
    // when the current value falls outside it (e.g. switching to
    // Hysteria 2 forces TLS). Protocols without a `flow` field clear it.
    if (security && !def.allowedSecurities.includes(security)) {
      form.setFieldValue('security', def.defaultSecurity);
    }
    if (!def.hasFlow && flow !== 'none') {
      form.setFieldValue('vless_flow', 'none');
    }

    // Same for the transport: the selector hides once a protocol allows a
    // single one, so a value carried over from the previous protocol would
    // be invisible and still reach `buildTransport`. Only snap to a
    // transport the network selector can actually hold — Hysteria 2's
    // 'hysteria' is not one of them, and it ignores `network` anyway.
    const snapTo = def.allowedTransports.find(
      (k): k is FormNetwork => k === 'tcp' || k === 'ws' || k === 'xhttp',
    );
    if (network && snapTo && !def.allowedTransports.includes(network)) {
      form.setFieldValue('network', snapTo);
    }

    // XTLS Vision is raw-TCP-only. Snap back to 'none' when the
    // operator picks a non-TCP transport.
    if (def.hasFlow && network !== undefined && network !== 'tcp' && flow === 'xtls-rprx-vision') {
      form.setFieldValue('vless_flow', 'none');
    }
    // Reality is RAW/XHTTP/gRPC only, never WebSocket — per xray's
    // `transport_internet.go` (`buildClientStreamSettings`). Fall back
    // to TLS when the combo would be rejected.
    if (network === 'ws' && security === 'reality') {
      form.setFieldValue('security', 'tls');
    }
  }, [protocol, network, flow, security, form]);

  // Same idea one layer down: not every FinalMask runs on every transport, and
  // the one that no longer does has to leave with the transport that carried
  // it. Kept here rather than in the tab that renders it — this hook is
  // mounted for the whole life of the form, that tab is not.
  useFinalMaskGuard(
    // No fallbacks: an unknown transport must stay unknown. Substituting
    // 'tcp'/'none' here made the guard judge a not-yet-registered form
    // against the wrong matrix and silently turn off a legitimate mask.
    // Two protocols carry their own socket and are keyed as transports in the
    // matrix; everything else is judged by the transport it selected.
    protocol === 'hysteria2' ? 'hysteria' : protocol === 'wireguard' ? 'wireguard' : network,
    security,
    () => form.getFieldValue('finalmask_kind'),
    () => form.setFieldValue('finalmask_kind', 'none'),
  );
}
