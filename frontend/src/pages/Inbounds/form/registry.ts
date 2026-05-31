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
import { HysteriaTab } from '../tabs/HysteriaTab';
import { VlessEncryption } from '../tabs/VlessEncryption';
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
    defaultTransport: 'tcp',
    defaultSecurity: 'reality',
    hasFlow: true,
    MainTabExtras: VlessEncryption,
  },
  hysteria2: {
    label: 'Hysteria 2',
    allowedTransports: ['hysteria'],
    allowedSecurities: ['tls'],
    defaultTransport: 'hysteria',
    defaultSecurity: 'tls',
    hasFlow: false,
    extraTabs: [
      { key: 'hysteria', labelKey: 'inbounds.tabHysteria', Component: HysteriaTab },
    ],
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
}
