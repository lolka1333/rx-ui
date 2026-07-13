//! Shared `PanelSettings` → `PanelSettingsUpdate` helpers. Extracted from the
//! Settings page so non-component consumers (the reverse-pair wizard) can build
//! a full PUT body without importing a component module (which would trip
//! react-refresh's only-export-components rule).

import type { PanelSettings, PanelSettingsUpdate, RoutingRule } from '@/api/types';

/** Fallback values for the subscription side of `PanelSettings`, mirroring the
 *  backend column defaults in `backend/migrations/0024_subscription_settings.sql`,
 *  `0025_subscription_enabled.sql` + `0037_subscription_link_host.sql`. */
const SUBSCRIPTION_DEFAULTS = {
  sub_enabled: true,
  sub_host_override: '',
  sub_link_host: '',
  sub_update_interval_hours: 12,
  sub_brand_name: '',
  sub_service_url: '',
  sub_port: 0,
  sub_tls_mode: 'inherit',
  sub_cert_pem: '',
} as const;

/** Fallback values for the xray side of `PanelSettings`, mirroring the backend
 *  column defaults in `backend/migrations/0031_xray_settings.sql` +
 *  `0032_xray_routing.sql`. Consumed by `mergePanelSettings` for the
 *  not-yet-loaded case. */
const XRAY_DEFAULTS = {
  xray_freedom_strategy: 'AsIs',
  xray_routing_strategy: 'AsIs',
  xray_test_url: '',
  xray_block_bittorrent: false,
  xray_blocked_ips: [] as string[],
  xray_blocked_domains: [] as string[],
  xray_ipv4_domains: [] as string[],
  xray_custom_rules: [] as RoutingRule[],
  xray_rule_order: [] as string[],
} as const;

/** Fallback values for the panel-HTTPS side of `PanelSettings`, mirroring the
 *  backend column defaults in `backend/migrations/0036_panel_tls.sql`. The
 *  private key is never read back from the server (only `panel_tls_key_set`),
 *  so the merge always sends `panel_tls_key: ''` — the backend reads empty as
 *  "keep the stored key", and the TLS section overrides it only when the
 *  operator pastes a replacement. */
const TLS_DEFAULTS = {
  panel_tls_enabled: false,
  panel_tls_cert: '',
} as const;

/** `PUT /settings/panel` replaces the whole row, so every save must send all
 *  fields. Each settings section owns only a slice; this builds the full body
 *  from the cached settings (or the *_DEFAULTS, pre-load) and applies the
 *  caller's overrides — keeping the forward-everything-else logic in one place
 *  so a newly added field can't silently drop from any of the saves. */
export function mergePanelSettings(
  current: PanelSettings | undefined,
  overrides: Partial<PanelSettingsUpdate>,
): PanelSettingsUpdate {
  return {
    panel_port: current?.panel_port ?? 8080,
    panel_base_path: current?.panel_base_path ?? '',
    sub_enabled: current?.sub_enabled ?? SUBSCRIPTION_DEFAULTS.sub_enabled,
    sub_host_override: current?.sub_host_override ?? SUBSCRIPTION_DEFAULTS.sub_host_override,
    sub_link_host: current?.sub_link_host ?? SUBSCRIPTION_DEFAULTS.sub_link_host,
    sub_update_interval_hours:
      current?.sub_update_interval_hours ?? SUBSCRIPTION_DEFAULTS.sub_update_interval_hours,
    sub_brand_name: current?.sub_brand_name ?? SUBSCRIPTION_DEFAULTS.sub_brand_name,
    sub_service_url: current?.sub_service_url ?? SUBSCRIPTION_DEFAULTS.sub_service_url,
    sub_port: current?.sub_port ?? SUBSCRIPTION_DEFAULTS.sub_port,
    xray_freedom_strategy: current?.xray_freedom_strategy ?? XRAY_DEFAULTS.xray_freedom_strategy,
    xray_routing_strategy: current?.xray_routing_strategy ?? XRAY_DEFAULTS.xray_routing_strategy,
    xray_test_url: current?.xray_test_url ?? XRAY_DEFAULTS.xray_test_url,
    xray_block_bittorrent: current?.xray_block_bittorrent ?? XRAY_DEFAULTS.xray_block_bittorrent,
    xray_blocked_ips: current?.xray_blocked_ips ?? XRAY_DEFAULTS.xray_blocked_ips,
    xray_blocked_domains: current?.xray_blocked_domains ?? XRAY_DEFAULTS.xray_blocked_domains,
    xray_ipv4_domains: current?.xray_ipv4_domains ?? XRAY_DEFAULTS.xray_ipv4_domains,
    xray_custom_rules: current?.xray_custom_rules ?? XRAY_DEFAULTS.xray_custom_rules,
    xray_rule_order: current?.xray_rule_order ?? XRAY_DEFAULTS.xray_rule_order,
    panel_tls_enabled: current?.panel_tls_enabled ?? TLS_DEFAULTS.panel_tls_enabled,
    panel_tls_cert: current?.panel_tls_cert ?? TLS_DEFAULTS.panel_tls_cert,
    // Empty ≡ keep the stored key; the TLS section overrides this with the
    // pasted PEM when (and only when) the operator supplies a new key.
    panel_tls_key: '',
    sub_tls_mode: current?.sub_tls_mode ?? SUBSCRIPTION_DEFAULTS.sub_tls_mode,
    sub_cert_pem: current?.sub_cert_pem ?? SUBSCRIPTION_DEFAULTS.sub_cert_pem,
    // Empty ≡ keep the stored subscription key (same as panel_tls_key).
    sub_key_pem: '',
    ...overrides,
  };
}
