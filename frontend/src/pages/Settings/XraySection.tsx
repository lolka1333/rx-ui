/**
 * Xray — engine settings (outbound/routing). These live in xray's bootstrap
 * config, so a Freedom/routing strategy change only applies on an xray
 * restart — the section saves to the DB, then offers to restart (which
 * regenerates the bootstrap and bounces the process).
 */
import { App, Form, Input, Select, Tabs, Tag, Tooltip, Typography } from 'antd';
import type { SelectProps } from 'antd';
import { BranchesOutlined, GlobalOutlined, CheckOutlined, CloseOutlined, ControlOutlined, DownOutlined, LoadingOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useLoadState } from '@/api/loadState';
import { LoadError, LoadStale } from '@/components/LoadState';
import type { PanelSettings, RoutingRule } from '@/api/types';
import { GEOIP_PRESETS, GEOSITE_PRESETS, GEO_PRESET_BY_VALUE } from '@/lib/geoPresets';
import type { GeoPreset } from '@/lib/geoPresets';
import { DnsTab } from '@/components/DnsTab';
import { mergePanelSettings } from '@/lib/panelSettings';
import { reportRouting } from '@/lib/routingReport';
import type { RoutingApplyResult } from '@/lib/routingReport';
import type { DnsHost, DnsServer } from '@/api/types/settings';
import { type DirtyHandle, differsFromSaved, useSectionDirtyPublish } from './dirty';
import { SectionFrame, FieldLabel, FieldGroup, RowSwitch } from './fields';

/** No-op control that only registers the `xray_rule_order` array field on the
 *  form, so it's reactive via `Form.useWatch` and writable via `setFieldsValue`
 *  — the value is rendered/edited by RoutingRulesField, not here. Antd injects
 *  value/onChange at runtime; this control intentionally ignores them. */
const HiddenField = () => null;

/** The three panes of the Xray settings page. */
type XrayTab = 'basic' | 'routing' | 'dns';

interface XrayFormValues {
  xray_freedom_strategy: string;
  xray_routing_strategy: string;
  xray_freedom_allow_private: string[];
  xray_freedom_block_delay: string;
  xray_test_url: string;
  xray_block_bittorrent: boolean;
  xray_blocked_ips: string[];
  xray_blocked_domains: string[];
  xray_direct_ips: string[];
  xray_direct_domains: string[];
  xray_ipv4_domains: string[];
  xray_dns_servers: DnsServer[];
  xray_dns_hosts: DnsHost[];
  xray_dns_query_strategy: string;
  xray_dns_client_ip: string;
  xray_dns_tag: string;
  xray_dns_disable_cache: boolean;
  xray_dns_disable_fallback: boolean;
  xray_dns_disable_fallback_if_match: boolean;
  xray_dns_parallel_query: boolean;
  xray_dns_use_system_hosts: boolean;
  xray_dns_serve_stale: boolean;
  xray_dns_serve_expired_ttl: number;
  xray_custom_rules: RoutingRule[];
  xray_rule_order: string[];
}

/** Freedom-outbound `domainStrategy` values; mirrors the backend allowlist
 *  in `api/settings.rs`. AsIs = no DNS forcing; the UseIP / ForceIP families
 *  pick the egress address family. */
/// Suggested entries for the private-range allow-list: the three RFC1918
/// blocks plus the CGNAT range a home router may hand out. Suggestions only —
/// the field is free text, and a single host (`192.168.1.10/32`) is usually
/// the better answer than a whole subnet.
const PRIVATE_ALLOW_PRESETS = [
  '192.168.0.0/16',
  '10.0.0.0/8',
  '172.16.0.0/12',
  '100.64.0.0/10',
].map((value) => ({ value, label: value }));

const FREEDOM_STRATEGY_OPTIONS = [
  'AsIs',
  'UseIP',
  'UseIPv4',
  'UseIPv6',
  'UseIPv4v6',
  'UseIPv6v4',
  'ForceIP',
  'ForceIPv4',
  'ForceIPv6',
  'ForceIPv4v6',
  'ForceIPv6v4',
].map((value) => ({ value, label: value }));

/** Routing-block `domainStrategy` values. */
const ROUTING_STRATEGY_OPTIONS = ['AsIs', 'IPIfNonMatch', 'IPOnDemand'].map(
  (value) => ({ value, label: value }),
);

/**
 * Endpoints offered for the egress test. The list is deliberately closed: the
 * result is only useful when the backend can read the exit IP out of the reply,
 * and it understands exactly two shapes (see `outbound_test::parse_trace`) —
 * a Cloudflare `cdn-cgi/trace` block, which also carries the country, and a
 * bare single-line IP. A URL like `generate_204` answers with an empty body, so
 * the exit IP on this page and on Outbounds stays blank — which is what this
 * list exists to prevent.
 */
const TEST_URL_TRACE = [
  'https://www.cloudflare.com/cdn-cgi/trace',
  'https://speed.cloudflare.com/cdn-cgi/trace',
  'https://1.1.1.1/cdn-cgi/trace',
];
const TEST_URL_PLAIN = [
  'https://api.ipify.org',
  'https://api64.ipify.org',
  'https://ifconfig.me/ip',
  'https://icanhazip.com',
  'https://ipinfo.io/ip',
  'https://checkip.amazonaws.com',
];
const hostOf = (u: string) => {
  try {
    return new URL(u).host;
  } catch {
    return u;
  }
};

/** Dropdown row: "<code> <name>". A custom (typed) option has no code. */
const renderGeoOption: NonNullable<SelectProps['optionRender']> = (option) => {
  const o = option.data as GeoPreset;
  return (
    <span>
      {o.code ? <span className="geo-code">{o.code}</span> : null}
      {o.label}
    </span>
  );
};

/** Selected chip: a preset shows "<code> <name>", a custom value shows raw. */
const renderGeoTag: NonNullable<SelectProps['tagRender']> = (props) => {
  const o = GEO_PRESET_BY_VALUE.get(String(props.value));
  return (
    <Tag closable={props.closable} onClose={props.onClose}>
      {o ? (
        <>
          {o.code ? <span className="geo-code">{o.code}</span> : null}
          {o.label}
        </>
      ) : (
        String(props.value)
      )}
    </Tag>
  );
};

/** Shape of `POST /api/xray/test-outbound` — the panel's own egress probe.
 *  Distinct from the generated `OutboundTestResult` in `@/api/types`, which
 *  belongs to `/outbounds/{id}/test`; the two endpoints answer different
 *  questions and the names must not be confusable. */
interface XrayEgressTestResult {
  ok: boolean;
  status: number;
  latency_ms: number;
  /** Exit IP the probe endpoint saw — null when its reply carried no IP. */
  exit_ip?: string | null;
  /** Country code, only Cloudflare's trace block reports one. */
  exit_loc?: string | null;
  error?: string;
}

export function XraySection({
  onDirtyChange,
}: {
  onDirtyChange: (h: DirtyHandle | null) => void;
}) {
  const { t } = useTranslation();
  const { message, modal } = App.useApp();
  const qc = useQueryClient();
  const [form] = Form.useForm<XrayFormValues>();
  const [dirty, setDirty] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<XrayEgressTestResult | null>(null);
  const [xrayTab, setXrayTab] = useState<XrayTab>('basic');

  const settingsQuery = useQuery<PanelSettings>({
    queryKey: ['panel-settings'],
    queryFn: async () => (await apiClient.get<PanelSettings>('/settings/panel')).data,
  });

  const mutation = useMutation({
    mutationFn: async (values: XrayFormValues) => {
      // PUT replaces the whole row; mergePanelSettings forwards the panel /
      // subscription fields from the cache so saving xray doesn't reset them.
      // Read the cache at SEND time, not from the render closure: with two
      // sections dirty, the second save would otherwise merge a snapshot
      // taken before the first one landed and revert its fields.
      const current =
        qc.getQueryData<PanelSettings>(['panel-settings']) ?? settingsQuery.data;
      // The response says whether the LIVE router actually took the rules —
      // the row is saved either way, so a save that didn't reach xray still
      // succeeds at the HTTP level and would otherwise look like it worked.
      const res = await apiClient.put<RoutingApplyResult>(
        '/settings/panel',
        mergePanelSettings(current, {
          xray_freedom_strategy: values.xray_freedom_strategy,
          xray_routing_strategy: values.xray_routing_strategy,
          xray_freedom_allow_private: values.xray_freedom_allow_private,
          xray_freedom_block_delay: values.xray_freedom_block_delay,
          xray_test_url: values.xray_test_url,
          xray_block_bittorrent: values.xray_block_bittorrent,
          xray_blocked_ips: values.xray_blocked_ips,
          xray_blocked_domains: values.xray_blocked_domains,
          xray_direct_ips: values.xray_direct_ips,
          xray_direct_domains: values.xray_direct_domains,
          xray_ipv4_domains: values.xray_ipv4_domains,
          xray_dns_servers: values.xray_dns_servers,
          xray_dns_hosts: values.xray_dns_hosts,
          xray_dns_query_strategy: values.xray_dns_query_strategy,
          xray_dns_client_ip: values.xray_dns_client_ip,
          xray_dns_tag: values.xray_dns_tag,
          xray_dns_disable_cache: values.xray_dns_disable_cache,
          xray_dns_disable_fallback: values.xray_dns_disable_fallback,
          xray_dns_disable_fallback_if_match: values.xray_dns_disable_fallback_if_match,
          xray_dns_parallel_query: values.xray_dns_parallel_query,
          xray_dns_use_system_hosts: values.xray_dns_use_system_hosts,
          xray_dns_serve_stale: values.xray_dns_serve_stale,
          xray_dns_serve_expired_ttl: values.xray_dns_serve_expired_ttl,
          xray_custom_rules: values.xray_custom_rules,
          xray_rule_order: values.xray_rule_order,
        }),
      );
      return { values, routing: res.data ?? {} };
    },
    onSuccess: ({ values, routing }) => {
      // Two different kinds of xray-affecting field, and they must not share a
      // prompt. The rule fields are pushed into the LIVE router by the save
      // itself (the backend's `routing_fields_changed` gate covers exactly the
      // six below), so asking for a restart there would drop every connection
      // to apply what is already applied. The strategies live in the config
      // file and genuinely only take effect on the next load.
      const old = settingsQuery.data;
      const sameList = (a: string[], b: string[] | undefined) =>
        JSON.stringify(a) === JSON.stringify(b ?? []);
      const restartNeeded =
        old != null &&
        (values.xray_freedom_strategy !== old.xray_freedom_strategy ||
          values.xray_routing_strategy !== old.xray_routing_strategy ||
          // Lives on the `direct` outbound, which only the bootstrap writes.
          !sameList(values.xray_freedom_allow_private, old.xray_freedom_allow_private) ||
          values.xray_freedom_block_delay !== old.xray_freedom_block_delay ||
          // The core exposes no DNS service on its gRPC API, so every field of
          // the resolver lives in the config file only until the next load.
          JSON.stringify(values.xray_dns_servers) !==
            JSON.stringify(old.xray_dns_servers ?? []) ||
          JSON.stringify(values.xray_dns_hosts) !== JSON.stringify(old.xray_dns_hosts ?? []) ||
          values.xray_dns_query_strategy !== old.xray_dns_query_strategy ||
          values.xray_dns_client_ip !== old.xray_dns_client_ip ||
          values.xray_dns_tag !== old.xray_dns_tag ||
          values.xray_dns_disable_cache !== old.xray_dns_disable_cache ||
          values.xray_dns_disable_fallback !== old.xray_dns_disable_fallback ||
          values.xray_dns_disable_fallback_if_match !== old.xray_dns_disable_fallback_if_match ||
          values.xray_dns_parallel_query !== old.xray_dns_parallel_query ||
          values.xray_dns_use_system_hosts !== old.xray_dns_use_system_hosts ||
          values.xray_dns_serve_stale !== old.xray_dns_serve_stale ||
          values.xray_dns_serve_expired_ttl !== old.xray_dns_serve_expired_ttl);
      const appliedLive =
        old != null &&
        (values.xray_block_bittorrent !== old.xray_block_bittorrent ||
          !sameList(values.xray_blocked_ips, old.xray_blocked_ips) ||
          !sameList(values.xray_blocked_domains, old.xray_blocked_domains) ||
          !sameList(values.xray_direct_ips, old.xray_direct_ips) ||
          !sameList(values.xray_direct_domains, old.xray_direct_domains) ||
          !sameList(values.xray_ipv4_domains, old.xray_ipv4_domains) ||
          JSON.stringify(values.xray_custom_rules) !==
            JSON.stringify(old.xray_custom_rules ?? []) ||
          JSON.stringify(values.xray_rule_order) !==
            JSON.stringify(old.xray_rule_order ?? []));
      qc.invalidateQueries({ queryKey: ['panel-settings'] });
      setDirty(false);
      // First and unconditionally: strategy fields and rule fields share this
      // form and this button, so a save can both need a restart and have failed
      // to reach the live router. Reporting only one would drop the message the
      // operator can actually act on.
      const report = reportRouting(routing, message, t);
      // Don't prompt when the backend already bounced xray: it regenerated the
      // config from the DB, so the strategy change came up with it and a second
      // outage would buy nothing.
      if (restartNeeded && !routing.routing_restarted) {
        modal.confirm({
          title: t('settings.xrayRestartTitle'),
          content: t('settings.xrayRestartBody'),
          okText: t('settings.xrayRestartConfirm'),
          cancelText: t('settings.xrayRestartLater'),
          okButtonProps: { danger: true },
          onOk: async () => {
            try {
              await apiClient.post('/xray/restart');
              message.success(t('settings.xrayRestarted'));
            } catch (err: unknown) {
              message.error(apiErrorMessage(err) ?? t('settings.xrayRestartError'));
            }
          },
        });
      } else if (report === 'clean') {
        // Only claim success when the reporter didn't already say otherwise —
        // it owns both the not-live warning and the restart notice.
        message.success(
          appliedLive ? t('settings.xrayRoutingApplied') : t('settings.panelSaved'),
        );
      }
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('settings.panelSaveError')),
  });

  // Publishes this section's dirty state to the page-level bar.
  useSectionDirtyPublish({ dirty, setDirty, form, mutation, onDirtyChange, qc });

  // "Test outbound": the server fetches the current URL field value through
  // its own egress (the same path xray's freedom outbound uses) and reports
  // the HTTP status + latency. Reads the live form value so it works before
  // the operator saves.
  const runTest = useCallback(async () => {
    const url = String(form.getFieldValue('xray_test_url') ?? '').trim();
    if (!url) {
      message.warning(t('settings.xrayTestEmpty'));
      return;
    }
    setTesting(true);
    setTestResult(null);
    try {
      const { data } = await apiClient.post<XrayEgressTestResult>(
        '/xray/test-outbound',
        { url },
      );
      setTestResult(data);
      if (data.ok) {
        // The exit IP is the point of the probe, so lead the toast with it when
        // the endpoint returned one; a URL whose reply carries no IP still gets
        // the plain status/latency line.
        const exit = [data.exit_ip, data.exit_loc].filter(Boolean).join(' · ');
        message.success(
          exit
            ? t('settings.xrayTestOkIp', {
                exit,
                status: data.status,
                ms: data.latency_ms,
              })
            : t('settings.xrayTestOk', {
                status: data.status,
                ms: data.latency_ms,
              }),
        );
      } else {
        message.error(
          t('settings.xrayTestFail', {
            status: data.status,
            error: data.error ?? '',
          }),
        );
      }
    } catch (err: unknown) {
      const error = apiErrorMessage(err) ?? t('settings.xrayTestError');
      setTestResult({ ok: false, status: 0, latency_ms: 0, error });
      message.error(error);
    } finally {
      setTesting(false);
    }
  }, [form, message, t]);

  const data = settingsQuery.data;
  const state = useLoadState([settingsQuery]);
  const xrayBaseline = useMemo(
    () => (data ? {
            xray_freedom_strategy: data.xray_freedom_strategy,
            xray_routing_strategy: data.xray_routing_strategy,
            xray_freedom_allow_private: data.xray_freedom_allow_private ?? [],
            xray_freedom_block_delay: data.xray_freedom_block_delay ?? '',
            xray_test_url: data.xray_test_url,
            xray_block_bittorrent: data.xray_block_bittorrent,
            xray_blocked_ips: data.xray_blocked_ips,
            xray_blocked_domains: data.xray_blocked_domains,
            xray_direct_ips: data.xray_direct_ips,
            xray_direct_domains: data.xray_direct_domains,
            xray_ipv4_domains: data.xray_ipv4_domains,
            xray_dns_servers: data.xray_dns_servers ?? [],
            xray_dns_hosts: data.xray_dns_hosts ?? [],
            xray_dns_query_strategy: data.xray_dns_query_strategy || 'UseIP',
            xray_dns_client_ip: data.xray_dns_client_ip ?? '',
            xray_dns_tag: data.xray_dns_tag ?? '',
            xray_dns_disable_cache: data.xray_dns_disable_cache ?? false,
            xray_dns_disable_fallback: data.xray_dns_disable_fallback ?? false,
            xray_dns_disable_fallback_if_match: data.xray_dns_disable_fallback_if_match ?? false,
            xray_dns_parallel_query: data.xray_dns_parallel_query ?? false,
            xray_dns_use_system_hosts: data.xray_dns_use_system_hosts ?? false,
            xray_dns_serve_stale: data.xray_dns_serve_stale ?? false,
            xray_dns_serve_expired_ttl: data.xray_dns_serve_expired_ttl ?? 0,
            xray_custom_rules: data.xray_custom_rules ?? [],
            xray_rule_order: data.xray_rule_order ?? [],
          } : {}),
    [data],
  );
  return (
    <SectionFrame title={t('settings.xraySection')}>
      <LoadError state={state} />
      <LoadStale state={state} />
      {data && (
        <Form<XrayFormValues>
          form={form}
          layout="vertical"
          autoComplete="off"
          key={JSON.stringify([
            data.xray_freedom_strategy,
            data.xray_routing_strategy,
            data.xray_freedom_allow_private ?? [],
            data.xray_freedom_block_delay ?? '',
            data.xray_test_url,
            data.xray_block_bittorrent,
            data.xray_blocked_ips,
            data.xray_blocked_domains,
            data.xray_direct_ips,
            data.xray_direct_domains,
            data.xray_ipv4_domains,
            data.xray_dns_servers ?? [],
            data.xray_dns_hosts ?? [],
            data.xray_dns_query_strategy,
            data.xray_dns_client_ip,
            data.xray_dns_tag,
            data.xray_dns_disable_cache,
            data.xray_dns_disable_fallback,
            data.xray_dns_disable_fallback_if_match,
            data.xray_dns_parallel_query,
            data.xray_dns_use_system_hosts,
            data.xray_dns_serve_stale,
            data.xray_dns_serve_expired_ttl,
            data.xray_custom_rules ?? [],
            data.xray_rule_order ?? [],
          ])}
          initialValues={xrayBaseline}
          disabled={mutation.isPending}
          onValuesChange={() =>
            setDirty(differsFromSaved(form.getFieldsValue(true), xrayBaseline))
          }
          onFinish={(v) => mutation.mutate(v)}
        >
          <Tabs
            className="xray-tabs app-settings-tabs"
            activeKey={xrayTab}
            onChange={(k) => setXrayTab(k as XrayTab)}
            items={[
              {
                key: 'basic',
                // forceRender keeps every tab's fields mounted in the form even
                // while another tab is shown — otherwise antd lazy-mounts panes
                // and an unvisited tab's fields drop out of the submit payload.
                forceRender: true,
                label: t('settings.xrayTabBasic'),
                icon: <ControlOutlined />,
                children: (
                  <FieldGroup title={t('settings.xrayGroupBasic')}>
                    <Form.Item
                      name="xray_freedom_strategy"
                      label={
                        <FieldLabel
                          title={t('settings.xrayFreedomStrategy')}
                          desc={t('settings.xrayFreedomStrategyHint')}
                        />
                      }
                    >
                      <Select options={FREEDOM_STRATEGY_OPTIONS} />
                    </Form.Item>
                    {/* Sits with Freedom rather than among the routing lists
                        because it is a property of that outbound and, like the
                        strategy above it, only reaches xray on the next
                        restart — the routing lists are pushed into the live
                        router instead, and mixing the two rhythms in one group
                        made "saved" mean two different things. */}
                    <Form.Item
                      name="xray_freedom_allow_private"
                      label={
                        <FieldLabel
                          title={t('settings.xrayFreedomAllowPrivate')}
                          desc={t('settings.xrayFreedomAllowPrivateHint')}
                        />
                      }
                    >
                      <Select
                        mode="tags"
                        options={PRIVATE_ALLOW_PRESETS}
                        showSearch={{ optionFilterProp: 'label' }}
                        tokenSeparators={[',', ' ']}
                        placeholder={t('settings.xrayFreedomAllowPrivatePlaceholder')}
                      />
                    </Form.Item>
                    {/* Same outbound, same restart-to-apply rhythm, so it sits
                        with the two above rather than near the routing lists. */}
                    <Form.Item
                      name="xray_freedom_block_delay"
                      label={
                        <FieldLabel
                          title={t('settings.xrayFreedomBlockDelay')}
                          desc={t('settings.xrayFreedomBlockDelayHint')}
                        />
                      }
                    >
                      <Input
                        placeholder={t('settings.xrayFreedomBlockDelayPlaceholder')}
                        spellCheck={false}
                      />
                    </Form.Item>
                    <Form.Item
                      name="xray_routing_strategy"
                      label={
                        <FieldLabel
                          title={t('settings.xrayRoutingStrategy')}
                          desc={t('settings.xrayRoutingStrategyHint')}
                        />
                      }
                    >
                      <Select options={ROUTING_STRATEGY_OPTIONS} />
                    </Form.Item>
                    {/* A closed list, not free text: the exit IP only shows up
                        when the reply is one the backend can read (see
                        TEST_URL_TRACE / TEST_URL_PLAIN). The test action is the
                        icon beside the field — click to run, then it recolours
                        by result, with status / latency / exit IP in its
                        tooltip. The detailed toast still fires on click. */}
                    <Form.Item
                      name="xray_test_url"
                      className="app-field-testurl"
                      label={
                        <FieldLabel
                          title={t('settings.xrayTestUrl')}
                          desc={t('settings.xrayTestUrlHint')}
                        />
                      }
                    >
                      <Select
                        popupMatchSelectWidth={false}
                        options={[
                          {
                            label: t('settings.xrayTestGroupTrace'),
                            options: TEST_URL_TRACE.map((value) => ({
                              value,
                              label: hostOf(value),
                            })),
                          },
                          {
                            label: t('settings.xrayTestGroupPlain'),
                            options: TEST_URL_PLAIN.map((value) => ({
                              value,
                              label: hostOf(value),
                            })),
                          },
                        ]}
                        suffixIcon={
                          <span className="app-testurl-suffix">
                          <Tooltip
                            // Force the tooltip shut while a test runs. Clicking
                            // the icon with the result tooltip open would swap its
                            // text and reposition the *open* popup, briefly
                            // overflowing for one frame (a scrollbar flash / jerk).
                            // Hiding it during the test skips that reposition; a
                            // fresh show afterwards positions cleanly on its own.
                            open={testing ? false : undefined}
                            title={
                              testResult
                                ? testResult.ok
                                  ? [
                                      `${testResult.status} · ${testResult.latency_ms} ms`,
                                      testResult.exit_ip,
                                      testResult.exit_loc,
                                    ]
                                      .filter(Boolean)
                                      .join(' · ')
                                  : testResult.status
                                    ? `HTTP ${testResult.status}`
                                    : (testResult.error ??
                                      t('settings.xrayTestError'))
                                : t('settings.xrayTestRun')
                            }
                          >
                            <span
                              role="button"
                              aria-label={t('settings.xrayTestRun')}
                              // Don't let the icon steal focus into the URL input
                              // on click — focusing a partly-scrolled field makes
                              // the browser scroll it into view, jerking the modal.
                              onMouseDown={(e) => e.preventDefault()}
                              onClick={(e) => {
                                e.stopPropagation();
                                if (!testing) runTest();
                              }}
                              style={{
                                cursor: testing ? 'default' : 'pointer',
                                display: 'inline-flex',
                                fontSize: 16,
                              }}
                            >
                              {testing ? (
                                <LoadingOutlined />
                              ) : testResult ? (
                                testResult.ok ? (
                                  <CheckOutlined style={{ color: '#52c41a' }} />
                                ) : (
                                  <CloseOutlined style={{ color: '#ff4d4f' }} />
                                )
                              ) : (
                                <CheckOutlined style={{ opacity: 0.45 }} />
                              )}
                            </span>
                          </Tooltip>
                          {/* Keep a chevron so the field still reads as a list.
                              It is inert (see CSS): the click falls through to
                              the selector, which opens the dropdown. */}
                          <DownOutlined className="app-testurl-chevron" />
                          </span>
                        }
                      />
                    </Form.Item>
                  </FieldGroup>
                ),
              },
              {
                key: 'routing',
                forceRender: true,
                label: t('settings.xrayTabRouting'),
                icon: <BranchesOutlined />,
                children: (
                  <>
                  <FieldGroup
                    title={t('settings.xrayGroupRouting')}
                    sub={t('settings.hoverForHint')}
                    className="app-rt-dense"
                  >
                    <Form.Item
                      name="xray_block_bittorrent"
                      className="app-field-switch"
                      label={
                        <FieldLabel
                          title={t('settings.xrayBlockBittorrent')}
                          hint={t('settings.xrayBlockBittorrentHint')}
                        />
                      }
                      valuePropName="checked"
                    >
                      <RowSwitch />
                    </Form.Item>
                    <Form.Item
                      name="xray_blocked_ips"
                      label={
                        <FieldLabel
                          title={t('settings.xrayBlockedIps')}
                          hint={t('settings.xrayBlockedIpsHint')}
                        />
                      }
                    >
                      <Select
                        mode="tags"
                        options={GEOIP_PRESETS}
                        showSearch={{ optionFilterProp: 'label' }}
                        optionRender={renderGeoOption}
                        tagRender={renderGeoTag}
                        tokenSeparators={[',', ' ']}
                        placeholder={t('settings.xrayGeoIpPlaceholder')}
                      />
                    </Form.Item>
                    <Form.Item
                      name="xray_blocked_domains"
                      label={
                        <FieldLabel
                          title={t('settings.xrayBlockedDomains')}
                          hint={t('settings.xrayBlockedDomainsHint')}
                        />
                      }
                    >
                      <Select
                        mode="tags"
                        options={GEOSITE_PRESETS}
                        showSearch={{ optionFilterProp: 'label' }}
                        optionRender={renderGeoOption}
                        tagRender={renderGeoTag}
                        tokenSeparators={[',', ' ']}
                        placeholder={t('settings.xrayGeoSitePlaceholder')}
                      />
                    </Form.Item>
                    {/* The mirror of the two lists above: same matcher syntax
                        and the same presets, opposite destination. Placed
                        between them and the IPv4 list because that is the order
                        the rules are evaluated in — block first, then bypass. */}
                    <Form.Item
                      name="xray_direct_ips"
                      label={
                        <FieldLabel
                          title={t('settings.xrayDirectIps')}
                          hint={t('settings.xrayDirectIpsHint')}
                        />
                      }
                    >
                      <Select
                        mode="tags"
                        options={GEOIP_PRESETS}
                        showSearch={{ optionFilterProp: 'label' }}
                        optionRender={renderGeoOption}
                        tagRender={renderGeoTag}
                        tokenSeparators={[',', ' ']}
                        placeholder={t('settings.xrayGeoIpPlaceholder')}
                      />
                    </Form.Item>
                    <Form.Item
                      name="xray_direct_domains"
                      label={
                        <FieldLabel
                          title={t('settings.xrayDirectDomains')}
                          hint={t('settings.xrayDirectDomainsHint')}
                        />
                      }
                    >
                      <Select
                        mode="tags"
                        options={GEOSITE_PRESETS}
                        showSearch={{ optionFilterProp: 'label' }}
                        optionRender={renderGeoOption}
                        tagRender={renderGeoTag}
                        tokenSeparators={[',', ' ']}
                        placeholder={t('settings.xrayGeoSitePlaceholder')}
                      />
                    </Form.Item>
                    <Form.Item
                      name="xray_ipv4_domains"
                      label={
                        <FieldLabel
                          title={t('settings.xrayIpv4Domains')}
                          hint={t('settings.xrayIpv4DomainsHint')}
                        />
                      }
                    >
                      <Select
                        mode="tags"
                        open={false}
                        tokenSeparators={[',', ' ']}
                        placeholder={t('settings.xrayListPlaceholder')}
                        // Same chip renderer as the two lists above it. Without
                        // it antd draws its own chip, 27.6px against their 21px,
                        // so one field in the group wrapped on a different pitch
                        // and clipped its last row against the shared height cap.
                        tagRender={renderGeoTag}
                      />
                    </Form.Item>
                  </FieldGroup>
                  {/* Where it went. These four lists are what the built-in
                      rules are made of, so an operator editing them is the one
                      most likely to look for the order here. */}
                  <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>
                    {t('settings.rulesMovedHint')}
                  </Typography.Text>
                  {/* The table moved to its own page in the sidebar. Both
                      fields stay registered here, hidden: they carry
                      `#[serde(default)]` on the backend, so a settings save
                      that omitted them would write an empty list over whatever
                      the operator had — the rules would vanish on the next save
                      of an unrelated field. Registered and untouched, they
                      round-trip. */}
                  <Form.Item name="xray_custom_rules" hidden>
                    <HiddenField />
                  </Form.Item>
                  <Form.Item name="xray_rule_order" hidden>
                    <HiddenField />
                  </Form.Item>
                  </>
                ),
              },
              {
                key: 'dns',
                forceRender: true,
                label: t('settings.xrayTabDns'),
                icon: <GlobalOutlined />,
                // The DNS tab's "поставить UseIP" button writes a field this
                // tab owns, and `setFieldValue` updates antd's store without
                // firing `onValuesChange` — so the fix landed and the save bar
                // never appeared. Same recompute, reached directly.
                children: (
                  <DnsTab
                    onExternalChange={() =>
                      setDirty(differsFromSaved(form.getFieldsValue(true), xrayBaseline))
                    }
                  />
                ),
              },
            ]}
          />
        </Form>
      )}
    </SectionFrame>
  );
}
