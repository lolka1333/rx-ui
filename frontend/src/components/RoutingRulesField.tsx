//! Custom routing-rules editor for the Xray "Routing" settings tab.
//!
//! Renders below the "Basic connections" block as an ordered list of
//! user rules (first-match-wins, evaluated top-to-bottom *after* the
//! built-in api/block/ipv4 rules). Each rule is a compact surface row:
//! drag affordance · condition tags · → target tag · enable switch · ⋮.
//! Edits flow through the parent Xray form (value/onChange), so the
//! page-level dirty bar + save/restart path pick the rules up for free.
//!
//! v1 scope: single `outboundTag` target (direct / blocked / direct-ipv4),
//! the common matchers, reorder via the row menu. No balancers.

import {
  App,
  Button,
  Dropdown,
  Form,
  Grid,
  Input,
  Modal,
  Popover,
  Select,
  Space,
  Switch,
  Tag,
  theme,
} from 'antd';
import type { MenuProps } from 'antd';
import {
  ArrowDownOutlined,
  ArrowRightOutlined,
  ArrowUpOutlined,
  DeleteOutlined,
  EditOutlined,
  FilterOutlined,
  FlagOutlined,
  HolderOutlined,
  LockOutlined,
  MoreOutlined,
  PlusOutlined,
} from '@ant-design/icons';
import { useMemo, useRef, useState, type CSSProperties, type DragEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { uuid } from '@/lib/id';
import type { Client, CustomOutbound, Inbound, RoutingRule } from '@/api/types';
// Reuse the inbound editor's form widgets so this modal matches the rest of
// the panel — compact 12px field spacing, pill ChipGroups, and the collapsible
// Section header used across the app's forms.
import { ChipGroup, Section } from '@/pages/Inbounds/widgets';

/** Targets a rule can route to. Mirrors the outbound tags the backend's
 *  `build_bootstrap_config` emits — `direct-ipv4` only exists when at least
 *  one IPv4-force domain (or one rule targeting it) is configured, so the
 *  backend grows the outbound on demand. Tag colour maps to antd's themed
 *  success/error/processing families (the same green/red/blue as elsewhere).
 *  Keep in sync with the backend's `VALID_RULE_TARGETS` (api/settings.rs). */
const TARGETS: { value: string; color: string }[] = [
  { value: 'direct', color: 'success' },
  { value: 'blocked', color: 'error' },
  { value: 'direct-ipv4', color: 'processing' },
];

const targetColor = (tag: string): string =>
  TARGETS.find((tg) => tg.value === tag)?.color ?? 'default';

/** Friendly presets for the domain / IP tag inputs — a curated slice of the
 *  geosite / geoip vocabulary in the bundled `*.dat`. Labels are short, plain
 *  English (no icons, no i18n): service names are proper nouns and the rest
 *  echo the token meaning ("Ads All", "Private IP"), so they read the same in
 *  any UI language. The dropdown shows the label; the selected chip keeps the
 *  raw token (`optionLabelProp="value"`), matching the row summary + JSON
 *  preview. The inputs stay `mode="tags"`, so any custom matcher (full:,
 *  regexp:, CIDR, ext:…) still works. Every token is verified present in
 *  geosite.dat / geoip.dat. */
const DOMAIN_PRESETS: { value: string; label: string }[] = [
  { value: 'geosite:category-ru', label: 'Russia' },
  { value: 'geosite:private', label: 'Private' },
  { value: 'geosite:category-ads-all', label: 'Ads All' },
  { value: 'geosite:category-porn', label: 'Porn (18+)' },
  { value: 'geosite:google', label: 'Google' },
  { value: 'geosite:youtube', label: 'YouTube' },
  { value: 'geosite:telegram', label: 'Telegram' },
  { value: 'geosite:netflix', label: 'Netflix' },
  { value: 'geosite:openai', label: 'OpenAI' },
  { value: 'geosite:meta', label: 'Meta' },
  { value: 'geosite:twitter', label: 'Twitter / X' },
  { value: 'geosite:tiktok', label: 'TikTok' },
  { value: 'geosite:spotify', label: 'Spotify' },
  { value: 'geosite:steam', label: 'Steam' },
  { value: 'geosite:apple', label: 'Apple' },
  { value: 'geosite:microsoft', label: 'Microsoft' },
  { value: 'geosite:cn', label: 'China' },
];
const IP_PRESETS: { value: string; label: string }[] = [
  { value: 'geoip:ru', label: 'Russia' },
  { value: 'geoip:private', label: 'Private IP' },
  { value: 'geoip:cn', label: 'China' },
  { value: 'geoip:telegram', label: 'Telegram' },
  { value: 'geoip:google', label: 'Google' },
  { value: 'geoip:netflix', label: 'Netflix' },
  { value: 'geoip:twitter', label: 'Twitter / X' },
  { value: 'geoip:facebook', label: 'Facebook' },
  { value: 'geoip:cloudflare', label: 'Cloudflare' },
  { value: 'geoip:us', label: 'USA' },
  { value: 'geoip:de', label: 'Germany' },
  { value: 'geoip:nl', label: 'Netherlands' },
  { value: 'geoip:gb', label: 'UK' },
];

/** Filter a preset Select by both the friendly label and the raw token, so
 *  typing "russia" or "category-ru" both surface the Russia entry. */
const presetFilter = (input: string, value?: unknown, label?: unknown): boolean => {
  const q = input.trim().toLowerCase();
  if (!q) return true;
  const v = typeof value === 'string' ? value.toLowerCase() : '';
  const l = typeof label === 'string' ? label.toLowerCase() : '';
  return v.includes(q) || l.includes(q);
};
const NETWORK_OPTIONS = ['tcp', 'udp', 'unix'].map((v) => ({ value: v, label: v }));
const PROTOCOL_OPTIONS = ['http', 'tls', 'quic', 'bittorrent', 'dns'].map((v) => ({
  value: v,
  label: v,
}));

interface RuleFormValues {
  name?: string;
  outbound_tag: string;
  domain?: string[];
  ip?: string[];
  port?: string;
  network?: string[];
  protocol?: string[];
  // Advanced matchers.
  source_ip?: string[];
  source_port?: string;
  inbound_tag?: string[];
  user?: string[];
}

const EMPTY_RULE: RoutingRule = {
  id: '',
  enabled: true,
  name: '',
  domain: [],
  ip: [],
  source_ip: [],
  port: '',
  source_port: '',
  network: [],
  protocol: [],
  inbound_tag: [],
  user: [],
  outbound_tag: 'blocked',
};

/** Build the xray routing-rule object the backend would emit — also drives
 *  the live preview so the operator sees exactly what lands in config.json. */
function toXrayRule(v: RuleFormValues): Record<string, unknown> {
  const rule: Record<string, unknown> = { type: 'field' };
  const nonEmpty = (a?: string[]) => (a && a.length ? a : undefined);
  if (nonEmpty(v.domain)) rule.domain = v.domain;
  if (nonEmpty(v.ip)) rule.ip = v.ip;
  if (v.port?.trim()) rule.port = v.port.trim();
  if (nonEmpty(v.network)) rule.network = v.network;
  if (nonEmpty(v.protocol)) rule.protocol = v.protocol;
  if (nonEmpty(v.source_ip)) rule.source = v.source_ip;
  if (v.source_port?.trim()) rule.sourcePort = v.source_port.trim();
  if (nonEmpty(v.inbound_tag)) rule.inboundTag = v.inbound_tag;
  if (nonEmpty(v.user)) rule.user = v.user;
  rule.outboundTag = v.outbound_tag || '';
  return rule;
}

const hasCondition = (v: RuleFormValues): boolean =>
  Boolean(
    v.domain?.length ||
      v.ip?.length ||
      v.port?.trim() ||
      v.network?.length ||
      v.protocol?.length ||
      v.source_ip?.length ||
      v.source_port?.trim() ||
      v.inbound_tag?.length ||
      v.user?.length,
  );

/** Short condition labels for a rule's row summary. */
function summarize(rule: RoutingRule): string[] {
  const out: string[] = [];
  rule.domain.forEach((d) => out.push(d));
  rule.ip.forEach((d) => out.push(d));
  rule.source_ip.forEach((d) => out.push(`src:${d}`));
  if (rule.port) out.push(`port ${rule.port}`);
  if (rule.source_port) out.push(`sport ${rule.source_port}`);
  rule.network.forEach((n) => out.push(n));
  rule.protocol.forEach((p) => out.push(p));
  rule.inbound_tag.forEach((i) => out.push(`in:${i}`));
  rule.user.forEach((u) => out.push(u));
  return out;
}

export function RoutingRulesField({
  value,
  onChange,
}: {
  value?: RoutingRule[];
  onChange?: (v: RoutingRule[]) => void;
}) {
  const { t } = useTranslation();
  const { token } = theme.useToken();
  // Phone layout: collapse each rule's condition chips into one count-pill so
  // the name + a tappable conditions affordance both fit on a narrow row.
  const isMobile = !Grid.useBreakpoint().md;
  const rules = value ?? [];
  // Enabled custom outbound tags become additional rule targets — the backend's
  // `valid_rule_targets` does the same (reserved ∪ enabled outbound tags). A
  // disabled or deleted outbound drops out of the picker; a rule still pointing
  // at it keeps the raw tag (shown, but no longer offered).
  const { data: customOutbounds = [] } = useQuery<CustomOutbound[]>({
    queryKey: ['outbounds'],
    queryFn: async () => (await apiClient.get<CustomOutbound[]>('/outbounds')).data,
  });
  const customTags = useMemo(
    () => customOutbounds.filter((o) => o.enabled).map((o) => o.tag),
    [customOutbounds],
  );
  // Inbound tags + client emails to pre-fill the matcher pickers — the operator
  // usually wants to choose an existing one, not retype it. The Selects stay
  // mode="tags" so free entry (geo / advanced) still works.
  const { data: inbounds = [] } = useQuery<Inbound[]>({
    queryKey: ['inbounds'],
    queryFn: async () => (await apiClient.get<Inbound[]>('/inbounds')).data,
  });
  const { data: clients = [] } = useQuery<Client[]>({
    queryKey: ['clients-global', null],
    queryFn: async () => (await apiClient.get<Client[]>('/clients')).data,
  });
  const inboundTagOptions = useMemo(
    () => inbounds.map((i) => ({ value: i.tag, label: i.tag })),
    [inbounds],
  );
  const userEmailOptions = useMemo(
    () =>
      Array.from(new Set(clients.map((c) => c.email))).map((e) => ({ value: e, label: e })),
    [clients],
  );
  // VLESS Reverse Proxy portal tags: a client's reverse_tag becomes a routing
  // target on this (portal) server once a bridge dials in — offer it alongside
  // the custom outbounds so the operator can route traffic down the tunnel.
  const reverseTags = useMemo(
    () =>
      Array.from(
        new Set(clients.map((c) => c.reverse_tag?.trim()).filter((t): t is string => !!t)),
      ),
    [clients],
  );
  // A live reverse-tunnel target (e.g. the wizard's `portal → <tag>` rule) is a
  // real destination — colour it distinctly so it doesn't read as an orphaned
  // (gray) tag pointing at a deleted outbound.
  const colorOf = (tag: string): string =>
    reverseTags.includes(tag)
      ? 'purple'
      : customTags.includes(tag)
        ? 'geekblue'
        : targetColor(tag);
  // Read the sibling "Basic connections" fields so the built-in rules they
  // generate can be shown read-only above the custom ones — the list then
  // reflects the real first-match-wins order (api → blocks → ipv4 → custom →
  // direct), matching build_bootstrap_config on the backend.
  const parentForm = Form.useFormInstance();
  const sysBittorrent = Form.useWatch('xray_block_bittorrent', parentForm) as boolean | undefined;
  const sysBlockedIps = (Form.useWatch('xray_blocked_ips', parentForm) as string[] | undefined) ?? [];
  const sysBlockedDomains =
    (Form.useWatch('xray_blocked_domains', parentForm) as string[] | undefined) ?? [];
  const sysIpv4 = (Form.useWatch('xray_ipv4_domains', parentForm) as string[] | undefined) ?? [];
  // Full evaluation order as a list of tokens (system keys + custom rule ids).
  const ruleOrder = (Form.useWatch('xray_rule_order', parentForm) as string[] | undefined) ?? [];
  // `direct-ipv4` is a grown-on-demand built-in: it only exists once an IPv4
  // domain is listed OR an enabled rule already targets it (mirrors the
  // Outbounds list + config_gen's `needs_ipv4`). Don't offer it as a target
  // before then — a rule can't route to an outbound the config won't emit yet;
  // the IPv4-domains field is the way to bring it into being.
  const needsIpv4 =
    sysIpv4.length > 0 || rules.some((r) => r.enabled && r.outbound_tag === 'direct-ipv4');
  const targetOptions = useMemo(
    () => [
      ...TARGETS.filter((tg) => tg.value !== 'direct-ipv4' || needsIpv4).map((tg) => ({
        value: tg.value,
        label: tg.value,
      })),
      ...customTags.map((tag) => ({ value: tag, label: tag })),
      ...reverseTags.map((tag) => ({ value: tag, label: t('reverse.tunnelTargetLabel', { tag }) })),
    ],
    [customTags, reverseTags, needsIpv4, t],
  );
  const [modalOpen, setModalOpen] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  // Native drag-reorder for the custom rows (no dnd dependency). The source
  // index lives in a ref so `onDrop` reads the current value regardless of
  // React's render timing; the state mirrors it only to drive the visuals.
  const dragIndexRef = useRef<number | null>(null);
  const [dragIndex, setDragIndex] = useState<number | null>(null);
  const [overIndex, setOverIndex] = useState<number | null>(null);

  // ---- ordering model ----
  // System rows are derived live from "Basic connections"; custom rows live in
  // `value`. The full evaluation order is a list of tokens (system keys +
  // custom ids) on `xray_rule_order`. The block rows are reorderable; the api
  // row is not, and the backend hoists it to the front regardless of what gets
  // saved (`ordered_rule_tokens`) — a rule above it could capture the panel's
  // own control traffic and cut the channel needed to undo that. SYS_KEYS MUST
  // stay in sync with the backend `SYSTEM_TOKENS` (xray/config_gen.rs) — the
  // same reconcile-then-emit runs there over the saved order.
  const SYS_KEYS = ['api', 'bittorrent', 'blocked_domains', 'blocked_ips', 'ipv4'];
  const sysInfo: Record<string, { label: string; target: string }> = {
    api: { label: t('settings.rulesSysApi'), target: 'api' },
    bittorrent: { label: 'BitTorrent', target: 'blocked' },
    blocked_domains: {
      label: `${t('settings.xrayBlockedDomains')} · ${sysBlockedDomains.length}`,
      target: 'blocked',
    },
    blocked_ips: {
      label: `${t('settings.xrayBlockedIps')} · ${sysBlockedIps.length}`,
      target: 'blocked',
    },
    ipv4: { label: `${t('settings.xrayIpv4Domains')} · ${sysIpv4.length}`, target: 'direct-ipv4' },
  };
  const activeSys: string[] = ['api'];
  if (sysBittorrent) activeSys.push('bittorrent');
  if (sysBlockedDomains.length) activeSys.push('blocked_domains');
  if (sysBlockedIps.length) activeSys.push('blocked_ips');
  if (sysIpv4.length) activeSys.push('ipv4');

  const customById = new Map(rules.map((r) => [r.id, r] as const));
  const valid = new Set<string>([...activeSys, ...customById.keys()]);

  // Reconcile the saved order against what currently exists: keep known tokens
  // in place, slot new system rows into the system block, append new custom
  // rows at the end.
  // First occurrence wins, mirroring the backend reconcile: a repeated token
  // would render a phantom duplicate row here while the emitter collapses it,
  // so the list would stop matching what xray evaluates.
  const seenTok = new Set<string>();
  const order = ruleOrder.filter((tok) => {
    if (!valid.has(tok) || seenTok.has(tok)) return false;
    seenTok.add(tok);
    return true;
  });
  let insertAt = 0;
  order.forEach((tok, idx) => {
    if (SYS_KEYS.includes(tok)) insertAt = idx + 1;
  });
  order.splice(insertAt, 0, ...activeSys.filter((k) => !order.includes(k)));
  rules.forEach((r) => {
    if (!order.includes(r.id)) order.push(r.id);
  });
  // Mirror the backend's final step (`ordered_rule_tokens`): the api pin leads
  // whatever was saved. With the dedup above, this list is now the emitted list
  // for every input the backend accepts — including orders stored before the
  // pin became fixed.
  const apiAt = order.indexOf('api');
  if (apiAt > 0) order.unshift(...order.splice(apiAt, 1));

  // Persist the custom-rule set + the full order, marking the form dirty
  // (setFieldsValue alone won't fire onValuesChange, so bounce the bound value
  // through onChange every time).
  const apply = (nextRules: RoutingRule[], nextOrder: string[]) => {
    parentForm.setFieldsValue({ xray_rule_order: nextOrder });
    onChange?.(nextRules);
  };
  const moveToken = (from: number, to: number) => {
    if (from === to || from < 0 || to < 0 || from >= order.length || to >= order.length) return;
    const next = order.slice();
    const [moved] = next.splice(from, 1);
    next.splice(to, 0, moved);
    apply(rules.slice(), next);
  };
  const toggleId = (id: string) =>
    apply(rules.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)), order);
  const deleteId = (id: string) =>
    apply(
      rules.filter((r) => r.id !== id),
      order.filter((tok) => tok !== id),
    );
  const openAdd = () => {
    setEditId(null);
    setModalOpen(true);
  };
  const openEditId = (id: string) => {
    setEditId(id);
    setModalOpen(true);
  };
  const handleSave = (rule: RoutingRule) => {
    if (customById.has(rule.id)) {
      apply(rules.map((r) => (r.id === rule.id ? rule : r)), order);
    } else {
      apply([...rules, rule], [...order, rule.id]);
    }
    setModalOpen(false);
  };

  // Shared native-DnD handlers, keyed by the row's index in `order`.
  const rowDnd = (i: number) => ({
    draggable: true,
    onDragStart: (e: DragEvent) => {
      dragIndexRef.current = i;
      setDragIndex(i);
      e.dataTransfer.effectAllowed = 'move';
      e.dataTransfer.setData('text/plain', String(i));
    },
    onDragOver: (e: DragEvent) => {
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
      if (overIndex !== i) setOverIndex(i);
    },
    onDrop: (e: DragEvent) => {
      e.preventDefault();
      const from = dragIndexRef.current;
      if (from !== null) moveToken(from, i);
      dragIndexRef.current = null;
      setDragIndex(null);
      setOverIndex(null);
    },
    onDragEnd: () => {
      dragIndexRef.current = null;
      setDragIndex(null);
      setOverIndex(null);
    },
  });

  const titleStyle: CSSProperties = {
    fontSize: 11,
    fontWeight: 600,
    letterSpacing: '0.66px',
    textTransform: 'uppercase',
    color: token.colorTextTertiary,
  };

  const rowBase: CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    gap: 9,
    padding: '10px 14px',
  };
  const divider = `1px solid ${token.colorSplit}`;
  const iconGrabStyle: CSSProperties = {
    color: token.colorTextQuaternary,
    cursor: 'grab',
    fontSize: 14,
  };
  const iconArrowStyle: CSSProperties = { color: token.colorTextQuaternary, fontSize: 13 };

  return (
    <div style={{ marginTop: 20 }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 11,
        }}
      >
        <span style={titleStyle}>{t('settings.rulesOrderGroup')}</span>
        <Button type="primary" size="small" icon={<PlusOutlined />} onClick={openAdd}>
          {t('settings.rulesAdd')}
        </Button>
      </div>

      <div
        style={{
          background: token.colorBgElevated,
          border: `1px solid ${token.colorBorderSecondary}`,
          borderRadius: 14,
          overflow: 'hidden',
        }}
      >
        {order.map((tok, i) => {
          const dragging = dragIndex === i;
          const dropTarget = overIndex === i && dragIndex !== null && dragIndex !== i;
          const rowStyle: CSSProperties = {
            ...rowBase,
            borderTop: i === 0 ? undefined : divider,
            boxShadow: dropTarget ? `inset 0 2px 0 ${token.colorPrimary}` : undefined,
          };

          // System row — read-only content (edited in "Basic connections"),
          // but reorderable like any other.
          if (SYS_KEYS.includes(tok)) {
            const info = sysInfo[tok];
            // The api pin is pinned: no drag handle, and the backend puts it
            // first anyway, so offering the gesture would only mislead.
            const pinned = tok === 'api';
            return (
              <div
                key={tok}
                {...(pinned ? {} : rowDnd(i))}
                style={{ ...rowStyle, opacity: dragging && !pinned ? 0.4 : 0.6 }}
              >
                <HolderOutlined
                  style={pinned ? { ...iconGrabStyle, cursor: 'default', opacity: 0.35 } : iconGrabStyle}
                />
                <LockOutlined style={{ color: token.colorTextQuaternary, fontSize: 12 }} />
                <span
                  style={{
                    flex: 1,
                    minWidth: 0,
                    fontSize: 12.5,
                    color: token.colorTextSecondary,
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {info.label}
                </span>
                <ArrowRightOutlined style={iconArrowStyle} />
                <Tag color={colorOf(info.target)} style={{ margin: 0 }}>
                  {info.target}
                </Tag>
              </div>
            );
          }

          const rule = customById.get(tok);
          if (!rule) return null;
          const conds = summarize(rule);
          const shown = conds.slice(0, 2);
          const rest = conds.length - shown.length;
          const menu: MenuProps['items'] = [
            { key: 'edit', icon: <EditOutlined />, label: t('settings.rulesEdit') },
            {
              key: 'up',
              icon: <ArrowUpOutlined />,
              label: t('settings.rulesMoveUp'),
              // Not across the api pin: the backend hoists it back to the front,
              // so the move would only desync this list from what xray evaluates.
              disabled: i === 0 || order[i - 1] === 'api',
            },
            {
              key: 'down',
              icon: <ArrowDownOutlined />,
              label: t('settings.rulesMoveDown'),
              disabled: i === order.length - 1,
            },
            { type: 'divider' },
            { key: 'delete', icon: <DeleteOutlined />, label: t('settings.rulesDelete'), danger: true },
          ];
          const onMenu: MenuProps['onClick'] = ({ key }) => {
            if (key === 'edit') openEditId(rule.id);
            else if (key === 'up') moveToken(i, i - 1);
            else if (key === 'down') moveToken(i, i + 1);
            else if (key === 'delete') deleteId(rule.id);
          };
          return (
            <div
              key={rule.id}
              {...rowDnd(i)}
              style={{ ...rowStyle, opacity: dragging ? 0.4 : rule.enabled ? 1 : 0.5 }}
            >
              <HolderOutlined
                style={iconGrabStyle}
              />
              <div
                style={{
                  flex: 1,
                  minWidth: 0,
                  display: 'flex',
                  gap: 6,
                  alignItems: 'center',
                  flexWrap: 'nowrap',
                  overflow: 'hidden',
                }}
              >
                {rule.name && (
                  <span
                    style={{
                      fontSize: 12.5,
                      fontWeight: 500,
                      whiteSpace: 'nowrap',
                      color: token.colorText,
                      minWidth: 0,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      flexShrink: 1,
                    }}
                  >
                    {rule.name}
                  </span>
                )}
                {conds.length === 0 ? (
                  <span
                    style={{ fontSize: 11.5, color: token.colorTextTertiary, flexShrink: 0 }}
                  >
                    {t('settings.rulesMatchAll')}
                  </span>
                ) : isMobile ? (
                  // Phone: inline chips never fit beside the name, so collapse
                  // every condition into one count-pill → Popover with the full
                  // list. flexShrink:0 keeps it visible however long the name is.
                  <Popover
                    trigger="click"
                    content={
                      <Space size={[6, 6]} wrap style={{ maxWidth: 280 }}>
                        {conds.map((c, k) => (
                          <Tag key={k} style={{ margin: 0 }}>
                            {c}
                          </Tag>
                        ))}
                      </Space>
                    }
                  >
                    <Tag
                      style={{ cursor: 'pointer', margin: 0, flexShrink: 0 }}
                      onClick={(e) => e.stopPropagation()}
                    >
                      <FilterOutlined style={{ marginInlineEnd: 4 }} />
                      {conds.length}
                    </Tag>
                  </Popover>
                ) : (
                  <>
                    {shown.map((c, k) => (
                      <Tag
                        key={k}
                        style={{
                          margin: 0,
                          maxWidth: 180,
                          minWidth: 0,
                          flexShrink: 1,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {c}
                      </Tag>
                    ))}
                    {rest > 0 && (
                      // "+N" pill — click opens a Popover listing the hidden
                      // conditions, same affordance as the Clients page's inbound
                      // overflow. Click-only (touch double-fires hover+click); stop
                      // propagation so it doesn't reach the draggable row.
                      // flexShrink:0 keeps it visible as the chips shrink.
                      <Popover
                        trigger="click"
                        content={
                          <Space size={[6, 6]} wrap style={{ maxWidth: 320 }}>
                            {conds.slice(shown.length).map((c, k) => (
                              <Tag key={k} style={{ margin: 0 }}>
                                {c}
                              </Tag>
                            ))}
                          </Space>
                        }
                      >
                        <Tag
                          style={{ cursor: 'pointer', margin: 0, flexShrink: 0 }}
                          onClick={(e) => e.stopPropagation()}
                        >
                          +{rest}
                        </Tag>
                      </Popover>
                    )}
                  </>
                )}
              </div>
              <ArrowRightOutlined style={iconArrowStyle} />
              <Tag color={colorOf(rule.outbound_tag)} style={{ margin: 0 }}>
                {rule.outbound_tag}
              </Tag>
              <Switch size="small" checked={rule.enabled} onChange={() => toggleId(rule.id)} />
              <Dropdown menu={{ items: menu, onClick: onMenu }} trigger={['click']}>
                <MoreOutlined
                  style={{ color: token.colorTextSecondary, cursor: 'pointer', fontSize: 16 }}
                />
              </Dropdown>
            </div>
          );
        })}

        <div style={{ ...rowBase, borderTop: divider, opacity: 0.6 }}>
          <FlagOutlined style={iconArrowStyle} />
          <span style={{ flex: 1, fontSize: 12.5, color: token.colorTextSecondary }}>
            {t('settings.rulesDefaultLabel')}
          </span>
          <ArrowRightOutlined style={iconArrowStyle} />
          <Tag color="success" style={{ margin: 0 }}>
            direct
          </Tag>
        </div>
      </div>

      <RuleModal
        open={modalOpen}
        initial={editId ? (customById.get(editId) ?? null) : null}
        targetOptions={targetOptions}
        inboundTagOptions={inboundTagOptions}
        userEmailOptions={userEmailOptions}
        onCancel={() => setModalOpen(false)}
        onSave={handleSave}
      />
    </div>
  );
}

function RuleModal({
  open,
  initial,
  targetOptions,
  inboundTagOptions,
  userEmailOptions,
  onCancel,
  onSave,
}: {
  open: boolean;
  initial: RoutingRule | null;
  targetOptions: { value: string; label: string }[];
  inboundTagOptions: { value: string; label: string }[];
  userEmailOptions: { value: string; label: string }[];
  onCancel: () => void;
  onSave: (rule: RoutingRule) => void;
}) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const { token } = theme.useToken();
  const screens = Grid.useBreakpoint();
  const isMobile = !screens.md;
  const [form] = Form.useForm<RuleFormValues>();

  const submit = () => {
    // Read the FULL form state, not just the fields antd passes to onFinish.
    // The "advanced conditions" (source IP/port, inbound tag, user) live in a
    // lazily-mounted <Section> (an antd Collapse) whose children aren't rendered
    // until it's first expanded. onFinish only reports mounted fields, so a rule
    // whose only conditions sit in that still-collapsed section would otherwise
    // validate as "no condition" and drop those values on save. getFieldsValue
    // (true) returns every stored value, mounted or not.
    const v = form.getFieldsValue(true) as RuleFormValues;
    if (!hasCondition(v)) {
      message.warning(t('settings.rulesNeedCondition'));
      return;
    }
    const base = initial ?? EMPTY_RULE;
    onSave({
      ...base,
      id: base.id || uuid(),
      enabled: initial?.enabled ?? true,
      name: (v.name ?? '').trim(),
      domain: v.domain ?? [],
      ip: v.ip ?? [],
      port: (v.port ?? '').trim(),
      source_ip: v.source_ip ?? [],
      source_port: (v.source_port ?? '').trim(),
      network: v.network ?? [],
      protocol: v.protocol ?? [],
      inbound_tag: v.inbound_tag ?? [],
      user: v.user ?? [],
      outbound_tag: v.outbound_tag,
    });
  };

  return (
    <Modal
      open={open}
      title={initial ? t('settings.ruleEditTitle') : t('settings.ruleAddTitle')}
      okText={t('settings.save')}
      cancelText={t('common.cancel')}
      width={isMobile ? '100%' : 540}
      style={isMobile ? { top: 0, maxWidth: '100vw', margin: 0, paddingBottom: 0 } : undefined}
      styles={{
        body: {
          scrollbarGutter: 'stable',
          paddingInline: 12,
          paddingBlock: 4,
          ...(isMobile ? { maxHeight: 'calc(100dvh - 160px)', overflowY: 'auto' } : {}),
        },
      }}
      onCancel={onCancel}
      onOk={() => form.submit()}
      afterOpenChange={(o) => {
        if (o) {
          form.resetFields();
          form.setFieldsValue({
            name: initial?.name ?? '',
            outbound_tag: initial?.outbound_tag ?? 'blocked',
            domain: initial?.domain ?? [],
            ip: initial?.ip ?? [],
            port: initial?.port ?? '',
            network: initial?.network ?? [],
            protocol: initial?.protocol ?? [],
            source_ip: initial?.source_ip ?? [],
            source_port: initial?.source_port ?? '',
            inbound_tag: initial?.inbound_tag ?? [],
            user: initial?.user ?? [],
          });
        }
      }}
      destroyOnHidden
    >
      <Form form={form} layout="vertical" autoComplete="off" onFinish={submit}>
        <Form.Item name="name" label={t('settings.ruleName')} style={{ marginBottom: 12 }}>
          <Input placeholder={t('settings.ruleNamePlaceholder')} maxLength={60} />
        </Form.Item>
        <Form.Item
          name="outbound_tag"
          label={t('settings.ruleTarget')}
          rules={[{ required: true, message: t('settings.ruleTargetRequired') }]}
          style={{ marginBottom: 12 }}
        >
          <Select options={targetOptions} />
        </Form.Item>
        <Form.Item name="domain" label={t('settings.ruleDomain')} style={{ marginBottom: 12 }}>
          <Select
            mode="tags"
            options={DOMAIN_PRESETS}
            optionLabelProp="value"
            showSearch={{ filterOption: (input, option) => presetFilter(input, option?.value, option?.label) }}
            tokenSeparators={[',', ' ']}
            placeholder="geosite:netflix, full:example.com"
          />
        </Form.Item>
        <Form.Item name="ip" label={t('settings.ruleIp')} style={{ marginBottom: 12 }}>
          <Select
            mode="tags"
            options={IP_PRESETS}
            optionLabelProp="value"
            showSearch={{ filterOption: (input, option) => presetFilter(input, option?.value, option?.label) }}
            tokenSeparators={[',', ' ']}
            placeholder="geoip:ru, 10.0.0.0/8"
          />
        </Form.Item>
        <Form.Item name="port" label={t('settings.rulePort')} style={{ marginBottom: 12 }}>
          <Input placeholder="443, 1024-65535" />
        </Form.Item>
        <Form.Item name="network" label={t('settings.ruleNetwork')} style={{ marginBottom: 12 }}>
          <ChipGroup options={NETWORK_OPTIONS} />
        </Form.Item>
        <Form.Item name="protocol" label={t('settings.ruleProtocol')} style={{ marginBottom: 0 }}>
          <ChipGroup options={PROTOCOL_OPTIONS} />
        </Form.Item>

        <Section itemKey="adv" labelKey="settings.ruleAdvanced">
          <Form.Item name="source_ip" label={t('settings.ruleSourceIp')} style={{ marginBottom: 12 }}>
            <Select
              mode="tags"
              options={IP_PRESETS}
              optionLabelProp="value"
              showSearch={{ filterOption: (input, option) => presetFilter(input, option?.value, option?.label) }}
              tokenSeparators={[',', ' ']}
              placeholder="geoip:ru, 10.0.0.0/8"
            />
          </Form.Item>
          <Form.Item
            name="source_port"
            label={t('settings.ruleSourcePort')}
            style={{ marginBottom: 12 }}
          >
            <Input placeholder="1024-65535" />
          </Form.Item>
          <Form.Item
            name="inbound_tag"
            label={t('settings.ruleInboundTag')}
            style={{ marginBottom: 12 }}
          >
            <Select
              mode="tags"
              tokenSeparators={[',', ' ']}
              placeholder="inbound-tag"
              options={inboundTagOptions}
              showSearch={{ optionFilterProp: 'value' }}
            />
          </Form.Item>
          <Form.Item name="user" label={t('settings.ruleUser')} style={{ marginBottom: 0 }}>
            <Select
              mode="tags"
              tokenSeparators={[',', ' ']}
              placeholder="user@email"
              options={userEmailOptions}
              showSearch={{ optionFilterProp: 'value' }}
            />
          </Form.Item>
        </Section>

        <Section itemKey="preview" labelKey="settings.rulePreview">
          <Form.Item noStyle shouldUpdate>
            {() => (
              <pre
                style={{
                  margin: 0,
                  padding: '10px 12px',
                  borderRadius: token.borderRadius,
                  background: token.colorFillTertiary,
                  color: token.colorTextSecondary,
                  fontFamily:
                    "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace",
                  fontSize: 12,
                  lineHeight: 1.6,
                  overflowX: 'auto',
                }}
              >
                {JSON.stringify(toXrayRule(form.getFieldsValue(true)), null, 2)}
              </pre>
            )}
          </Form.Item>
        </Section>
      </Form>
    </Modal>
  );
}
