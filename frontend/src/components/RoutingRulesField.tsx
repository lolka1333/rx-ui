//! Custom routing-rules editor for the Xray "Routing" settings tab.
//!
//! Renders below the "Basic connections" block as an ordered list of
//! user rules (first-match-wins, evaluated top-to-bottom *after* the
//! built-in api/block/ipv4 rules). Each rule is a compact surface row:
//! a numbered spine — the list is the evaluation order, first match wins — with
//! each rule as name + condition tags beneath, then target tag · switch · ⋮.
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
import {
  BUILTIN_OUTBOUND_TAGS,
  needsIpv4,
  type BuiltinOutboundTag,
} from '@/lib/builtinOutbounds';
import { GEOIP_PRESETS, GEOSITE_PRESETS } from '@/lib/geoPresets';
import { uuid } from '@/lib/id';
import type {
  Client,
  CustomOutbound,
  Inbound,
  RoutingRule,
  SystemToken,
} from '@/api/types';
// Reuse the inbound editor's form widgets so this modal matches the rest of
// the panel — compact 12px field spacing, pill ChipGroups, and the collapsible
// Section header used across the app's forms.
import { ChipGroup, Section } from '@/pages/Inbounds/widgets';

/** Colour per built-in target — antd's themed success/error/processing
 *  families, the same green/red/blue as elsewhere. Keyed by the shared tag
 *  union, so a built-in added there fails the build until it gets a colour. */
const TARGET_COLORS: Record<BuiltinOutboundTag, string> = {
  direct: 'success',
  blocked: 'error',
  'direct-ipv4': 'processing',
};

/** Targets a rule can route to, in the order the backend emits them.
 *  `direct-ipv4` only exists once an IPv4-force domain (or a rule targeting it)
 *  is configured — the backend grows that outbound on demand.
 *  Keep in sync with the backend's `VALID_RULE_TARGETS` (api/settings.rs). */
const TARGETS = BUILTIN_OUTBOUND_TAGS.map((value) => ({
  value,
  color: TARGET_COLORS[value],
}));

const targetColor = (tag: string): string =>
  TARGETS.find((tg) => tg.value === tag)?.color ?? 'default';

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

/** One kind of matcher plus its values, for the row summary. */
interface CondGroup {
  /** i18n key of the matcher's own field label, reused from the edit modal. */
  key: string;
  items: string[];
}

/**
 * A rule's conditions, grouped by matcher kind.
 *
 * The row used to flatten all nine matcher kinds into one undifferentiated
 * chip list, where `geosite:category-ru` (a domain) and `xhttp-via-de2` (an
 * inbound) looked identical and only the token syntax hinted at which was
 * which — and a bare `example.com`, a user email and a network name were
 * genuinely indistinguishable. Naming the kind is the information the row was
 * missing, and the row has the width to carry it.
 */
function summarizeGroups(rule: RoutingRule): CondGroup[] {
  const groups: CondGroup[] = [
    { key: 'settings.ruleDomain', items: rule.domain },
    { key: 'settings.ruleIp', items: rule.ip },
    { key: 'settings.ruleSourceIp', items: rule.source_ip },
    { key: 'settings.rulePort', items: rule.port ? [rule.port] : [] },
    { key: 'settings.ruleSourcePort', items: rule.source_port ? [rule.source_port] : [] },
    { key: 'settings.ruleNetwork', items: rule.network },
    { key: 'settings.ruleProtocol', items: rule.protocol },
    { key: 'settings.ruleInboundTag', items: rule.inbound_tag },
    { key: 'settings.ruleUser', items: rule.user },
  ];
  return groups.filter((g) => g.items.length > 0);
}

/** Flat count of a rule's conditions — drives the overflow pill. */
const condCount = (groups: CondGroup[]): number =>
  groups.reduce((n, g) => n + g.items.length, 0);

/** Grouped condition list for the overflow / phone popovers — same kind
 *  labels as the row, so the two read alike. */
function GroupList({
  groups,
  t,
}: {
  groups: CondGroup[];
  t: (k: string) => string;
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 320 }}>
      {groups.map((g) => (
        <div key={g.key}>
          <div style={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: '0.04em', opacity: 0.6, marginBottom: 4 }}>
            {t(g.key)}
          </div>
          <Space size={[6, 6]} wrap>
            {g.items.map((c) => (
              <Tag key={c} style={{ margin: 0 }}>
                {c}
              </Tag>
            ))}
          </Space>
        </div>
      ))}
    </div>
  );
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
  // How many condition chips ride inline before the rest collapse into "+N".
  // It used to be a flat 2, which hid most of a rule's matchers behind a
  // popover while the row sat half empty. The row is now capped (see the
  // wrapper below), so this is a flat budget too rather than one tied to the
  // viewport: ~500px of the 780px row is left for labelled chips, which fits
  // about four.
  const inlineConds = isMobile ? 2 : 4;
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
        new Set(clients.map((c) => c.reverse_tag?.trim()).filter((tag): tag is string => !!tag)),
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
  // `direct-ipv4` is a grown-on-demand built-in. Don't offer it as a target
  // before it exists — a rule can't route to an outbound the config won't
  // emit yet; listing an IPv4 domain is the way to bring it into being.
  const ipv4Live = needsIpv4(sysIpv4, rules);
  const targetOptions = useMemo(
    () => [
      ...TARGETS.filter((tg) => tg.value !== 'direct-ipv4' || ipv4Live).map((tg) => ({
        value: tg.value,
        label: tg.value,
      })),
      ...customTags.map((tag) => ({ value: tag, label: tag })),
      ...reverseTags.map((tag) => ({ value: tag, label: t('reverse.tunnelTargetLabel', { tag }) })),
    ],
    [customTags, reverseTags, ipv4Live, t],
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
  // own control traffic and cut the channel needed to undo that.
  //
  // The table below is keyed by `SystemToken`, the union ts-rs generates from
  // the backend's own enum (xray/config_gen.rs). That is what keeps the two
  // sides together: add a token there and this file stops compiling until the
  // row it needs is written, and `isSystemToken` below reads its membership
  // off the same table rather than a second hand-written list.
  const sysInfo: Record<SystemToken, { label: string; target: string }> = {
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
  // A token in the evaluation order is either a system row or a custom rule id;
  // this is what tells them apart, and it narrows the type so `sysInfo[tok]` is
  // a lookup the compiler can check rather than an index into `any`.
  const isSystemToken = (tok: string): tok is SystemToken => tok in sysInfo;
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
    if (isSystemToken(tok)) insertAt = idx + 1;
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

  // Persist the custom-rule set, marking the form dirty (setFieldsValue alone
  // won't fire onValuesChange, so bounce the bound value through onChange every
  // time).
  //
  // The order is written ONLY when the caller actually reordered something.
  // `order` above is the DERIVED list — it carries the system tokens (api,
  // bittorrent, ipv4) that the stored `xray_rule_order` may not — so writing it
  // on every interaction left the form permanently dirty: flipping a rule's
  // switch rewrote the order field, and flipping it back restored `enabled` but
  // never the field, so the unsaved-changes bar could not be cleared without a
  // save or a discard.
  const apply = (nextRules: RoutingRule[], nextOrder?: string[]) => {
    if (nextOrder) parentForm.setFieldsValue({ xray_rule_order: nextOrder });
    onChange?.(nextRules);
  };
  const moveToken = (from: number, to: number) => {
    if (from === to || from < 0 || to < 0 || from >= order.length || to >= order.length) return;
    const next = order.slice();
    const [moved] = next.splice(from, 1);
    next.splice(to, 0, moved);
    apply(rules.slice(), next);
  };
  // Flipping a switch is not a reorder — leave the order field alone.
  const toggleId = (id: string) =>
    apply(rules.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)));
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
      // Editing a rule in place leaves the evaluation order untouched.
      apply(rules.map((r) => (r.id === rule.id ? rule : r)));
    } else {
      // A new rule genuinely extends the order, so it has to be written.
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

  // The list IS the evaluation order — rules are tried top to bottom and the
  // first match wins — but nothing said so, which is what made a plain stack of
  // rows feel arbitrary (and left the drag handle unexplained). A numbered
  // spine down the left says it, and it uses the width that a single line of
  // conditions could never fill: conditions move to a second line under the
  // name, the way every other settings tab already reads.
  const SPINE_X = 30;
  const rowBase: CSSProperties = {
    position: 'relative',
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    padding: '9px 14px 9px 52px',
  };
  /** Vertical line segment through a row, joining its neighbours' nodes. */
  const spineSeg = (first: boolean, last: boolean): CSSProperties => ({
    position: 'absolute',
    left: SPINE_X,
    top: first ? '50%' : 0,
    bottom: last ? '50%' : 0,
    width: 2,
    background: token.colorBorderSecondary,
    pointerEvents: 'none',
  });
  /** The node on the spine: filled for a live rule, hollow for system rows. */
  const spineNode = (live: boolean): CSSProperties => ({
    position: 'absolute',
    left: SPINE_X - 3,
    top: '50%',
    transform: 'translateY(-50%)',
    width: 8,
    height: 8,
    borderRadius: '50%',
    background: live ? token.colorPrimary : token.colorTextQuaternary,
    boxShadow: `0 0 0 3px ${token.colorBgElevated}`,
    pointerEvents: 'none',
  });
  /** Evaluation position, sitting left of the spine. */
  const ordStyle: CSSProperties = {
    position: 'absolute',
    left: 0,
    width: SPINE_X - 9,
    top: '50%',
    transform: 'translateY(-50%)',
    textAlign: 'right',
    fontSize: 10,
    fontVariantNumeric: 'tabular-nums',
    color: token.colorTextQuaternary,
    pointerEvents: 'none',
  };
  /** Second line of a rule: its conditions, muted under the name. */
  const condRowStyle: CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: 6,
    marginTop: 4,
  };
  const divider = `1px solid ${token.colorSplit}`;
  const iconGrabStyle: CSSProperties = {
    color: token.colorTextQuaternary,
    cursor: 'grab',
    fontSize: 14,
  };
  const iconArrowStyle: CSSProperties = { color: token.colorTextQuaternary, fontSize: 13 };
  // Kind label before each group of condition chips. Quiet and small: it is
  // there to be read when the eye stops on a rule, not to compete with the
  // values themselves.
  const condLabelStyle: CSSProperties = {
    fontSize: 10,
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    color: token.colorTextQuaternary,
    whiteSpace: 'nowrap',
    flexShrink: 0,
  };
  // Trailing controls (switch + ⋮) live in a fixed-width slot. System and
  // default rows have neither, so without a reserved slot their target tag ran
  // ~66px further right than every editable rule's — the target column the rail
  // is there to create was bent by the rows that happen to carry no controls.
  const tailStyle: CSSProperties = {
    flex: 'none',
    width: 52,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'flex-end',
    gap: 9,
  };

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
          // The default row below is always last, so no row in this map ever
          // terminates the spine.
          const spine = (
            <>
              <span style={spineSeg(i === 0, false)} aria-hidden="true" />
              <span style={spineNode(!isSystemToken(tok))} aria-hidden="true" />
              <span style={ordStyle} aria-hidden="true">
                {i + 1}
              </span>
            </>
          );

          // System row — read-only content (edited in "Basic connections"),
          // but reorderable like any other.
          if (isSystemToken(tok)) {
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
                {spine}
                <HolderOutlined
                  style={pinned ? { ...iconGrabStyle, cursor: 'default', opacity: 0.35 } : iconGrabStyle}
                />
                <LockOutlined style={{ color: token.colorTextQuaternary, fontSize: 12 }} />
                {/* A system rule's matchers live in "Basic connections", so
                    there is no second line to show — just its label. */}
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
                <Tag color={colorOf(info.target)} style={{ margin: 0 }}>
                  {info.target}
                </Tag>
                <span style={tailStyle} aria-hidden="true" />
              </div>
            );
          }

          const rule = customById.get(tok);
          if (!rule) return null;
          const groups = summarizeGroups(rule);
          const total = condCount(groups);
          // Fill the row group by group until the inline budget runs out; the
          // remainder collapses into one "+N" pill. Splitting a group across
          // the boundary would leave a labelled kind showing only some of its
          // values with no sign the rest exist, so a group is taken whole or
          // deferred whole.
          const shownGroups: CondGroup[] = [];
          let budget = inlineConds;
          for (const g of groups) {
            if (g.items.length > budget) break;
            shownGroups.push(g);
            budget -= g.items.length;
          }
          const rest = total - condCount(shownGroups);
          const hiddenGroups = groups.slice(shownGroups.length);
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
              {spine}
              <HolderOutlined
                style={iconGrabStyle}
              />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div
                  style={{
                    fontSize: 12.5,
                    fontWeight: 500,
                    whiteSpace: 'nowrap',
                    color: rule.name ? token.colorText : token.colorTextQuaternary,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {/* An unnamed rule still needs a first line, else its
                      conditions read as a continuation of the row above. */}
                  {rule.name || t('settings.rulesUnnamed')}
                </div>
                <div style={condRowStyle}>
                {total === 0 ? (
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
                    content={<GroupList groups={groups} t={t} />}
                  >
                    <Tag
                      style={{ cursor: 'pointer', margin: 0, flexShrink: 0 }}
                      onClick={(e) => e.stopPropagation()}
                    >
                      <FilterOutlined style={{ marginInlineEnd: 4 }} />
                      {total}
                    </Tag>
                  </Popover>
                ) : (
                  <>
                    {shownGroups.map((g) => (
                      <span
                        key={g.key}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 5,
                          minWidth: 0,
                          flexShrink: 1,
                        }}
                      >
                        <span style={condLabelStyle}>{t(g.key)}</span>
                        {g.items.map((c) => (
                          <Tag
                            key={c}
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
                      </span>
                    ))}
                    {rest > 0 && (
                      // "+N" pill — click opens a Popover listing the hidden
                      // conditions, same affordance as the Clients page's inbound
                      // overflow. Click-only (touch double-fires hover+click); stop
                      // propagation so it doesn't reach the draggable row.
                      // flexShrink:0 keeps it visible as the chips shrink.
                      <Popover
                        trigger="click"
                        content={<GroupList groups={hiddenGroups} t={t} />}
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
              </div>
              <Tag color={colorOf(rule.outbound_tag)} style={{ margin: 0 }}>
                {rule.outbound_tag}
              </Tag>
              <span style={tailStyle}>
                <Switch size="small" checked={rule.enabled} onChange={() => toggleId(rule.id)} />
                <Dropdown menu={{ items: menu, onClick: onMenu }} trigger={['click']}>
                  <MoreOutlined
                    style={{ color: token.colorTextSecondary, cursor: 'pointer', fontSize: 16 }}
                  />
                </Dropdown>
              </span>
            </div>
          );
        })}

        {/* The fallback: it matches whatever reached it, so it has no
            conditions of its own — and it always ends the chain, so it is the
            row that terminates the spine. */}
        <div style={{ ...rowBase, borderTop: divider, opacity: 0.6 }}>
          <span style={spineSeg(false, true)} aria-hidden="true" />
          <span style={spineNode(false)} aria-hidden="true" />
          <FlagOutlined style={iconArrowStyle} />
          <span style={{ flex: 1, fontSize: 12.5, color: token.colorTextSecondary }}>
            {t('settings.rulesDefaultLabel')}
          </span>
          <Tag color="success" style={{ margin: 0 }}>
            direct
          </Tag>
          <span style={tailStyle} aria-hidden="true" />
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
      <Form
        className="app-form-rows"
        form={form}
        layout="vertical"
        autoComplete="off"
        onFinish={submit}
      >
        <Form.Item name="name" label={t('settings.ruleName')}>
          <Input placeholder={t('settings.ruleNamePlaceholder')} maxLength={60} />
        </Form.Item>
        <Form.Item
          name="outbound_tag"
          label={t('settings.ruleTarget')}
          rules={[{ required: true, message: t('settings.ruleTargetRequired') }]}
        >
          <Select options={targetOptions} />
        </Form.Item>
        <Form.Item name="domain" label={t('settings.ruleDomain')}>
          <Select
            mode="tags"
            options={GEOSITE_PRESETS}
            optionLabelProp="value"
            showSearch={{ filterOption: (input, option) => presetFilter(input, option?.value, option?.label) }}
            tokenSeparators={[',', ' ']}
            placeholder="geosite:netflix, full:example.com"
          />
        </Form.Item>
        <Form.Item name="ip" label={t('settings.ruleIp')}>
          <Select
            mode="tags"
            options={GEOIP_PRESETS}
            optionLabelProp="value"
            showSearch={{ filterOption: (input, option) => presetFilter(input, option?.value, option?.label) }}
            tokenSeparators={[',', ' ']}
            placeholder="geoip:ru, 10.0.0.0/8"
          />
        </Form.Item>
        <Form.Item name="port" label={t('settings.rulePort')}>
          <Input placeholder="443, 1024-65535" />
        </Form.Item>
        <Form.Item name="network" label={t('settings.ruleNetwork')}>
          <ChipGroup options={NETWORK_OPTIONS} />
        </Form.Item>
        <Form.Item name="protocol" label={t('settings.ruleProtocol')} style={{ marginBottom: 0 }}>
          <ChipGroup options={PROTOCOL_OPTIONS} />
        </Form.Item>

        <Section itemKey="adv" labelKey="settings.ruleAdvanced">
          <Form.Item name="source_ip" label={t('settings.ruleSourceIp')}>
            <Select
              mode="tags"
              options={GEOIP_PRESETS}
              optionLabelProp="value"
              showSearch={{ filterOption: (input, option) => presetFilter(input, option?.value, option?.label) }}
              tokenSeparators={[',', ' ']}
              placeholder="geoip:ru, 10.0.0.0/8"
            />
          </Form.Item>
          <Form.Item
            name="source_port"
            label={t('settings.ruleSourcePort')}
          >
            <Input placeholder="1024-65535" />
          </Form.Item>
          <Form.Item
            name="inbound_tag"
            label={t('settings.ruleInboundTag')}
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
                  fontFamily: 'var(--font-mono)',
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
