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
  Tooltip,
  theme,
} from 'antd';
import type { MenuProps } from 'antd';
import {
  ArrowDownOutlined,
  ArrowUpOutlined,
  CloudOutlined,
  DeleteOutlined,
  EditOutlined,
  FilterOutlined,
  FlagOutlined,
  HolderOutlined,
  LockOutlined,
  MoreOutlined,
  PlusOutlined,
} from '@ant-design/icons';
import {
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type DragEvent,
} from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
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
// tcp/udp only, and `unix` is deliberately absent even though xray's own conf
// parser accepts it (`infra/conf/common.go` maps it to Network_UNIX). Client
// traffic through an inbound is never a unix socket, so the rule could not
// match anything — and the backend refuses to store it, because the two config
// paths disagree about what an unknown network means: the JSON emitter keeps it
// as a matcher that never fires, while the proto builder drops it and the rule
// then fires on EVERYTHING. Offering it here only produced rules that could not
// be saved — and, once saved by an older build, blocked every unrelated
// settings save until the rule was fixed.
const NETWORK_OPTIONS = ['tcp', 'udp'].map((v) => ({ value: v, label: v }));
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

/* How many chips fit is a question about the column, not about the viewport: a
   `geosite:category-ads-all` chip is three times the width of a `tcp` one, so a
   budget counted per breakpoint either wastes half the column or squeezes every
   chip into an ellipsis. These estimate a chip from its text — the mono face
   makes that reliable to a few pixels — and the column reports its own width. */
const CHIP_CHAR = 6.7;
const CHIP_PAD = 20;
const CHIP_GAP = 6;
/** Room kept for the "+N" pill, so it is never the thing that gets clipped. */
const OVERFLOW_PILL = 46;
/** Matches the cap in the stylesheet: past it a chip ellipsizes, so the
 *  estimate must stop growing too or the fitting would reserve room the chip
 *  never takes. */
const CHIP_MAX = 280;
const chipWidth = (text: string) => Math.min(text.length * CHIP_CHAR + CHIP_PAD, CHIP_MAX);

/** How many of `items` fit `width`, leaving room for "+N" when some do not. */
function fitChips(items: string[], width: number, reserve = 0): number {
  if (width <= 0) return items.length;
  let used = reserve;
  let n = 0;
  for (const it of items) {
    const w = chipWidth(it) + (n ? CHIP_GAP : 0);
    // The last one may use the pill's reserve: nothing is hidden behind it.
    const avail = width - (n === items.length - 1 ? 0 : OVERFLOW_PILL);
    if (used + w > avail) break;
    used += w;
    n++;
  }
  return Math.max(1, n);
}

/** A flat list of matchers in a table cell: as many as fit the budget, the rest
 *  behind a "+N" that opens the full list. What a system row shows — it has one
 *  kind of matcher, so it needs no per-kind headings. */
function ChipList({ items, budget }: { items: string[]; budget: number }) {
  const shown = items.slice(0, budget);
  const rest = items.length - shown.length;
  return (
    <>
      {shown.map((c) => (
        <Tag key={c}>{c}</Tag>
      ))}
      {rest > 0 && (
        <Popover
          trigger="click"
          content={
            <Space size={[6, 6]} wrap style={{ maxWidth: 320 }}>
              {items.map((c) => (
                <Tag key={c} style={{ margin: 0 }}>
                  {c}
                </Tag>
              ))}
            </Space>
          }
        >
          {/* Click-only, and it must not reach the draggable row underneath. */}
          <Tag style={{ cursor: 'pointer', flexShrink: 0 }} onClick={(e) => e.stopPropagation()}>
            +{rest}
          </Tag>
        </Popover>
      )}
    </>
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
  const { message } = App.useApp();
  const qc = useQueryClient();
  // Phone layout: collapse each rule's condition chips into one count-pill so
  // the name + a tappable conditions affordance both fit on a narrow row.
  const screens = Grid.useBreakpoint();
  const isMobile = !screens.md;
  // The conditions column reports its own width, and the chips are laid out to
  // it (see `fitChips`). A flat budget was written for a row capped at 780px;
  // on a wide monitor it left the widest column mostly empty with the rest of
  // the rule behind a pill nobody clicks, and on a narrow one it squeezed every
  // chip into an ellipsis.
  const condsRef = useRef<HTMLSpanElement>(null);
  const [condsWidth, setCondsWidth] = useState(0);
  useLayoutEffect(() => {
    const el = condsRef.current;
    if (!el) return undefined;
    const measure = () => setCondsWidth(el.getBoundingClientRect().width);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const rules = value ?? [];
  // Enabled custom outbound tags become additional rule targets — the backend's
  // `valid_rule_targets` does the same (reserved ∪ enabled outbound tags). A
  // disabled or deleted outbound drops out of the picker; a rule still pointing
  // at it keeps the raw tag (shown, but no longer offered).
  const { data: customOutbounds = [] } = useQuery<CustomOutbound[]>({
    queryKey: ['outbounds'],
    queryFn: async () => (await apiClient.get<CustomOutbound[]>('/outbounds')).data,
  });
  // Register a Cloudflare WARP tunnel and put it in the outbound list. The
  // panel only does the part the operator cannot — generate the keys and talk
  // to Cloudflare; saving goes through the ordinary whole-list PUT, so the
  // tunnel is validated and applied exactly like a hand-written outbound.
  const [warpOpen, setWarpOpen] = useState(false);
  // Bumped on every opening so the sheet is a fresh component: `destroyOnHidden`
  // clears the dialog's DOM but not the state of the component around it, and a
  // second tunnel must not arrive pre-loaded with the first one's services.
  const [warpKey, setWarpKey] = useState(0);
  const [warpBusy, setWarpBusy] = useState(false);
  /** Register, save the outbound, and — for the services ticked in the sheet —
   *  add one rule that sends them into the new tunnel. */
  const addWarp = async (license: string, services: string[]) => {
    setWarpBusy(true);
    try {
      const { data: warp } = await apiClient.post<CustomOutbound>('/outbounds/warp', {
        license,
      });
      const { data: current } = await apiClient.get<CustomOutbound[]>('/outbounds');
      await apiClient.put('/outbounds', [...current, warp]);
      await qc.invalidateQueries({ queryKey: ['outbounds'] });
      if (services.length > 0) {
        // One rule, not one per service: they all go to the same place, and a
        // rule per service would bury the list under a click. Splitting it
        // later is a chip away; merging six rules back is not.
        const rule: RoutingRule = {
          ...EMPTY_RULE,
          id: uuid(),
          name: t('settings.warpRuleName', { tag: warp.tag }),
          domain: services,
          outbound_tag: warp.tag,
        };
        apply([...rules, rule], [...order, rule.id]);
      }
      setWarpOpen(false);
      message.success(
        services.length > 0
          ? t('settings.warpAddedWithRule', { tag: warp.tag })
          : t('settings.warpAdded', { tag: warp.tag }),
      );
    } catch (e) {
      message.error(apiErrorMessage(e) ?? t('settings.warpFailed'));
    } finally {
      setWarpBusy(false);
    }
  };

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
  const sysDirectIps = (Form.useWatch('xray_direct_ips', parentForm) as string[] | undefined) ?? [];
  const sysDirectDomains =
    (Form.useWatch('xray_direct_domains', parentForm) as string[] | undefined) ?? [];
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
  // `items` is what the row actually matches on. It is shown in the conditions
  // column as chips, the same way a custom rule shows its own — the row used to
  // say "set in the block above", which is true and tells the operator nothing
  // about what is in there. The two rows with no list of their own (the control
  // channel, and BitTorrent, which matches a protocol) keep a short descriptor.
  const sysInfo: Record<SystemToken, { label: string; target: string; items: string[] }> = {
    api: { label: t('settings.rulesSysApi'), target: 'api', items: ['inbound: api'] },
    bittorrent: { label: 'BitTorrent', target: 'blocked', items: ['protocol: bittorrent'] },
    blocked_domains: {
      label: t('settings.xrayBlockedDomains'),
      target: 'blocked',
      items: sysBlockedDomains,
    },
    blocked_ips: {
      label: t('settings.xrayBlockedIps'),
      target: 'blocked',
      items: sysBlockedIps,
    },
    ipv4: { label: t('settings.xrayIpv4Domains'), target: 'direct-ipv4', items: sysIpv4 },
    direct_domains: {
      label: t('settings.xrayDirectDomains'),
      target: 'direct',
      items: sysDirectDomains,
    },
    direct_ips: {
      label: t('settings.xrayDirectIps'),
      target: 'direct',
      items: sysDirectIps,
    },
  };
  // A token in the evaluation order is either a system row or a custom rule id;
  // this is what tells them apart, and it narrows the type so `sysInfo[tok]` is
  // a lookup the compiler can check rather than an index into `any`.
  const isSystemToken = (tok: string): tok is SystemToken => tok in sysInfo;
  const activeSys: string[] = ['api'];
  if (sysBittorrent) activeSys.push('bittorrent');
  if (sysBlockedDomains.length) activeSys.push('blocked_domains');
  if (sysBlockedIps.length) activeSys.push('blocked_ips');
  if (sysDirectDomains.length) activeSys.push('direct_domains');
  if (sysDirectIps.length) activeSys.push('direct_ips');
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

  // The list IS the evaluation order — rules are tried top to bottom and the
  // first match wins. The numbered column says so, and it is the same column
  // you grab to change that order, exactly as in the resolver table: a spine
  // with its own handle column beside it spent two columns of chrome before a
  // row said anything at all.
  //
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
  return (
    <section className="app-rt-section">
      <div className="app-rt-head">
        <span className="app-rt-title">{t('settings.rulesOrderGroup')}</span>
        <span className="app-rt-sub">{t('settings.rulesOrderSub')}</span>
        {/* A rule needs somewhere to send traffic, and this is the one exit a
            server can grow without owning a second server — so it is offered
            here, beside the rules, rather than only on the outbounds page. */}
        <Tooltip title={t('settings.warpHint')}>
          <Button
            size="small"
            icon={<CloudOutlined />}
            onClick={() => {
              setWarpKey((k) => k + 1);
              setWarpOpen(true);
            }}
          >
            {t('settings.warpAdd')}
          </Button>
        </Tooltip>
        {/* Quiet, like the "add" buttons on the DNS tab. As a primary button it
            was the loudest thing on the tab, which put the accent on adding a
            rule rather than on the order the rules are read in. */}
        <Button size="small" icon={<PlusOutlined />} onClick={openAdd}>
          {t('settings.rulesAdd')}
        </Button>
      </div>

      {/* A table, the same one the resolver list is: the numbered spine and its
          separate handle column spent two columns of chrome before a row said
          anything, and the conditions — the part worth reading — got what was
          left. Columns name themselves in a header instead. */}
      <div className="app-rt-table">
        <div className="app-rt-tr app-rt-th">
          <span>№</span>
          <span>{t('settings.rulesColRule')}</span>
          {/* The column measures itself here, once, for every row below it. */}
          <span ref={condsRef}>{t('settings.rulesColConditions')}</span>
          <span>{t('settings.rulesColTarget')}</span>
          <span />
        </div>

        {order.map((tok, i) => {
          const dragging = dragIndex === i;
          const dropTarget = overIndex === i && dragIndex !== null && dragIndex !== i;
          const rowClass = (extra?: string) =>
            [
              'app-rt-tr',
              dragging ? 'is-drag' : '',
              dropTarget ? 'is-over' : '',
              extra ?? '',
            ]
              .filter(Boolean)
              .join(' ');
          /** The rank, which is also the grip — one cell, as in the DNS table. */
          const ord = (grabbable: boolean) => (
            <span className="app-rt-num">
              <span className="app-rt-ord">{i + 1}</span>
              {grabbable && <HolderOutlined className="app-rt-grip" aria-hidden="true" />}
            </span>
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
                className={rowClass('is-sys')}
                {...(pinned ? {} : rowDnd(i))}
              >
                {ord(!pinned)}
                <span className="app-rt-name">
                  <LockOutlined className="app-rt-icon" />
                  <span className="app-rt-label">{info.label}</span>
                </span>
                {/* What the row matches on, in its own words. Edited in the
                    block above — the tooltip on the name says so — but shown
                    here, because "set in the block above" filled the widest
                    column of the table with a sentence about somewhere else. */}
                <div className="app-rt-conds">
                  {info.items.length === 0 ? (
                    <span className="app-rt-muted">{t('settings.rulesSysEmpty')}</span>
                  ) : (
                    <ChipList
                      items={info.items}
                      budget={isMobile ? 1 : fitChips(info.items, condsWidth)}
                    />
                  )}
                </div>
                <Tag color={colorOf(info.target)} style={{ margin: 0 }}>
                  {info.target}
                </Tag>
                <span aria-hidden="true" />
              </div>
            );
          }

          const rule = customById.get(tok);
          if (!rule) return null;
          const groups = summarizeGroups(rule);
          const total = condCount(groups);
          // Fill the row group by group until the column runs out; the
          // remainder collapses into one "+N" pill. Splitting a group across
          // the boundary would leave a labelled kind showing only some of its
          // values with no sign the rest exist, so a group is taken whole or
          // deferred whole — and a group's kind label is part of what it costs.
          const shownGroups: CondGroup[] = [];
          let used = 0;
          for (const g of groups) {
            const cost =
              t(g.key).length * CHIP_CHAR +
              CHIP_GAP * 2 +
              g.items.reduce((s, c) => s + chipWidth(c) + CHIP_GAP, 0);
            const avail = condsWidth - (g === groups[groups.length - 1] ? 0 : OVERFLOW_PILL);
            if (condsWidth > 0 && used + cost > avail) break;
            shownGroups.push(g);
            used += cost;
          }
          // Never collapse to a bare "+N": a row that shows only a count says
          // nothing about the rule it belongs to. When even the first group is
          // too wide, it comes along cut to the chips that fit whole — the
          // pill counts what was left out, so a part-shown group still says
          // there is more. Squeezing the whole group into ellipses instead
          // would spend the same width on `geosi…`, which names nothing.
          if (shownGroups.length === 0 && groups.length > 0) {
            const [first] = groups;
            const room = condsWidth - t(first.key).length * CHIP_CHAR - CHIP_GAP * 2 - OVERFLOW_PILL;
            shownGroups.push({ ...first, items: first.items.slice(0, fitChips(first.items, room)) });
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
              className={rowClass(rule.enabled ? undefined : 'is-off')}
              {...rowDnd(i)}
            >
              {ord(true)}
              <span className={rule.name ? 'app-rt-label' : 'app-rt-label app-rt-muted'}>
                {rule.name || t('settings.rulesUnnamed')}
              </span>
              <div className="app-rt-conds">
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
              <Tag color={colorOf(rule.outbound_tag)} style={{ margin: 0 }}>
                {rule.outbound_tag}
              </Tag>
              <span className="app-rt-tail">
                <Switch size="small" checked={rule.enabled} onChange={() => toggleId(rule.id)} />
                <Dropdown menu={{ items: menu, onClick: onMenu }} trigger={['click']}>
                  <MoreOutlined className="app-rt-more" />
                </Dropdown>
              </span>
            </div>
          );
        })}

        {/* The fallback: it matches whatever reached it, so it has no
            conditions of its own, and it always ends the chain — no rank, and
            no grip, because there is nowhere for it to move. */}
        <div className="app-rt-tr is-sys">
          <span className="app-rt-num" aria-hidden="true" />
          <span className="app-rt-name">
            <FlagOutlined className="app-rt-icon" />
            <span className="app-rt-label">{t('settings.rulesDefaultLabel')}</span>
          </span>
          <span className="app-rt-muted">{t('settings.rulesDefaultConds')}</span>
          <Tag color="success" style={{ margin: 0 }}>
            direct
          </Tag>
          <span aria-hidden="true" />
        </div>
      </div>

      <WarpModal
        key={warpKey}
        open={warpOpen}
        busy={warpBusy}
        onCancel={() => setWarpOpen(false)}
        onCreate={addWarp}
      />

      <RuleModal
        open={modalOpen}
        initial={editId ? (customById.get(editId) ?? null) : null}
        targetOptions={targetOptions}
        inboundTagOptions={inboundTagOptions}
        userEmailOptions={userEmailOptions}
        onCancel={() => setModalOpen(false)}
        onSave={handleSave}
      />
    </section>
  );
}

/** What a WARP tunnel is usually built for: services that answer a datacentre
 *  address with a block page, or not at all. Drawn from the panel's own geosite
 *  presets, so every token here is one the bundled `geosite.dat` carries. */
const WARP_SERVICES = [
  'geosite:openai',
  'geosite:spotify',
  'geosite:netflix',
  'geosite:youtube',
  'geosite:google',
  'geosite:tiktok',
  'geosite:twitter',
  'geosite:telegram',
  'geosite:apple',
  'geosite:microsoft',
].map((value) => ({
  value,
  label: GEOSITE_PRESETS.find((p) => p.value === value)?.label ?? value,
}));

/** The sheet the WARP button opens: the services to point at the tunnel, and
 *  an optional WARP+ key. Both are optional — the plain path is "press create,
 *  get a tunnel".
 *
 *  Two rows of the panel's own field grid, the services first: that is what the
 *  sheet is opened for, while the key is a thing few operators have. The
 *  explanations live in tooltips on the names rather than in paragraphs under
 *  the fields, the way the routing tab reads. */
function WarpModal({
  open,
  busy,
  onCancel,
  onCreate,
}: {
  open: boolean;
  busy: boolean;
  onCancel: () => void;
  onCreate: (license: string, services: string[]) => void;
}) {
  const { t } = useTranslation();
  const [license, setLicense] = useState('');
  const [services, setServices] = useState<string[]>([]);
  return (
    <Modal
      open={open}
      title={t('settings.warpTitle')}
      okText={t('settings.warpCreate')}
      cancelText={t('common.cancel')}
      confirmLoading={busy}
      onOk={() => onCreate(license.trim(), services)}
      onCancel={onCancel}
      destroyOnHidden
      width={520}
    >
      <div className="app-warp-rows">
        <label className="app-warp-row">
          <Tooltip title={t('settings.warpServicesHint')}>
            <span className="app-warp-label">{t('settings.warpServices')}</span>
          </Tooltip>
          {/* `tags`, not a fixed list: the presets are the common answers, and
              anything the routing lists accept — a geosite category, a bare
              domain — belongs here too. */}
          <Select
            mode="tags"
            value={services}
            onChange={setServices}
            options={WARP_SERVICES}
            tokenSeparators={[',', ' ']}
            placeholder={t('settings.warpServicesPlaceholder')}
            showSearch={{ optionFilterProp: 'label' }}
          />
        </label>

        <label className="app-warp-row">
          <Tooltip title={t('settings.warpLicenseHint')}>
            <span className="app-warp-label">{t('settings.warpLicense')}</span>
          </Tooltip>
          <Input
            value={license}
            onChange={(e) => setLicense(e.target.value)}
            placeholder={t('settings.warpLicensePlaceholder')}
            autoComplete="off"
            spellCheck={false}
            allowClear
          />
        </label>
      </div>
    </Modal>
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
