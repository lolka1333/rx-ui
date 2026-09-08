//! Name-server list for the Xray "DNS" settings tab — stage 2 of the lookup.
//!
//! A resolver list is ordered: xray walks it top-down, picks the first server
//! whose `domains` match (or the first one with no `domains` at all), and falls
//! back down the list when that one fails. So this is a numbered list, and the
//! number is the setting.
//!
//! What the row shows is the consequence of that order, not a dump of fields.
//! Every server gets a ROLE computed from its own `domains` and from where it
//! sits among the others: "свои домены", "всё остальное", or "запасной" — with
//! a line saying whom it stands in for. The old table showed two domain-less
//! servers as two identical rows reading "всё остальное", which is exactly
//! wrong: the second one is only ever reached when the first fails. The role
//! also reacts to the section switches, so turning on parallel queries or
//! turning off fallback changes the list instead of changing nothing on screen.
//!
//! Below the role line, a second line carries every per-server value that is
//! actually set — matchers, answer filters, port, timeout, EDNS, strategy,
//! flags. Nine of those ten fields used to be reachable only through the row
//! menu, an edit dialog and its second tab, and the table showed "—" instead.
//! A server with nothing set stays one quiet line; nothing anywhere shows a
//! dash any more.
//!
//! Value/onChange flow through the parent Xray form, so the page dirty bar and
//! the save-then-restart path pick the list up for free.

import {
  AutoComplete,
  Button,
  Dropdown,
  Form,
  Input,
  InputNumber,
  Modal,
  Segmented,
  Select,
  Switch,
  Tag,
} from 'antd';
import type { FormInstance, MenuProps } from 'antd';
import {
  ArrowDownOutlined,
  ArrowUpOutlined,
  DeleteOutlined,
  DownOutlined,
  EditOutlined,
  HolderOutlined,
  MoreOutlined,
  PlusOutlined,
  RightOutlined,
} from '@ant-design/icons';
import { useCallback, useMemo, useRef, useState, type DragEvent } from 'react';
import { useTranslation } from 'react-i18next';
import type { DnsServer } from '@/api/types/settings';
import { DNS_PRESETS, DNS_QUERY_STRATEGIES, DNS_RECIPES, strategyClashes } from '@/lib/dnsPresets';
import { GEOIP_PRESETS, GEOSITE_PRESETS } from '@/lib/geoPresets';

/** A server with nothing but an address — what "+ Add" starts from and what
 *  the backend emits as a bare string. Not exported: react-refresh wants this
 *  file to export components only, and nothing outside needs it. */
const emptyDnsServer = (): DnsServer => ({
  address: '',
  port: 0,
  domains: [],
  expect_ips: [],
  unexpected_ips: [],
  skip_fallback: false,
  final_query: false,
  timeout_ms: 0,
  client_ip: '',
  query_strategy: '',
});

/** How this server's own queries travel: the transport, and whether they go out
 *  through xray's routing or straight off the node.
 *
 *  That second half is the part with a cost attached. A plain `https://`
 *  resolver sends its lookups back through the outbounds, so on a relay the
 *  DoH request rides the same tunnel as the traffic it is resolving for; the
 *  `+local` spelling is the one that does not. */
function wireOf(address: string): { code: string; qual: 'local' | 'chain' | null } {
  const a = address.trim().toLowerCase();
  if (a.startsWith('https+local://') || a.startsWith('h2c+local://'))
    return { code: 'DoH', qual: 'local' };
  if (a.startsWith('https://') || a.startsWith('h2c://')) return { code: 'DoH', qual: 'chain' };
  if (a.startsWith('quic+local://')) return { code: 'DoQ', qual: 'local' };
  if (a.startsWith('tcp+local://')) return { code: 'TCP', qual: 'local' };
  if (a.startsWith('tcp://')) return { code: 'TCP', qual: 'chain' };
  if (a === 'localhost') return { code: 'SYS', qual: null };
  return { code: 'UDP', qual: null };
}

/** What the row shows for an address: everything but the scheme.
 *
 *  The scheme is already spelled out by the badge beside it, and the path is
 *  what tells two resolvers of the same provider apart — dropping it, as this
 *  used to, left `https://1.1.1.1/dns-query` and a plain `1.1.1.1` looking like
 *  the same row. */
function displayAddress(address: string): string {
  const m = /^[a-z0-9+]+:\/\/(.+)$/i.exec(address.trim());
  return m ? m[1] : address.trim();
}

type Role = 'own' | 'rest' | 'back' | 'dead';

/** Index of the first server that answers for anything — the one an unmatched
 *  name reaches. -1 when every server is scoped to its own domains. */
const firstGeneral = (list: DnsServer[]): number =>
  list.findIndex((s) => (s.domains?.length ?? 0) === 0);

/** What this server is FOR, given the list it is in and the switches above it.
 *
 *  With parallel queries on, the order stops meaning anything — every server is
 *  asked at once — so nothing is a fallback any more and saying otherwise would
 *  be a lie the list tells. With fallback off, a general server that is not the
 *  first one is never reached at all. */
function roleOf(list: DnsServer[], i: number, parallel: boolean, noFallback: boolean): Role {
  if ((list[i].domains?.length ?? 0) > 0) return 'own';
  if (parallel) return 'rest';
  if (i === firstGeneral(list)) return 'rest';
  return noFallback ? 'dead' : 'back';
}

/** `editing` while the dialog holds a server that is not in the list yet. */
const NEW = -1;

interface Props {
  /** Which step of the lookup this block is, drawn in its heading. */
  step?: number;
  value?: DnsServer[];
  onChange?: (next: DnsServer[]) => void;
}

export function DnsServersField({ step, value, onChange }: Props) {
  const { t } = useTranslation();
  // The section's own settings, read from the page form this field lives in.
  // The strategy is checked against a per-server one before it can be picked;
  // the two switches decide what the roles in this list actually mean.
  const page = Form.useFormInstance();
  // `useWatch` has nothing on the first render — it subscribes in an effect —
  // and the form itself already knows the answer.
  const watched = Form.useWatch<string>('xray_dns_query_strategy', page);
  const sectionStrategy = watched ?? page.getFieldValue('xray_dns_query_strategy') ?? 'UseIP';
  const parallel = Form.useWatch<boolean>('xray_dns_parallel_query', page) ?? false;
  const noFallback = Form.useWatch<boolean>('xray_dns_disable_fallback', page) ?? false;

  const list = useMemo(() => value ?? [], [value]);
  const [editing, setEditing] = useState<number | null>(null);

  const commit = useCallback((next: DnsServer[]) => onChange?.(next), [onChange]);

  const move = (from: number, to: number) => {
    if (to < 0 || to >= list.length) return;
    const next = [...list];
    const [row] = next.splice(from, 1);
    next.splice(to, 0, row);
    commit(next);
  };

  // Drag-reorder, the same native handlers the routing rules use — the source
  // index lives in a ref so `onDrop` reads the current value whatever React's
  // render timing does, and the state only drives the visuals.
  //
  // The order is the setting here: xray asks these servers top to bottom, so
  // the menu's up/down alone made moving a server to the top of a five-row
  // list four separate menu trips. The menu stays for keyboards and touch.
  const dragFrom = useRef<number | null>(null);
  const [dragIndex, setDragIndex] = useState<number | null>(null);
  const [overIndex, setOverIndex] = useState<number | null>(null);
  const rowDnd = (i: number) => ({
    draggable: true,
    onDragStart: (e: DragEvent) => {
      dragFrom.current = i;
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
      const from = dragFrom.current;
      if (from !== null && from !== i) move(from, i);
      dragFrom.current = null;
      setDragIndex(null);
      setOverIndex(null);
    },
    onDragEnd: () => {
      dragFrom.current = null;
      setDragIndex(null);
      setOverIndex(null);
    },
  });

  // Adding used to append an empty server and then open the dialog on it, so
  // pressing Cancel left a nameless row behind — click the button five times,
  // get five of them. Nothing is committed until Save now.
  const addMenu: MenuProps['items'] = [
    ...DNS_RECIPES.map((r) => ({ key: r.address, label: t(`settings.${r.labelKey}`) })),
    { type: 'divider' as const },
    { key: 'custom', label: t('settings.dnsAddCustom') },
  ];
  const addPick = (key: string) => {
    if (key === 'custom') setEditing(NEW);
    else commit([...list, { ...emptyDnsServer(), address: key }]);
  };

  return (
    <section className="app-dns-section">
      <div className="app-dns-head">
        {step !== undefined && (
          <span className="app-dns-stage-n" aria-hidden="true">
            {step}
          </span>
        )}
        <span className="app-dns-title">{t('settings.xrayDnsServers')}</span>
        <span className="app-dns-sub">{t('settings.dnsServersSub')}</span>
        {/* The quick picks lived inside the dialog's autocomplete, which is
            behind the very button an operator with an empty list is looking
            at. They are the menu on that button now. */}
        <Dropdown trigger={['click']} menu={{ items: addMenu, onClick: ({ key }) => addPick(key) }}>
          <Button size="small" icon={<PlusOutlined />}>
            {t('settings.dnsAddServer')}
            <DownOutlined style={{ fontSize: 10 }} />
          </Button>
        </Dropdown>
      </div>

      {/* With every server asked at once, the numbers are not a fallback chain
          and the roles below stop promising one. Saying so here is the only
          place an operator can find out — the switch itself is three blocks
          down and, before this, changed nothing they could see. */}
      {parallel && list.length > 1 && (
        <div className="app-dns-strip">{t('settings.dnsParallelStrip')}</div>
      )}

      <div className="app-dns-table">
        {list.length === 0 ? (
          <div className="app-dns-empty">
            <span>{t('settings.dnsNoServers')}</span>
            <span className="app-dns-recipes">
              {DNS_RECIPES.map((r) => (
                <Button
                  key={r.address}
                  size="small"
                  onClick={() => commit([{ ...emptyDnsServer(), address: r.address }])}
                >
                  {t(`settings.${r.labelKey}`)}
                </Button>
              ))}
              <Button size="small" onClick={() => setEditing(NEW)}>
                {t('settings.dnsAddCustom')}
              </Button>
            </span>
          </div>
        ) : (
          list.map((s, i) => {
            const wire = s.address.trim() ? wireOf(s.address) : null;
            const role = roleOf(list, i, parallel, noFallback);
            const general = firstGeneral(list);
            const menu: MenuProps['items'] = [
              { key: 'edit', icon: <EditOutlined />, label: t('common.edit') },
              {
                key: 'up',
                icon: <ArrowUpOutlined />,
                label: t('settings.dnsMoveUp'),
                disabled: i === 0,
              },
              {
                key: 'down',
                icon: <ArrowDownOutlined />,
                label: t('settings.dnsMoveDown'),
                disabled: i === list.length - 1,
              },
              { type: 'divider' },
              { key: 'del', icon: <DeleteOutlined />, label: t('common.delete'), danger: true },
            ];
            // Every per-server value that carries something, in the order an
            // operator reads them: what it answers for, what it may answer
            // with, then how it is dialled.
            const chips: { k: string; label: string; cls?: string }[] = [
              ...s.domains.map((d) => ({ k: `d-${d}`, label: d })),
              ...s.expect_ips.map((ip) => ({
                k: `e-${ip}`,
                label: t('settings.dnsOnlyIp', { v: ip }),
                cls: 'app-dns-t-ok',
              })),
              ...s.unexpected_ips.map((ip) => ({
                k: `u-${ip}`,
                label: t('settings.dnsExceptIp', { v: ip }),
                cls: 'app-dns-t-no',
              })),
              ...(s.port ? [{ k: 'port', label: `:${s.port}` }] : []),
              ...(s.timeout_ms
                ? [{ k: 'to', label: t('settings.dnsChipTimeoutVal', { v: s.timeout_ms }) }]
                : []),
              ...(s.client_ip
                ? [{ k: 'ip', label: t('settings.dnsChipEdnsVal', { v: s.client_ip }) }]
                : []),
              ...(s.query_strategy ? [{ k: 'qs', label: s.query_strategy }] : []),
              ...(s.skip_fallback
                ? [{ k: 'sf', label: t('settings.dnsSkipFallbackTag'), cls: 'app-dns-t-word' }]
                : []),
              ...(s.final_query
                ? [{ k: 'fq', label: t('settings.dnsFinalQueryTag'), cls: 'app-dns-t-word' }]
                : []),
            ];
            const hint =
              role === 'back'
                ? t('settings.dnsRoleBackHint', { n: general + 1 })
                : role === 'dead'
                  ? t('settings.dnsRoleDeadHint', { n: general + 1 })
                  : null;

            return (
              <div
                key={`${s.address}-${i}`}
                className={`app-dns-tr${role === 'dead' ? ' is-dead' : ''}${
                  dragIndex === i ? ' is-drag' : ''
                }${overIndex === i && dragIndex !== null && dragIndex !== i ? ' is-over' : ''}`}
                {...rowDnd(i)}
              >
                {/* The row number doubles as the grip: the two swap inside one
                    fixed cell, so hovering says the row can be grabbed without
                    a permanent handle column or a width that shifts. */}
                <span className="app-dns-num">
                  <span className="app-dns-ord">{i + 1}</span>
                  <HolderOutlined className="app-dns-grip" aria-hidden="true" />
                </span>

                <span className="app-dns-srv">
                  <span className="app-dns-srv-l1">
                    <span className="app-dns-addr" title={s.address || undefined}>
                      {s.address ? displayAddress(s.address) : t('settings.dnsNoAddress')}
                    </span>
                    {wire && <span className="app-dns-badge">{wire.code}</span>}
                    {wire?.qual && (
                      <span className="app-dns-wire">
                        {t(`settings.dnsWire${wire.qual === 'local' ? 'Local' : 'Chain'}`)}
                      </span>
                    )}
                    <span className={`app-dns-role is-${role}`}>
                      {t(`settings.dnsRole${role[0].toUpperCase()}${role.slice(1)}`)}
                    </span>
                  </span>

                  {chips.length > 0 && (
                    <span className="app-dns-srv-l2 app-dns-tags">
                      {chips.map((c) => (
                        <Tag key={c.k} className={c.cls}>
                          {c.label}
                        </Tag>
                      ))}
                    </span>
                  )}

                  {hint && (
                    <span className={`app-dns-hint${role === 'dead' ? ' is-warn' : ''}`}>
                      {hint}
                    </span>
                  )}
                </span>

                <Dropdown
                  trigger={['click']}
                  menu={{
                    items: menu,
                    onClick: ({ key }) => {
                      if (key === 'edit') setEditing(i);
                      else if (key === 'up') move(i, i - 1);
                      else if (key === 'down') move(i, i + 1);
                      else if (key === 'del') commit(list.filter((_, j) => j !== i));
                    },
                  }}
                >
                  <Button type="text" size="small" icon={<MoreOutlined />} />
                </Dropdown>
              </div>
            );
          })
        )}
      </div>

      {/* Always mounted, opened by the prop — the way the inbound dialog does
          it. Rendered conditionally, the component left the tree the moment it
          closed, so there was nothing on screen for antd to animate out. */}
      <ServerModal
        open={editing !== null}
        sectionStrategy={sectionStrategy}
        formKey={editing ?? NEW}
        server={(editing !== null && editing !== NEW && list[editing]) || emptyDnsServer()}
        onCancel={() => setEditing(null)}
        onOk={(next) => {
          if (editing === NEW) {
            commit([...list, next]);
          } else if (editing !== null) {
            commit(list.map((s, j) => (j === editing ? next : s)));
          }
          setEditing(null);
        }}
      />
    </section>
  );
}

/** The per-server sheet: one column, grouped by question, with the three
 *  rarely-touched fields behind a disclosure.
 *
 *  It used to be two tabs, which was the right fix for the wrong problem — ten
 *  fields stacked in one column ran 888px tall, so half of them went behind a
 *  tab and needed a counter badge on that tab to admit that values were hiding
 *  in there. Grouping gets the height back without hiding anything: what is
 *  behind the disclosure is summarised on its own line, and every value set
 *  here also shows on the row in the list. */
function ServerModal({
  open,
  formKey,
  sectionStrategy,
  server,
  onOk,
  onCancel,
}: {
  open: boolean;
  /** What the section as a whole asks for. A server may narrow it, never
   *  contradict it. */
  sectionStrategy: string;
  /** Remounts the form per opened row: `destroyOnHidden` clears the fields,
   *  and a fresh key makes the next row's `initialValues` actually apply. */
  formKey: number;
  server: DnsServer;
  onOk: (next: DnsServer) => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const [form] = Form.useForm<DnsServer>();
  const address = Form.useWatch('address', form);

  return (
    <Modal
      open={open}
      width={640}
      // Unmounts the form after the close animation, so the next row opens on
      // its own values instead of the previous one's.
      destroyOnHidden
      title={t('settings.dnsServerTitle')}
      okText={t('common.save')}
      cancelText={t('common.cancel')}
      // A server without an address is not a server: the backend drops it on
      // save, so letting it into the list only shows the operator a row that
      // silently disappears later.
      okButtonProps={{ disabled: !String(address ?? '').trim() }}
      onCancel={onCancel}
      onOk={() => {
        // The whole store, not just the mounted fields: the disclosure hides
        // its three fields with CSS for exactly this reason, but reading the
        // store keeps the save correct however the sheet is laid out later.
        const v = form.getFieldsValue(true) as DnsServer;
        onOk({
          ...server,
          ...v,
          address: (v.address ?? '').trim(),
          port: Number(v.port) || 0,
          timeout_ms: Number(v.timeout_ms) || 0,
          client_ip: (v.client_ip ?? '').trim(),
          domains: v.domains ?? [],
          expect_ips: v.expect_ips ?? [],
          unexpected_ips: v.unexpected_ips ?? [],
        });
      }}
    >
      <ServerForm key={formKey} form={form} server={server} sectionStrategy={sectionStrategy} />
    </Modal>
  );
}

/** The sheet's body. Keyed by the opened row so its own state — which scope the
 *  server has, whether the disclosure is open — resets with the fields. */
function ServerForm({
  form,
  server,
  sectionStrategy,
}: {
  form: FormInstance<DnsServer>;
  server: DnsServer;
  sectionStrategy: string;
}) {
  const { t } = useTranslation();
  // 0 means "whatever the core does by default" — showing it as a literal zero
  // reads as "zero milliseconds", so these two open empty and carry a
  // placeholder instead. `onOk` maps the empty field back to 0.
  const initial = {
    ...server,
    port: server.port || undefined,
    timeout_ms: server.timeout_ms || undefined,
  };

  // Whether this server answers for its own list of names or for everything
  // else. It is a choice, so it is asked as one — before, it was inferred from
  // whether the operator happened to fill in a field, and a server meant to be
  // the general one looked identical to a half-finished scoped one.
  const [scope, setScope] = useState<'rest' | 'own'>(server.domains?.length ? 'own' : 'rest');
  const [extraOpen, setExtraOpen] = useState(
    Boolean(server.query_strategy || server.client_ip || server.timeout_ms),
  );

  const address = Form.useWatch('address', form) ?? '';
  const wire = String(address).trim() ? wireOf(String(address)) : null;
  const isUrl = String(address).includes('://');

  return (
    <Form form={form} layout="vertical" initialValues={initial} className="app-form-rows">
      <div className="app-dns-form-group">
        {/* Free text with suggestions, not a tag select: an address is one
            string, and a tags control held an array that only became a value
            after Enter — type it, click Save, and the server was stored with no
            address at all. */}
        <div className="app-dns-form-pair">
          <Form.Item name="address" label={t('settings.dnsServerAddress')}>
            <AutoComplete
              options={DNS_PRESETS.map((o) => ({
                value: o.value,
                label: (
                  <span className="app-dns-opt">
                    {o.code ? <span className="geo-code">{o.code}</span> : null}
                    <span className="app-dns-opt-name">{o.label}</span>
                    <span className="app-dns-opt-addr">{o.value}</span>
                  </span>
                ),
              }))}
              filterOption={(input, option) =>
                String(option?.value ?? '')
                  .toLowerCase()
                  .includes(input.toLowerCase())
              }
            >
              {/* Its own input, which is how antd lets the field be customised.
                  The one rc-select builds carries `autocomplete="new-password"`,
                  and Chrome reads that as a password box: clicking the field
                  covered the resolver list with the browser's saved passwords
                  and strings typed into other forms. */}
              <Input placeholder="1.1.1.1" autoComplete="off" spellCheck={false} />
            </AutoComplete>
          </Form.Item>
          {/* A `scheme://` address carries its own port and the core ignores
              this one, which the backend rejects rather than storing a setting
              that does nothing. Say it here instead of at save time. */}
          <Form.Item
            name="port"
            label={t('settings.dnsServerPort')}
            tooltip={t('settings.dnsServerPortHint')}
          >
            <InputNumber
              min={0}
              max={65535}
              disabled={isUrl}
              placeholder={isUrl ? t('settings.dnsPortInUrl') : '53'}
              style={{ width: '100%' }}
            />
          </Form.Item>
        </div>
        {wire && (
          <div className="app-dns-read">
            <span className="app-dns-badge">{wire.code}</span>
            {t(`settings.dnsWireRead${wire.qual === 'local' ? 'Local' : wire.qual === 'chain' ? 'Chain' : 'Plain'}`)}
          </div>
        )}
      </div>

      <div className="app-dns-form-group">
        <div className="app-dns-form-label">
          <span className="app-dns-form-name">{t('settings.dnsServerScope')}</span>
        </div>
        <Segmented
          value={scope}
          onChange={(next: string) => {
            setScope(next as 'rest' | 'own');
            // Leaving the scoped mode has to clear the list, or the server
            // keeps answering only for names the operator can no longer see.
            if (next === 'rest') form.setFieldValue('domains', []);
          }}
          options={[
            { value: 'rest', label: t('settings.dnsScopeRest') },
            { value: 'own', label: t('settings.dnsScopeOwn') },
          ]}
        />
        <div className={`app-dns-scope${scope === 'own' ? '' : ' app-dns-hidden'}`}>
          <Form.Item
            name="domains"
            label={t('settings.dnsServerDomains')}
            tooltip={t('settings.dnsServerDomainsHint')}
            style={{ marginTop: 12 }}
          >
            <Select mode="tags" options={GEOSITE_PRESETS} tokenSeparators={[',', ' ']} />
          </Form.Item>
        </div>
        {scope === 'rest' && (
          <div className="app-dns-read">{t('settings.dnsScopeRestRead')}</div>
        )}
      </div>

      <div className="app-dns-form-group">
        <div className="app-dns-form-label">
          <span className="app-dns-form-name">{t('settings.dnsServerCheck')}</span>
          <span className="app-dns-form-sub">{t('settings.dnsServerCheckSub')}</span>
        </div>
        {/* One decision with two sides, so the two lists sit side by side. */}
        <div className="app-dns-form-duo">
          <Form.Item name="expect_ips" label={t('settings.dnsServerExpectIps')}>
            <Select mode="tags" options={GEOIP_PRESETS} tokenSeparators={[',', ' ']} />
          </Form.Item>
          <Form.Item name="unexpected_ips" label={t('settings.dnsServerUnexpectedIps')}>
            <Select mode="tags" options={GEOIP_PRESETS} tokenSeparators={[',', ' ']} />
          </Form.Item>
        </div>
      </div>

      <div className="app-dns-form-group">
        <div className="app-dns-form-label">
          <span className="app-dns-form-name">{t('settings.dnsServerPlace')}</span>
        </div>
        {/* Switch rows, not "label above, switch below": the label and the thing
            it controls belong on one line. */}
        <div className="app-dns-form-switch">
          <span>
            <span className="app-dns-form-switch-name">
              {t('settings.dnsServerSkipFallback')}
            </span>
            <span className="app-dns-form-switch-desc">
              {t('settings.dnsServerSkipFallbackHint')}
            </span>
          </span>
          <Form.Item name="skip_fallback" noStyle valuePropName="checked">
            <Switch size="small" />
          </Form.Item>
        </div>
        <div className="app-dns-form-switch">
          <span>
            <span className="app-dns-form-switch-name">{t('settings.dnsServerFinalQuery')}</span>
            <span className="app-dns-form-switch-desc">
              {t('settings.dnsServerFinalQueryHint')}
            </span>
          </span>
          <Form.Item name="final_query" noStyle valuePropName="checked">
            <Switch size="small" />
          </Form.Item>
        </div>
      </div>

      <button
        type="button"
        className="app-dns-fold"
        aria-expanded={extraOpen}
        onClick={() => setExtraOpen((v) => !v)}
      >
        <RightOutlined className="app-dns-fold-icon" />
        {t('settings.dnsServerFine')}
        <span className="app-dns-fold-sub">{t('settings.dnsServerFineSub')}</span>
      </button>

      <div className={`app-dns-form-trio${extraOpen ? '' : ' app-dns-hidden'}`}>
        <Form.Item
          name="query_strategy"
          label={t('settings.dnsServerQueryStrategy')}
          extra={
            sectionStrategy === 'UseIPv4' || sectionStrategy === 'UseIPv6'
              ? t('settings.dnsStrategyClashHint', { section: sectionStrategy })
              : undefined
          }
        >
          <Select
            allowClear
            placeholder={t('settings.dnsInherit')}
            options={DNS_QUERY_STRATEGIES.map((v) => ({
              value: v,
              label: v,
              disabled: strategyClashes(sectionStrategy, v),
            }))}
          />
        </Form.Item>
        <Form.Item
          name="client_ip"
          label={t('settings.dnsServerClientIp')}
          tooltip={t('settings.dnsServerClientIpHint')}
        >
          <Input placeholder={t('settings.dnsInherit')} spellCheck={false} />
        </Form.Item>
        <Form.Item
          name="timeout_ms"
          label={t('settings.dnsServerTimeout')}
          tooltip={t('settings.dnsServerTimeoutHint')}
        >
          <InputNumber
            min={0}
            max={60000}
            step={500}
            placeholder={t('settings.dnsDefault')}
            style={{ width: '100%' }}
          />
        </Form.Item>
      </div>
    </Form>
  );
}
