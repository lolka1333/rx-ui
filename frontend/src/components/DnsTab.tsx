//! The whole "DNS" tab of the Xray settings: a status line, then the three
//! stages of a lookup in the order the core performs them — static answers,
//! the server list, and the rules that govern both.
//!
//! It lives outside `Settings.tsx` because it is not built from that page's
//! two-column field rows. Those rows put a paragraph of explanation beside
//! every control, which is right for four settings and wrong for fourteen: the
//! resolver's switches ran six paragraphs deep and buried the one thing that
//! matters — the list of servers.
//!
//! Two ideas drive the layout. First, ORDER: xray answers from `hosts` before
//! it asks anyone, then walks the servers top-down, and the blocks sit in that
//! order — the static answers used to be UNDER the list they precede. Each
//! heading's subtitle says where its block falls in the sequence, which is why
//! there is no numbering on top of that: a step number in the heading was one
//! more thing to read for something the position already says.
//!
//! Second, NAMED OUTCOMES: the six section switches were three separate
//! subjects written as negations, so "off" meant "yes, do it". They are three
//! controls now, each listing what will actually happen, with the consequence
//! shown under the row whose value just moved and behind every name on hover.
//!
//! Everything still binds through the parent `Form`, so the page dirty bar and
//! the save-then-restart prompt keep working untouched.

import { Button, Form, Input, InputNumber, Segmented, Select, Switch, Tooltip } from 'antd';
import { RightOutlined } from '@ant-design/icons';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { DnsServersField } from '@/components/DnsServersField';
import { DnsHostsField } from '@/components/DnsHostsField';
import { DNS_QUERY_STRATEGIES } from '@/lib/dnsPresets';
import type { DnsHost, DnsServer } from '@/api/types/settings';

interface Props {
  /** Recompute the page's dirty state after a write that did NOT go through a
   *  bound control.
   *
   *  antd fires `onValuesChange` only from a field's own `onChange`;
   *  `setFieldValue` updates the store silently. The "поставить UseIP" button
   *  writes a field owned by another tab, so without this the strategy changed
   *  and the save bar never appeared — the operator saw the fix applied and
   *  left without saving it. */
  onExternalChange?: () => void;
}

export function DnsTab({ onExternalChange }: Props) {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  // `useWatch` returns nothing on the first render — it subscribes in an
  // effect — so a resolver saved as off used to paint one frame at full
  // opacity, hint and all, before dimming. The form knows the value already.
  const watched = Form.useWatch<boolean>('xray_dns_enabled', form);
  const on = (watched ?? form.getFieldValue('xray_dns_enabled')) !== false;

  const servers = Form.useWatch<DnsServer[]>('xray_dns_servers', form) ?? [];
  const hosts = Form.useWatch<DnsHost[]>('xray_dns_hosts', form) ?? [];
  const freedom = Form.useWatch<string>('xray_freedom_strategy', form);
  const routing = Form.useWatch<string>('xray_routing_strategy', form);

  const serverCount = servers.filter((v) => v?.address?.trim()).length;
  const hostCount = hosts.filter((v) => v?.domain?.trim()).length;
  const configured = serverCount > 0 || hostCount > 0;

  // Whether this whole tab is currently doing nothing.
  //
  // The core reaches its internal resolver only when something asks it for an
  // IP: a Freedom `domainStrategy` of `UseIP*`/`ForceIP*`, or a routing
  // strategy that has to resolve a domain to match an IP rule. With both left
  // at `AsIs` the freedom outbound hands the domain to the Go dialer, which
  // uses the host's own `/etc/resolv.conf` — every server configured here is
  // skipped. Nothing errors, the config is valid and xray loads it happily, so
  // the only signal an operator ever gets is that their resolver changed
  // nothing. Say so instead.
  const inert = on && configured && freedom === 'AsIs' && routing === 'AsIs';

  // One sentence for the whole tab, where a plaque and a warning banner used
  // to be two blocks asking the same question: is this setup in effect?
  const summary = [
    ...(hostCount ? [t('settings.dnsStatusHosts', { n: hostCount })] : []),
    ...(serverCount ? [t('settings.dnsStatusServers', { n: serverCount })] : []),
  ].join(', ');
  const state = !on ? 'off' : inert ? 'inert' : configured ? 'ok' : 'idle';
  const statusText = {
    off: t('settings.dnsEnabledOffHint'),
    inert: t('settings.dnsStatusInert'),
    idle: t('settings.dnsStatusEmpty'),
    ok: t('settings.dnsStatusOn', { what: summary }),
  }[state];

  return (
    <div className="app-dns">
      {/* The master switch, its state and the one warning this tab can raise,
          all on one line. Off keeps every field below on screen — dimmed, not
          hidden: a setup that disappears reads as deleted, and the whole point
          of the switch is that nothing is lost. */}
      <div className="app-dns-status">
        {/* `htmlFor` rather than wrapping: the switch is at the far end of the
            row and the action button sits between the two, and a label that
            reached around both would make a click on "поставить UseIP" a click
            on the label as well. */}
        <label className="app-dns-status-txt" htmlFor="xray_dns_enabled">
          <span className="app-dns-status-name">
            {/* Only for the one state worth a colour. A dot beside a switch
                that already reads on/off was two indicators arguing about the
                same thing; the amber one earns its place because nothing else
                on the line says "configured but never asked". */}
            {inert && <span className="app-dns-dot is-warn" aria-hidden="true" />}
            {t('settings.dnsEnabled')}
          </span>
          <span className="app-dns-status-sub">{statusText}</span>
        </label>
        {inert && (
          <span className="app-dns-status-act">
            <Button
              size="small"
              onClick={() => {
                form.setFieldValue('xray_freedom_strategy', 'UseIP');
                onExternalChange?.();
              }}
            >
              {t('settings.dnsInertAction')}
            </Button>
          </span>
        )}
        <Form.Item name="xray_dns_enabled" noStyle valuePropName="checked">
          <Switch id="xray_dns_enabled" />
        </Form.Item>
      </div>

      {/* The wrapper always carries `app-dns-body` — the spacing between the
          sections lives there. It used to live in `app-dns-off`, which is only
          applied while the resolver is switched off, so with DNS ON the
          sections had no gap at all and sat glued to each other. */}
      <div className={`app-dns-body${on ? '' : ' app-dns-off'}`}>
        <div className="app-dns-flow">
          {/* Answered without asking anyone. This sat UNDER the servers
              before, which is the opposite of the order the core uses — the
              blocks are in that order now, and each heading's subtitle says
              where it falls in it, so the sequence needs no numbering on top
              of that. */}
          <Form.Item name="xray_dns_hosts" noStyle>
            <DnsHostsField />
          </Form.Item>

          <Form.Item name="xray_dns_servers" noStyle>
            <DnsServersField />
          </Form.Item>

          <BehaviourSection />
        </div>
      </div>
    </div>
  );
}

/** One row of the behaviour card: the setting's name, its control, and the
 *  consequence of the current choice.
 *
 *  That consequence used to sit under every control at once — five permanent
 *  grey lines that made this card 405px, more than half the tab, while the
 *  server list had 88px. It shows under the row that was just changed, which
 *  is the moment it answers a question, and hovering the name gives the same
 *  sentence at any other moment. */
function RuleCell({
  name,
  hint,
  active,
  wide,
  inline,
  children,
}: {
  name: string;
  hint: string;
  /** This is the setting whose value changed last. */
  active: boolean;
  /** Takes the whole row: its control is wider than half the card. */
  wide?: boolean;
  /** Name and control on one line. For a control that cannot be stretched to
   *  fill a cell — a lone switch left one two-thirds empty and twice as tall
   *  as it needed to be. */
  inline?: boolean;
  children: ReactNode;
}) {
  return (
    <div className={`app-dns-cell${wide ? ' is-wide' : ''}${inline ? ' is-inline' : ''}`}>
      <Tooltip title={hint}>
        <span className="app-dns-cell-name">{name}</span>
      </Tooltip>
      <div className="app-dns-cell-ctl">{children}</div>
      {active && <span className="app-dns-hint">{hint}</span>}
    </div>
  );
}

function BehaviourSection() {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  const [extraOpen, setExtraOpen] = useState(false);

  // `useWatch` has nothing on the first render — it subscribes in an effect —
  // so every one of these falls back to the value the form already holds. It
  // is not cosmetic here: the "changed last" check below compares renders, and
  // a field that reads empty once and then its real value looks exactly like
  // the operator having just set it. That is what made the strategy row
  // explain itself on load, before anyone touched anything.
  const w = <T,>(name: string, watched: T | undefined, fallback: T): T =>
    watched ?? (form.getFieldValue(name) as T | undefined) ?? fallback;
  const parallel = w('xray_dns_parallel_query', Form.useWatch<boolean>('xray_dns_parallel_query', form), false);
  const noFallback = w('xray_dns_disable_fallback', Form.useWatch<boolean>('xray_dns_disable_fallback', form), false);
  const ifMatch = w('xray_dns_disable_fallback_if_match', Form.useWatch<boolean>('xray_dns_disable_fallback_if_match', form), false);
  const noCache = w('xray_dns_disable_cache', Form.useWatch<boolean>('xray_dns_disable_cache', form), false);
  const stale = w('xray_dns_serve_stale', Form.useWatch<boolean>('xray_dns_serve_stale', form), false);
  const strategy = w('xray_dns_query_strategy', Form.useWatch<string>('xray_dns_query_strategy', form), '');
  const sysHosts = w('xray_dns_use_system_hosts', Form.useWatch<boolean>('xray_dns_use_system_hosts', form), false);
  const clientIp = (Form.useWatch<string>('xray_dns_client_ip', form) ?? '').trim();
  const tag = (Form.useWatch<string>('xray_dns_tag', form) ?? '').trim();

  // Which row explains itself right now: the one whose value moved last.
  //
  // Watching the values rather than wiring a callback through every control
  // keeps the three segmented components unaware of this, and it catches the
  // paired flags too — the fallback and cache modes each write a second field
  // with `setFieldValue`, which no `onChange` of theirs would report.
  const [touched, setTouched] = useState<string | null>(null);
  const seen = useRef<Record<string, unknown> | null>(null);
  const values: Record<string, unknown> = {
    ask: parallel,
    fallback: `${noFallback}/${ifMatch}`,
    cache: `${noCache}/${stale}`,
    strategy,
    hosts: sysHosts,
  };
  useEffect(() => {
    const before = seen.current;
    seen.current = values;
    // First run only records: the values arriving from the server are not a
    // change the operator made, and a hint on load would explain nothing.
    if (!before) return;
    const moved = Object.keys(values).find((k) => values[k] !== before[k]);
    if (moved) setTouched(moved);
    // `values` is rebuilt every render; the watched fields are the real deps.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [parallel, noFallback, ifMatch, noCache, stale, strategy, sysHosts]);

  const fallbackHint = noFallback
    ? t('settings.dnsFallbackNoneHint')
    : ifMatch
      ? t('settings.dnsFallbackMatchHint')
      : t('settings.dnsFallbackNextHint');
  const cacheHint = noCache
    ? t('settings.dnsCacheOffHint')
    : stale
      ? t('settings.dnsCacheStaleHint')
      : t('settings.dnsCacheNormalHint');
  const extraSummary =
    clientIp || tag
      ? [
          ...(clientIp ? [t('settings.dnsMoreEdns', { v: clientIp })] : []),
          ...(tag ? [t('settings.dnsMoreTag', { v: tag })] : []),
        ].join(', ')
      : t('settings.dnsMoreEmpty');

  return (
    <section className="app-dns-section">
      <div className="app-dns-head">
        <span className="app-dns-title">{t('settings.xrayGroupDnsBehaviour')}</span>
        <span className="app-dns-sub">{t('settings.dnsBehaviourSub')}</span>
      </div>

      {/* Two settings to a row.
       *
       * One per row left the right half of the card empty at every width, and
       * the fallback below is the only control too wide to share. The columns
       * follow the CARD's width through a container query rather than the
       * window's: with a sidebar and a browser zoom in play, a viewport
       * breakpoint was guessing, and it guessed wrong — the block fell back to
       * name-over-control on screens that had room for two columns.
       *
       * The cells always fill their rows (2 + 1 wide + 2, then 2 in the
       * disclosure). An odd one out would leave a gap showing the grid's own
       * background, which is what draws the hairlines. */}
      <div className="app-dns-table app-dns-beh">
        <div className="app-dns-grid">
          <RuleCell
            name={t('settings.dnsAskMode')}
            hint={parallel ? t('settings.dnsAskAllHint') : t('settings.dnsAskOrderHint')}
            active={touched === 'ask'}
          >
            <Form.Item name="xray_dns_parallel_query" noStyle>
              <AskMode />
            </Form.Item>
          </RuleCell>

          <RuleCell
            name={t('settings.dnsCacheMode')}
            hint={cacheHint}
            active={touched === 'cache'}
          >
            <Form.Item name="xray_dns_disable_cache" noStyle>
              <CacheMode />
            </Form.Item>
            {/* Hidden rather than unmounted: an unmounted Form.Item drops out
                of the values antd hands to `onFinish`, and the backend takes
                the field as `#[serde(default)]` — so saving with stale answers
                off silently reset this to zero. */}
            <span className={`app-dns-ttl${stale ? '' : ' app-dns-hidden'}`}>
              {t('settings.dnsCacheTtl')}
              <Form.Item name="xray_dns_serve_expired_ttl" noStyle>
                <InputNumber size="small" min={0} max={86400} step={60} controls={false} />
              </Form.Item>
            </span>
            {/* Bound but not drawn, for the same two reasons as the fallback
                flag below: it has to reach `onFinish`, and `useWatch` only
                tracks a field something has registered. */}
            <span className="app-dns-hidden">
              <Form.Item name="xray_dns_serve_stale" noStyle valuePropName="checked">
                <Switch />
              </Form.Item>
            </span>
          </RuleCell>

          <RuleCell
            wide
            name={t('settings.dnsFallbackMode')}
            hint={fallbackHint}
            active={touched === 'fallback'}
          >
            <Form.Item name="xray_dns_disable_fallback" noStyle>
              <FallbackMode />
            </Form.Item>
            <span className="app-dns-hidden">
              <Form.Item name="xray_dns_disable_fallback_if_match" noStyle valuePropName="checked">
                <Switch />
              </Form.Item>
            </span>
          </RuleCell>

          <RuleCell
            name={t('settings.xrayDnsQueryStrategy')}
            hint={t('settings.xrayDnsQueryStrategyHint')}
            active={touched === 'strategy'}
          >
            <Form.Item name="xray_dns_query_strategy" noStyle>
              <Select
                size="small"
                popupMatchSelectWidth={false}
                style={{ width: '100%' }}
                options={DNS_QUERY_STRATEGIES.map((v) => ({ value: v, label: v }))}
              />
            </Form.Item>
          </RuleCell>

          <RuleCell
            inline
            name={t('settings.xrayDnsUseSystemHosts')}
            hint={t('settings.xrayDnsUseSystemHostsHint')}
            active={touched === 'hosts'}
          >
            <Form.Item name="xray_dns_use_system_hosts" noStyle valuePropName="checked">
              <Switch size="small" />
            </Form.Item>
          </RuleCell>
        </div>

        <button
          type="button"
          className="app-dns-fold"
          aria-expanded={extraOpen}
          onClick={() => setExtraOpen((v) => !v)}
        >
          <RightOutlined className="app-dns-fold-icon" />
          {t('settings.dnsMore')}
          <span className="app-dns-fold-sub">{extraSummary}</span>
        </button>

        <div className={`app-dns-grid app-dns-extra${extraOpen ? '' : ' app-dns-hidden'}`}>
          <RuleCell
            name={t('settings.xrayDnsClientIp')}
            hint={t('settings.xrayDnsClientIpHint')}
            active={false}
          >
            <Form.Item name="xray_dns_client_ip" noStyle>
              <Input size="small" spellCheck={false} placeholder={t('settings.dnsChipEmpty')} />
            </Form.Item>
          </RuleCell>
          <RuleCell
            name={t('settings.xrayDnsTag')}
            hint={t('settings.xrayDnsTagHint')}
            active={false}
          >
            <Form.Item name="xray_dns_tag" noStyle>
              <Input size="small" spellCheck={false} placeholder={t('settings.dnsChipEmpty')} />
            </Form.Item>
          </RuleCell>
        </div>
      </div>
    </section>
  );
}

/** `parallelQuery` as two named modes.
 *
 *  A control rather than `getValueProps` on the Form.Item: that mapping applied
 *  on the first render and then stopped, so picking "все сразу" set the field
 *  and left the segmented showing neither option selected. */
function AskMode({ value, onChange }: { value?: boolean; onChange?: (v: boolean) => void }) {
  const { t } = useTranslation();
  return (
    <Segmented
      block
      size="small"
      value={value ? 'all' : 'order'}
      onChange={(next: string) => onChange?.(next === 'all')}
      options={[
        { value: 'order', label: t('settings.dnsAskOrder') },
        { value: 'all', label: t('settings.dnsAskAll') },
      ]}
    />
  );
}

/** `disableFallback` + `disableFallbackIfMatch` as three named outcomes.
 *
 *  The pair is not two independent switches: the core checks `disableFallback`
 *  first, so `(true, true)` behaves exactly as `(true, false)`. Three modes
 *  therefore cover every distinct behaviour, and picking "никуда" normalises
 *  the dead combination away.
 *
 *  Bound to `disableFallback`; the second field is written first, because the
 *  bound `onChange` below is what notifies the page — and antd builds the
 *  "all values" it passes along from the store as it stands at that moment. */
function FallbackMode({ value, onChange }: { value?: boolean; onChange?: (v: boolean) => void }) {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  const watched = Form.useWatch<boolean>('xray_dns_disable_fallback_if_match', form);
  const ifMatch = watched ?? form.getFieldValue('xray_dns_disable_fallback_if_match') ?? false;
  const mode = value ? 'none' : ifMatch ? 'match' : 'next';

  return (
    <Segmented
      block
      size="small"
      value={mode}
      onChange={(next: string) => {
        form.setFieldValue('xray_dns_disable_fallback_if_match', next === 'match');
        onChange?.(next === 'none');
      }}
      options={[
        { value: 'next', label: t('settings.dnsFallbackNext') },
        { value: 'match', label: t('settings.dnsFallbackMatch') },
        { value: 'none', label: t('settings.dnsFallbackNone') },
      ]}
    />
  );
}

/** `disableCache` + `serveStale` as three named outcomes.
 *
 *  With the cache off there is nothing to serve stale, so `(true, true)` is
 *  the same as `(true, false)`; the three modes are the three behaviours. */
function CacheMode({ value, onChange }: { value?: boolean; onChange?: (v: boolean) => void }) {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  const watched = Form.useWatch<boolean>('xray_dns_serve_stale', form);
  const stale = watched ?? form.getFieldValue('xray_dns_serve_stale') ?? false;
  const mode = value ? 'off' : stale ? 'stale' : 'normal';

  return (
    <Segmented
      block
      size="small"
      value={mode}
      onChange={(next: string) => {
        form.setFieldValue('xray_dns_serve_stale', next === 'stale');
        onChange?.(next === 'off');
      }}
      options={[
        { value: 'normal', label: t('settings.dnsCacheNormal') },
        { value: 'off', label: t('settings.dnsCacheOff') },
        { value: 'stale', label: t('settings.dnsCacheStale') },
      ]}
    />
  );
}
