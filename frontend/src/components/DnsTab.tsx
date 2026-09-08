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
//! it asks anyone, then walks the servers top-down. The tab is numbered in that
//! order, so the page itself says what the old subtitle ("отдаются до
//! серверов") had to explain. Second, NAMED OUTCOMES: the six section switches
//! were three separate subjects written as negations, so "off" meant "yes, do
//! it". They are three controls now, each listing what will actually happen,
//! with the consequence spelled out underneath instead of hidden in a tooltip.
//!
//! Everything still binds through the parent `Form`, so the page dirty bar and
//! the save-then-restart prompt keep working untouched.

import { Button, Form, Input, InputNumber, Segmented, Select, Switch } from 'antd';
import { RightOutlined } from '@ant-design/icons';
import { useState, type ReactNode } from 'react';
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
        {/* The label covers the switch and its text and stops there. With the
            button inside it too, a click on "поставить UseIP" would also be a
            click on the label — and the only thing keeping that from toggling
            the resolver off is that a button counts as interactive content. */}
        <label className="app-dns-status-main">
          <Form.Item name="xray_dns_enabled" noStyle valuePropName="checked">
            <Switch />
          </Form.Item>
          <span className="app-dns-status-txt">
            <span className="app-dns-status-name">
              <span
                className={`app-dns-dot${state === 'ok' ? ' is-ok' : state === 'inert' ? ' is-warn' : ''}`}
                aria-hidden="true"
              />
              {t('settings.dnsEnabled')}
            </span>
            <span className="app-dns-status-sub">{statusText}</span>
          </span>
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
      </div>

      {/* The wrapper always carries `app-dns-body` — the spacing between the
          sections lives there. It used to live in `app-dns-off`, which is only
          applied while the resolver is switched off, so with DNS ON the
          sections had no gap at all and sat glued to each other. */}
      <div className={`app-dns-body${on ? '' : ' app-dns-off'}`}>
        <div className="app-dns-flow">
          {/* 1 — answered without asking anyone. It sat UNDER the servers
              before, which is the opposite of the order the core uses. */}
          <div className="app-dns-stage">
            <span className="app-dns-stage-n" aria-hidden="true">
              1
            </span>
            <Form.Item name="xray_dns_hosts" noStyle>
              <DnsHostsField />
            </Form.Item>
          </div>

          {/* 2 — the ordered list. */}
          <div className="app-dns-stage">
            <span className="app-dns-stage-n" aria-hidden="true">
              2
            </span>
            <Form.Item name="xray_dns_servers" noStyle>
              <DnsServersField />
            </Form.Item>
          </div>

          {/* 3 — what governs the two above. */}
          <div className="app-dns-stage">
            <span className="app-dns-stage-n" aria-hidden="true">
              3
            </span>
            <BehaviourSection />
          </div>
        </div>
      </div>
    </div>
  );
}

/** One row of the behaviour card: the setting's name, then the control with
 *  its consequence written underneath. */
function RuleRow({ name, children }: { name: string; children: ReactNode }) {
  return (
    <div className="app-dns-rule">
      <span className="app-dns-rule-name">{name}</span>
      <div className="app-dns-rule-r">{children}</div>
    </div>
  );
}

function BehaviourSection() {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  const [extraOpen, setExtraOpen] = useState(false);

  const parallel = Form.useWatch<boolean>('xray_dns_parallel_query', form) ?? false;
  const noFallback = Form.useWatch<boolean>('xray_dns_disable_fallback', form) ?? false;
  const ifMatch = Form.useWatch<boolean>('xray_dns_disable_fallback_if_match', form) ?? false;
  const noCache = Form.useWatch<boolean>('xray_dns_disable_cache', form) ?? false;
  const stale = Form.useWatch<boolean>('xray_dns_serve_stale', form) ?? false;
  const clientIp = (Form.useWatch<string>('xray_dns_client_ip', form) ?? '').trim();
  const tag = (Form.useWatch<string>('xray_dns_tag', form) ?? '').trim();

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

      <div className="app-dns-table">
        {/* One field, two named modes — the switch was called "Спрашивать все
            сразу", so its OFF state ("по порядку") had no name at all. */}
        <RuleRow name={t('settings.dnsAskMode')}>
          <Form.Item name="xray_dns_parallel_query" noStyle>
            <AskMode />
          </Form.Item>
          <span className="app-dns-hint">
            {parallel ? t('settings.dnsAskAllHint') : t('settings.dnsAskOrderHint')}
          </span>
        </RuleRow>

        <RuleRow name={t('settings.dnsFallbackMode')}>
          <Form.Item name="xray_dns_disable_fallback" noStyle>
            <FallbackMode />
          </Form.Item>
          {/* The second half of this control, bound but not drawn. A field with
              no mounted `Form.Item` is not registered, so antd leaves it out of
              the values `onFinish` receives — and the backend takes it as
              `#[serde(default)]`, which would turn every save into a silent
              reset. Being registered also makes `useWatch` above see the write
              the segmented does with `setFieldValue`. */}
          <span className="app-dns-hidden">
            <Form.Item name="xray_dns_disable_fallback_if_match" noStyle valuePropName="checked">
              <Switch />
            </Form.Item>
          </span>
          <span className="app-dns-hint">{fallbackHint}</span>
        </RuleRow>

        <RuleRow name={t('settings.dnsCacheMode')}>
          <div className="app-dns-rule-line">
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
                flag above: it has to reach `onFinish`, and `useWatch` only
                tracks a field something has registered. */}
            <span className="app-dns-hidden">
              <Form.Item name="xray_dns_serve_stale" noStyle valuePropName="checked">
                <Switch />
              </Form.Item>
            </span>
          </div>
          <span className="app-dns-hint">{cacheHint}</span>
        </RuleRow>

        <RuleRow name={t('settings.xrayDnsQueryStrategy')}>
          <Form.Item name="xray_dns_query_strategy" noStyle>
            <Select
              size="small"
              popupMatchSelectWidth={false}
              options={DNS_QUERY_STRATEGIES.map((v) => ({ value: v, label: v }))}
            />
          </Form.Item>
          <span className="app-dns-hint">{t('settings.xrayDnsQueryStrategyHint')}</span>
        </RuleRow>

        <RuleRow name={t('settings.xrayDnsUseSystemHosts')}>
          <Form.Item name="xray_dns_use_system_hosts" noStyle valuePropName="checked">
            <Switch size="small" />
          </Form.Item>
          <span className="app-dns-hint">{t('settings.xrayDnsUseSystemHostsHint')}</span>
        </RuleRow>

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

        <div className={`app-dns-extra${extraOpen ? '' : ' app-dns-hidden'}`}>
          <RuleRow name={t('settings.xrayDnsClientIp')}>
            <Form.Item name="xray_dns_client_ip" noStyle>
              <Input size="small" spellCheck={false} placeholder={t('settings.dnsChipEmpty')} />
            </Form.Item>
            <span className="app-dns-hint">{t('settings.xrayDnsClientIpHint')}</span>
          </RuleRow>
          <RuleRow name={t('settings.xrayDnsTag')}>
            <Form.Item name="xray_dns_tag" noStyle>
              <Input size="small" spellCheck={false} placeholder={t('settings.dnsChipEmpty')} />
            </Form.Item>
            <span className="app-dns-hint">{t('settings.xrayDnsTagHint')}</span>
          </RuleRow>
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
