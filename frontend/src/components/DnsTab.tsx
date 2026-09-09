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
//! standing beside it in a column of its own — and behind the name on hover
//! where the card is too narrow to carry that column.
//!
//! Everything still binds through the parent `Form`, so the page dirty bar and
//! the save-then-restart prompt keep working untouched.

import { Button, Form, Input, InputNumber, Segmented, Select, Switch, Tooltip } from 'antd';
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
  const inert = configured && freedom === 'AsIs' && routing === 'AsIs';

  return (
    <div className="app-dns">
      {/* The one thing this tab has to say that nothing else on it does, and
          nothing at all the rest of the time.

          A heading used to stand here permanently, carrying a sentence about
          the state of the resolver. Two of its three states said what the
          sections below already say — "серверов: 1" duplicated the list right
          under it, and "ничего не задано" duplicated that list's own empty
          state — and the tab is titled by its own tab strip, so the name on it
          was a title for something already titled. What was left was a short
          line stranded on a full-width band, which is what it looked like.

          The third state is the one worth a band, precisely because it is not
          always there: a resolver the core will never ask is invisible in
          every other way. */}
      {inert && (
        <div className="app-dns-warn">
          <span className="app-dns-dot is-warn" aria-hidden="true" />
          <p className="app-dns-warn-text">{t('settings.dnsStatusInert')}</p>
          <Button
            size="small"
            onClick={() => {
              form.setFieldValue('xray_freedom_strategy', 'UseIP');
              onExternalChange?.();
            }}
          >
            {t('settings.dnsInertAction')}
          </Button>
        </div>
      )}

      {/* Carries the spacing between the sections. */}
      <div className="app-dns-body">
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
 *  consequence of the choice standing in it — three columns, in that order.
 *
 *  Every one of the three keeps its own left edge across all five rows. The
 *  layout before this pinned the controls to the RIGHT edge instead, and their
 *  left edges then landed wherever each control's width put them: on a 1250px
 *  card they staggered across 730px of empty middle. A ragged right edge reads
 *  as the end of content; a ragged left edge reads as a mistake.
 *
 *  The consequence is always on screen rather than appearing on the row that
 *  moved last. It is what fills the space to the right of the controls, so the
 *  block has no empty middle to explain away — and changing a mode rewrites
 *  the sentence in place, which says more than lighting the row up did. Below
 *  1100px the third column is too narrow to hold a sentence, and the CSS drops
 *  it; the name still carries it on hover at every width. */
function SettingRow({
  name,
  hint,
  children,
}: {
  name: string;
  hint: string;
  children: ReactNode;
}) {
  return (
    <div className="app-dns-row">
      <Tooltip title={hint}>
        <span className="app-dns-row-name">{name}</span>
      </Tooltip>
      <div className="app-dns-row-ctl">{children}</div>
      <span className="app-dns-why">{hint}</span>
    </div>
  );
}

function BehaviourSection() {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  const [extraOpen, setExtraOpen] = useState(false);

  // `useWatch` has nothing on the first render — it subscribes in an effect —
  // so every one of these falls back to the value the form already holds. The
  // sentences below are picked by these values, and a field that reads empty
  // for one frame would put the wrong sentence on screen and then swap it.
  const w = <T,>(name: string, watched: T | undefined, fallback: T): T =>
    watched ?? (form.getFieldValue(name) as T | undefined) ?? fallback;
  const parallel = w('xray_dns_parallel_query', Form.useWatch<boolean>('xray_dns_parallel_query', form), false);
  const noFallback = w('xray_dns_disable_fallback', Form.useWatch<boolean>('xray_dns_disable_fallback', form), false);
  const ifMatch = w('xray_dns_disable_fallback_if_match', Form.useWatch<boolean>('xray_dns_disable_fallback_if_match', form), false);
  const noCache = w('xray_dns_disable_cache', Form.useWatch<boolean>('xray_dns_disable_cache', form), false);
  const stale = w('xray_dns_serve_stale', Form.useWatch<boolean>('xray_dns_serve_stale', form), false);
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

      {/* Two groups, because the five are not one subject: three of them say
          how the core asks, and two say what it asks for. They are told apart
          by a quiet caption, by one hairline in the whole block, and by the
          second group being set smaller and tighter than the first — five rows
          of identical weight read as a list of five equal things, which these
          are not. */}
      <div className="app-dns-table app-dns-beh">
        <div className="app-dns-set">
          <div className="app-dns-set-cap">{t('settings.dnsGroupHow')}</div>

          <SettingRow
            name={t('settings.dnsAskMode')}
            hint={parallel ? t('settings.dnsAskAllHint') : t('settings.dnsAskOrderHint')}
          >
            <Form.Item name="xray_dns_parallel_query" noStyle>
              <AskMode />
            </Form.Item>
          </SettingRow>

          {/* The order is the order of a lookup: ask, then what happens when
              nobody answers, then what is kept from the answer. */}
          <SettingRow name={t('settings.dnsFallbackMode')} hint={fallbackHint}>
            <Form.Item name="xray_dns_disable_fallback" noStyle>
              <FallbackMode />
            </Form.Item>
            {/* Bound but not drawn: an unmounted Form.Item drops out of the
                values antd hands to `onFinish`, and every field here carries
                `#[serde(default)]` on the backend — so a save would quietly
                reset it. `useWatch` also only tracks a registered field. */}
            <span className="app-dns-hidden">
              <Form.Item name="xray_dns_disable_fallback_if_match" noStyle valuePropName="checked">
                <Switch />
              </Form.Item>
            </span>
          </SettingRow>

          <SettingRow name={t('settings.dnsCacheMode')} hint={cacheHint}>
            <Form.Item name="xray_dns_disable_cache" noStyle>
              <CacheMode />
            </Form.Item>
            <span className={`app-dns-ttl${stale ? '' : ' app-dns-hidden'}`}>
              {t('settings.dnsCacheTtl')}
              <Form.Item name="xray_dns_serve_expired_ttl" noStyle>
                <InputNumber size="small" min={0} max={86400} step={60} controls={false} />
              </Form.Item>
            </span>
            <span className="app-dns-hidden">
              <Form.Item name="xray_dns_serve_stale" noStyle valuePropName="checked">
                <Switch />
              </Form.Item>
            </span>
          </SettingRow>
        </div>

        <div className="app-dns-set is-minor">
          <div className="app-dns-set-cap">{t('settings.dnsGroupWhat')}</div>

          <SettingRow
            name={t('settings.xrayDnsQueryStrategy')}
            hint={t('settings.xrayDnsQueryStrategyHint')}
          >
            <Form.Item name="xray_dns_query_strategy" noStyle>
              <Select
                size="small"
                popupMatchSelectWidth={false}
                style={{ width: 136 }}
                options={DNS_QUERY_STRATEGIES.map((v) => ({ value: v, label: v }))}
              />
            </Form.Item>
          </SettingRow>

          <SettingRow
            name={t('settings.xrayDnsUseSystemHosts')}
            hint={t('settings.xrayDnsUseSystemHostsHint')}
          >
            <Form.Item name="xray_dns_use_system_hosts" noStyle valuePropName="checked">
              <Switch size="small" />
            </Form.Item>
          </SettingRow>
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

        {/* Revealed rather than snapped in, in both directions, and kept mounted
            while shut: `{cond && <Block/>}` tears the node out the instant cond
            turns false and leaves nothing to animate on the way out — and these
            two fields have to stay registered anyway, or they drop out of the
            values antd hands to `onFinish`.

            `inert` is what makes "collapsed" mean collapsed for the keyboard
            too: the CSS collapse hides the rows but leaves both inputs
            focusable, so tabbing through the tab would put the caret in an
            invisible field. */}
        <div
          className={`app-reveal app-dns-reveal${extraOpen ? ' is-in' : ''}`}
          inert={!extraOpen}
        >
          <div className="app-dns-set is-minor">
            <SettingRow name={t('settings.xrayDnsClientIp')} hint={t('settings.xrayDnsClientIpHint')}>
              <Form.Item name="xray_dns_client_ip" noStyle>
                <Input
                  size="small"
                  spellCheck={false}
                  style={{ width: 260 }}
                  placeholder={t('settings.dnsChipEmpty')}
                />
              </Form.Item>
            </SettingRow>
            <SettingRow name={t('settings.xrayDnsTag')} hint={t('settings.xrayDnsTagHint')}>
              <Form.Item name="xray_dns_tag" noStyle>
                <Input
                  size="small"
                  spellCheck={false}
                  style={{ width: 260 }}
                  placeholder={t('settings.dnsChipEmpty')}
                />
              </Form.Item>
            </SettingRow>
          </div>
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
