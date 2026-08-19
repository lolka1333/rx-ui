//! The whole "DNS" tab of the Xray settings: server table, static answers, and
//! one dense behaviour strip.
//!
//! It lives outside `Settings.tsx` because it is not built from that page's
//! two-column field rows. Those rows put a paragraph of explanation beside
//! every control, which is right for four settings and wrong for fourteen: the
//! resolver's switches ran six paragraphs deep and buried the one thing that
//! matters — the list of servers. Here the explanations move into tooltips and
//! the switches into a grid, so the tab opens on data instead of prose.
//!
//! Everything still binds through the parent `Form`, so the page dirty bar and
//! the save-then-restart prompt keep working untouched.

import { Form, Input, InputNumber, Select, Switch, Tooltip } from 'antd';
import { useTranslation } from 'react-i18next';
import { DnsServersField } from '@/components/DnsServersField';
import { DnsHostsField } from '@/components/DnsHostsField';
import { DNS_QUERY_STRATEGIES } from '@/lib/dnsPresets';

/** The section-wide switches, in the order an operator meets them: what to ask,
 *  what to do when it fails, then what to keep. */
const SWITCHES = [
  { name: 'xray_dns_parallel_query', label: 'xrayDnsParallelQuery' },
  { name: 'xray_dns_disable_fallback', label: 'xrayDnsDisableFallback' },
  { name: 'xray_dns_disable_fallback_if_match', label: 'xrayDnsDisableFallbackIfMatch' },
  { name: 'xray_dns_use_system_hosts', label: 'xrayDnsUseSystemHosts' },
  { name: 'xray_dns_disable_cache', label: 'xrayDnsDisableCache' },
  { name: 'xray_dns_serve_stale', label: 'xrayDnsServeStale' },
] as const;

export function DnsTab() {
  const { t } = useTranslation();
  const enabled = Form.useWatch<boolean>('xray_dns_enabled');
  const on = enabled !== false;

  return (
    <div className="app-dns">
      {/* The master switch. Off keeps every field below on screen — dimmed,
          not hidden: a setup that disappears reads as deleted, and the whole
          point of the switch is that nothing is lost. */}
      <label className="app-dns-master">
        <Form.Item name="xray_dns_enabled" noStyle valuePropName="checked">
          <Switch />
        </Form.Item>
        <span className="app-dns-master-text">
          <span className="app-dns-master-name">{t('settings.dnsEnabled')}</span>
          <span className="app-dns-master-desc">
            {on ? t('settings.dnsEnabledOnHint') : t('settings.dnsEnabledOffHint')}
          </span>
        </span>
      </label>

      {/* The wrapper always carries `app-dns-body` — the spacing between the
          sections lives there. It used to live in `app-dns-off`, which is only
          applied while the resolver is switched off, so with DNS ON the
          sections had no gap at all and sat glued to each other. */}
      <div className={`app-dns-body${on ? '' : ' app-dns-off'}`} aria-disabled={!on}>
      <Form.Item name="xray_dns_servers" noStyle>
        <DnsServersField />
      </Form.Item>

      <Form.Item name="xray_dns_hosts" noStyle>
        <DnsHostsField />
      </Form.Item>

      <section className="app-dns-section">
        <div className="app-dns-head">
          <span className="app-dns-title">{t('settings.xrayGroupDnsBehaviour')}</span>
          <span className="app-dns-sub">{t('settings.dnsHoverHint')}</span>
        </div>

        <div className="app-dns-behaviour">
          {/* The three values that describe the section as a whole. Compact
              controls rather than full rows: each is one short value, and
              stacked full-width they read as three unrelated forms. */}
          <div className="app-dns-chips">
            <label className="app-dns-chip">
              <span className="app-dns-chip-name">{t('settings.dnsChipStrategy')}</span>
              <Form.Item name="xray_dns_query_strategy" noStyle>
                <Select
                  variant="borderless"
                  size="small"
                  popupMatchSelectWidth={false}
                  options={DNS_QUERY_STRATEGIES.map((v) => ({ value: v, label: v }))}
                />
              </Form.Item>
            </label>

            <Tooltip title={t('settings.xrayDnsClientIpHint')}>
              <label className="app-dns-chip app-dns-chip-grow">
                <span className="app-dns-chip-name">{t('settings.dnsChipEdns')}</span>
                <Form.Item name="xray_dns_client_ip" noStyle>
                  <Input
                    variant="borderless"
                    size="small"
                    spellCheck={false}
                    placeholder={t('settings.dnsChipEmpty')}
                  />
                </Form.Item>
              </label>
            </Tooltip>

            <Tooltip title={t('settings.xrayDnsTagHint')}>
              <label className="app-dns-chip app-dns-chip-grow">
                <span className="app-dns-chip-name">{t('settings.dnsChipTag')}</span>
                <Form.Item name="xray_dns_tag" noStyle>
                  <Input
                    variant="borderless"
                    size="small"
                    spellCheck={false}
                    placeholder={t('settings.dnsChipEmpty')}
                  />
                </Form.Item>
              </label>
            </Tooltip>

            {/* Only meaningful while stale answers are allowed, so it appears
                with them instead of sitting in the strip doing nothing. */}
            <Form.Item
              noStyle
              shouldUpdate={(a, b) => a.xray_dns_serve_stale !== b.xray_dns_serve_stale}
            >
              {({ getFieldValue }) =>
                getFieldValue('xray_dns_serve_stale') ? (
                  <Tooltip title={t('settings.xrayDnsServeExpiredTtlHint')}>
                    <label className="app-dns-chip">
                      <span className="app-dns-chip-name">{t('settings.dnsChipTtl')}</span>
                      <Form.Item name="xray_dns_serve_expired_ttl" noStyle>
                        <InputNumber
                          variant="borderless"
                          size="small"
                          min={0}
                          max={86400}
                          step={60}
                          controls={false}
                          placeholder="0"
                        />
                      </Form.Item>
                    </label>
                  </Tooltip>
                ) : null
              }
            </Form.Item>
          </div>

          <div className="app-dns-rule" />

          {/* Switch first, name right after it: with the name on the left and
              the switch pushed to the column's far edge, every item carried a
              strip of dead space in the middle and the block read as mostly
              nothing. Content-sized items that wrap have no such gap. */}
          <div className="app-dns-switches">
            {SWITCHES.map((s) => (
              <span key={s.name} className="app-dns-switch">
                <Form.Item name={s.name} noStyle valuePropName="checked">
                  <Switch size="small" />
                </Form.Item>
                <Tooltip title={t(`settings.${s.label}Hint`)}>
                  <span className="app-dns-switch-name">{t(`settings.${s.label}`)}</span>
                </Tooltip>
              </span>
            ))}
          </div>
        </div>
      </section>
      </div>
    </div>
  );
}
