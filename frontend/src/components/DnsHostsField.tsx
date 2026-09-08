//! Static `hosts` editor for the Xray "DNS" tab — stage 1 of the lookup.
//!
//! These answers are given before any server is asked, which makes the block do
//! two different jobs: pin a name to an address the resolver would not return
//! (a LAN box, a service reached by its internal IP), or point a whole geosite
//! category at `127.0.0.1` and have it answered into the void.
//!
//! The key is a matcher, not just a hostname: `domain:`, `geosite:`, `regexp:`
//! and `keyword:` all work, exactly as they do in the routing lists. Which KIND
//! of matcher it is changes what the row covers — one host or a whole category
//! — so the prefix is called out as a badge instead of running into the name.
//!
//! The two controls keep their normal borders. Stripping them read as clean
//! until you had to use the block: a matcher and an address in plain text look
//! like a printed row, and nothing said you could type there.

import { Button, Input, Select, Tag } from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { DnsHost } from '@/api/types/settings';

/** Which matcher family a key belongs to, as a translation suffix. The prefixes
 *  are xray's own (`infra/conf/dns.go`); anything without one is a plain name.
 *  `geoip:` is deliberately absent — a hosts KEY is a domain matcher, so an IP
 *  list there would never match. */
function matcherKey(key: string): string {
  const k = key.trim().toLowerCase();
  if (k.startsWith('geosite:')) return 'Geosite';
  if (k.startsWith('domain:')) return 'Domain';
  if (k.startsWith('regexp:')) return 'Regexp';
  if (k.startsWith('keyword:')) return 'Keyword';
  if (k.startsWith('full:')) return 'Full';
  return 'Plain';
}

/** Addresses that mean "answer, but with nowhere to go". Pointing a category
 *  here is how the block is mostly used, and it is worth naming: a row reading
 *  `geosite:category-ads-all → 127.0.0.1` only says "blocked" to someone who
 *  already knows the idiom. */
const VOID_ADDRESSES = new Set(['127.0.0.1', '0.0.0.0', '::1', '::']);
const answersIntoTheVoid = (values: string[]): boolean =>
  values.length > 0 && values.every((v) => VOID_ADDRESSES.has(v.trim()));

interface Props {
  /** Which step of the lookup this block is, drawn in its heading. */
  step?: number;
  value?: DnsHost[];
  onChange?: (next: DnsHost[]) => void;
}

export function DnsHostsField({ step, value, onChange }: Props) {
  const { t } = useTranslation();
  const list = useMemo(() => value ?? [], [value]);

  const patch = (i: number, next: Partial<DnsHost>) =>
    onChange?.(list.map((h, j) => (j === i ? { ...h, ...next } : h)));
  const append = (row: DnsHost) => onChange?.([...list, row]);

  return (
    <section className="app-dns-section">
      <div className="app-dns-head">
        {step !== undefined && (
          <span className="app-dns-stage-n" aria-hidden="true">
            {step}
          </span>
        )}
        <span className="app-dns-title">{t('settings.xrayDnsHosts')}</span>
        <span className="app-dns-sub">{t('settings.dnsHostsSub')}</span>
        <Button
          size="small"
          icon={<PlusOutlined />}
          onClick={() => append({ domain: '', values: [] })}
        >
          {t('settings.dnsAddHost')}
        </Button>
      </div>

      <div className="app-dns-table">
        {list.length === 0 ? (
          /* An empty block is where an operator is most stuck, so it offers to
             do the work rather than reporting that there is none. Blocking ads
             is what this block is for more often than anything else. */
          <div className="app-dns-empty">
            <span>{t('settings.dnsNoHosts')}</span>
            <span className="app-dns-recipes">
              <Button
                size="small"
                onClick={() =>
                  append({ domain: 'geosite:category-ads-all', values: ['127.0.0.1'] })
                }
              >
                {t('settings.dnsHostRecipeAds')}
              </Button>
              <Button size="small" onClick={() => append({ domain: '', values: [] })}>
                {t('settings.dnsHostRecipeOwn')}
              </Button>
            </span>
          </div>
        ) : (
          list.map((h, i) => (
            <div key={i} className="app-dns-hr-row">
              <Input
                className="app-dns-host-key"
                value={h.domain}
                onChange={(e) => patch(i, { domain: e.target.value })}
                placeholder={t('settings.dnsHostDomainPlaceholder')}
                spellCheck={false}
                prefix={
                  <span className="app-dns-badge">
                    {t(`settings.dnsMatcher${matcherKey(h.domain)}`)}
                  </span>
                }
              />
              <span className="app-dns-arrow" aria-hidden="true">
                →
              </span>
              <span className="app-dns-host-val">
                <Select
                  className="app-dns-host-values"
                  mode="tags"
                  value={h.values}
                  onChange={(v: string[]) => patch(i, { values: v })}
                  tokenSeparators={[',', ' ']}
                  placeholder={t('settings.dnsHostValuePlaceholder')}
                  open={false}
                />
                {answersIntoTheVoid(h.values) && (
                  <Tag color="red" className="app-dns-void">
                    {t('settings.dnsHostVoid')}
                  </Tag>
                )}
              </span>
              <Button
                type="text"
                size="small"
                icon={<DeleteOutlined />}
                onClick={() => onChange?.(list.filter((_, j) => j !== i))}
              />
            </div>
          ))
        )}
      </div>
    </section>
  );
}
