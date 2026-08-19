//! Static `hosts` editor for the Xray "DNS" tab.
//!
//! These answers are given before any server is asked, which makes the block do
//! two different jobs: pin a name to an address the resolver would not return
//! (a LAN box, a service reached by its internal IP), or point a whole geosite
//! category at `127.0.0.1` and have it answered into the void.
//!
//! The key is a matcher, not just a hostname: `domain:`, `geosite:`, `regexp:`
//! and `keyword:` all work, exactly as they do in the routing lists.
//!
//! The two controls keep their normal borders. Stripping them read as clean
//! until you had to use the block: a matcher and an address in plain text look
//! like a printed row, and nothing said you could type there.

import { Button, Input, Select } from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { DnsHost } from '@/api/types/settings';

interface Props {
  value?: DnsHost[];
  onChange?: (next: DnsHost[]) => void;
}

export function DnsHostsField({ value, onChange }: Props) {
  const { t } = useTranslation();
  const list = useMemo(() => value ?? [], [value]);

  const patch = (i: number, next: Partial<DnsHost>) =>
    onChange?.(list.map((h, j) => (j === i ? { ...h, ...next } : h)));

  return (
    <section className="app-dns-section">
      <div className="app-dns-head">
        <span className="app-dns-title">{t('settings.xrayDnsHosts')}</span>
        <span className="app-dns-sub">{t('settings.dnsHostsSub')}</span>
        <Button
          size="small"
          icon={<PlusOutlined />}
          onClick={() => onChange?.([...list, { domain: '', values: [] }])}
        >
          {t('settings.dnsAddHost')}
        </Button>
      </div>

      {list.length === 0 ? (
        <div className="app-dns-empty">{t('settings.dnsNoHosts')}</div>
      ) : (
        <div className="app-dns-table">
          {list.map((h, i) => (
            <div key={i} className="app-dns-hr-row">
              <Input
                className="app-dns-host-key"
                value={h.domain}
                onChange={(e) => patch(i, { domain: e.target.value })}
                placeholder={t('settings.dnsHostDomainPlaceholder')}
                spellCheck={false}
              />
              <span className="app-dns-arrow" aria-hidden="true">
                →
              </span>
              <Select
                className="app-dns-host-values"
                mode="tags"
                value={h.values}
                onChange={(v: string[]) => patch(i, { values: v })}
                tokenSeparators={[',', ' ']}
                placeholder={t('settings.dnsHostValuePlaceholder')}
                open={false}
              />
              <Button
                type="text"
                size="small"
                icon={<DeleteOutlined />}
                onClick={() => onChange?.(list.filter((_, j) => j !== i))}
              />
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
