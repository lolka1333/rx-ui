//! Name-server table for the Xray "DNS" settings tab.
//!
//! A resolver list is ordered — xray walks it top-down and falls back down the
//! list — so this is a numbered list, not a bag of chips. And every server
//! carries its own rules, which is what earns it a TABLE rather than a stack of
//! addresses: the columns answer the two questions an operator actually has —
//! which names does this one answer, and what is it allowed to answer with.
//! Before, both lived behind the row's edit dialog, so the list showed three
//! identical-looking addresses and told you nothing.
//!
//! `domains` is what makes split-horizon resolution possible (a country's
//! resolver for the country's own names, a foreign one for the rest);
//! `expectedIPs` / `unexpectedIPs` filter the answer itself, the standard
//! defence against a resolver that lies about where an address is.
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
  Select,
  Switch,
  Tabs,
  Tag,
} from 'antd';
import type { MenuProps } from 'antd';
import {
  ArrowDownOutlined,
  ArrowUpOutlined,
  CheckOutlined,
  CloseOutlined,
  DeleteOutlined,
  EditOutlined,
  MoreOutlined,
  PlusOutlined,
} from '@ant-design/icons';
import { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { DnsServer } from '@/api/types/settings';
import { DNS_PRESETS, DNS_QUERY_STRATEGIES, strategyClashes } from '@/lib/dnsPresets';
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

/** What the row says under the address: how this query travels. That is the
 *  one difference an operator cares about between two spellings of the same
 *  provider — a `+local` resolver answers from the node, a plain one sends its
 *  own queries back through routing and, on a relay, down the tunnel.
 *
 *  Returns a translation key, or null when the address says it already. */
function transportKeyOf(address: string): string | null {
  const a = address.toLowerCase();
  if (a.startsWith('https+local://') || a.startsWith('h2c+local://')) return 'dnsWireDohLocal';
  if (a.startsWith('https://') || a.startsWith('h2c://')) return 'dnsWireDoh';
  if (a.startsWith('quic+local://')) return 'dnsWireQuicLocal';
  if (a.startsWith('tcp+local://')) return 'dnsWireTcpLocal';
  if (a.startsWith('tcp://')) return 'dnsWireTcp';
  if (a === 'localhost' || a === '') return null;
  return 'dnsWireUdp';
}

/** What the table shows for an address. For a URL form that is the host alone:
 *  the scheme is already spelled out by the transport label beside it, and the
 *  path is the least useful part of `https://1.1.1.1/dns-query` — spelling the
 *  whole thing out clipped the row instead of informing it. The full value
 *  stays one hover (and one dialog) away. */
function displayAddress(address: string): string {
  const m = /^[a-z0-9+]+:\/\/([^/]+)/i.exec(address.trim());
  return m ? m[1] : address;
}

/** `editing` while the dialog holds a server that is not in the list yet. */
const NEW = -1;

interface Props {
  value?: DnsServer[];
  onChange?: (next: DnsServer[]) => void;
}

export function DnsServersField({ value, onChange }: Props) {
  const { t } = useTranslation();
  // The section's own strategy, read from the page form this field lives in:
  // a per-server value is checked against it before it can be picked.
  const page = Form.useFormInstance();
  // `useWatch` has nothing on the first render — it subscribes in an effect —
  // and the form itself already knows the answer.
  const watched = Form.useWatch<string>('xray_dns_query_strategy', page);
  const sectionStrategy = watched ?? page.getFieldValue('xray_dns_query_strategy') ?? 'UseIP';
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

  // Adding used to append an empty server and then open the dialog on it, so
  // pressing Cancel left a nameless row behind — click the button five times,
  // get five of them. Nothing is committed until Save now.
  const add = () => setEditing(NEW);

  return (
    <section className="app-dns-section">
      <div className="app-dns-head">
        <span className="app-dns-title">{t('settings.xrayDnsServers')}</span>
        <span className="app-dns-sub">{t('settings.dnsServersSub')}</span>
        <Button size="small" icon={<PlusOutlined />} onClick={add}>
          {t('settings.dnsAddServer')}
        </Button>
      </div>

      {list.length === 0 ? (
        <div className="app-dns-empty">{t('settings.dnsNoServers')}</div>
      ) : (
        <div className="app-dns-table">
          <div className="app-dns-tr app-dns-th">
            <span>№</span>
            <span>{t('settings.dnsColAddress')}</span>
            <span>{t('settings.dnsColDomains')}</span>
            <span>{t('settings.dnsColFilter')}</span>
            <span>{t('settings.dnsColMode')}</span>
            <span />
          </div>

          {list.map((s, i) => {
            const wire = transportKeyOf(s.address);
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
            const mode = [
              ...(s.skip_fallback ? [t('settings.dnsSkipFallbackTag')] : []),
              ...(s.final_query ? [t('settings.dnsFinalQueryTag')] : []),
            ];
            return (
              <div key={`${s.address}-${i}`} className="app-dns-tr">
                <span className="app-dns-num">{i + 1}</span>

                {/* Address and how the query travels on ONE line: stacked, they
                    set the height of every row in the table for a value most
                    rows spend on the word "UDP". The provider's name is gone
                    from here on purpose — the address already says it. */}
                <span className="app-dns-cell app-dns-cell-addr">
                  <span className="app-dns-addr" title={s.address || undefined}>
                    {s.address ? displayAddress(s.address) : t('settings.dnsNoAddress')}
                    {s.port ? <span className="app-dns-port">:{s.port}</span> : null}
                  </span>
                  {wire && <span className="app-dns-sub">{t(`settings.${wire}`)}</span>}
                </span>

                <span className="app-dns-cell">
                  {s.domains.length === 0 ? (
                    <span className="app-dns-muted">{t('settings.dnsAllOther')}</span>
                  ) : (
                    <span className="app-dns-tags">
                      {s.domains.map((d) => (
                        <Tag key={d}>{d}</Tag>
                      ))}
                    </span>
                  )}
                </span>

                <span className="app-dns-cell">
                  {s.expect_ips.length === 0 && s.unexpected_ips.length === 0 ? (
                    <span className="app-dns-dash">—</span>
                  ) : (
                    <span className="app-dns-tags">
                      {s.expect_ips.map((ip) => (
                        <Tag key={`e-${ip}`} color="green" icon={<CheckOutlined />}>
                          {ip}
                        </Tag>
                      ))}
                      {s.unexpected_ips.map((ip) => (
                        <Tag key={`u-${ip}`} color="red" icon={<CloseOutlined />}>
                          {ip}
                        </Tag>
                      ))}
                    </span>
                  )}
                </span>

                <span className="app-dns-cell">
                  {mode.length === 0 ? (
                    <span className="app-dns-dash">—</span>
                  ) : (
                    <span className="app-dns-tags">
                      {mode.map((m) => (
                        <Tag key={m}>{m}</Tag>
                      ))}
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
          })}
        </div>
      )}

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

/** The per-server sheet, on tabs — the same shape the inbound dialog uses, so
 *  the panel keeps one answer for "this form is bigger than a dialog". Ten
 *  fields in one column made it 888px tall: taller than most screens, always
 *  scrolling, and half of it sitting at "same as the section".
 *
 *  What a tab costs is visibility: a value set on the hidden tab is a value the
 *  operator cannot see. Hence the count on "Дополнительно" — the tab says how
 *  many of its fields carry something, so nothing hides in there silently.
 *
 *  Everything is optional except the address; a server saved with only an
 *  address is stored — and emitted — as a plain address. */
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
  // 0 means "whatever the core does by default" — showing it as a literal zero
  // reads as "zero milliseconds", so these two open empty and carry a
  // placeholder instead. `onOk` maps the empty field back to 0.
  const initial = {
    ...server,
    port: server.port || undefined,
    timeout_ms: server.timeout_ms || undefined,
  };

  const address = Form.useWatch('address', form);
  const strategy = Form.useWatch('query_strategy', form);
  const clientIp = Form.useWatch('client_ip', form);
  const timeout = Form.useWatch('timeout_ms', form);
  const extraSet = [strategy, clientIp, timeout].filter(Boolean).length;

  const main = (
    <>
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
                <span>
                  {o.code ? <span className="geo-code">{o.code}</span> : null}
                  {o.label}
                  <span className="app-dns-note">{o.value}</span>
                </span>
              ),
            }))}
            filterOption={(input, option) =>
              String(option?.value ?? '')
                .toLowerCase()
                .includes(input.toLowerCase())
            }
            placeholder="1.1.1.1"
          />
        </Form.Item>
        <Form.Item
          name="port"
          label={t('settings.dnsServerPort')}
          tooltip={t('settings.dnsServerPortHint')}
        >
          <InputNumber min={0} max={65535} placeholder="53" style={{ width: '100%' }} />
        </Form.Item>
      </div>

      <Form.Item
        name="domains"
        label={t('settings.dnsServerDomains')}
        tooltip={t('settings.dnsServerDomainsHint')}
      >
        <Select mode="tags" options={GEOSITE_PRESETS} tokenSeparators={[',', ' ']} />
      </Form.Item>

      {/* One decision with two sides, so the two lists sit side by side. */}
      <div className="app-dns-form-duo">
        <Form.Item
          name="expect_ips"
          label={t('settings.dnsServerExpectIps')}
          tooltip={t('settings.dnsServerExpectIpsHint')}
        >
          <Select mode="tags" options={GEOIP_PRESETS} tokenSeparators={[',', ' ']} />
        </Form.Item>
        <Form.Item
          name="unexpected_ips"
          label={t('settings.dnsServerUnexpectedIps')}
          tooltip={t('settings.dnsServerUnexpectedIpsHint')}
        >
          <Select mode="tags" options={GEOIP_PRESETS} tokenSeparators={[',', ' ']} />
        </Form.Item>
      </div>

      {/* Switch rows, not "label above, switch below": the label and the thing
          it controls belong on one line. */}
      <div className="app-dns-form-switch">
        <span>
          <span className="app-dns-form-switch-name">{t('settings.dnsServerSkipFallback')}</span>
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
          <span className="app-dns-form-switch-desc">{t('settings.dnsServerFinalQueryHint')}</span>
        </span>
        <Form.Item name="final_query" noStyle valuePropName="checked">
          <Switch size="small" />
        </Form.Item>
      </div>
    </>
  );

  const extra = (
    <>
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
        tooltip={t('settings.dnsClientIpHint')}
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
    </>
  );

  return (
    <Modal
      open={open}
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
        const v = form.getFieldsValue();
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
      <Form
        key={formKey}
        form={form}
        layout="vertical"
        initialValues={initial}
        className="app-form-rows"
      >
        <Tabs
          className="app-dns-form-tabs"
          items={[
            {
              key: 'main',
              // Both panes stay mounted: the save reads the whole form at once,
              // and a lazily-mounted tab is a tab whose values arrive late.
              forceRender: true,
              label: t('settings.dnsTabServer'),
              children: main,
            },
            {
              key: 'extra',
              forceRender: true,
              label: (
                <span className="app-dns-tab-label">
                  {t('settings.dnsTabExtra')}
                  {extraSet > 0 && <span className="app-dns-tab-count">{extraSet}</span>}
                </span>
              ),
              children: extra,
            },
          ]}
        />
      </Form>
    </Modal>
  );
}
