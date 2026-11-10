/** The clients table: one row per email, with the live state and the
 *  per-user actions. */
import { Button, Popconfirm, Popover, Space, Switch, Table, Tag, Typography } from 'antd';
import { DeleteOutlined, EditOutlined, ShareAltOutlined, UndoOutlined } from '@ant-design/icons';
import { useLayoutEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc';
import { TrafficCell } from '@/components/TrafficCell';
import { fmtBytes } from '@/lib/format';
import type { Client, Inbound } from '@/api/types';
import type { TrafficSnapshotMap, ClientGroup } from './groups';
import type { ClientActions } from './useClientActions';
import { fitCount } from './tagFit';

// Expiry timestamps are stored UTC; parse/format them in UTC and let the
// browser localize for display.
dayjs.extend(utc);

export function ClientsTable({
  groups,
  clientsCount,
  stats,
  inboundById,
  onPickInbound,
  onEdit,
  actions,
}: {
  groups: ClientGroup[];
  /** Rows before any filter: tells "no clients" from "none match". */
  clientsCount: number;
  stats: TrafficSnapshotMap;
  inboundById: Map<string, Inbound>;
  onPickInbound: (id: string) => void;
  onEdit: (client: Client) => void;
  actions: ClientActions;
}) {
  const { t } = useTranslation();
  const { toggleGroup, resetTrafficGroup, deleteGroup, openShare } = actions;
  return (
    <Table<ClientGroup>
      rowKey="email"
      dataSource={groups}
      pagination={{
        defaultPageSize: 25,
        showSizeChanger: true,
        pageSizeOptions: ['10', '25', '50', '100'],
      }}
      size="small"
      scroll={{ x: 'max-content' }}
      locale={{
        emptyText: (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {clientsCount === 0
              ? t('clients.empty')
              : t('clients.emptyFiltered')}
          </Typography.Text>
        ),
      }}
      columns={[
        {
          title: '',
          key: 'enabled',
          width: 50,
          // Switch is checked only when ALL rows in the group are
          // enabled — partial state renders as off, so one click
          // flips the whole identity on (no ambiguity about what
          // "checked" means for a mixed group). `loading` while the save
          // is in flight shows a spinner AND blocks re-clicks, so spamming
          // it back-and-forth can't flood the API or thrash the list. antd
          // draws a not-allowed cursor on a loading switch; styles/chrome.css
          // overrides it to a pointer so it reads as "saving", not "blocked".
          render: (_, g) => (
            <Switch
              size="small"
              checked={g.allEnabled}
              loading={
                toggleGroup.isPending &&
                toggleGroup.variables?.email === g.email
              }
              onChange={(v) =>
                toggleGroup.mutate({ email: g.email, rows: g.rows, enabled: v })
              }
            />
          ),
        },
        {
          // Email + first non-empty note across the group's rows. The
          // note is per-row in the DB but bulk-assign keeps them in
          // sync, so taking the first non-empty is harmless and reads
          // as "the user's note."
          title: t('clients.email'),
          key: 'email',
          // As narrow as its content: the spare width belongs to the inbound
          // column, the one column that has a use for it. `nowrap` is what
          // keeps "as narrow as" from meaning "broken at every hyphen", and
          // the note is capped so a long one truncates instead of widening.
          width: 1,
          render: (_, g) => (
            <div
              style={{ display: 'flex', flexDirection: 'column', minWidth: 0, whiteSpace: 'nowrap' }}
            >
              <Typography.Text strong>{g.email}</Typography.Text>
              {g.note && (
                <Typography.Text
                  type="secondary"
                  ellipsis={{ tooltip: g.note }}
                  style={{ fontSize: 11, lineHeight: '14px', maxWidth: 260 }}
                >
                  {g.note}
                </Typography.Text>
              )}
              {g.expiresAt && (
                <Typography.Text
                  type={g.anyDisabledByExpiry ? 'danger' : 'secondary'}
                  style={{ fontSize: 11, lineHeight: '14px' }}
                >
                  {g.anyDisabledByExpiry
                    ? t('clients.expired')
                    : t('clients.expiresOn', {
                        date: dayjs
                          .utc(g.expiresAt)
                          .local()
                          .format('YYYY-MM-DD HH:mm'),
                      })}
                </Typography.Text>
              )}
            </div>
          ),
        },
        {
          // The one column without a width: whatever the table has left over
          // goes here, and `InboundTags` fills it with as many tags as fit.
          title: t('clients.inbound'),
          key: 'inbound',
          render: (_, g) => (
            <InboundTags
              inboundIds={g.inboundIds}
              inboundById={inboundById}
              onPickFilter={onPickInbound}
            />
          ),
        },
        {
          title: t('clients.online'),
          key: 'online',
          width: 90,
          align: 'center',
          // Online state is per-email in xray's StatsService — all
          // rows of the group share it. Read once.
          render: (_, g) => {
            const online = stats[g.email]?.online ?? false;
            // Real CSS dot — bullet glyphs (●/○) hint at the font's
            // own dot metrics, which on Inter/Segoe UI render
            // stem-heavy and slightly off-baseline. `vertical-align:
            // middle` aligns the dot to the text's lowercase visual
            // centre (not the line-box centre), which for short
            // Cyrillic labels with no descenders is what reads as
            // "centred". The `.live` pulse comes from the same
            // status-dot class as the xray indicator.
            // Hand-styled Tag instead of Antd's `color="green"`
            // preset — the latter resolves to #52c41a (lime-yellow
            // green that reads sickly against the dark surface).
            // Emerald 500 matches the dot colour and the accent
            // palette. `variant="filled"` drops the 1 px outline —
            // on a low-contrast translucent fill the border showed
            // as a pale rim that read as "white stripes" against
            // the dark table row. Fixed `minWidth` keeps online
            // and offline pills the same width so the column
            // doesn't wobble between "в сети" and "не в сети".
            const fg = online ? '#34d399' : '#94a3b8';
            const bg = online ? 'rgba(34, 197, 94, 0.14)' : 'rgba(148, 163, 184, 0.12)';
            return (
              <Tag
                variant="filled"
                style={{
                  color: fg,
                  background: bg,
                  minWidth: 78,
                  textAlign: 'center',
                  margin: 0,
                }}
              >
                <span
                  className="app-status-dot"
                  style={{
                    color: fg,
                    verticalAlign: 'middle',
                    marginInlineEnd: 6,
                  }}
                />
                {online ? t('clients.statusOnline') : t('clients.statusOffline')}
              </Tag>
            );
          },
        },
        {
          title: t('clients.traffic'),
          key: 'traffic',
          width: 200,
          // Traffic and rate are email-keyed in xray's StatsService —
          // read once per group (vs once per row), so the same number
          // doesn't appear on three rows of the same identity. Limit
          // is the aggregate cap across the group's rows; unlimited
          // on ANY row makes the group unlimited.
          render: (_, g) => {
            const s = stats[g.email];
            if (!s) {
              return <Typography.Text type="secondary">—</Typography.Text>;
            }
            const live =
              g.anyEnabled && (s.uplink_bps > 0 || s.downlink_bps > 0);
            return (
              <TrafficCell
                live={live}
                up={fmtBytes(s.uplink_total)}
                down={fmtBytes(s.downlink_total)}
                used={s.uplink_total + s.downlink_total}
                limit={g.totalLimit}
              />
            );
          },
        },
        {
          title: t('clients.rate'),
          key: 'rate',
          width: 180,
          align: 'center',
          render: (_, g) => {
            const s = stats[g.email];
            if (!s || (s.uplink_bps === 0 && s.downlink_bps === 0)) {
              return <Typography.Text type="secondary">—</Typography.Text>;
            }
            return (
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 12,
                  fontSize: 12,
                  color: '#60a5fa',
                  fontVariantNumeric: 'tabular-nums',
                  whiteSpace: 'nowrap',
                }}
              >
                <span>↑ {fmtBytes(s.uplink_bps)}/s</span>
                <span>↓ {fmtBytes(s.downlink_bps)}/s</span>
              </span>
            );
          },
        },
        {
          title: t('clients.actions'),
          key: 'actions',
          align: 'right',
          width: 180,
          render: (_, g) => (
            <Space>
              <Button
                type="text"
                size="small"
                icon={<ShareAltOutlined />}
                loading={
                  openShare.isPending && openShare.variables?.email === g.email
                }
                onClick={() => openShare.mutate(g)}
                title={t('clients.shareLink')}
              />
              <Popconfirm
                title={t('clients.resetTrafficConfirm')}
                okText={t('common.confirm')}
                cancelText={t('common.cancel')}
                onConfirm={() =>
                  resetTrafficGroup.mutate({ email: g.email, rows: g.rows })
                }
              >
                <Button
                  type="text"
                  size="small"
                  icon={<UndoOutlined />}
                  loading={
                    resetTrafficGroup.isPending &&
                    resetTrafficGroup.variables?.email === g.email
                  }
                  title={t('clients.resetTraffic')}
                />
              </Popconfirm>
              <Button
                type="text"
                size="small"
                icon={<EditOutlined />}
                onClick={() => onEdit(g.rows[0])}
              />
              <Popconfirm
                title={t('clients.deleteConfirm')}
                okType="danger"
                okText={t('common.delete')}
                cancelText={t('common.cancel')}
                onConfirm={() =>
                  deleteGroup.mutate({ email: g.email, rows: g.rows })
                }
              >
                <Button type="text" danger size="small" icon={<DeleteOutlined />} />
              </Popconfirm>
            </Space>
          ),
        },
      ]}
    />
  );
}

/** 6 px between chips — 4 px read as "almost-touching" when adjacent chips have
 *  wider Antd padding (the visual margin between borders shrinks to ~1 px),
 *  8 px feels loose. 6 lands at the eye's notion of "small but clearly
 *  separated." */
const TAG_GAP = 6;

/** An email-group's assigned inbounds: as many tags as the column has room for,
 *  the rest folded into a "+N" chip whose Popover lists them. On a wide screen
 *  that is usually all of them; on a phone, one or two.
 *
 *  The row never decides the column's width — `contain: inline-size` keeps the
 *  tags out of the table's sizing, so a user on ten servers cannot stretch the
 *  table, and the column takes what the layout leaves (see the column's note).
 *  The tags are measured in a hidden copy of the row and re-fitted whenever the
 *  cell changes size. Each tag stays click-to-filter so the keyboard-light
 *  workflow ("show me everyone on this inbound") still works. */
function InboundTags({
  inboundIds,
  inboundById,
  onPickFilter,
}: {
  inboundIds: string[];
  inboundById: Map<string, Inbound>;
  onPickFilter: (id: string) => void;
}) {
  const { t } = useTranslation();
  const boxRef = useRef<HTMLDivElement>(null);
  const measureRef = useRef<HTMLDivElement>(null);
  const [shown, setShown] = useState(inboundIds.length);
  const renderTag = (id: string, interactive = true) => {
    const ib = inboundById.get(id);
    return ib ? (
      <Tag
        key={id}
        color="geekblue"
        style={{ cursor: 'pointer', marginInlineEnd: 0, flexShrink: 0 }}
        onClick={interactive ? () => onPickFilter(id) : undefined}
        title={interactive ? t('clients.filterByThisInbound') : undefined}
      >
        {ib.tag}
      </Tag>
    ) : (
      <Typography.Text key={id} type="secondary" style={{ fontSize: 12, flexShrink: 0 }}>
        {id.slice(0, 8)}…
      </Typography.Text>
    );
  };
  // What the row shows, as a string: a re-fit is due when a tag is added,
  // removed or renamed, not on every 5 s poll that hands over a fresh array.
  const signature = inboundIds.map((id) => inboundById.get(id)?.tag ?? id).join('\n');
  useLayoutEffect(() => {
    const box = boxRef.current;
    const measure = measureRef.current;
    if (!box || !measure) return undefined;
    const fit = () => {
      const widths = Array.from(measure.children, (el) => (el as HTMLElement).offsetWidth);
      const more = widths.pop() ?? 0;
      setShown(fitCount(widths, more, TAG_GAP, box.clientWidth));
    };
    fit();
    const observer = new ResizeObserver(fit);
    observer.observe(box);
    return () => observer.disconnect();
  }, [signature]);

  const visibleIds = inboundIds.slice(0, shown);
  const hiddenIds = inboundIds.slice(shown);
  return (
    <div
      ref={boxRef}
      style={{
        position: 'relative',
        display: 'flex',
        alignItems: 'center',
        gap: TAG_GAP,
        overflow: 'hidden',
        // The tags never size the column; it is at least this wide — two
        // typical tags and a "+N", what the column always showed before it
        // learned to stretch — even on a phone, where the table scrolls
        // sideways instead.
        contain: 'inline-size',
        minWidth: 260,
      }}
    >
      {/* Every tag plus a "+N" sample, laid out exactly like the real row and
          never seen — the widths `fitCount` works from. */}
      <div
        ref={measureRef}
        aria-hidden
        style={{
          position: 'absolute',
          visibility: 'hidden',
          pointerEvents: 'none',
          display: 'flex',
          gap: TAG_GAP,
          whiteSpace: 'nowrap',
        }}
      >
        {inboundIds.map((id) => renderTag(id, false))}
        <Tag style={{ marginInlineEnd: 0, flexShrink: 0 }}>+{inboundIds.length}</Tag>
      </div>
      {visibleIds.map((id) => renderTag(id))}
      {hiddenIds.length > 0 && (
        <Popover
          // Click-only: on touch devices the combined hover-and-click
          // trigger fires twice from one tap, flickering the popover
          // open then immediately closed. Click is unambiguous on both
          // pointer and touch.
          trigger="click"
          content={
            <Space size={TAG_GAP} wrap style={{ maxWidth: 320 }}>
              {hiddenIds.map((id) => renderTag(id))}
            </Space>
          }
        >
          <Tag style={{ cursor: 'pointer', marginInlineEnd: 0, flexShrink: 0 }}>
            +{hiddenIds.length}
          </Tag>
        </Popover>
      )}
    </div>
  );
}
