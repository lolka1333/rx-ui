//! Inbounds page — the table of configured inbounds plus the create/edit
//! modal. The form-side logic lives in `./InboundForm`; this file owns
//! the table, the modal shell, and the per-row toggle/delete mutations.

import {
  App,
  Button,
  Form,
  Grid,
  Modal,
  Popconfirm,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
  theme,
} from 'antd';
import {
  CloudOutlined,
  DeleteOutlined,
  EditOutlined,
  PlusOutlined,
  TeamOutlined,
} from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useClientsFilter } from '@/stores/clientsFilter';
import { useNav } from '@/stores/nav';
import type { Client, Inbound, TrafficSnapshot } from '@/api/types';
import { TrafficCell } from '@/components/TrafficCell';
import { fmtBytes } from '@/lib/format';
import { InboundForm } from './InboundForm';
import { formToCreate, formToUpdate } from './form/adapters';
import type { FormValues } from './form/types';
import { PROTOCOL_COLOR, TRANSPORT_LABEL, vlessFlow } from './helpers';

type TrafficSnapshotMap = Record<string, TrafficSnapshot>;

interface InboundTraffic {
  up: number;
  down: number;
  /** True when ANY client on this inbound is moving bytes right now. */
  live: boolean;
}

export function Inbounds() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const qc = useQueryClient();
  // Only poll while this tab is visible — it stays mounted (display:none) on
  // other tabs, so gating keeps it from hitting the API in the background and
  // draining a phone for stats nobody is watching.
  const isActive = useNav((s) => s.current === 'inbounds');
  const screens = Grid.useBreakpoint();
  const { token } = theme.useToken();
  const isMobile = !screens.md;
  const [editOpen, setEditOpen] = useState(false);
  const [editing, setEditing] = useState<Inbound | null>(null);
  const [form] = Form.useForm<FormValues>();

  const { data } = useQuery<Inbound[]>({
    queryKey: ['inbounds'],
    queryFn: async () => (await apiClient.get<Inbound[]>('/inbounds')).data,
  });
  const inbounds = data ?? [];

  // Lightweight cross-inbound client count for the "Клиенты" column. One
  // query that returns every client (no filter), grouped in-memory by
  // inbound_id. Cheaper than per-row queries — the Clients page uses the
  // same endpoint, so this cache hit is shared between tabs.
  const { data: allClients = [] } = useQuery<Client[]>({
    queryKey: ['clients-global', null],
    queryFn: async () => (await apiClient.get<Client[]>('/clients')).data,
  });
  const clientCountByInbound = useMemo(() => {
    const m = new Map<string, number>();
    for (const c of allClients) m.set(c.inbound_id, (m.get(c.inbound_id) ?? 0) + 1);
    return m;
  }, [allClients]);

  // Per-inbound traffic totals — derived from each bound client's lifetime
  // counters in `/clients/stats`. xray's StatsService counts bytes per email,
  // not per (email, inbound), so a user shared across several inbounds has one
  // per-email total. Credit it to a single inbound (the first row seen) rather
  // than every membership — otherwise the same bytes surface under each inbound
  // and the column reads ~Nx for one connection. Shares the Clients page's
  // react-query key so polling cost is paid once.
  const { data: stats = {} } = useQuery<TrafficSnapshotMap>({
    queryKey: ['clients-stats'],
    queryFn: async () =>
      (await apiClient.get<TrafficSnapshotMap>('/clients/stats')).data,
    refetchInterval: isActive ? 5_000 : false,
    staleTime: 4_000,
  });
  // Inbounds don't have quotas of their own — caps live on clients.
  // The cell shows just the aggregate ↑/↓ that flowed through the
  // inbound; the rhythm-line bar underneath stays empty (no quota
  // semantics) and only takes on the live-blue overlay when bytes
  // are moving through any client on the inbound.
  const trafficByInbound = useMemo(() => {
    const m = new Map<string, InboundTraffic>();
    // Credit each email's per-email total once (to the first inbound it
    // appears in), so a user shared across inbounds isn't summed into every one.
    const credited = new Set<string>();
    for (const c of allClients) {
      const acc = m.get(c.inbound_id) ?? { up: 0, down: 0, live: false };
      const s = stats[c.email];
      if (s && !credited.has(c.email)) {
        credited.add(c.email);
        acc.up += s.uplink_total;
        acc.down += s.downlink_total;
        if (s.uplink_bps > 0 || s.downlink_bps > 0) acc.live = true;
      }
      m.set(c.inbound_id, acc);
    }
    return m;
  }, [allClients, stats]);

  // Wired to the Clients page navigation when the operator clicks the
  // "N клиентов" badge. Filter store carries the inbound_id across the
  // page switch so the Clients page lands pre-filtered.
  const setInboundIdFilter = useClientsFilter((s) => s.setInboundId);
  const setCurrentPage = useNav((s) => s.setCurrent);

  const toggle = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiClient.patch(`/inbounds/${id}`, { enabled }),
    // Optimistic update — without it the Switch shows antd's `loading`
    // overlay (a prohibition icon ⊘) while the PATCH round-trips,
    // which looks like a denied/forbidden state. Mutate the cache
    // synchronously so the toggle flips in the UI immediately;
    // `onError` rolls it back if the backend rejected.
    onMutate: ({ id, enabled }) => {
      const snapshots = qc.getQueriesData<Inbound[]>({ queryKey: ['inbounds'] });
      qc.setQueriesData<Inbound[]>({ queryKey: ['inbounds'] }, (old) =>
        old?.map((i) => (i.id === id ? { ...i, enabled } : i)),
      );
      return { snapshots };
    },
    onError: (err: unknown, _vars, ctx) => {
      if (ctx?.snapshots) {
        for (const [key, data] of ctx.snapshots) qc.setQueryData(key, data);
      }
      message.error(apiErrorMessage(err) ?? t('inbounds.saveError'));
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ['inbounds'] }),
  });

  const del = useMutation({
    mutationFn: async (id: string) => apiClient.delete(`/inbounds/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['inbounds'] });
      message.success(t('inbounds.deleted'));
    },
    onError: (err: unknown) => {
      message.error(apiErrorMessage(err) ?? t('inbounds.saveError'));
    },
  });

  const save = useMutation({
    mutationFn: async (values: FormValues) => {
      // The flat form values get projected through `formToCreate` /
      // `formToUpdate` so the backend sees the typed layer shape.
      if (editing) {
        return apiClient.patch<Inbound>(`/inbounds/${editing.id}`, formToUpdate(values));
      }
      return apiClient.post<Inbound>('/inbounds', formToCreate(values));
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['inbounds'] });
      setEditOpen(false);
      setEditing(null);
      form.resetFields();
      message.success(editing ? t('inbounds.saved') : t('inbounds.created'));
    },
    onError: (err: unknown) => {
      message.error(apiErrorMessage(err) ?? t('inbounds.saveError'));
    },
  });

  // Stable so the memoised <InboundForm> can skip background-poll re-renders
  // (see InboundForm). Antd's onFinish only delivers values for currently-
  // mounted Form.Items; the Reality/XHTTP tabs and the collapsed Sniffing
  // panel are lazy-mounted, so we pull the whole store with
  // getFieldsValue(true) instead — including arrays like xhttp_headers and
  // initialValues for never-mounted fields.
  const handleFinish = useCallback(() => {
    save.mutate(form.getFieldsValue(true) as FormValues);
  }, [save, form]);

  // The form's `initialValues` are read once on mount. To switch between
  // create-defaults and edit-record-values we re-mount the form via a `key`
  // that changes when we open it for a different inbound (or for a new one).
  // Without re-mount, Antd Select children mounted before `setFieldsValue`
  // ran would never see the value, leaving fingerprint/xhttp_mode empty.
  const [formKey, setFormKey] = useState(0);

  const openCreate = () => {
    setEditing(null);
    setFormKey((k) => k + 1);
    setEditOpen(true);
  };

  const openEdit = (record: Inbound) => {
    setEditing(record);
    setFormKey((k) => k + 1);
    setEditOpen(true);
  };

  if (!data) {
    return null;
  }

  return (
    <div className="app-content-reveal">
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'flex-end',
          marginBottom: 24,
        }}
      >
        <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
          {t('inbounds.addInbound')}
        </Button>
      </div>

      <Table<Inbound>
        rowKey="id"
        dataSource={inbounds}
        pagination={false}
        scroll={{ x: 'max-content' }}
        size={isMobile ? 'small' : 'middle'}
        columns={[
          {
            title: '',
            key: 'enabled',
            width: 60,
            render: (_, r) => (
              <Switch
                size="small"
                checked={r.enabled}
                onChange={(v) => toggle.mutate({ id: r.id, enabled: v })}
              />
            ),
          },
          {
            title: t('inbounds.tag'),
            dataIndex: 'tag',
            render: (v: string) => <Typography.Text strong>{v}</Typography.Text>,
          },
          {
            title: t('inbounds.network'),
            key: 'network',
            render: (_, r) => (
              <Space size={4}>
                <Tag color={PROTOCOL_COLOR}>{r.protocol.kind}</Tag>
                <Tag>{TRANSPORT_LABEL[r.transport.kind]}</Tag>
                {vlessFlow(r) === 'xtls-rprx-vision' && (
                  <Tag color="purple">Vision</Tag>
                )}
              </Space>
            ),
          },
          {
            title: t('inbounds.address'),
            key: 'address',
            render: (_, r) => (
              <Typography.Text code>
                {r.listen}:{r.port}
              </Typography.Text>
            ),
          },
          {
            title: t('inbounds.traffic'),
            key: 'traffic',
            width: 200,
            render: (_, r) => {
              const tr = trafficByInbound.get(r.id);
              if (!tr) {
                return <Typography.Text type="secondary">—</Typography.Text>;
              }
              return (
                <TrafficCell
                  up={fmtBytes(tr.up)}
                  down={fmtBytes(tr.down)}
                  live={tr.live}
                />
              );
            },
          },
          {
            // Click-through to Clients page filtered by this inbound. Replaces
            // the old expandable-row nested table; the count comes from the
            // page-level clients-count query so we don't N+1 the inbound list.
            title: t('inbounds.clientsColumn'),
            key: 'clients_count',
            width: 110,
            render: (_, r) => {
              const count = clientCountByInbound.get(r.id) ?? 0;
              return (
                <Tag
                  color={count > 0 ? 'geekblue' : 'default'}
                  style={{ cursor: 'pointer' }}
                  onClick={() => {
                    setInboundIdFilter(r.id);
                    setCurrentPage('clients');
                  }}
                  title={t('inbounds.clientsColumnGoto')}
                >
                  {count} <TeamOutlined style={{ marginLeft: 4 }} />
                </Tag>
              );
            },
          },
          {
            title: t('inbounds.actions'),
            key: 'actions',
            width: 110,
            align: 'right',
            render: (_, r) => (
              <Space>
                <Button
                  type="text"
                  size="small"
                  icon={<EditOutlined />}
                  onClick={() => openEdit(r)}
                />
                <Popconfirm
                  title={t('inbounds.deleteConfirm')}
                  okType="danger"
                  okText={t('common.delete')}
                  cancelText={t('common.cancel')}
                  onConfirm={() => del.mutate(r.id)}
                >
                  <Button type="text" danger size="small" icon={<DeleteOutlined />} />
                </Popconfirm>
              </Space>
            ),
          },
        ]}
        locale={{
          emptyText: (
            <div style={{ padding: 40, textAlign: 'center' }}>
              <CloudOutlined style={{ fontSize: 32, color: token.colorTextTertiary }} />
              <div style={{ marginTop: 12, color: token.colorTextSecondary }}>
                {t('inbounds.empty')}
              </div>
            </div>
          ),
        }}
      />

      <Modal
        // `destroyOnHidden` forces the Form (and its `useForm` instance
        // state) to fully unmount when the modal closes. Without it, the
        // form retains the previous open's values and `initialValues`
        // change is ignored on the second open.
        destroyOnHidden
        open={editOpen}
        title={
          editing ? t('inbounds.editTitle', { tag: editing.tag }) : t('inbounds.newTitle')
        }
        onCancel={() => {
          setEditOpen(false);
          setEditing(null);
        }}
        onOk={() => form.submit()}
        confirmLoading={save.isPending}
        // Compact form: ~540px on desktop, full-bleed on mobile. Most
        // fields stack single-column; only naturally-narrow pairs share a
        // row via inline flex (Antd Grid breakpoints look at viewport,
        // not container, so they wouldn't help inside a narrow modal).
        width={isMobile ? '100%' : 540}
        style={
          isMobile ? { top: 0, maxWidth: '100vw', margin: 0, paddingBottom: 0 } : undefined
        }
        styles={{
          // `scrollbar-gutter: stable` reserves a fixed-width gutter for
          // the scrollbar. Antd v6's modal body has `padding: 0` by
          // default (the content padding sits on `.ant-modal-content`
          // instead), so the gutter ends up flush against the rightmost
          // inputs. Explicit body padding gives the scrollbar visible
          // breathing room from form controls on Windows/Linux native
          // bars. (Mac uses overlay bars and is unaffected either way.)
          body: {
            scrollbarGutter: 'stable',
            paddingInline: 12,
            paddingBlock: 4,
            ...(isMobile ? { maxHeight: 'calc(100dvh - 160px)', overflowY: 'auto' } : {}),
          },
        }}
        okText={t('common.save')}
        cancelText={t('common.cancel')}
      >
        <InboundForm
          formKey={formKey}
          form={form}
          editing={editing}
          onFinish={handleFinish}
          onEditingChange={setEditing}
        />
      </Modal>
    </div>
  );
}
