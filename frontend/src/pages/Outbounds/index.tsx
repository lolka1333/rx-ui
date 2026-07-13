//! Outbounds page — table of operator-defined egress/relay outbounds plus the
//! create/edit modal. Storage is a single JSON array replaced atomically, so
//! every mutation (save / toggle / delete) recomputes the full list and PUTs
//! it; the backend resyncs the live xray over gRPC. Form logic lives in
//! `./OutboundForm`.

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
} from 'antd';
import {
  DeleteOutlined,
  EditOutlined,
  PlusOutlined,
  SwapOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type {
  CustomOutbound,
  OutboundTestResult,
  OutboundTraffic,
  PanelSettings,
} from '@/api/types';
import { TRANSPORT_LABEL } from '@/pages/Inbounds/helpers';
import { TrafficCell } from '@/components/TrafficCell';
import { useNav } from '@/stores/nav';
import { fmtBytes } from '@/lib/format';
import { OutboundForm } from './OutboundForm';
import { ReverseWizard } from './ReverseWizard';
import { formToOutbound, type OutboundFormValues } from './form';

/** Endpoint `address:port` for the table, regardless of protocol variant. */
function endpointOf(ob: CustomOutbound): string {
  if (ob.protocol.kind === 'vless') {
    return `${ob.protocol.address}:${ob.protocol.port}`;
  }
  return '—';
}

/** xray's always-present built-in outbounds — emitted into every bootstrap
 *  config, shown read-only above the custom ones. `direct-ipv4` is added
 *  separately because it's conditional (see `needsIpv4`). Keep in sync with
 *  the backend's `BUILTIN_OUTBOUND_TAGS`. */
interface SystemOutbound {
  tag: string;
  protocol: string;
  noteKey: string;
  /** `blocked` is a blackhole — dropping is its job, so there's nothing to test. */
  testable: boolean;
}

const SYSTEM_OUTBOUNDS: SystemOutbound[] = [
  { tag: 'direct', protocol: 'freedom', noteKey: 'outbounds.builtinDirect', testable: true },
  { tag: 'blocked', protocol: 'blackhole', noteKey: 'outbounds.builtinBlocked', testable: false },
];

/** The on-demand IPv4-force outbound — only emitted when the IPv4-rules list is
 *  non-empty or a routing rule targets it (mirrors `config_gen`'s `needs_ipv4`). */
const DIRECT_IPV4_ROW: SystemOutbound = {
  tag: 'direct-ipv4',
  protocol: 'freedom',
  noteKey: 'outbounds.builtinDirectIpv4',
  testable: true,
};

/** A table row is either a built-in system outbound (read-only) or a custom one. */
type Row = ({ rowKind: 'system' } & SystemOutbound) | { rowKind: 'custom'; ob: CustomOutbound };

export function Outbounds() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const qc = useQueryClient();
  const screens = Grid.useBreakpoint();
  const isMobile = !screens.md;
  const [editOpen, setEditOpen] = useState(false);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [editing, setEditing] = useState<CustomOutbound | null>(null);
  const [formKey, setFormKey] = useState(0);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [form] = Form.useForm<OutboundFormValues>();

  const { data } = useQuery<CustomOutbound[]>({
    queryKey: ['outbounds'],
    queryFn: async () => (await apiClient.get<CustomOutbound[]>('/outbounds')).data,
  });
  const outbounds = data ?? [];

  // `direct-ipv4` is only emitted into the bootstrap config when the IPv4-rules
  // list is non-empty or some enabled rule targets it — so only list it then,
  // mirroring `config_gen::build_bootstrap_config`'s `needs_ipv4`.
  const { data: settings } = useQuery<PanelSettings>({
    queryKey: ['panel-settings'],
    queryFn: async () => (await apiClient.get<PanelSettings>('/settings/panel')).data,
  });
  const needsIpv4 =
    !!settings &&
    (settings.xray_ipv4_domains.length > 0 ||
      settings.xray_custom_rules.some((r) => r.enabled && r.outbound_tag === 'direct-ipv4'));
  const systemRows = needsIpv4 ? [...SYSTEM_OUTBOUNDS, DIRECT_IPV4_ROW] : SYSTEM_OUTBOUNDS;

  // Per-outbound lifetime traffic (by tag, incl. built-ins) — persisted in the
  // backend, survives xray restarts. Poll only while this tab is visible so a
  // hidden page doesn't hit the API every 5s.
  const isActive = useNav((s) => s.current === 'outbounds');
  const { data: stats = {}, dataUpdatedAt } = useQuery<Record<string, OutboundTraffic>>({
    queryKey: ['outbounds-stats'],
    queryFn: async () =>
      (await apiClient.get<Record<string, OutboundTraffic>>('/outbounds/stats')).data,
    refetchInterval: isActive ? 5_000 : false,
    staleTime: 4_000,
  });

  // Live indicator: the endpoint returns cumulative totals, not a rate, so we
  // derive "currently flowing" by diffing each poll against the previous one —
  // a tag whose bytes grew since the last poll is live (its bar animates). This
  // is React's "store info from previous renders" pattern: a guarded setState
  // during render (not in an effect), keyed on `dataUpdatedAt` which ticks on
  // every fetch even when structural sharing keeps the same `stats` object, so
  // an idle tag clears on the next poll.
  const [liveTags, setLiveTags] = useState<Set<string>>(new Set());
  const [prevPoll, setPrevPoll] = useState<{ at: number; stats: Record<string, OutboundTraffic> }>(
    { at: 0, stats: {} },
  );
  if (dataUpdatedAt !== prevPoll.at) {
    const next = new Set<string>();
    for (const [tag, s] of Object.entries(stats)) {
      const p = prevPoll.stats[tag];
      if (p && (s.uplink > p.uplink || s.downlink > p.downlink)) next.add(tag);
    }
    setPrevPoll({ at: dataUpdatedAt, stats });
    setLiveTags(next);
  }

  // Persist the whole array — the backend replaces + resyncs xray on PUT.
  const putList = (list: CustomOutbound[]) => apiClient.put('/outbounds', list);

  const toggle = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) =>
      putList(
        outbounds.map((o) =>
          o.id === id ? { ...o, enabled, updated_at: new Date().toISOString() } : o,
        ),
      ),
    onMutate: ({ id, enabled }) => {
      const snapshots = qc.getQueriesData<CustomOutbound[]>({ queryKey: ['outbounds'] });
      qc.setQueriesData<CustomOutbound[]>({ queryKey: ['outbounds'] }, (old) =>
        old?.map((o) => (o.id === id ? { ...o, enabled } : o)),
      );
      return { snapshots };
    },
    onError: (err: unknown, _vars, ctx) => {
      if (ctx?.snapshots) {
        for (const [key, snap] of ctx.snapshots) qc.setQueryData(key, snap);
      }
      message.error(apiErrorMessage(err) ?? t('outbounds.saveError'));
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ['outbounds'] }),
  });

  const del = useMutation({
    mutationFn: async (id: string) => putList(outbounds.filter((o) => o.id !== id)),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['outbounds'] });
      message.success(t('outbounds.deleted'));
    },
    onError: (err: unknown) => {
      message.error(apiErrorMessage(err) ?? t('outbounds.saveError'));
    },
  });

  const save = useMutation({
    mutationFn: async (values: OutboundFormValues) => {
      const next = formToOutbound(values, editing);
      const list = editing
        ? outbounds.map((o) => (o.id === editing.id ? next : o))
        : [...outbounds, next];
      return putList(list);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['outbounds'] });
      setEditOpen(false);
      setEditing(null);
      form.resetFields();
      message.success(editing ? t('outbounds.saved') : t('outbounds.created'));
    },
    onError: (err: unknown) => {
      message.error(apiErrorMessage(err) ?? t('outbounds.saveError'));
    },
  });

  // Stable so the memoised <OutboundForm> can skip background re-renders.
  const handleFinish = useCallback(() => {
    save.mutate(form.getFieldsValue(true) as OutboundFormValues);
  }, [save, form]);

  // Connectivity test: the backend relays an HTTPS probe through this outbound
  // (or, for `direct`, a direct request) and reports whether traffic egressed +
  // the warm ping. Slow (~a few seconds) so the row button shows a spinner.
  // `testKey` distinguishes rows (custom id / `sys-<tag>`) for the loading state.
  const runTest = async (testKey: string, url: string) => {
    setTestingId(testKey);
    try {
      const r = (
        await apiClient.post<OutboundTestResult>(url, undefined, { timeout: 30_000 })
      ).data;
      if (r.ok) {
        message.success(
          t('outbounds.testOk', {
            ip: r.exit_ip ?? '?',
            loc: r.exit_loc ? ` (${r.exit_loc})` : '',
            ms: r.latency_ms ?? '?',
          }),
          7,
        );
      } else {
        message.error(t('outbounds.testFail', { error: r.error ?? '' }), 7);
      }
    } catch (e) {
      message.error(apiErrorMessage(e) ?? t('outbounds.testError'));
    } finally {
      setTestingId(null);
    }
  };

  const openCreate = () => {
    setEditing(null);
    setFormKey((k) => k + 1);
    setEditOpen(true);
  };

  const openEdit = (record: CustomOutbound) => {
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
        <Space>
          <Button icon={<SwapOutlined />} onClick={() => setWizardOpen(true)}>
            {t('reverse.button')}
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
            {t('outbounds.addOutbound')}
          </Button>
        </Space>
      </div>

      {wizardOpen && <ReverseWizard onClose={() => setWizardOpen(false)} />}

      <Table<Row>
        rowKey={(r) => (r.rowKind === 'system' ? `sys-${r.tag}` : r.ob.id)}
        dataSource={[
          ...systemRows.map((s) => ({ rowKind: 'system' as const, ...s })),
          ...outbounds.map((ob) => ({ rowKind: 'custom' as const, ob })),
        ]}
        pagination={false}
        scroll={{ x: 'max-content' }}
        size={isMobile ? 'small' : 'middle'}
        columns={[
          {
            title: '',
            key: 'enabled',
            width: 60,
            render: (_, r) =>
              r.rowKind === 'system' ? (
                // Built-ins are always active and not toggleable.
                <Switch size="small" checked disabled />
              ) : (
                <Switch
                  size="small"
                  checked={r.ob.enabled}
                  onChange={(v) => toggle.mutate({ id: r.ob.id, enabled: v })}
                />
              ),
          },
          {
            title: t('outbounds.tag'),
            key: 'tag',
            render: (_, r) =>
              r.rowKind === 'system' ? (
                <Space size={6}>
                  <Typography.Text strong>{r.tag}</Typography.Text>
                  <Tag color="default">{t('outbounds.builtin')}</Tag>
                </Space>
              ) : (
                <Typography.Text strong>{r.ob.tag}</Typography.Text>
              ),
          },
          {
            title: t('outbounds.protocol'),
            key: 'protocol',
            render: (_, r) =>
              r.rowKind === 'system' ? (
                <Tag>{r.protocol}</Tag>
              ) : (
                <Space size={4}>
                  <Tag color="geekblue">{r.ob.protocol.kind}</Tag>
                  <Tag>{TRANSPORT_LABEL[r.ob.transport.kind]}</Tag>
                  {r.ob.security.kind !== 'none' && (
                    <Tag color={r.ob.security.kind === 'reality' ? 'purple' : 'green'}>
                      {r.ob.security.kind}
                    </Tag>
                  )}
                </Space>
              ),
          },
          {
            title: t('outbounds.address'),
            key: 'address',
            render: (_, r) =>
              r.rowKind === 'system' ? (
                <Typography.Text type="secondary">{t(r.noteKey)}</Typography.Text>
              ) : (
                <Typography.Text code>{endpointOf(r.ob)}</Typography.Text>
              ),
          },
          {
            title: t('outbounds.traffic'),
            key: 'traffic',
            width: 180,
            render: (_, r) => {
              const tag = r.rowKind === 'system' ? r.tag : r.ob.tag;
              const s = stats[tag];
              return s ? (
                <TrafficCell
                  up={fmtBytes(s.uplink)}
                  down={fmtBytes(s.downlink)}
                  live={liveTags.has(tag)}
                />
              ) : (
                <Typography.Text type="secondary">—</Typography.Text>
              );
            },
          },
          {
            title: t('outbounds.actions'),
            key: 'actions',
            width: 140,
            align: 'right',
            render: (_, r) =>
              r.rowKind === 'system' ? (
                // Built-ins: only `direct`/`direct-ipv4` are testable (egress
                // baseline); `blocked` is a blackhole, nothing to test.
                r.testable ? (
                  <Button
                    type="text"
                    size="small"
                    icon={<ThunderboltOutlined />}
                    loading={testingId === `sys-${r.tag}`}
                    title={t('outbounds.test')}
                    onClick={() => runTest(`sys-${r.tag}`, `/outbounds/builtin/${r.tag}/test`)}
                  />
                ) : null
              ) : (
                <Space>
                  <Button
                    type="text"
                    size="small"
                    icon={<ThunderboltOutlined />}
                    loading={testingId === r.ob.id}
                    title={t('outbounds.test')}
                    onClick={() => runTest(r.ob.id, `/outbounds/${r.ob.id}/test`)}
                  />
                  <Button
                    type="text"
                    size="small"
                    icon={<EditOutlined />}
                    onClick={() => openEdit(r.ob)}
                  />
                  <Popconfirm
                    title={t('outbounds.deleteConfirm')}
                    okType="danger"
                    okText={t('common.delete')}
                    cancelText={t('common.cancel')}
                    onConfirm={() => del.mutate(r.ob.id)}
                  >
                    <Button type="text" danger size="small" icon={<DeleteOutlined />} />
                  </Popconfirm>
                </Space>
              ),
          },
        ]}
      />

      <Modal
        destroyOnHidden
        open={editOpen}
        title={
          editing ? t('outbounds.editTitle', { tag: editing.tag }) : t('outbounds.newTitle')
        }
        onCancel={() => {
          setEditOpen(false);
          setEditing(null);
        }}
        onOk={() => form.submit()}
        confirmLoading={save.isPending}
        width={isMobile ? '100%' : 540}
        style={
          isMobile ? { top: 0, maxWidth: '100vw', margin: 0, paddingBottom: 0 } : undefined
        }
        styles={{
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
        <OutboundForm
          formKey={formKey}
          form={form}
          editing={editing}
          onFinish={handleFinish}
        />
      </Modal>
    </div>
  );
}
