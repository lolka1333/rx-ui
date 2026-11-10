/**
 * The create / edit modal. The inbound multi-select IS editable in edit mode
 * — bulk-assign adds/removes the email's per-inbound rows atomically. The
 * email field, by contrast, is locked in edit mode: it is the client's
 * identity (bulk-assign keys on it), so changing it here would spawn a NEW
 * client rather than rename the existing one.
 */
import { Form, Input, InputNumber, Modal, Select, Space, Typography, App, DatePicker } from 'antd';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import dayjs, { type Dayjs } from 'dayjs';
import utc from 'dayjs/plugin/utc';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { Client, ClientBulkAssign, ClientBulkAssignResult, Inbound } from '@/api/types';
import { type TrafficUnit, bytesToTrafficForm, trafficFormToBytes } from './traffic';
import { ClientAuthField, ClientWireguardPending, ClientWireguardBlock, ClientUuidField, ClientFlowField, ClientReverseField } from './formFields';

// Expiry timestamps are stored UTC; parse/format them in UTC and let the
// DatePicker localize for display.
dayjs.extend(utc);

interface ClientFormValues {
  /** Target inbound set — same user appears in each, sharing uuid/auth/flow.
   *  Empty array is rejected by the form's required-rule (the bulk-assign
   *  backend also rejects it, so this is double-protected). */
  inbound_ids: string[];
  email: string;
  uuid: string;
  /** Hysteria 2 per-user auth secret. Ignored for VLESS inbounds (the
   *  panel still persists whatever the operator typed for forward-compat
   *  if the inbound is later migrated to Hysteria). Empty string for
   *  vless clients in the form. */
  auth: string;
  flow: '' | 'inherit' | 'xtls-rprx-vision';
  /** VLESS Reverse Proxy portal tag. Empty ≡ a normal client. A non-empty
   *  tag turns this user into a reverse portal endpoint: a bridge dialing in
   *  as this user registers a tunnel outbound under the tag on this server,
   *  which then becomes a routing target. */
  reverse_tag: string;
  note: string;
  /** `null` ≡ no quota. The number is in `traffic_limit_unit` units. */
  traffic_limit_value: number | null;
  traffic_limit_unit: TrafficUnit;
  /** `null` ≡ never expires. Absolute datetime; localized in the picker,
   *  sent to the backend as ISO-8601 (UTC). */
  expires_at: Dayjs | null;
}

export function ClientFormModal({
  open,
  editing,
  inbounds,
  inboundById,
  allClients,
  inboundIdFilter,
  onClose,
}: {
  open: boolean;
  /** Any row of the edited email; `null` for a new client. */
  editing: Client | null;
  inbounds: Inbound[];
  inboundById: Map<string, Inbound>;
  /** Every client, unfiltered: the edited email's full inbound set comes from
   *  here, whatever the page's inbound filter is. */
  allClients: Client[];
  inboundIdFilter: string | null;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const qc = useQueryClient();
  const [form] = Form.useForm<ClientFormValues>();
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['clients-global'] });
  };

  // Single save path: bulk-assign reconciles the per-inbound rows for
  // this email to the form's `inbound_ids` set. Create flow and edit
  // flow share the same endpoint — the backend's set math handles the
  // "no existing rows for this email" case as N pure INSERTs, and the
  // "edited row removed from an inbound" case as the matching DELETE.
  //
  // What this intentionally drops: changing `enabled` from the modal.
  // It's driven by the inline switch in the row; bundling it here lets
  // a stale form value flip a client that another tab (or the poller's
  // quota re-enable path) just changed.
  const save = useMutation({
    mutationFn: async (values: ClientFormValues) => {
      const flow = values.flow === 'inherit' ? null : values.flow;
      const trafficLimitBytes = trafficFormToBytes(
        values.traffic_limit_value,
        values.traffic_limit_unit,
      );
      const body: ClientBulkAssign = {
        email: values.email.trim(),
        inbound_ids: values.inbound_ids,
        uuid: values.uuid?.trim() ? values.uuid.trim() : null,
        // Empty auth → null. Backend mints one for hysteria inbounds in
        // the target set; vless inbounds ignore the column. `?.` is
        // load-bearing: ClientAuthField renders the `auth` Form.Item only
        // for hysteria targets, so on a VLESS-only selection the field is
        // never registered and `values.auth` is `undefined` — a bare
        // `.trim()` there threw a TypeError *before* the request was sent,
        // which surfaced (misleadingly) as "couldn't connect to backend".
        auth: values.auth?.trim() ? values.auth.trim() : null,
        flow,
        reverse_tag: values.reverse_tag?.trim() ? values.reverse_tag.trim() : null,
        note: values.note || null,
        traffic_limit_bytes: trafficLimitBytes,
        expires_at: values.expires_at ? values.expires_at.toISOString() : null,
      };
      return (await apiClient.post<ClientBulkAssignResult>('/clients/bulk-assign', body))
        .data;
    },
    onSuccess: (result) => {
      invalidate();
      onClose();
      const parts: string[] = [];
      if (result.created.length > 0) parts.push(`+${result.created.length}`);
      if (result.updated.length > 0) parts.push(`±${result.updated.length}`);
      if (result.removed.length > 0) parts.push(`−${result.removed.length}`);
      const countSummary = parts.length > 0 ? ` (${parts.join(' ')})` : '';
      message.success((editing ? t('clients.saved') : t('clients.created')) + countSummary);
      // DB succeeded, but one or more xray gRPC pushes didn't — the
      // operator needs to know so they can hit "Restart xray" instead
      // of watching the affected users silently fail to connect.
      if (result.xray_failures.length > 0) {
        const tags = result.xray_failures.map((f) => f.inbound_tag).join(', ');
        // 8 s timeout (default is 3 s) — this is an actionable
        // warning ("Restart xray to apply"); the operator stacks
        // success + warning toasts and we don't want the warning to
        // vanish while they're still reading the success line above.
        message.warning(t('clients.xrayDrift', { tags }), 8);
      }
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('clients.saveError')),
  });

  // Mint a fresh keypair + pre-shared key for one WireGuard peer. The address
  // inside the tunnel is kept — it is what xray identifies the peer by and what
  // its traffic is counted against — so only the secrets change. Every config
  // already handed out for this peer stops working, which is the point.
  const rotateWireguard = useMutation({
    mutationFn: async (clientId: string) =>
      (await apiClient.post<Client>(`/clients/${clientId}/rotate-wireguard`)).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['clients-global'] });
      message.success(t('clients.wgRotated'));
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('clients.saveError')),
  });

  // Rows of the edited email that live on a WireGuard inbound — one per
  // inbound, each with its own address and secrets.
  const editingWgRows = useMemo(() => {
    if (!editing) return [];
    return allClients.filter(
      (c) =>
        c.email === editing.email &&
        inboundById.get(c.inbound_id)?.protocol.kind === 'wireguard',
    );
  }, [editing, allClients, inboundById]);

  // Sensible default for the create form's inbound multi-select:
  //   * editing existing email → every inbound that email is already in
  //   * create + filter active → pre-select the filtered inbound
  //   * create + single inbound → pre-select it
  //   * otherwise → empty (operator must pick at least one)
  const editingInboundIds = useMemo(() => {
    if (!editing) return null;
    return allClients
      .filter((c) => c.email === editing.email)
      .map((c) => c.inbound_id);
  }, [editing, allClients]);
  const defaultCreateInboundIds: string[] = inboundIdFilter
    ? [inboundIdFilter]
    : inbounds.length === 1
      ? [inbounds[0].id]
      : [];

  // Seed the form when the modal opens — and only then. The modal reuses a
  // single controlled `form` instance whose store outlives each open, and
  // antd merges that lingering store *on top of* `initialValues` — so the
  // prop loses, the fields kept stale data, and after a create the next edit
  // showed a blank form. Writing the values imperatively here sidesteps the
  // merge entirely. editingInboundIds/defaultCreateInboundIds are read fresh
  // at open time but kept out of the deps on purpose: they change on
  // background client-list refetches, and re-seeding mid-edit would clobber
  // whatever the operator is typing.
  useEffect(() => {
    if (!open) return;
    const tl = bytesToTrafficForm(editing?.traffic_limit_bytes);
    form.setFieldsValue({
      inbound_ids: editingInboundIds ?? defaultCreateInboundIds,
      email: editing?.email ?? '',
      uuid: editing?.uuid ?? '',
      auth: editing?.auth ?? '',
      flow: editing
        ? editing.flow == null
          ? 'inherit'
          : editing.flow === 'xtls-rprx-vision'
            ? 'xtls-rprx-vision'
            : ''
        : 'inherit',
      reverse_tag: editing?.reverse_tag ?? '',
      note: editing?.note ?? '',
      traffic_limit_value: tl.value,
      traffic_limit_unit: tl.unit,
      expires_at: editing?.expires_at ? dayjs.utc(editing.expires_at).local() : null,
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, editing, form]);

  return (
    <Modal
      destroyOnHidden
      open={open}
      title={
        editing
          ? t('clients.editTitle', { email: editing.email })
          : t('clients.newTitle')
      }
      onCancel={onClose}
      onOk={() => form.submit()}
      confirmLoading={save.isPending}
      okText={t('common.save')}
      cancelText={t('common.cancel')}
      okButtonProps={{ disabled: inbounds.length === 0 }}
    >
      {inbounds.length === 0 ? (
        <Typography.Text type="warning">
          {t('clients.noInboundsYet')}
        </Typography.Text>
      ) : (
        // One controlled `form` instance, reused across opens and seeded
        // imperatively by the effect above — see the note there on why an
        // `initialValues` prop alone didn't hold.
        <Form form={form} layout="vertical" onFinish={(v) => save.mutate(v)}>
          {/* Multi-select inbounds — the same user gets created in
              each selected inbound, sharing uuid/auth/flow/limit. On
              edit, this is pre-populated with every inbound the email
              is currently assigned to; toggling adds/removes
              assignments atomically via bulk-assign. */}
          <Form.Item
            name="inbound_ids"
            label={t('clients.inboundMulti')}
            tooltip={t('clients.inboundMultiTooltip')}
            rules={[
              {
                validator: (_, v) =>
                  Array.isArray(v) && v.length > 0
                    ? Promise.resolve()
                    : Promise.reject(new Error(t('clients.inboundRequired'))),
              },
            ]}
          >
            <Select
              mode="multiple"
              showSearch={{ optionFilterProp: 'label' }}
              placeholder={t('clients.inboundPlaceholder')}
              // `maxTagCount="responsive"` — Antd measures the
              // control width and folds the overflow into a single
              // "+N…" pill with a hover tooltip listing the rest.
              // Stops the modal from stretching when a user picks
              // a lot of inbounds (or just a couple with long tags).
              maxTagCount="responsive"
              options={inbounds.map((ib) => ({ value: ib.id, label: ib.tag }))}
            />
          </Form.Item>
          <Form.Item
            name="email"
            label={t('clients.email')}
            tooltip={editing ? t('clients.emailLockedTooltip') : undefined}
            rules={[{ required: true, message: t('clients.emailRequired') }]}
          >
            {/* Locked in edit mode: bulk-assign keys on email, so changing
                it would create a new client instead of renaming. */}
            <Input placeholder="user@example.com" disabled={!!editing} />
          </Form.Item>
          <ClientUuidField inboundById={inboundById} />
          {/* Hysteria 2 per-user auth secret. Only mounted when a selected
              inbound is hysteria2 — for VLESS the field would be ignored on
              the wire and just confuse the operator. Watches `inbound_ids`
              so it appears as soon as such an inbound is picked above. */}
          <ClientAuthField inboundById={inboundById} />
          <ClientFlowField inboundById={inboundById} />
          <ClientReverseField inboundById={inboundById} />
          {/* The peer's own credentials, one block per WireGuard inbound this
              email is on. Read-only: the panel generates them, and a peer's
              address is what xray identifies it by. Only shown while editing
              — a client being created has none yet. */}
          {!editing && <ClientWireguardPending inboundById={inboundById} />}
          {editingWgRows.map((row) => (
            <ClientWireguardBlock
              key={row.id}
              row={row}
              inboundTag={inboundById.get(row.inbound_id)?.tag ?? row.inbound_id.slice(0, 8)}
              showTag={editingWgRows.length > 1}
              onRotate={() => rotateWireguard.mutate(row.id)}
              rotating={rotateWireguard.isPending}
            />
          ))}
          {/* Single-line Input, not TextArea: notes for VLESS users are
              typically short labels ("Bob's laptop", "office router") —
              a 2-row TextArea looks empty and visually heavy. If the
              operator ever wants multi-line content there's `\n`-aware
              copy-paste, but the affordance stays compact. */}
          <Form.Item name="note" label={t('clients.note')}>
            <Input placeholder={t('clients.notePlaceholder')} />
          </Form.Item>
          {/* Traffic limit: empty number = unlimited. Two fields paired
              in Space.Compact so they read as one control. Number takes
              the bulk of the width, unit is a fixed-width picker. */}
          {/* The outer Form.Item has a `label` but no `name` (it's a
              composite wrapper for two named children inside the
              Space.Compact). Antd's generated <label> would be orphan
              in that case, so we point `htmlFor` at the first inner
              field so the label-to-control association is valid. */}
          <Form.Item
            label={t('clients.trafficLimit')}
            tooltip={t('clients.trafficLimitTooltip')}
            htmlFor="traffic_limit_value"
          >
            <Space.Compact style={{ width: '100%' }}>
              <Form.Item name="traffic_limit_value" noStyle>
                <InputNumber
                  min={0}
                  step={1}
                  placeholder={t('clients.limitUnlimited')}
                  style={{ width: '100%' }}
                />
              </Form.Item>
              <Form.Item name="traffic_limit_unit" noStyle>
                <Select
                  style={{ width: 96 }}
                  options={[
                    { value: 'MB', label: 'MB' },
                    { value: 'GB', label: 'GB' },
                    { value: 'TB', label: 'TB' },
                  ]}
                />
              </Form.Item>
            </Space.Compact>
          </Form.Item>
          {/* Expiry: empty = never. showTime because the cutoff is a
              datetime, not a date. Stored UTC, shown in local. */}
          <Form.Item
            name="expires_at"
            label={t('clients.expiry')}
            tooltip={t('clients.expiryTooltip')}
          >
            <DatePicker
              showTime
              format="YYYY-MM-DD HH:mm:ss"
              inputReadOnly
              style={{ width: '100%' }}
              placeholder={t('clients.expiryNever')}
              classNames={{ popup: { root: 'expiry-picker-dropdown' } }}
            />
          </Form.Item>
          {/* Enabled state is operated from the inline switch in the
              table row instead — keeping both controls drifted in
              practice because the modal's form snapshot doesn't follow
              background refetches (poller re-enable after reset, a
              parallel admin tab, etc.). One source of truth → no
              stale toggle, fewer footgun moments. */}
        </Form>
      )}
    </Modal>
  );
}
