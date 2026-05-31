//! Tabbed form rendered inside the "Edit / New" modal. The tab list is
//! a derived view of the protocol registry — `extraTabs` from the
//! registry, plus reality/tls/ws/xhttp panes that show up only when the
//! matching value is currently picked in the General tab.
//!
//! Form state is shared via Antd's `Form` instance (Antd preserves field
//! values across tab unmounts by default), so picking up a previously
//! entered TLS cert when the operator flips back from XHTTP just works.
//!
//! Watched fields (`protocol_kind`, `network`, `security`) live here
//! rather than on the page root — only this layer reacts to them, so
//! the consumer is the right place to subscribe.

import { App, Form, Tabs } from 'antd';
import { memo, useLayoutEffect, useMemo } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { Inbound } from '@/api/types';
import { DEFAULTS } from './form/defaults';
import { inboundToForm } from './form/adapters';
import { PROTOCOL_REGISTRY, useProtocolGuards } from './form/registry';
import type { FormNetwork, FormProtocol, FormSecurity, FormValues } from './form/types';
import { FallbacksTab } from './tabs/FallbacksTab';
import { FinalMaskTab } from './tabs/FinalMaskTab';
import { GeneralTab } from './tabs/GeneralTab';
import { RealityTab } from './tabs/RealityTab';
import { SockoptTab } from './tabs/SockoptTab';
import { TlsTab } from './tabs/TlsTab';
import { WebSocketTab } from './tabs/WebSocketTab';
import { XhttpTab } from './tabs/XhttpTab';

interface InboundFormProps {
  formKey: number;
  form: ReturnType<typeof Form.useForm<FormValues>>[0];
  editing: Inbound | null;
  onFinish: (values: FormValues) => void;
  /** Replace the parent's `editing` row after a rotate-reality-keypair
   *  succeeds — the textarea reads `realityPublicKey(editing)` directly
   *  (not via the form instance) so a stale prop would keep showing the
   *  old key after rotation. */
  onEditingChange: (next: Inbound) => void;
}

// Memoised: the Inbounds page re-renders every ~5s because the always-
// mounted Clients page polls the shared `clients-stats` query, and this
// page consumes the same cache. Without memo that tick would re-render the
// modal's <Tabs>, and Antd re-aligns an overflowing tab row to the active
// (leftmost) tab — making a sideways-scrolled row "teleport" to the start
// on a narrow screen. Stable props (incl. a useCallback'd onFinish) let
// memo skip those background re-renders; real field edits still re-render
// via the internal Form.useWatch subscriptions.
export const InboundForm = memo(function InboundForm({
  formKey,
  form,
  editing,
  onFinish,
  onEditingChange,
}: InboundFormProps) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const qc = useQueryClient();

  const watchedProtocol = Form.useWatch('protocol_kind', form) as FormProtocol | undefined;
  const watchedNetwork = Form.useWatch('network', form) as FormNetwork | undefined;
  const watchedSecurity = Form.useWatch('security', form) as FormSecurity | undefined;
  useProtocolGuards(form);

  // Antd `Form.useForm()` returns a persistent form-instance that lives in
  // the parent. The `key={formKey}` below remounts the React tree, but the
  // form INSTANCE keeps its internal store across remounts. `initialValues`
  // only fills fields that are empty in the store — values from a prior
  // edit session (e.g. user opened inbound A, then opened inbound B) leak
  // through. Explicit `resetFields()` after each remount wipes the store
  // and re-applies the freshly-registered `initialValues` of the current
  // record. `useLayoutEffect` runs after mount but before paint, so the
  // user never sees the stale values flash during the modal-open animation.
  useLayoutEffect(() => {
    form.resetFields();
  }, [formKey, form]);

  const rotate = useMutation({
    mutationFn: async (inboundId: string) =>
      (await apiClient.post<Inbound>(
        `/inbounds/${inboundId}/rotate-reality-keypair`,
      )).data,
    onSuccess: (updated) => {
      onEditingChange(updated);
      qc.invalidateQueries({ queryKey: ['inbounds'] });
      message.success(t('inbounds.rotateKeypairDone'));
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('inbounds.rotateKeypairError')),
  });

  const initialValues = useMemo(
    () => (editing != null ? inboundToForm(editing) : DEFAULTS),
    [editing],
  );

  const tabItems = useMemo(() => {
    const def = PROTOCOL_REGISTRY[watchedProtocol ?? 'vless'];
    return [
      {
        key: 'main',
        label: t('inbounds.tabMain'),
        children: <GeneralTab />,
      },
      ...(watchedSecurity === 'reality' && def.allowedSecurities.includes('reality')
        ? [{
            key: 'reality',
            label: t('inbounds.tabReality'),
            children: (
              <RealityTab
                editing={editing}
                onRotate={() => editing && rotate.mutate(editing.id)}
                rotating={rotate.isPending}
              />
            ),
          }]
        : []),
      ...(watchedSecurity === 'tls'
        ? [{
            key: 'tls',
            label: t('inbounds.tabTls'),
            children: <TlsTab />,
          }]
        : []),
      ...(def.allowedTransports.includes('ws') && watchedNetwork === 'ws'
        ? [{
            key: 'ws',
            label: t('inbounds.tabWs'),
            children: <WebSocketTab />,
          }]
        : []),
      ...(def.allowedTransports.includes('xhttp') && watchedNetwork === 'xhttp'
        ? [{
            key: 'xhttp',
            label: t('inbounds.tabXhttp'),
            children: <XhttpTab />,
          }]
        : []),
      ...(def.extraTabs ?? []).map(({ key, labelKey, Component }) => ({
        key,
        label: t(labelKey),
        children: <Component />,
      })),
      // Fallbacks live only on VLESS, but we always render the tab so
      // the operator can discover that the feature exists — the tab
      // body itself shows an Alert when the current config rules it
      // out (non-VLESS / non-TCP / VLESS Encryption on).
      ...(watchedProtocol === 'vless'
        ? [{
            key: 'fallbacks',
            label: t('inbounds.tabFallbacks'),
            children: <FallbacksTab />,
          }]
        : []),
      // Sockopt is protocol-agnostic (socket-level options). Render it
      // before FinalMask; it stays a no-op until the operator sets a
      // value (most relevant: trustedXForwardedFor for XHTTP/WS).
      {
        key: 'sockopt',
        label: t('inbounds.tabSockopt'),
        children: <SockoptTab />,
      },
      // FinalMask is protocol-agnostic — sudoku wraps the socket after
      // TLS/Reality regardless of whether the proxy is vless or
      // hysteria. Always render the tab last; it stays cheap when the
      // operator leaves `kind = none`.
      {
        key: 'finalmask',
        label: t('inbounds.tabFinalMask'),
        children: <FinalMaskTab />,
      },
    ];
  }, [
    t,
    watchedProtocol,
    watchedNetwork,
    watchedSecurity,
    editing,
    rotate.isPending,
    rotate.mutate,
  ]);

  return (
    <Form
      key={formKey}
      form={form}
      layout="vertical"
      initialValues={initialValues}
      onFinish={onFinish}
      style={{ marginTop: 8 }}
    >
      <Tabs items={tabItems} />
    </Form>
  );
});
