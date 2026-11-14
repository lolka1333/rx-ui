//! Rules page — the routing order, on its own.
//!
//! It used to be the bottom half of the Xray settings' routing tab, under the
//! block- and direct-lists that generate the built-in rows. That put the one
//! table an operator reorders by hand two levels deep — a tab inside a settings
//! section — beside four fields it only reads.
//!
//! The rules are still two columns of `panel_settings` (`xray_custom_rules` and
//! `xray_rule_order`), so this page saves through the same endpoint the settings
//! page does. It does that as a read-modify-write: it re-reads the row at save
//! time and replaces only those two fields, so a save here cannot roll back
//! something changed on another page since this one loaded.
//!
//! The six other fields in the form are NOT edited here. `RoutingRulesField`
//! watches them to know which built-in rows exist (a blocked-IP list produces a
//! "block" row, and so on); they are seeded from the server and left alone.

import { App, Button, Form, Typography } from 'antd';
import { CloseOutlined, ReloadOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useLoadState } from '@/api/loadState';
import { LoadError, LoadStale } from '@/components/LoadState';
import { RoutingRulesField } from '@/components/RoutingRulesField';
import { reportRouting, type RoutingApplyResult } from '@/lib/routingReport';
import type { PanelSettings, RoutingRule } from '@/api/types';

/** The slice of the settings row this page puts in a form: the two fields it
 *  edits, and the six `RoutingRulesField` reads to build the system rows. */
interface RulesFormValues {
  xray_custom_rules: RoutingRule[];
  xray_rule_order: string[];
  xray_block_bittorrent: boolean;
  xray_blocked_ips: string[];
  xray_blocked_domains: string[];
  xray_direct_ips: string[];
  xray_direct_domains: string[];
  xray_ipv4_domains: string[];
}

function seed(d: PanelSettings): RulesFormValues {
  return {
    xray_custom_rules: d.xray_custom_rules ?? [],
    xray_rule_order: d.xray_rule_order ?? [],
    xray_block_bittorrent: d.xray_block_bittorrent,
    xray_blocked_ips: d.xray_blocked_ips ?? [],
    xray_blocked_domains: d.xray_blocked_domains ?? [],
    xray_direct_ips: d.xray_direct_ips ?? [],
    xray_direct_domains: d.xray_direct_domains ?? [],
    xray_ipv4_domains: d.xray_ipv4_domains ?? [],
  };
}

/** No-op control, the same one the settings page uses: `xray_rule_order` is an
 *  array with no widget, but it has to be a registered field for
 *  `RoutingRulesField` to watch it and for the save to carry it. */
function HiddenField() {
  return <span />;
}

export function Rules() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const qc = useQueryClient();
  const [form] = Form.useForm<RulesFormValues>();
  const [dirty, setDirty] = useState(false);
  // Set by a save the core took live. xray picks a route once, when a
  // connection opens, so those rules reach new connections only — a browser
  // tab keeps reusing the one it already has. The strip below says so and
  // offers the restart that moves everything at once.
  const [appliedNote, setAppliedNote] = useState(false);

  const query = useQuery<PanelSettings>({
    queryKey: ['panel-settings'],
    queryFn: async () => (await apiClient.get<PanelSettings>('/settings/panel')).data,
  });
  const page = useLoadState([query]);
  const data = query.data;

  // Seed once per server payload. Re-seeding while the operator has unsaved
  // edits would throw them away on any background refetch, so a dirty form is
  // left alone until it is saved or discarded.
  const baseline = useMemo(() => (data ? seed(data) : null), [data]);
  useEffect(() => {
    if (baseline && !dirty) form.setFieldsValue(baseline);
  }, [baseline, dirty, form]);

  const mutation = useMutation({
    mutationFn: async () => {
      const v = form.getFieldsValue(true) as RulesFormValues;
      // Re-read rather than send what this page loaded: the settings row is
      // written by several pages, and everything outside these two fields has
      // to go back exactly as it stands now.
      //
      // Spreading the GET response is safe even though the update body has two
      // fields the response does not — `panel_tls_key` and `sub_key_pem` are
      // never echoed back. Both are "keep what is stored" when sent empty,
      // which is what an absent field deserialises to.
      const fresh = (await apiClient.get<PanelSettings>('/settings/panel')).data;
      const res = await apiClient.put<RoutingApplyResult>('/settings/panel', {
        ...fresh,
        xray_custom_rules: v.xray_custom_rules,
        xray_rule_order: v.xray_rule_order,
      });
      return res.data ?? {};
    },
    onSuccess: async (routing) => {
      setDirty(false);
      await qc.invalidateQueries({ queryKey: ['panel-settings'] });
      // The response says what happened to the LIVE router, and this page is
      // the one whose every save is a routing change. `reportRouting` owns
      // both messages worth having — the rules did not reach the core, or they
      // did but only because xray was restarted and every client reconnected —
      // so a plain "saved" here would hide an unapplied rule set or an outage
      // this save caused. Claim success only when it had nothing to say.
      // When the rules went live without a restart, the strip takes over from
      // a toast: what is worth saying is what did NOT happen to the
      // connections already open, and that needs a button next to it.
      setAppliedNote(reportRouting(routing, message, t) === 'clean');
    },
    onError: (e: unknown) =>
      message.error(apiErrorMessage(e) ?? t('settings.panelSaveError')),
  });

  const discard = useCallback(() => {
    if (baseline) form.setFieldsValue(baseline);
    setDirty(false);
  }, [baseline, form]);

  // Every client reconnects, and on reconnecting each connection is routed by
  // the rules that are live now.
  const restart = useMutation({
    mutationFn: async () => apiClient.post('/xray/restart'),
    onSuccess: async () => {
      setAppliedNote(false);
      await qc.invalidateQueries({ queryKey: ['dashboard-overview'] });
      message.success(t('settings.rulesRestartedAll'));
    },
    onError: (e: unknown) => message.error(apiErrorMessage(e) ?? t('settings.xrayRestartError')),
  });
  const noteShown = appliedNote && !dirty;

  // The house pattern: nothing on screen until the row has arrived, then the
  // whole page fades in as one piece.
  if (page.blocked) {
    return null;
  }
  if (page.failed) {
    return <LoadError state={page} />;
  }

  return (
    <div className="app-content-reveal">
      <LoadStale state={page} />
      <Form
        form={form}
        layout="vertical"
        initialValues={baseline ?? undefined}
        onValuesChange={() => {
          setDirty(true);
          setAppliedNote(false);
        }}
      >
        <Form.Item name="xray_custom_rules" noStyle>
          <RoutingRulesField />
        </Form.Item>
        {/* Registered so the table can watch it and the save can carry it. The
            six context fields below are registered for the same reason — they
            are read, never written, and they must not reach the payload. */}
        <Form.Item name="xray_rule_order" hidden>
          <HiddenField />
        </Form.Item>
        <div style={{ display: 'none' }}>
          <Form.Item name="xray_block_bittorrent" valuePropName="checked">
            <HiddenField />
          </Form.Item>
          <Form.Item name="xray_blocked_ips">
            <HiddenField />
          </Form.Item>
          <Form.Item name="xray_blocked_domains">
            <HiddenField />
          </Form.Item>
          <Form.Item name="xray_direct_ips">
            <HiddenField />
          </Form.Item>
          <Form.Item name="xray_direct_domains">
            <HiddenField />
          </Form.Item>
          <Form.Item name="xray_ipv4_domains">
            <HiddenField />
          </Form.Item>
        </div>
      </Form>

      {/* The same bar the settings page raises, for the same reason: the table
          edits in place and nothing else on the page says the change is not
          stored yet. After a live save it stays up as a note about the
          connections already open. */}
      <div
        className={`app-settings-dirtybar${dirty || noteShown ? ' is-visible' : ''}${
          noteShown ? ' is-note' : ''
        }`}
        role="region"
        aria-live="polite"
      >
        {noteShown ? (
          <div className="app-settings-dirtybar-inner">
            <span className="app-settings-dirtybar-dot" aria-hidden="true" />
            <Typography.Text
              className="app-settings-dirtybar-text"
              style={{ flex: '1 1 auto', minWidth: 0 }}
              title={t('settings.rulesAppliedNewHint')}
            >
              {t('settings.rulesAppliedNew')}
            </Typography.Text>
            <Button
              type="primary"
              icon={<ReloadOutlined />}
              onClick={() => restart.mutate()}
              loading={restart.isPending}
            >
              {t('settings.rulesRestartNow')}
            </Button>
            <Button
              type="text"
              icon={<CloseOutlined />}
              aria-label={t('common.close')}
              onClick={() => setAppliedNote(false)}
              disabled={restart.isPending}
            />
          </div>
        ) : (
          <div className="app-settings-dirtybar-inner">
            <span className="app-settings-dirtybar-dot" aria-hidden="true" />
            <Typography.Text
              className="app-settings-dirtybar-text"
              style={{ flex: '1 1 auto', minWidth: 0 }}
            >
              {t('settings.dirtyHint')}
            </Typography.Text>
            <Button onClick={discard} disabled={mutation.isPending}>
              {t('settings.discard')}
            </Button>
            <Button type="primary" onClick={() => mutation.mutate()} loading={mutation.isPending}>
              {t('settings.save')}
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
