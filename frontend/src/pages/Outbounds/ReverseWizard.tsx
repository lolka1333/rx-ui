//! Reverse-pair wizard — a guided flow to stand up a VLESS Reverse Proxy pair
//! without hand-syncing uuid / transport / Reality keys / tag between two
//! servers. It orchestrates existing endpoints; there is no new backend.
//!
//! Role is chosen up front. PORTAL (public server): pick a VLESS inbound,
//! create a reverse client on it, optionally auto-add a routing rule that sends
//! traffic into the tunnel, then hand back an invite link (the client's
//! share-link, which now carries `reverse=<tag>`). BRIDGE (server behind NAT):
//! paste that invite, which fills a VLESS outbound (address / uuid / transport /
//! security / reverse tag) via the same Import path the outbound form uses, then
//! create it. Both ends finish with an optional "Apply (restart xray)" — reverse
//! is core config, so it only comes up on restart.
//!
//! Mounted only while open (Outbounds renders it conditionally), so every run
//! starts from fresh state — no reset plumbing.

import { App, Alert, Button, Form, Grid, Input, Modal, Radio, Select, Space, Steps, Typography, theme } from 'antd';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { uuid } from '@/lib/id';
import type {
  Client,
  CustomOutbound,
  Inbound,
  PanelSettings,
  RoutingRule,
  ShareLinkResponse,
} from '@/api/types';
import { mergePanelSettings } from '@/lib/panelSettings';
import { reportRouting } from '@/lib/routingReport';
import type { RoutingApplyResult } from '@/lib/routingReport';
import { LinkParseError, parseOutboundLink } from './parseLink';
import { OUTBOUND_DEFAULTS, formToOutbound, type OutboundFormValues } from './form';

type Role = 'portal' | 'bridge';
type TunnelMode = 'all' | 'domain' | 'none';

export function ReverseWizard({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const { token } = theme.useToken();
  const isMobile = !Grid.useBreakpoint().md;
  const qc = useQueryClient();
  const [role, setRole] = useState<Role | null>(null);
  const [step, setStep] = useState(0); // 0 role, 1 setup, 2 result

  // --- portal state ---
  const [inboundId, setInboundId] = useState<string | undefined>();
  const [reverseTag, setReverseTag] = useState('tunnel-home');
  const [email, setEmail] = useState('bridge-node');
  const [tunnelMode, setTunnelMode] = useState<TunnelMode>('all');
  const [domains, setDomains] = useState<string[]>([]);
  const [invite, setInvite] = useState('');
  // Resume markers so a retry after a partial failure doesn't re-create the
  // client (unique inbound_id+email → 409, orphan) or double-add the rule.
  const createdIdRef = useRef<string | null>(null);
  const ruleDoneRef = useRef(false);

  // --- bridge state ---
  const [linkText, setLinkText] = useState('');
  const [parsed, setParsed] = useState<Partial<OutboundFormValues> | null>(null);
  const [localTag, setLocalTag] = useState('');

  const { data: inbounds = [] } = useQuery<Inbound[]>({
    queryKey: ['inbounds'],
    queryFn: async () => (await apiClient.get<Inbound[]>('/inbounds')).data,
  });
  const vlessInbounds = inbounds.filter((i) => i.protocol.kind === 'vless');

  // Measure the current step's body so the modal animates its height between
  // steps instead of snapping when a short step gives way to the tall portal
  // form — see `.app-reverse-body`. Wired via a callback ref, not an effect: the
  // observer must attach the moment the node actually mounts, and a plain effect
  // can fire before antd's modal-appear motion has attached the content (leaving
  // it unmeasured, so the height never animates). The observer then tracks every
  // height change — switching steps or revealing a field within one. Runs on
  // mobile too: when a step is taller than the viewport the modal body
  // (maxHeight + overflowY:auto) scrolls, so the hidden overflow never clips.
  const [bodyHeight, setBodyHeight] = useState<number>();
  const observerRef = useRef<ResizeObserver | null>(null);
  const measureRef = useCallback((node: HTMLDivElement | null) => {
    observerRef.current?.disconnect();
    if (!node) return;
    setBodyHeight(node.offsetHeight);
    const ro = new ResizeObserver(() => setBodyHeight(node.offsetHeight));
    ro.observe(node);
    observerRef.current = ro;
  }, []);

  const createPortal = useMutation({
    mutationFn: async () => {
      const tag = reverseTag.trim();
      // 1) reverse client (portal endpoint). Created once — a retry after a
      //    later-step failure reuses the id instead of re-POSTing, which would
      //    409 on the unique (inbound_id, email) index and strand an orphan.
      let clientId = createdIdRef.current;
      if (!clientId) {
        clientId = (
          await apiClient.post<Client>(`/inbounds/${inboundId}/clients`, {
            email: email.trim(),
            uuid: null,
            auth: null,
            flow: null,
            reverse_tag: tag,
            note: null,
            traffic_limit_bytes: null,
            expires_at: null,
          })
        ).data.id;
        createdIdRef.current = clientId;
      }
      // 2) optional routing rule sending traffic into the tunnel (added once).
      //    Must come AFTER the client exists — the tag only becomes a legal
      //    target once a client carries it (valid_rule_targets checks live rows).
      if (tunnelMode !== 'none' && !ruleDoneRef.current) {
        const cur = (await apiClient.get<PanelSettings>('/settings/panel')).data;
        const rule: RoutingRule = {
          id: uuid(),
          enabled: true,
          name: t('reverse.ruleName', { tag }),
          domain: tunnelMode === 'domain' ? domains.map((d) => d.trim()).filter(Boolean) : [],
          ip: [],
          source_ip: [],
          port: '',
          source_port: '',
          // 'all' needs an explicit matcher — xray rejects a condition-less
          // rule ("no effective fields") and bricks the restart. tcp+udp
          // catches every connection.
          network: tunnelMode === 'all' ? ['tcp', 'udp'] : [],
          protocol: [],
          inbound_tag: [],
          user: [],
          outbound_tag: tag,
        };
        // This PUT always changes routing fields, so it always drives a live
        // push. Report the outcome, but keep going either way: the invite link
        // is about the client and stays valid, and the step this leads to is the
        // "Apply (restart xray)" button — which regenerates the config from the
        // database and is exactly the remedy for a rule the live router didn't
        // take. Stopping here would hide the link and leave no path forward.
        const res = await apiClient.put<RoutingApplyResult>(
          '/settings/panel',
          mergePanelSettings(cur, {
            xray_custom_rules: [...cur.xray_custom_rules, rule],
            xray_rule_order: [...cur.xray_rule_order, rule.id],
          }),
        );
        reportRouting(res.data ?? {}, message, t);
        ruleDoneRef.current = true;
      }
      // 3) invite = the client's share-link, which now carries reverse=<tag>.
      return (await apiClient.get<ShareLinkResponse>(`/clients/${clientId}/share-link`)).data.link;
    },
    onSuccess: (link) => {
      setInvite(link);
      setStep(2);
      // Prefix invalidation so the Clients page's filtered table cache
      // (['clients-global', inboundId]) refreshes too, not just the unfiltered one.
      qc.invalidateQueries({ queryKey: ['clients-global'] });
      qc.invalidateQueries({ queryKey: ['panel-settings'] });
    },
    onError: (e: unknown) => message.error(apiErrorMessage(e) ?? t('reverse.createPortalFailed')),
  });

  const createBridge = useMutation({
    mutationFn: async () => {
      if (!parsed) throw new Error('no imported link');
      const values: OutboundFormValues = {
        ...OUTBOUND_DEFAULTS,
        ...parsed,
        tag: localTag.trim(),
        enabled: true,
      };
      const ob = formToOutbound(values, null);
      const cur = (await apiClient.get<CustomOutbound[]>('/outbounds')).data;
      await apiClient.put('/outbounds', [...cur, ob]);
    },
    onSuccess: () => {
      setStep(2);
      qc.invalidateQueries({ queryKey: ['outbounds'] });
    },
    onError: (e: unknown) => message.error(apiErrorMessage(e) ?? t('reverse.createBridgeFailed')),
  });

  const restart = useMutation({
    mutationFn: async () => apiClient.post('/xray/restart'),
    onSuccess: () => message.success(t('reverse.restarted')),
    onError: (e: unknown) => message.error(apiErrorMessage(e) ?? t('reverse.restartFailed')),
  });

  const importLink = () => {
    try {
      const p = parseOutboundLink(linkText.trim());
      setParsed(p);
      setLocalTag(p.reverse_tag?.trim() || 'tunnel-home');
      if (!p.reverse_tag) {
        message.warning(t('reverse.linkNoReverse'));
      } else {
        message.success(t('reverse.imported'));
      }
    } catch (e) {
      message.error(
        e instanceof LinkParseError ? t(e.i18nKey, e.params) : t('reverse.linkParseError'),
      );
    }
  };

  // `hint` is mobile-only sub-copy (the compact header shows it under the step
  // title); antd Steps ignores the extra field on desktop.
  const steps = [
    { title: t('reverse.stepRole'), hint: t('reverse.stepRoleHint') },
    role === 'bridge'
      ? { title: t('reverse.stepPasteInvite'), hint: t('reverse.stepPasteInviteHint') }
      : { title: t('reverse.stepSetupPortal'), hint: t('reverse.stepSetupPortalHint') },
    {
      title: t('reverse.stepDone'),
      hint: role === 'bridge' ? t('reverse.stepDoneBridgeHint') : t('reverse.stepDonePortalHint'),
    },
  ];

  // ---- step bodies ----
  // Big selectable cards (not Radio.Button — that only makes the tiny inner
  // control clickable, so a click on the card body wouldn't register).
  const roleCard = (val: Role, title: string, desc: string) => {
    const active = role === val;
    return (
      <div
        role="button"
        tabIndex={0}
        onClick={() => setRole(val)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') setRole(val);
        }}
        style={{
          flex: 1,
          padding: 16,
          cursor: 'pointer',
          borderRadius: token.borderRadiusLG,
          border: `1px solid ${active ? token.colorPrimary : token.colorBorder}`,
          background: active ? token.colorPrimaryBg : 'transparent',
          transition: 'border-color 0.2s, background 0.2s',
        }}
      >
        <Typography.Text strong>{title}</Typography.Text>
        <br />
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {desc}
        </Typography.Text>
      </div>
    );
  };

  const roleStep = (
    <div
      style={{
        display: 'flex',
        flexDirection: isMobile ? 'column' : 'row',
        gap: 12,
        width: '100%',
      }}
    >
      {roleCard('portal', t('reverse.rolePortal'), t('reverse.rolePortalDesc'))}
      {roleCard('bridge', t('reverse.roleBridge'), t('reverse.roleBridgeDesc'))}
    </div>
  );

  const portalSetup = (
    <Form layout="vertical">
      <Form.Item label={t('reverse.inbound')} required tooltip={t('reverse.inboundHint')}>
        <Select
          value={inboundId}
          onChange={setInboundId}
          placeholder={t('reverse.inboundPlaceholder')}
          options={vlessInbounds.map((i) => ({ value: i.id, label: `${i.tag} (:${i.port})` }))}
          notFoundContent={t('reverse.inboundNotFound')}
        />
      </Form.Item>
      <Form.Item label={t('reverse.tag')} required tooltip={t('reverse.tagHint')}>
        <Input value={reverseTag} onChange={(e) => setReverseTag(e.target.value)} placeholder="tunnel-home" />
      </Form.Item>
      <Form.Item label={t('reverse.clientLabel')} tooltip={t('reverse.clientLabelHint')}>
        <Input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="bridge-node" />
      </Form.Item>
      <Form.Item label={t('reverse.tunnelMode')}>
        <Radio.Group value={tunnelMode} onChange={(e) => setTunnelMode(e.target.value as TunnelMode)}>
          <Radio value="all">{t('reverse.tunnelAll')}</Radio>
          <Radio value="domain">{t('reverse.tunnelDomain')}</Radio>
          <Radio value="none">{t('reverse.tunnelLater')}</Radio>
        </Radio.Group>
      </Form.Item>
      {tunnelMode === 'domain' && (
        <Form.Item label={t('reverse.domains')}>
          <Select mode="tags" value={domains} onChange={setDomains} placeholder={t('reverse.domainsPlaceholder')} tokenSeparators={[',', ' ']} />
        </Form.Item>
      )}
      {tunnelMode === 'all' && (
        <Alert type="warning" showIcon title={t('reverse.alertAll')} style={{ marginBottom: 8 }} />
      )}
      {tunnelMode === 'none' && (
        <Alert type="info" showIcon title={t('reverse.alertNone')} style={{ marginBottom: 8 }} />
      )}
    </Form>
  );

  const portalResult = (
    <Space orientation="vertical" style={{ width: '100%' }} size="middle">
      <Alert type="success" showIcon title={t('reverse.portalCreated')} />
      <div>
        <Typography.Text type="secondary">{t('reverse.inviteHint')}</Typography.Text>
        <Input.TextArea value={invite} readOnly autoSize={{ minRows: 3, maxRows: 6 }} style={{ marginTop: 4, fontFamily: 'monospace', fontSize: 12 }} />
        <Typography.Text
          copyable={{ text: invite, tooltips: [t('reverse.copyInvite'), t('reverse.copied')] }}
          style={{ marginTop: 8, display: 'inline-block' }}
        >
          {t('reverse.copyInvite')}
        </Typography.Text>
      </div>
      <Alert type="info" showIcon title={t('reverse.applyHint')} />
      <Button type="primary" loading={restart.isPending} onClick={() => restart.mutate()}>
        {t('reverse.apply')}
      </Button>
    </Space>
  );

  const bridgeSetup = (
    <Space orientation="vertical" style={{ width: '100%' }} size="middle">
      <Form layout="vertical">
        <Form.Item label={t('reverse.inviteLink')} required>
          <Space.Compact style={{ width: '100%' }}>
            <Input
              value={linkText}
              onChange={(e) => {
                setLinkText(e.target.value);
                // Editing after an Import invalidates the parsed result — force a
                // re-Import so Create bridge can't silently use the old link.
                setParsed(null);
              }}
              placeholder="vless://...&reverse=tunnel-home"
            />
            <Button onClick={importLink}>{t('reverse.import')}</Button>
          </Space.Compact>
        </Form.Item>
      </Form>
      {parsed && (
        <>
          <Alert
            type="success"
            showIcon
            title={
              <Space orientation="vertical" size={0}>
                <span>{t('reverse.portalSummary', { addr: `${parsed.address}:${parsed.port}` })}</span>
                <span>
                  {t('reverse.transportSummary', {
                    transport: parsed.network ?? 'tcp',
                    security: parsed.security ?? 'none',
                  })}
                </span>
              </Space>
            }
          />
          <Form layout="vertical">
            <Form.Item label={t('reverse.localTag')} tooltip={t('reverse.localTagHint')}>
              <Input value={localTag} onChange={(e) => setLocalTag(e.target.value)} placeholder="tunnel-home" />
            </Form.Item>
          </Form>
          <Alert type="warning" showIcon title={t('reverse.alertBridgeExit')} />
        </>
      )}
    </Space>
  );

  const bridgeResult = (
    <Space orientation="vertical" style={{ width: '100%' }} size="middle">
      <Alert type="success" showIcon title={t('reverse.bridgeCreated')} />
      <Alert type="info" showIcon title={t('reverse.applyHint')} />
      <Button type="primary" loading={restart.isPending} onClick={() => restart.mutate()}>
        {t('reverse.apply')}
      </Button>
    </Space>
  );

  const body =
    step === 0
      ? roleStep
      : step === 2
        ? role === 'bridge'
          ? bridgeResult
          : portalResult
        : role === 'bridge'
          ? bridgeSetup
          : portalSetup;

  // ---- footer ----
  const canNextRole = role !== null;
  const canCreatePortal =
    !!inboundId &&
    reverseTag.trim() !== '' &&
    // 'By domain' needs at least one non-blank domain, else the rule has no
    // matcher and xray rejects it.
    (tunnelMode !== 'domain' || domains.some((d) => d.trim()));
  const canCreateBridge = !!parsed && localTag.trim() !== '';

  let footer: React.ReactNode;
  if (step === 0) {
    footer = [
      <Button key="cancel" onClick={onClose}>{t('common.cancel')}</Button>,
      <Button key="next" type="primary" disabled={!canNextRole} onClick={() => setStep(1)}>{t('common.next')}</Button>,
    ];
  } else if (step === 1) {
    footer = [
      <Button key="back" onClick={() => setStep(0)}>{t('common.back')}</Button>,
      role === 'bridge' ? (
        <Button key="create" type="primary" disabled={!canCreateBridge} loading={createBridge.isPending} onClick={() => createBridge.mutate()}>
          {t('reverse.createBridge')}
        </Button>
      ) : (
        <Button key="create" type="primary" disabled={!canCreatePortal} loading={createPortal.isPending} onClick={() => createPortal.mutate()}>
          {t('reverse.createPortal')}
        </Button>
      ),
    ];
  } else {
    footer = [<Button key="done" type="primary" onClick={onClose}>{t('common.done')}</Button>];
  }

  return (
    <Modal
      open
      onCancel={onClose}
      title={t('reverse.title')}
      width={isMobile ? '100%' : 720}
      style={isMobile ? { top: 0, maxWidth: '100vw', margin: 0, paddingBottom: 0 } : undefined}
      styles={{
        body: isMobile ? { maxHeight: 'calc(100dvh - 180px)', overflowY: 'auto' } : undefined,
      }}
      mask={{ closable: false }}
      footer={footer}
    >
      {isMobile ? (
        // Full vertical Steps eat half the screen on a phone and push the body
        // out of view. A segment bar shows progress in one line; the step title
        // and a short hint tell the operator where they are and what to do.
        <div style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
            {steps.map((s, i) => (
              <div
                key={s.title}
                style={{
                  flex: 1,
                  height: 4,
                  borderRadius: 4,
                  background: i <= step ? token.colorPrimary : token.colorFillSecondary,
                  transition: 'background 0.3s',
                }}
              />
            ))}
          </div>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t('reverse.stepCounter', { n: step + 1, total: steps.length })}
          </Typography.Text>
          <br />
          <Typography.Text strong style={{ fontSize: 16 }}>
            {steps[step].title}
          </Typography.Text>
          <br />
          <Typography.Text type="secondary" style={{ fontSize: 13 }}>
            {steps[step].hint}
          </Typography.Text>
        </div>
      ) : (
        <Steps current={step} items={steps} size="small" style={{ marginBottom: 20 }} />
      )}
      <div className="app-reverse-body" style={{ height: bodyHeight }}>
        <div ref={measureRef}>
          <div key={step} className="app-reverse-step">
            {body}
          </div>
        </div>
      </div>
    </Modal>
  );
}
