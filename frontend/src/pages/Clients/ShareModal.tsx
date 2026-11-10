/**
 * Share modal — two tabs: a single vless:// link (the original
 * QR) and a multi-config subscription URL (one URL → every
 * share-link for this email, auto-imported by v2rayN / Hiddify /
 * sing-box). QRs render as SVG so they stay crisp at any size;
 * background stays white regardless of theme — that's a hard
 * requirement for reliable scanning by client cameras.
 */
import { Modal, Tabs, App } from 'antd';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import type { Dispatch, SetStateAction } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { Client, Inbound, ShareLinkResponse } from '@/api/types';
import type { ShareState } from './useClientActions';
import { ShareLinkPane, SubscriptionPane } from './sharePanes';

export function ShareModal({
  shareOpen,
  setShareOpen,
  inboundById,
}: {
  shareOpen: ShareState | null;
  setShareOpen: Dispatch<SetStateAction<ShareState | null>>;
  inboundById: Map<string, Inbound>;
}) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const qc = useQueryClient();

  // Switching inbounds inside the open modal: same per-row share-link
  // endpoint as opening it, only the state it lands in differs.
  const switchShareInbound = useMutation({
    mutationFn: async (client: Client) => {
      const share = (
        await apiClient.get<ShareLinkResponse>(`/clients/${client.id}/share-link`)
      ).data;
      return { clientId: client.id, share };
    },
    onSuccess: ({ clientId, share }) => {
      setShareOpen((cur) =>
        cur ? { ...cur, currentClientId: clientId, share } : cur,
      );
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('clients.saveError')),
  });

  // Rotate the per-client subscription token. The previous URL stops
  // resolving the moment the response lands — useful when a URL leaks
  // or the operator just wants a clean break for a paying customer.
  // Refetches the global client list so the new token shows up on
  // every page that shares the cache.
  const rotateSubToken = useMutation({
    mutationFn: async (clientId: string) =>
      (await apiClient.post<Client>(`/clients/${clientId}/rotate-sub-token`)).data,
    onSuccess: (updated) => {
      qc.invalidateQueries({ queryKey: ['clients-global'] });
      // Patch the open group in place so the QR re-renders with the new
      // token without waiting for the cache refetch. The token is the
      // email's — the backend replaced it on every attachment — so every
      // row of the group takes it, not just the one the call named.
      setShareOpen((cur) => {
        if (!cur) return cur;
        const rows = cur.group.rows.map((r) =>
          r.id === updated.id ? updated : { ...r, sub_token: updated.sub_token },
        );
        return { ...cur, group: { ...cur.group, rows } };
      });
      message.success(t('clients.subRotated'));
    },
    onError: (err: unknown) =>
      message.error(apiErrorMessage(err) ?? t('clients.saveError')),
  });

  return (
    <Modal
      destroyOnHidden
      open={shareOpen != null}
      title={t('clients.shareLinkTitle')}
      onCancel={() => setShareOpen(null)}
      onOk={() => setShareOpen(null)}
      okText={t('common.close')}
      cancelButtonProps={{ style: { display: 'none' } }}
    >
      {shareOpen && (
        <Tabs
          // Subscription tab opens by default for multi-inbound groups
          // — the one URL covers all configs and is the recommended
          // import path. Single-inbound clients see the direct
          // share-link tab first (subscription is overkill for one).
          defaultActiveKey={shareOpen.group.rows.length > 1 ? 'sub' : 'link'}
          items={[
            {
              key: 'link',
              label: t('clients.shareTabLink'),
              children: (
                <ShareLinkPane
                  group={shareOpen.group}
                  currentClientId={shareOpen.currentClientId}
                  share={shareOpen.share}
                  inboundById={inboundById}
                  onSwitchInbound={(client) => switchShareInbound.mutate(client)}
                  switching={switchShareInbound.isPending}
                />
              ),
            },
            {
              key: 'sub',
              label: t('clients.shareTabSub'),
              children: (
                <SubscriptionPane
                  client={shareOpen.group.rows[0]}
                  onRotate={() =>
                    rotateSubToken.mutate(shareOpen.group.rows[0].id)
                  }
                  rotating={rotateSubToken.isPending}
                />
              ),
            },
          ]}
        />
      )}
    </Modal>
  );
}
