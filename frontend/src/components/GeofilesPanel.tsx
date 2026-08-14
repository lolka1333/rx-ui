//! Geofile source panel, shown inside the Xray-updates modal.
//!
//! `geoip.dat` / `geosite.dat` used to arrive only inside the xray release
//! archive, which pinned the routing lists to the core's release cadence. This
//! panel lets the operator point at a rules repository instead, see whether the
//! files on disk are still the ones that source publishes, and refresh them.
//!
//! It is built from the panel's OWN row idiom (`app-settings-inforow` — icon
//! tile, name + description on the left, value on the right), the same one the
//! Account tab uses. The first version of this file stacked bare divs with
//! inline flex/gap and a CSS class that was never written, so it read as a
//! foreign block dropped into the modal.
//!
//! Two things it deliberately shows rather than hides: the SHA-256 prefix of
//! each file (the only honest answer to "is this current?" — a mirror's
//! timestamp is not), and that a download does NOT make the new lists live,
//! because the core only reads them at startup.

import { Alert, App, Button, Input, Select, Switch, Typography } from 'antd';
import { DatabaseOutlined, ReloadOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useLoadState } from '@/api/loadState';
import { LoadError } from '@/components/LoadState';
import { fmtBytes } from '@/lib/format';
import type { GeoPanel, GeoUpdateResult } from '@/api/types/geofiles';

/** Preset ids, `xray` first because it is the default and the status quo. */
const SOURCE_ORDER = ['xray', 'loyalsoldier', 'runet', 'v2fly', 'custom'] as const;

/** One file, in the panel's standard row: icon tile, name + what we know about
 *  it, hash on the right. The hash is the value because it is the only field
 *  that answers "is this the current release?". */
function FileRow({ name, meta, hash }: { name: string; meta: string; hash: string }) {
  return (
    <div className="app-settings-inforow">
      <span className="app-settings-inforow-id">
        <span className="app-settings-inforow-icon" aria-hidden="true">
          <DatabaseOutlined />
        </span>
        <span className="app-field-label">
          <span className="app-field-title">{name}</span>
          <span className="app-field-desc">{meta}</span>
        </span>
      </span>
      <div className="app-settings-inforow-control">
        <span className="app-settings-inforow-value">
          <Typography.Text code style={{ fontSize: 12 }}>
            {hash}
          </Typography.Text>
        </span>
      </div>
    </div>
  );
}

export function GeofilesPanel() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const qc = useQueryClient();

  const panelQ = useQuery<GeoPanel>({
    queryKey: ['geofiles'],
    queryFn: async () => (await apiClient.get<GeoPanel>('/xray/geofiles')).data,
  });
  const state = useLoadState([panelQ]);
  const data = panelQ.data;

  // The edit state is a DRAFT laid over the server's answer, not a copy seeded
  // in an effect: null means "nothing edited, show what the server last said",
  // so a refetch is picked up for free and no stale local copy can overwrite
  // it. Saving clears the draft, handing control back to the server value.
  const [draft, setDraft] = useState<{
    source: string;
    geoip: string;
    geosite: string;
    auto: boolean;
  } | null>(null);
  const eff = draft ?? {
    source: data?.source ?? 'xray',
    geoip: data?.custom_geoip_url ?? '',
    geosite: data?.custom_geosite_url ?? '',
    auto: data?.auto_update ?? false,
  };
  const edit = (patch: Partial<typeof eff>) => setDraft({ ...eff, ...patch });

  const save = useMutation({
    mutationFn: async (body: {
      source: string;
      custom_geoip_url: string;
      custom_geosite_url: string;
      auto_update: boolean;
    }) => (await apiClient.put<GeoPanel>('/xray/geofiles', body)).data,
    onSuccess: (d) => {
      qc.setQueryData(['geofiles'], d);
      setDraft(null);
      message.success(t('xrayUpdates.geoSaved'));
    },
    onError: (e: unknown) => message.error(apiErrorMessage(e) ?? t('common.error')),
  });

  const update = useMutation({
    // Two ~20 MB downloads plus a restart: the global 15s axios timeout would
    // abort the request on essentially every real refresh while the backend
    // carried on working. Same override the binary install uses.
    mutationFn: async () =>
      (
        await apiClient.post<GeoUpdateResult>('/xray/geofiles/update', undefined, {
          timeout: 10 * 60_000,
        })
      ).data,
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ['geofiles'] });
      if (!r.changed) {
        message.info(t('xrayUpdates.geoAlreadyCurrent'));
      } else if (r.restarted) {
        message.success(t('xrayUpdates.geoUpdatedRestarted'));
      } else {
        // Changed but not applied: xray was down, so the next start reads them.
        message.success(t('xrayUpdates.geoUpdatedNoRestart'));
      }
    },
    onError: (e: unknown) => message.error(apiErrorMessage(e) ?? t('common.error')),
  });

  if (state.blocked) return null;
  if (state.failed) return <LoadError state={state} />;

  const isCustom = eff.source === 'custom';
  const fromArchive = eff.source === 'xray';
  const dirty =
    !!data &&
    (eff.source !== data.source ||
      eff.auto !== data.auto_update ||
      (isCustom &&
        (eff.geoip !== data.custom_geoip_url || eff.geosite !== data.custom_geosite_url)));

  return (
    <div className="app-geo">
      <Typography.Text type="secondary" className="app-geo-note">
        {t('xrayUpdates.geofilesNote')}
      </Typography.Text>

      {/* Source and its one action sit on the same line: picking a source and
          pulling from it are the same thought. */}
      <div className="app-geo-source">
        <Select
          value={eff.source}
          onChange={(v) => edit({ source: v })}
          className="app-geo-select"
          options={SOURCE_ORDER.filter(
            (id) => id === 'xray' || id === 'custom' || (data?.sources ?? []).includes(id),
          ).map((id) => ({ value: id, label: t(`xrayUpdates.geoSource_${id}`) }))}
        />
        {/* Hidden rather than disabled when the archive is the source: a
            greyed-out button invites the operator to wonder what unlocks it,
            and the answer — "reinstall the core, one section up" — is not
            something a disabled state can say. */}
        {!fromArchive && (
          <Button
            icon={<ReloadOutlined />}
            loading={update.isPending}
            disabled={dirty}
            title={dirty ? t('xrayUpdates.geoSaveFirst') : undefined}
            onClick={() => update.mutate()}
          >
            {t('xrayUpdates.geoRefresh')}
          </Button>
        )}
      </div>

      {isCustom && (
        <div className="app-geo-urls">
          <Input
            value={eff.geoip}
            onChange={(e) => edit({ geoip: e.target.value })}
            placeholder="https://…/geoip.dat"
            spellCheck={false}
            addonBefore="geoip"
          />
          <Input
            value={eff.geosite}
            onChange={(e) => edit({ geosite: e.target.value })}
            placeholder="https://…/geosite.dat"
            spellCheck={false}
            addonBefore="geosite"
          />
          <Typography.Text type="secondary" className="app-geo-hint">
            {t('xrayUpdates.geoCustomHint')}
          </Typography.Text>
        </div>
      )}

      {/* The auto switch rides the same row grid as the files below it, so the
          section reads as one column instead of three stacked fragments. */}
      <div className="app-settings-inforow app-geo-auto">
        <span className="app-settings-inforow-id">
          <span className="app-field-label">
            <span className="app-field-title">{t('xrayUpdates.geoAuto')}</span>
            <span className="app-field-desc">{t('xrayUpdates.geoAutoHint')}</span>
          </span>
        </span>
        <div className="app-settings-inforow-control">
          <Switch checked={eff.auto} onChange={(v) => edit({ auto: v })} disabled={fromArchive} />
        </div>
      </div>

      {dirty && (
        <div className="app-geo-save">
          <Button
            type="primary"
            size="small"
            loading={save.isPending}
            onClick={() =>
              save.mutate({
                source: eff.source,
                custom_geoip_url: eff.geoip,
                custom_geosite_url: eff.geosite,
                auto_update: eff.auto,
              })
            }
          >
            {t('common.save')}
          </Button>
        </div>
      )}

      {data?.apply_pending && (
        <Alert
          type="warning"
          showIcon
          title={t('xrayUpdates.geoPending')}
          action={
            <Button size="small" loading={update.isPending} onClick={() => update.mutate()}>
              {t('xrayUpdates.geoApply')}
            </Button>
          }
        />
      )}

      <div className="app-geo-files">
        {(data?.files ?? []).map((f) =>
          f.present ? (
            <FileRow
              key={f.name}
              name={f.name}
              meta={`${fmtBytes(f.size_bytes)} · ${f.modified_at.slice(0, 10)}`}
              hash={f.sha256.slice(0, 12)}
            />
          ) : (
            <FileRow
              key={f.name}
              name={f.name}
              meta={t('xrayUpdates.geoMissing')}
              hash="—"
            />
          ),
        )}
      </div>

      {data?.updated_at && (
        <Typography.Text type="secondary" className="app-geo-hint">
          {t('xrayUpdates.geoLastUpdate', {
            when: data.updated_at.slice(0, 16).replace('T', ' '),
          })}
        </Typography.Text>
      )}
    </div>
  );
}
