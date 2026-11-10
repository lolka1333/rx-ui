import { describe, expect, it } from 'vitest';
import type { PanelSettings } from '@/api/types';
import { mergePanelSettings } from './panelSettings';

// Every settings page saves the WHOLE row through `mergePanelSettings`, so a
// field it fails to carry over is reset by a save on a page that never shows
// it. The test builds a "current" row where every field differs from its
// default and checks each one comes through untouched.

const defaults = mergePanelSettings(undefined, {});

function distinct(value: unknown): unknown {
  if (typeof value === 'boolean') return !value;
  if (typeof value === 'number') return value + 7;
  if (Array.isArray(value)) return ['probe'];
  if (typeof value === 'string') return 'probe';
  return value;
}

const current = Object.fromEntries(
  Object.entries(defaults).map(([k, v]) => [k, distinct(v)]),
) as unknown as PanelSettings;

// Write-only secrets: never echoed by the API, sent empty to mean "keep the
// stored one".
const SECRETS = new Set(['panel_tls_key', 'sub_key_pem']);

describe('mergePanelSettings', () => {
  const merged = mergePanelSettings(current, {});

  it.each(Object.keys(defaults).filter((k) => !SECRETS.has(k)))('carries %s over', (key) => {
    expect(merged[key as keyof typeof merged]).toEqual(current[key as keyof PanelSettings]);
  });

  it('sends the write-only secrets empty, meaning "keep the stored one"', () => {
    expect(merged.panel_tls_key).toBe('');
    expect(merged.sub_key_pem).toBe('');
  });

  it('lets the caller override only what it edits', () => {
    const out = mergePanelSettings(current, { sub_brand_name: 'mine' });
    expect(out.sub_brand_name).toBe('mine');
    expect(out.xray_dns_tag).toBe(current.xray_dns_tag);
  });

  it('falls back to the default query strategy for an empty stored value', () => {
    const out = mergePanelSettings({ ...current, xray_dns_query_strategy: '' }, {});
    expect(out.xray_dns_query_strategy).toBe('UseIP');
  });
});
