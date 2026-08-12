//! Quick-pick presets for every field that takes an xray geo matcher.
//!
//! Two pages ask the same question — "which domains / IPs?" — the Xray
//! settings tab (blocked lists) and the routing rules editor. They used to
//! carry a list each, and the lists had already drifted: the same
//! `geoip:private` read "Private IPs" in one field and "Private IP" in the
//! other, and each knew a handful of tokens the other did not.
//!
//! Labels are short, plain English with no icons and no translation: service
//! names are proper nouns and the rest echo the token ("Ads All", "Private
//! IP"), so they read the same in any UI language. `code` is the two-letter
//! badge the settings fields show; entries that are not a country simply have
//! none.
//!
//! Every field using these stays `mode="tags"`, so any custom matcher
//! (`full:`, `regexp:`, a CIDR, `ext:…`) still works — the presets are a
//! shortcut, never a whitelist. All tokens are present in the bundled
//! `geoip.dat` / `geosite.dat`.

export type GeoPreset = { value: string; label: string; code?: string };

export const GEOIP_PRESETS: GeoPreset[] = [
  { value: 'geoip:private', code: 'IP', label: 'Private IP' },
  { value: 'geoip:ru', code: 'RU', label: 'Russia' },
  { value: 'geoip:ua', code: 'UA', label: 'Ukraine' },
  { value: 'geoip:by', code: 'BY', label: 'Belarus' },
  { value: 'geoip:kz', code: 'KZ', label: 'Kazakhstan' },
  { value: 'geoip:cn', code: 'CN', label: 'China' },
  { value: 'geoip:ir', code: 'IR', label: 'Iran' },
  { value: 'geoip:us', code: 'US', label: 'USA' },
  { value: 'geoip:de', code: 'DE', label: 'Germany' },
  { value: 'geoip:nl', code: 'NL', label: 'Netherlands' },
  { value: 'geoip:gb', code: 'GB', label: 'UK' },
  { value: 'geoip:tr', code: 'TR', label: 'Turkey' },
  { value: 'geoip:br', code: 'BR', label: 'Brazil' },
  { value: 'geoip:vn', code: 'VN', label: 'Vietnam' },
  { value: 'geoip:es', code: 'ES', label: 'Spain' },
  { value: 'geoip:id', code: 'ID', label: 'Indonesia' },
  { value: 'geoip:telegram', label: 'Telegram' },
  { value: 'geoip:google', label: 'Google' },
  { value: 'geoip:netflix', label: 'Netflix' },
  { value: 'geoip:twitter', label: 'Twitter / X' },
  { value: 'geoip:facebook', label: 'Facebook' },
  { value: 'geoip:cloudflare', label: 'Cloudflare' },
];

export const GEOSITE_PRESETS: GeoPreset[] = [
  { value: 'geosite:category-ads-all', code: 'AD', label: 'Ads All' },
  { value: 'geosite:category-porn', code: '18', label: 'Porn (18+)' },
  { value: 'geosite:private', code: 'IP', label: 'Private' },
  { value: 'geosite:category-ru', code: 'RU', label: 'Russia' },
  { value: 'geosite:cn', code: 'CN', label: 'China' },
  { value: 'geosite:google', label: 'Google' },
  { value: 'geosite:youtube', label: 'YouTube' },
  { value: 'geosite:telegram', label: 'Telegram' },
  { value: 'geosite:netflix', label: 'Netflix' },
  { value: 'geosite:openai', label: 'OpenAI' },
  { value: 'geosite:meta', label: 'Meta' },
  { value: 'geosite:twitter', label: 'Twitter / X' },
  { value: 'geosite:tiktok', label: 'TikTok' },
  { value: 'geosite:spotify', label: 'Spotify' },
  { value: 'geosite:steam', label: 'Steam' },
  { value: 'geosite:apple', label: 'Apple' },
  { value: 'geosite:microsoft', label: 'Microsoft' },
  // TLD matchers, not geosite categories — xray takes a bare `regexp:` in the
  // same field, and blocking a whole zone is a common ask.
  { value: 'regexp:\\.ru$', code: 'RU', label: '.ru' },
  { value: 'regexp:\\.su$', code: 'RU', label: '.su' },
  { value: 'regexp:\\.xn--p1ai$', code: 'RU', label: '.рф' },
  { value: 'regexp:\\.ua$', code: 'UA', label: '.ua' },
  { value: 'regexp:\\.cn$', code: 'CN', label: '.cn' },
  { value: 'regexp:\\.vn$', code: 'VN', label: '.vn' },
];

/** value → preset, so a selected chip can show the same badge and label. */
export const GEO_PRESET_BY_VALUE = new Map<string, GeoPreset>(
  [...GEOIP_PRESETS, ...GEOSITE_PRESETS].map((o) => [o.value, o]),
);
