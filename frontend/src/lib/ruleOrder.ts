//! The routing table's evaluation order, derived the way the backend derives it
//! (`ordered_rule_tokens` in xray/config_gen.rs).
//!
//! Shared by the table that renders the order and the Rules page that decides
//! whether there is anything to save. The two have to agree: moving a rule
//! writes the full derived list (system tokens included), while the stored
//! order may be shorter — older, or never touched — so comparing the raw field
//! against the saved one called a rule moved away and back "unsaved".

/** The settings that decide which built-in rows exist. */
export interface SystemRowSources {
  xray_block_bittorrent?: boolean;
  xray_blocked_domains?: string[];
  xray_blocked_ips?: string[];
  xray_direct_domains?: string[];
  xray_direct_ips?: string[];
  xray_ipv4_domains?: string[];
}

/** The built-in rows present for these settings, in their default order. The
 *  api pin is always there. */
export function activeSystemTokens(v: SystemRowSources): string[] {
  const out = ['api'];
  if (v.xray_block_bittorrent) out.push('bittorrent');
  if (v.xray_blocked_domains?.length) out.push('blocked_domains');
  if (v.xray_blocked_ips?.length) out.push('blocked_ips');
  if (v.xray_direct_domains?.length) out.push('direct_domains');
  if (v.xray_direct_ips?.length) out.push('direct_ips');
  if (v.xray_ipv4_domains?.length) out.push('ipv4');
  return out;
}

/** Reconcile a saved order against what currently exists: drop tokens that are
 *  gone (first occurrence wins), slot missing built-in rows into the built-in
 *  block, append new custom rules at the end, and put the api pin first. */
export function deriveRuleOrder(saved: string[], ruleIds: string[], activeSys: string[]): string[] {
  const valid = new Set([...activeSys, ...ruleIds]);
  const isSystem = new Set(activeSys);
  const seen = new Set<string>();
  const order = saved.filter((tok) => {
    if (!valid.has(tok) || seen.has(tok)) return false;
    seen.add(tok);
    return true;
  });
  let insertAt = 0;
  order.forEach((tok, idx) => {
    if (isSystem.has(tok)) insertAt = idx + 1;
  });
  order.splice(insertAt, 0, ...activeSys.filter((k) => !order.includes(k)));
  ruleIds.forEach((id) => {
    if (!order.includes(id)) order.push(id);
  });
  const apiAt = order.indexOf('api');
  if (apiAt > 0) order.unshift(...order.splice(apiAt, 1));
  return order;
}
