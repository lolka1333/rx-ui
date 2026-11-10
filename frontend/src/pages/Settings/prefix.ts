/** The URL prefix in the form the backend stores it (`normalize_base_path`):
 *  empty, or one leading slash and no trailing one. Lets a section tell whether
 *  a save moved the panel and build its new address. */
export function normaliseClientPrefix(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed || trimmed === '/') return '';
  const inner = trimmed.replace(/^\/+|\/+$/g, '');
  return inner ? `/${inner}` : '';
}
