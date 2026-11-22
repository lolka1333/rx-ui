//! QUIC tuning bits shared by the inbound and outbound forms.

/** The smallest receive window the core's config loader takes. The panel
 *  refuses less on save, because a share link carrying it makes the client
 *  refuse its whole config. Empty or 0 means the core default. */
export const MIN_RECEIVE_WINDOW = 16384;

/** Form rule for a receive-window field. It flags a value under the minimum
 *  while it is typed, instead of the save failing — or the input quietly
 *  raising it to the minimum, as its own `min` would. */
export function receiveWindowRule(message: string) {
  return {
    validator: (_: unknown, value: number | null | undefined) =>
      value == null || value === 0 || value >= MIN_RECEIVE_WINDOW
        ? Promise.resolve()
        : Promise.reject(new Error(message)),
  };
}

/** BBR profiles in the exact spelling the core accepts (the panel checks it on
 *  save); '' leaves the core on `standard`. */
export function bbrProfileSelectOptions(t: (key: string) => string) {
  return [
    { value: '', label: t('inbounds.quicBbrProfileDefault') },
    { value: 'conservative', label: 'Conservative' },
    { value: 'standard', label: 'Standard' },
    { value: 'aggressive', label: 'Aggressive' },
  ];
}
