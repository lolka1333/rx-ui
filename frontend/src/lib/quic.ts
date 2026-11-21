//! QUIC tuning bits shared by the inbound and outbound forms.

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
