import type { MessageInstance } from 'antd/es/message/interface';
import type { TFunction } from 'i18next';

/** What `PUT /settings/panel` reports about the live router. Empty when the save
 *  neither pushed rules nor found the router stale from an earlier attempt. */
export interface RoutingApplyResult {
  routing_live?: boolean;
  /** True when the rules are live only because xray was restarted. */
  routing_restarted?: boolean;
  routing_detail?: string;
}

/** What the caller still has to say after this reporter has spoken. */
export type RoutingReport =
  /** Nothing router-related happened; the caller's own success toast stands. */
  | 'clean'
  /** The rules aren't live and the operator has been warned — don't also
   *  claim the save succeeded. */
  | 'warned'
  /** The rules are live, but only because xray was restarted and every client
   *  reconnected. The operator has been told; a plain "saved" would hide it. */
  | 'restarted';

/** Report what happened to the live router after a settings save.
 *
 *  This lives outside the Settings page because EVERY caller of
 *  `PUT /settings/panel` can now reach the router: the backend re-pushes on any
 *  save while an earlier attempt is unresolved, and it reports a stale router on
 *  saves that pushed nothing at all. A caller that only showed its own "saved"
 *  toast would hide either an unapplied rule set or an outage it caused.
 *
 *  One function owns the whole response shape so a new caller can't half-handle
 *  it — pass the result in, act on what comes back. */
export function reportRouting(
  routing: RoutingApplyResult,
  message: MessageInstance,
  t: TFunction,
): RoutingReport {
  if (routing.routing_live === false) {
    message.warning({
      // Shared key: a multi-section save runs each section in turn and they all
      // get the same lingering detail, so without it the operator collects one
      // identical 10-second toast per section.
      key: 'routing-not-live',
      content: t('settings.xrayRoutingNotLive', { detail: routing.routing_detail ?? '' }),
      duration: 10,
    });
    return 'warned';
  }
  // Both remaining outcomes mean the router is in step, so retract any warning a
  // previous section raised — leaving "not applied" next to "applied" makes the
  // operator guess which is current.
  message.destroy('routing-not-live');
  if (routing.routing_restarted) {
    message.info({
      key: 'routing-restarted',
      content: t('settings.xrayRoutingAppliedRestart'),
      duration: 8,
    });
    return 'restarted';
  }
  return 'clean';
}
