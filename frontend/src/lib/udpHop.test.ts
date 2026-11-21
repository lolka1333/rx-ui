import { describe, expect, it } from 'vitest';
import { formToHop, HOP_DEFAULTS, hopRedirectCommands, hopToForm } from './udpHop';

describe('port hopping form fields', () => {
  it('stores nothing while nothing hops', () => {
    expect(formToHop({ ...HOP_DEFAULTS, hy_hop_ports: '20000-30000' })).toBeNull();
  });

  it('leaves hopping out under XICMP, which cannot run beside it', () => {
    const v = { ...HOP_DEFAULTS, hy_hop_local: true };
    expect(formToHop({ ...v, finalmask_kind: 'xicmp' })).toBeNull();
    expect(formToHop({ ...v, finalmask_kind: 'salamander' })).not.toBeNull();
  });

  it('round-trips an active block', () => {
    const v = {
      hy_hop_local: true,
      hy_hop_remote: 'interval' as const,
      hy_hop_ports: ' 20000-30000 ',
      hy_hop_interval_min: 20,
      hy_hop_interval_max: 40,
    };
    const stored = formToHop(v);
    expect(stored).toEqual({
      local: true,
      remote: 'interval',
      ports: '20000-30000',
      interval_min: 20,
      interval_max: 40,
    });
    expect(hopToForm(stored)).toEqual({ ...v, hy_hop_ports: '20000-30000' });
    expect(hopToForm(null)).toEqual(HOP_DEFAULTS);
  });
});

describe('redirect commands for the server half', () => {
  it('turns one range into --dport with a colon', () => {
    expect(hopRedirectCommands('20000-30000', 27500)).toEqual([
      'iptables -t nat -A PREROUTING -p udp --dport 20000:30000 -j REDIRECT --to-ports 27500',
      'ip6tables -t nat -A PREROUTING -p udp --dport 20000:30000 -j REDIRECT --to-ports 27500',
    ]);
  });

  it('uses multiport for a list', () => {
    expect(hopRedirectCommands('443, 20000-20100', 8443)[0]).toBe(
      'iptables -t nat -A PREROUTING -p udp -m multiport --dports 443,20000:20100 -j REDIRECT --to-ports 8443',
    );
  });

  it('gives nothing for an unusable list or a missing port', () => {
    expect(hopRedirectCommands('', 27500)).toEqual([]);
    expect(hopRedirectCommands('20000-abc', 27500)).toEqual([]);
    expect(hopRedirectCommands('20000-30000', null)).toEqual([]);
  });
});
