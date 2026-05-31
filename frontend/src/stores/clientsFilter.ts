import { create } from 'zustand';

/**
 * Cross-page state for the Clients listing.
 *
 * Why a store and not local component state: when the operator clicks
 * "N клиентов" on a row in the Inbounds table, we want to (a) navigate
 * to the Clients page and (b) pre-apply a filter so they land in the
 * right context. Local state in Clients.tsx wouldn't see the click; a
 * URL query param would work but we deliberately don't use React Router
 * (see stores/nav.ts), so a tiny module-level store is the right shape.
 *
 * Not persisted — filter resets on reload. Persisting it would
 * surprise an operator returning to "Clients" expecting the full list.
 */
interface ClientsFilterState {
  inboundId: string | null;
  email: string;
  setInboundId: (id: string | null) => void;
  setEmail: (s: string) => void;
}

export const useClientsFilter = create<ClientsFilterState>((set) => ({
  inboundId: null,
  email: '',
  setInboundId: (id) => set({ inboundId: id }),
  setEmail: (s) => set({ email: s }),
}));
