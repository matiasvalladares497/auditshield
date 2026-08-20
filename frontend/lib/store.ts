import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { User, Audit } from './api';

// ─── Auth Store ───────────────────────────────────────────────────────────────

interface AuthState {
  user: User | null;
  token: string | null;
  setUser: (user: User | null) => void;
  setToken: (token: string | null) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      token: null,

      setUser: (user) => set({ user }),

      setToken: (token) => {
        set({ token });
        if (typeof window !== 'undefined') {
          if (token) {
            localStorage.setItem('auth_token', token);
          } else {
            localStorage.removeItem('auth_token');
          }
        }
      },

      logout: () => {
        if (typeof window !== 'undefined') {
          localStorage.removeItem('auth_token');
          localStorage.removeItem('auth_user');
        }
        set({ user: null, token: null });
      },
    }),
    {
      name: 'auth_store',
      partialize: (state) => ({ user: state.user, token: state.token }),
    }
  )
);

// ─── Audit Store ──────────────────────────────────────────────────────────────

interface AuditState {
  audits: Audit[];
  currentAudit: Audit | null;
  setAudits: (audits: Audit[]) => void;
  setCurrentAudit: (audit: Audit | null) => void;
  updateAuditInList: (audit: Audit) => void;
  removeAudit: (id: number) => void;
}

export const useAuditStore = create<AuditState>((set) => ({
  audits: [],
  currentAudit: null,

  setAudits: (audits) => set({ audits }),

  setCurrentAudit: (audit) => set({ currentAudit: audit }),

  updateAuditInList: (audit) =>
    set((state) => ({
      audits: state.audits.map((a) => (a.id === audit.id ? audit : a)),
      currentAudit:
        state.currentAudit?.id === audit.id ? audit : state.currentAudit,
    })),

  removeAudit: (id) =>
    set((state) => ({
      audits: state.audits.filter((a) => a.id !== id),
      currentAudit: state.currentAudit?.id === id ? null : state.currentAudit,
    })),
}));
