'use client';

import React, { useEffect, useState } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { useAuthStore } from '@/lib/store';
import Sidebar from '@/components/Sidebar';
import { Bell, Plus, Loader2, Search, ChevronRight } from 'lucide-react';
import Link from 'next/link';

const ROUTE_LABELS: Record<string, string> = {
  dashboard: 'Panel',
  audits: 'Auditorías',
  new: 'Nueva',
  assets: 'Activos',
  reports: 'Reportes',
  settings: 'Configuración',
};

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { token, user } = useAuthStore();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    if (mounted && !token) {
      router.push('/login');
    }
  }, [token, mounted, router]);

  if (!mounted || !token || !user) {
    return (
      <div style={{
        minHeight: '100vh',
        background: '#020817',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexDirection: 'column',
        gap: 16,
      }}>
        <div style={{
          width: 44,
          height: 44,
          borderRadius: '50%',
          border: '2px solid rgba(99,102,241,0.3)',
          borderTopColor: '#6366F1',
          animation: 'spin 1s linear infinite',
        }} />
        <p style={{ color: '#64748B', fontSize: 13, fontWeight: 500 }}>Validando sesión...</p>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>
    );
  }

  // Breadcrumbs
  const paths = pathname.split('/').filter(Boolean);

  return (
    <div style={{ minHeight: '100vh', background: 'linear-gradient(160deg, #020817 0%, #030a17 100%)', color: '#F1F5F9' }}>
      <Sidebar />

      {/* Main Area */}
      <div style={{ paddingLeft: 240, minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
        
        {/* Topbar */}
        <header style={{
          height: 64,
          borderBottom: '1px solid rgba(99,102,241,0.1)',
          background: 'rgba(8,13,26,0.85)',
          backdropFilter: 'blur(12px)',
          padding: '0 32px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          position: 'sticky',
          top: 0,
          zIndex: 20,
        }}>
          {/* Breadcrumbs */}
          <nav style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            {paths.map((p, index) => {
              const isLast = index === paths.length - 1;
              const label = ROUTE_LABELS[p] || p;
              const href = '/' + paths.slice(0, index + 1).join('/');
              
              return (
                <React.Fragment key={href}>
                  {index > 0 && <ChevronRight size={13} color="#374151" />}
                  {isLast ? (
                    <span style={{ fontSize: 13, fontWeight: 600, color: '#818CF8' }}>
                      {label}
                    </span>
                  ) : (
                    <Link
                      href={href}
                      style={{
                        fontSize: 13,
                        fontWeight: 500,
                        color: '#6B7280',
                        textDecoration: 'none',
                        transition: 'color 0.15s',
                      }}
                    >
                      {label}
                    </Link>
                  )}
                </React.Fragment>
              );
            })}
          </nav>

          {/* Right side actions */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {/* Status indicator */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '5px 10px',
              borderRadius: 8,
              background: 'rgba(16,185,129,0.08)',
              border: '1px solid rgba(16,185,129,0.2)',
            }}>
              <div style={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                background: '#10B981',
                boxShadow: '0 0 6px #10B981',
                animation: 'pulse 2s ease-in-out infinite',
              }} />
              <span style={{ fontSize: 11, fontWeight: 600, color: '#34D399' }}>Sistema activo</span>
            </div>

            {/* Org badge */}
            <div style={{
              padding: '5px 12px',
              borderRadius: 8,
              background: 'rgba(30,41,59,0.6)',
              border: '1px solid rgba(51,65,85,0.5)',
              fontSize: 11,
              fontWeight: 700,
              color: '#94A3B8',
              fontFamily: 'monospace',
              letterSpacing: '0.05em',
            }}>
              ORG #{(user as any).organization_id ?? 'N/A'}
            </div>

            {/* New Audit CTA */}
            <Link
              href="/dashboard/audits/new"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '7px 14px',
                borderRadius: 9,
                textDecoration: 'none',
                background: 'linear-gradient(135deg, #4F46E5, #6366F1)',
                color: 'white',
                fontSize: 12,
                fontWeight: 700,
                boxShadow: '0 2px 12px rgba(99,102,241,0.3)',
                transition: 'all 0.2s',
              }}
            >
              <Plus size={14} />
              Nueva Auditoría
            </Link>
          </div>
        </header>

        {/* Page Content */}
        <main style={{
          flex: 1,
          padding: '32px',
          overflowY: 'auto',
        }}>
          {children}
        </main>
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
      `}</style>
    </div>
  );
}
