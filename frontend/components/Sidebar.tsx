'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { 
  Shield, 
  LayoutDashboard, 
  ScanLine, 
  Server, 
  FileSpreadsheet, 
  Settings, 
  LogOut,
  Zap,
  ChevronRight,
  Terminal
} from 'lucide-react';
import { cn, getInitials } from '@/lib/utils';
import { useAuthStore } from '@/lib/store';
import toast from 'react-hot-toast';

const navItems = [
  {
    label: 'Dashboard',
    href: '/dashboard',
    icon: LayoutDashboard,
    description: 'Visión general'
  },
  {
    label: 'Nueva Auditoría',
    href: '/dashboard/audits/new',
    icon: ScanLine,
    description: 'Lanzar escaneo'
  },
  {
    label: 'Activos',
    href: '/dashboard/assets',
    icon: Server,
    description: 'Gestión de activos'
  },
  {
    label: 'Reportes PDF',
    href: '/dashboard/reports',
    icon: FileSpreadsheet,
    description: 'Historial de reportes'
  },
  {
    label: 'Configuración',
    href: '/dashboard/settings',
    icon: Settings,
    description: 'Ajustes y perfil'
  }
];

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const { user, logout } = useAuthStore();

  const handleLogout = () => {
    logout();
    toast.success('Sesión cerrada correctamente');
    router.push('/login');
  };

  return (
    <aside
      style={{
        width: 240,
        background: 'linear-gradient(180deg, #0a0f1e 0%, #080d1a 100%)',
        borderRight: '1px solid rgba(99,102,241,0.12)',
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        position: 'fixed',
        left: 0,
        top: 0,
        zIndex: 30,
        userSelect: 'none',
      }}
    >
      {/* Brand Header */}
      <div style={{
        height: 64,
        display: 'flex',
        alignItems: 'center',
        padding: '0 20px',
        borderBottom: '1px solid rgba(99,102,241,0.1)',
        background: 'rgba(99,102,241,0.03)',
      }}>
        <Link href="/dashboard" style={{ display: 'flex', alignItems: 'center', gap: 10, textDecoration: 'none' }}>
          <div style={{
            width: 34,
            height: 34,
            background: 'linear-gradient(135deg, rgba(99,102,241,0.3), rgba(129,140,248,0.15))',
            border: '1px solid rgba(99,102,241,0.4)',
            borderRadius: 10,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 16px rgba(99,102,241,0.2)',
          }}>
            <Shield size={18} color="#818CF8" />
          </div>
          <div>
            <span style={{
              fontWeight: 800,
              fontSize: 15,
              background: 'linear-gradient(135deg, #e0e7ff, #818CF8)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              letterSpacing: '-0.3px',
              display: 'block',
              lineHeight: 1,
            }}>
              AuditShield
            </span>
            <span style={{ fontSize: 9, color: '#4B5563', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              Security Platform
            </span>
          </div>
        </Link>
      </div>

      {/* Section Label */}
      <div style={{ padding: '20px 20px 8px', fontSize: 9, fontWeight: 700, color: '#374151', letterSpacing: '0.12em', textTransform: 'uppercase' }}>
        Navegación
      </div>

      {/* Navigation Links */}
      <nav style={{ flex: 1, padding: '0 10px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 2 }}>
        {navItems.map((item) => {
          const isActive = pathname === item.href || (item.href !== '/dashboard' && pathname.startsWith(item.href));
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '9px 12px',
                borderRadius: 10,
                textDecoration: 'none',
                transition: 'all 0.2s',
                background: isActive 
                  ? 'linear-gradient(135deg, rgba(99,102,241,0.18), rgba(99,102,241,0.08))' 
                  : 'transparent',
                border: isActive 
                  ? '1px solid rgba(99,102,241,0.25)' 
                  : '1px solid transparent',
                boxShadow: isActive ? '0 0 20px rgba(99,102,241,0.08)' : 'none',
                position: 'relative',
                overflow: 'hidden',
              }}
              className={cn('sidebar-link', isActive && 'sidebar-link-active')}
            >
              {isActive && (
                <div style={{
                  position: 'absolute',
                  left: 0,
                  top: '50%',
                  transform: 'translateY(-50%)',
                  width: 3,
                  height: '60%',
                  background: 'linear-gradient(180deg, #6366F1, #818CF8)',
                  borderRadius: '0 2px 2px 0',
                  boxShadow: '0 0 8px rgba(99,102,241,0.6)',
                }} />
              )}
              <div style={{
                width: 32,
                height: 32,
                borderRadius: 8,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: isActive ? 'rgba(99,102,241,0.2)' : 'rgba(255,255,255,0.03)',
                border: isActive ? '1px solid rgba(99,102,241,0.3)' : '1px solid rgba(255,255,255,0.04)',
                flexShrink: 0,
              }}>
                <Icon size={15} color={isActive ? '#818CF8' : '#6B7280'} />
              </div>
              <div style={{ minWidth: 0, flex: 1 }}>
                <div style={{
                  fontSize: 13,
                  fontWeight: isActive ? 600 : 500,
                  color: isActive ? '#C7D2FE' : '#9CA3AF',
                  lineHeight: 1.2,
                }}>
                  {item.label}
                </div>
                <div style={{ fontSize: 10, color: '#374151', marginTop: 1 }}>
                  {item.description}
                </div>
              </div>
              {isActive && <ChevronRight size={12} color="#6366F1" />}
            </Link>
          );
        })}
      </nav>

      {/* Quick Action CTA */}
      <div style={{ padding: '0 10px 10px' }}>
        <Link
          href="/dashboard/audits/new"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            padding: '10px 14px',
            borderRadius: 10,
            textDecoration: 'none',
            background: 'linear-gradient(135deg, #4F46E5, #6366F1)',
            boxShadow: '0 4px 20px rgba(99,102,241,0.35)',
            transition: 'all 0.2s',
          }}
        >
          <Zap size={14} color="white" />
          <span style={{ fontSize: 12, fontWeight: 700, color: 'white' }}>Lanzar Escaneo</span>
        </Link>
      </div>

      {/* Profile Box */}
      {user && (
        <div style={{
          padding: '12px 10px',
          borderTop: '1px solid rgba(99,102,241,0.1)',
          background: 'rgba(0,0,0,0.2)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0, flex: 1 }}>
              <div style={{
                width: 34,
                height: 34,
                borderRadius: 10,
                background: 'linear-gradient(135deg, rgba(99,102,241,0.3), rgba(129,140,248,0.15))',
                border: '1px solid rgba(99,102,241,0.35)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 12,
                fontWeight: 700,
                color: '#818CF8',
                flexShrink: 0,
              }}>
                {getInitials(user.full_name || user.username)}
              </div>
              <div style={{ minWidth: 0 }}>
                <p style={{ fontSize: 12, fontWeight: 600, color: '#E2E8F0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', margin: 0 }}>
                  {user.full_name || user.username}
                </p>
                <p style={{ fontSize: 9, color: '#4B5563', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700, margin: 0 }}>
                  {user.role}
                </p>
              </div>
            </div>
            <button
              onClick={handleLogout}
              title="Cerrar sesión"
              style={{
                padding: 7,
                borderRadius: 8,
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                color: '#6B7280',
                transition: 'all 0.2s',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
              onMouseEnter={e => {
                (e.currentTarget as HTMLElement).style.color = '#FCA5A5';
                (e.currentTarget as HTMLElement).style.background = 'rgba(239,68,68,0.1)';
              }}
              onMouseLeave={e => {
                (e.currentTarget as HTMLElement).style.color = '#6B7280';
                (e.currentTarget as HTMLElement).style.background = 'transparent';
              }}
            >
              <LogOut size={15} />
            </button>
          </div>
        </div>
      )}

      {/* Version */}
      <div style={{
        padding: '6px 16px',
        fontSize: 9,
        color: '#1F2937',
        fontFamily: 'monospace',
        textAlign: 'center',
        borderTop: '1px solid rgba(255,255,255,0.02)',
        background: 'rgba(0,0,0,0.3)',
      }}>
        v1.0.0 · AuditShield Security Platform
      </div>
    </aside>
  );
}
