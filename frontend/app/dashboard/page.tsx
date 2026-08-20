'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { 
  ScanLine, 
  AlertTriangle, 
  Activity, 
  Server, 
  ArrowRight,
  TrendingUp,
  RefreshCw,
  LayoutDashboard,
  ShieldCheck,
  Zap,
  ExternalLink,
  Clock,
  Target
} from 'lucide-react';
import StatCard from '@/components/ui/StatCard';
import { 
  cn, 
  formatDate, 
  getScoreColor, 
  getScoreLetter, 
  getStatusIcon, 
  getStatusLabel, 
  getStatusBadgeClass 
} from '@/lib/utils';
import { auditsApi, assetsApi, type Audit, type Asset } from '@/lib/api';
import toast from 'react-hot-toast';

const DEMO_AUDITS = [
  {
    id: 1, title: 'Auditoría Portal Web', target: 'www.mipagina.cl',
    status: 'completed', security_score: 72, score_letter: 'B',
    created_at: new Date(Date.now() - 2 * 86400000).toISOString(),
    summary: { critical: 1, high: 3, medium: 7, low: 4, total: 15, info: 2 },
    modules: ['osint', 'ssl', 'web', 'ports'], target_type: 'domain'
  },
  {
    id: 2, title: 'Revisión Servidor Linux', target: '192.168.1.10',
    status: 'completed', security_score: 55, score_letter: 'D',
    created_at: new Date(Date.now() - 5 * 86400000).toISOString(),
    summary: { critical: 3, high: 5, medium: 4, low: 2, total: 14, info: 1 },
    modules: ['ports', 'ssl'], target_type: 'ip'
  },
  {
    id: 3, title: 'Scan Rápido DNS', target: 'liceo.edu.cl',
    status: 'completed', security_score: 88, score_letter: 'A',
    created_at: new Date(Date.now() - 1 * 86400000).toISOString(),
    summary: { critical: 0, high: 1, medium: 2, low: 3, total: 6, info: 4 },
    modules: ['dns', 'ssl'], target_type: 'domain'
  },
  {
    id: 4, title: 'Auditoría Completa ERP', target: 'erp.empresa.cl',
    status: 'running', security_score: null, score_letter: null,
    created_at: new Date(Date.now() - 30 * 60000).toISOString(),
    summary: {}, modules: ['osint', 'ssl', 'web', 'ports', 'dns', 'cve'], target_type: 'domain'
  },
];

const DEMO_ASSETS = [
  { id: 1, name: 'Portal Web Liceo', target: 'www.liceo.edu.cl', asset_type: 'domain' },
  { id: 2, name: 'Servidor Interno', target: '192.168.1.10', asset_type: 'ip' },
  { id: 3, name: 'API Backend', target: 'api.liceo.edu.cl', asset_type: 'domain' },
];

const STATUS_STYLES: Record<string, { bg: string; border: string; color: string; dot: string }> = {
  completed: { bg: 'rgba(16,185,129,0.08)', border: 'rgba(16,185,129,0.2)', color: '#34D399', dot: '#10B981' },
  running: { bg: 'rgba(99,102,241,0.08)', border: 'rgba(99,102,241,0.2)', color: '#818CF8', dot: '#6366F1' },
  pending: { bg: 'rgba(107,114,128,0.08)', border: 'rgba(107,114,128,0.2)', color: '#9CA3AF', dot: '#6B7280' },
  failed: { bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.2)', color: '#FCA5A5', dot: '#EF4444' },
  cancelled: { bg: 'rgba(107,114,128,0.08)', border: 'rgba(107,114,128,0.2)', color: '#9CA3AF', dot: '#6B7280' },
};

function ScoreCircle({ score, letter }: { score: number | null | undefined; letter: string | null | undefined }) {
  if (score == null) return <span style={{ color: '#4B5563', fontWeight: 600 }}>—</span>;
  const color = score >= 80 ? '#10B981' : score >= 60 ? '#F59E0B' : '#EF4444';
  return (
    <div style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
      <span style={{ fontSize: 14, fontWeight: 800, color, letterSpacing: '-0.5px' }}>{Math.round(score)}%</span>
      <span style={{
        fontSize: 10,
        fontWeight: 700,
        padding: '1px 5px',
        borderRadius: 5,
        background: `${color}15`,
        border: `1px solid ${color}30`,
        color,
      }}>{letter}</span>
    </div>
  );
}

export default function DashboardPage() {
  const [audits, setAudits] = useState<Audit[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [isDemo, setIsDemo] = useState(false);

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      const [auditsList, assetsList] = await Promise.all([
        auditsApi.list(),
        assetsApi.list()
      ]);
      setAudits(auditsList);
      setAssets(assetsList);
      setIsDemo(false);
    } catch {
      setAudits(DEMO_AUDITS as unknown as Audit[]);
      setAssets(DEMO_ASSETS as unknown as Asset[]);
      setIsDemo(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const totalAudits = audits.length;
  const totalAssets = assets.length;
  const completedAudits = audits.filter(a => a.status === 'completed');
  const runningAudits = audits.filter(a => a.status === 'running' || a.status === 'pending');
  
  const avgScore = completedAudits.length > 0 
    ? Math.round(completedAudits.reduce((acc, curr) => acc + (curr.security_score || 0), 0) / completedAudits.length)
    : null;

  let totalCritical = 0;
  let totalHigh = 0;
  let totalMedium = 0;
  let totalLow = 0;

  completedAudits.forEach(audit => {
    const s = audit.summary || {};
    totalCritical += s.critical || 0;
    totalHigh += s.high || 0;
    totalMedium += s.medium || 0;
    totalLow += s.low || 0;
  });

  const totalVulns = totalCritical + totalHigh + totalMedium + totalLow;

  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 24, animation: 'fadeIn 0.3s ease' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 20 }}>
          {[...Array(4)].map((_, i) => (
            <div key={i} style={{
              height: 120,
              borderRadius: 16,
              background: 'linear-gradient(90deg, #0d1424, #111827, #0d1424)',
              backgroundSize: '200% 100%',
              animation: 'shimmer 1.5s infinite',
              border: '1px solid rgba(30,41,59,0.5)',
            }} />
          ))}
        </div>
        <style>{`
          @keyframes shimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } }
          @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        `}</style>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 28, animation: 'fadeIn 0.3s ease' }}>
      <style>{`
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
        .audit-row:hover { background: rgba(30,41,59,0.25) !important; }
        .audit-row:hover .row-action { color: #818CF8 !important; }
      `}</style>

      {/* Page Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 800, color: '#F1F5F9', letterSpacing: '-0.5px', margin: 0 }}>
            Panel de Seguridad
          </h1>
          <p style={{ fontSize: 13, color: '#64748B', marginTop: 4, margin: '4px 0 0' }}>
            Supervisión centralizada del estado de seguridad de tu infraestructura
          </p>
        </div>
        <button
          onClick={fetchDashboardData}
          disabled={loading}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            padding: '7px 14px',
            borderRadius: 9,
            background: 'rgba(30,41,59,0.5)',
            border: '1px solid rgba(51,65,85,0.6)',
            color: '#94A3B8',
            fontSize: 12,
            fontWeight: 600,
            cursor: 'pointer',
            transition: 'all 0.2s',
          }}
        >
          <RefreshCw size={13} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
          Actualizar
        </button>
      </div>

      {/* Demo banner */}
      {isDemo && (
        <div style={{
          padding: '12px 18px',
          borderRadius: 12,
          background: 'rgba(245,158,11,0.07)',
          border: '1px solid rgba(245,158,11,0.2)',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
        }}>
          <div style={{
            width: 30,
            height: 30,
            borderRadius: 8,
            background: 'rgba(245,158,11,0.15)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
          }}>
            <TrendingUp size={15} color="#FCD34D" />
          </div>
          <div>
            <span style={{ color: '#FCD34D', fontWeight: 700, fontSize: 12 }}>Modo Demo activo </span>
            <span style={{ color: '#94A3B8', fontSize: 12 }}>— Estás viendo datos de ejemplo. Para usar datos reales, levanta el backend con Docker.</span>
          </div>
        </div>
      )}

      {/* Running audits indicator */}
      {runningAudits.length > 0 && (
        <div style={{
          padding: '10px 18px',
          borderRadius: 12,
          background: 'rgba(99,102,241,0.07)',
          border: '1px solid rgba(99,102,241,0.2)',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
        }}>
          <div style={{
            width: 8,
            height: 8,
            borderRadius: '50%',
            background: '#6366F1',
            boxShadow: '0 0 8px #6366F1',
            animation: 'pulse 1.5s ease-in-out infinite',
            flexShrink: 0,
          }} />
          <span style={{ fontSize: 12, color: '#818CF8', fontWeight: 600 }}>
            {runningAudits.length} auditoría{runningAudits.length > 1 ? 's' : ''} en ejecución actualmente
          </span>
          <Link href={`/dashboard/audits/${runningAudits[0].id}`} style={{
            marginLeft: 'auto',
            display: 'flex',
            alignItems: 'center',
            gap: 4,
            fontSize: 11,
            fontWeight: 700,
            color: '#6366F1',
            textDecoration: 'none',
          }}>
            Ver progreso <ArrowRight size={11} />
          </Link>
        </div>
      )}

      {/* Stat Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 20 }}>
        <StatCard
          title="Total Auditorías"
          value={totalAudits}
          subtitle={`${completedAudits.length} completadas`}
          icon={ScanLine}
          variant="brand"
        />
        <StatCard
          title="Vulnerabilidades Críticas"
          value={totalCritical}
          subtitle={`${totalHigh} de alta severidad`}
          icon={AlertTriangle}
          variant={totalCritical > 0 ? 'danger' : 'success'}
        />
        <StatCard
          title="Score Promedio"
          value={avgScore != null ? `${avgScore}%` : '—'}
          subtitle={avgScore != null ? `Clasificación: ${getScoreLetter(avgScore)}` : 'Sin datos aún'}
          icon={Activity}
          variant={avgScore == null ? 'info' : avgScore >= 75 ? 'success' : avgScore >= 60 ? 'warning' : 'danger'}
        />
        <StatCard
          title="Activos Registrados"
          value={totalAssets}
          subtitle="Dominios, IPs y servidores"
          icon={Server}
          variant="info"
        />
      </div>

      {/* Main Dashboard Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 24 }}>
        
        {/* Left: Audit History Table */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <h2 style={{ fontSize: 16, fontWeight: 700, color: '#E2E8F0', margin: 0 }}>Auditorías Recientes</h2>
            <Link href="/dashboard/audits/new" style={{
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              fontSize: 12,
              fontWeight: 600,
              color: '#6366F1',
              textDecoration: 'none',
            }}>
              <Zap size={12} />
              Nueva auditoría
            </Link>
          </div>

          <div style={{
            background: 'linear-gradient(145deg, #0d1424, #0a101e)',
            border: '1px solid rgba(30,41,59,0.7)',
            borderRadius: 16,
            overflow: 'hidden',
          }}>
            {totalAudits === 0 ? (
              <div style={{
                padding: '48px 24px',
                textAlign: 'center',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: 12,
              }}>
                <div style={{
                  width: 52,
                  height: 52,
                  borderRadius: 14,
                  background: 'rgba(30,41,59,0.5)',
                  border: '1px solid rgba(51,65,85,0.4)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}>
                  <LayoutDashboard size={22} color="#374151" />
                </div>
                <div>
                  <p style={{ fontSize: 14, fontWeight: 600, color: '#64748B', margin: 0 }}>Sin auditorías registradas</p>
                  <p style={{ fontSize: 12, color: '#374151', marginTop: 4 }}>Lanza tu primer escaneo de seguridad</p>
                </div>
                <Link href="/dashboard/audits/new" style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '9px 18px',
                  borderRadius: 10,
                  background: 'linear-gradient(135deg, #4F46E5, #6366F1)',
                  color: 'white',
                  fontSize: 12,
                  fontWeight: 700,
                  textDecoration: 'none',
                  boxShadow: '0 4px 16px rgba(99,102,241,0.3)',
                }}>
                  <Zap size={13} />
                  Iniciar escaneo
                </Link>
              </div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ background: 'rgba(15,23,42,0.6)', borderBottom: '1px solid rgba(30,41,59,0.7)' }}>
                    {['Objetivo / Título', 'Score', 'Estado', 'Crít / Alt', 'Fecha', ''].map((h, i) => (
                      <th key={i} style={{
                        padding: '10px 16px',
                        textAlign: i >= 1 && i < 5 ? 'center' : i === 5 ? 'right' : 'left',
                        fontSize: 10,
                        fontWeight: 700,
                        color: '#475569',
                        letterSpacing: '0.08em',
                        textTransform: 'uppercase',
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {audits.slice(0, 6).map((audit) => {
                    const s = audit.summary || {};
                    const statusStyle = STATUS_STYLES[audit.status] || STATUS_STYLES.pending;
                    
                    return (
                      <tr
                        key={audit.id}
                        className="audit-row"
                        style={{
                          borderBottom: '1px solid rgba(15,23,42,0.8)',
                          transition: 'background 0.15s',
                          cursor: 'pointer',
                        }}
                      >
                        <td style={{ padding: '13px 16px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <div style={{
                              width: 32,
                              height: 32,
                              borderRadius: 8,
                              background: 'rgba(30,41,59,0.5)',
                              border: '1px solid rgba(51,65,85,0.3)',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              flexShrink: 0,
                            }}>
                              <Target size={14} color="#6B7280" />
                            </div>
                            <div>
                              <p style={{ fontSize: 13, fontWeight: 600, color: '#CBD5E1', margin: 0, fontFamily: 'monospace' }}>
                                {audit.target}
                              </p>
                              <p style={{ fontSize: 11, color: '#475569', margin: 0 }}>{audit.title}</p>
                            </div>
                          </div>
                        </td>
                        <td style={{ padding: '13px 16px', textAlign: 'center' }}>
                          <ScoreCircle score={audit.security_score} letter={audit.score_letter} />
                        </td>
                        <td style={{ padding: '13px 16px', textAlign: 'center' }}>
                          <span style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 5,
                            padding: '3px 10px',
                            borderRadius: 9999,
                            fontSize: 11,
                            fontWeight: 600,
                            background: statusStyle.bg,
                            border: `1px solid ${statusStyle.border}`,
                            color: statusStyle.color,
                          }}>
                            <span style={{
                              width: 5,
                              height: 5,
                              borderRadius: '50%',
                              background: statusStyle.dot,
                              display: 'inline-block',
                              ...(audit.status === 'running' ? { animation: 'pulse 1.5s infinite' } : {}),
                            }} />
                            {getStatusLabel(audit.status)}
                          </span>
                        </td>
                        <td style={{ padding: '13px 16px', textAlign: 'center' }}>
                          {audit.status === 'completed' ? (
                            <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4, fontSize: 13 }}>
                              <span style={{ fontWeight: 700, color: (s.critical || 0) > 0 ? '#F87171' : '#475569' }}>
                                {s.critical || 0}
                              </span>
                              <span style={{ color: '#374151' }}>/</span>
                              <span style={{ fontWeight: 600, color: (s.high || 0) > 0 ? '#FBBF24' : '#475569' }}>
                                {s.high || 0}
                              </span>
                            </span>
                          ) : (
                            <span style={{ color: '#374151', fontSize: 13 }}>—</span>
                          )}
                        </td>
                        <td style={{ padding: '13px 16px', textAlign: 'center' }}>
                          <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4, fontSize: 11, color: '#475569' }}>
                            <Clock size={11} />
                            {formatDate(audit.created_at)}
                          </span>
                        </td>
                        <td style={{ padding: '13px 16px', textAlign: 'right' }}>
                          <Link
                            href={`/dashboard/audits/${audit.id}`}
                            className="row-action"
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 3,
                              fontSize: 11,
                              fontWeight: 700,
                              color: '#475569',
                              textDecoration: 'none',
                              transition: 'color 0.15s',
                            }}
                          >
                            Ver <ExternalLink size={10} />
                          </Link>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Right: Security Posture Panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <h2 style={{ fontSize: 16, fontWeight: 700, color: '#E2E8F0', margin: 0 }}>Postura Global</h2>
          
          {/* Score card */}
          <div style={{
            background: 'linear-gradient(145deg, #0d1424, #0a101e)',
            border: '1px solid rgba(30,41,59,0.7)',
            borderRadius: 16,
            padding: 24,
            display: 'flex',
            flexDirection: 'column',
            gap: 20,
          }}>
            
            {/* Overall score */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
              <div style={{
                width: 48,
                height: 48,
                borderRadius: 14,
                background: 'rgba(99,102,241,0.12)',
                border: '1px solid rgba(99,102,241,0.25)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}>
                <ShieldCheck size={22} color="#818CF8" />
              </div>
              <div>
                <h3 style={{ fontSize: 14, fontWeight: 700, color: '#CBD5E1', margin: 0 }}>
                  Postura de Seguridad
                </h3>
                <p style={{ fontSize: 11, color: '#475569', margin: '3px 0 0' }}>
                  {totalAudits === 0 
                    ? 'No se han auditado activos aún'
                    : `Basado en ${completedAudits.length} escaneo${completedAudits.length !== 1 ? 's' : ''}`
                  }
                </p>
              </div>
              {avgScore != null && (
                <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
                  <span style={{
                    fontSize: 22,
                    fontWeight: 800,
                    color: avgScore >= 75 ? '#34D399' : avgScore >= 60 ? '#FCD34D' : '#FCA5A5',
                    letterSpacing: '-1px',
                  }}>{avgScore}%</span>
                </div>
              )}
            </div>

            {/* Vulnerability breakdown */}
            {totalVulns > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <p style={{ fontSize: 10, fontWeight: 700, color: '#374151', letterSpacing: '0.1em', textTransform: 'uppercase', margin: 0 }}>
                  Resumen de Vulnerabilidades
                </p>
                
                {[
                  { label: 'Crítico', count: totalCritical, color: '#EF4444' },
                  { label: 'Alto', count: totalHigh, color: '#F59E0B' },
                  { label: 'Medio', count: totalMedium, color: '#EAB308' },
                  { label: 'Bajo', count: totalLow, color: '#3B82F6' },
                ].map(({ label, count, color }) => (
                  <div key={label}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5, alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <div style={{ width: 6, height: 6, borderRadius: '50%', background: color, flexShrink: 0 }} />
                        <span style={{ fontSize: 12, fontWeight: 500, color: '#94A3B8' }}>{label}</span>
                      </div>
                      <span style={{ fontSize: 12, fontWeight: 700, color: count > 0 ? color : '#374151' }}>{count}</span>
                    </div>
                    <div style={{ height: 4, background: 'rgba(30,41,59,0.8)', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{
                        height: '100%',
                        width: `${Math.min(100, totalVulns > 0 ? (count / totalVulns) * 100 : 0)}%`,
                        background: `linear-gradient(90deg, ${color}, ${color}88)`,
                        borderRadius: 2,
                        transition: 'width 0.6s ease',
                      }} />
                    </div>
                  </div>
                ))}

                <div style={{
                  padding: '10px 14px',
                  borderRadius: 10,
                  background: 'rgba(15,23,42,0.6)',
                  border: '1px solid rgba(30,41,59,0.6)',
                  fontSize: 11,
                  color: '#475569',
                  textAlign: 'center',
                }}>
                  <span style={{ fontWeight: 700, color: '#64748B' }}>{totalVulns}</span> vulnerabilidades totales detectadas
                </div>
              </div>
            )}

            {/* Quick links */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, borderTop: '1px solid rgba(30,41,59,0.6)', paddingTop: 18 }}>
              <p style={{ fontSize: 10, fontWeight: 700, color: '#374151', letterSpacing: '0.1em', textTransform: 'uppercase', margin: 0 }}>
                Acciones rápidas
              </p>
              {[
                { label: 'Lanzar nueva auditoría', href: '/dashboard/audits/new', icon: ScanLine, color: '#6366F1' },
                { label: 'Ver reportes PDF', href: '/dashboard/reports', icon: Activity, color: '#10B981' },
                { label: 'Gestionar activos', href: '/dashboard/assets', icon: Server, color: '#3B82F6' },
              ].map(({ label, href, icon: Icon, color }) => (
                <Link
                  key={href}
                  href={href}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                    padding: '9px 12px',
                    borderRadius: 9,
                    textDecoration: 'none',
                    background: 'rgba(15,23,42,0.5)',
                    border: '1px solid rgba(30,41,59,0.5)',
                    transition: 'all 0.15s',
                  }}
                  onMouseEnter={e => {
                    (e.currentTarget as HTMLElement).style.borderColor = `${color}30`;
                    (e.currentTarget as HTMLElement).style.background = `${color}08`;
                  }}
                  onMouseLeave={e => {
                    (e.currentTarget as HTMLElement).style.borderColor = 'rgba(30,41,59,0.5)';
                    (e.currentTarget as HTMLElement).style.background = 'rgba(15,23,42,0.5)';
                  }}
                >
                  <div style={{
                    width: 26,
                    height: 26,
                    borderRadius: 7,
                    background: `${color}15`,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                  }}>
                    <Icon size={13} color={color} />
                  </div>
                  <span style={{ fontSize: 12, fontWeight: 500, color: '#94A3B8' }}>{label}</span>
                  <ArrowRight size={12} color="#374151" style={{ marginLeft: 'auto' }} />
                </Link>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
