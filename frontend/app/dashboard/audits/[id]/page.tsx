'use client';

import React, { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { 
  ArrowLeft, 
  FileDown, 
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Search
} from 'lucide-react';
import Link from 'next/link';
import { auditsApi, reportsApi, type Audit, type Finding } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import ScoreGauge from '@/components/ui/ScoreGauge';
import FindingCard from '@/components/ui/FindingCard';
import AuditProgressLive from '@/components/AuditProgressLive';
import toast from 'react-hot-toast';

export default function AuditDetailPage() {
  const params = useParams();
  const router = useRouter();
  const auditId = parseInt(params.id as string);

  const [audit, setAudit] = useState<Audit | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [generatingReport, setGeneratingReport] = useState(false);

  // Filtros de Hallazgos
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [hideRemediated, setHideRemediated] = useState(false);
  const [hideFalsePositives, setHideFalsePositives] = useState(true);

  const fetchAuditData = async () => {
    try {
      const data = await auditsApi.get(auditId);
      setAudit(data);
      if (data.findings) {
        setFindings(data.findings);
      }
    } catch (error) {
      toast.error('Error al cargar detalles de la auditoría');
      router.push('/dashboard');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAuditData();
  }, [auditId]);

  const handleScanComplete = (scanData: any) => {
    toast.success('¡Escaneo de ciberseguridad completado con éxito!');
    fetchAuditData();
  };

  const handleUpdateFinding = (updated: Finding) => {
    setFindings(prev => prev.map(f => f.id === updated.id ? updated : f));
  };

  const handleGeneratePdf = async () => {
    if (!audit) return;
    setGeneratingReport(true);
    toast.loading('Generando reporte PDF profesional...', { id: 'pdf-gen' });
    try {
      await reportsApi.generate({
        audit_id: audit.id,
        report_type: 'full'
      });
      toast.success('Reporte PDF compilado con éxito.', { id: 'pdf-gen' });
      router.push('/dashboard/reports');
    } catch (error) {
      toast.error('Error al compilar el reporte PDF.', { id: 'pdf-gen' });
    } finally {
      setGeneratingReport(false);
    }
  };

  const handleCancelScan = async () => {
    if (!confirm('¿Seguro que deseas cancelar este escaneo en ejecución?')) return;
    try {
      await auditsApi.cancel(auditId);
      toast.success('Petición de cancelación enviada.');
      fetchAuditData();
    } catch (error) {
      toast.error('Error al cancelar la auditoría.');
    }
  };

  const filteredFindings = findings.filter(f => {
    const matchSearch = f.title.toLowerCase().includes(search.toLowerCase()) || 
                        f.description.toLowerCase().includes(search.toLowerCase());
    const matchSeverity = severityFilter === 'all' || f.severity.toLowerCase() === severityFilter.toLowerCase();
    const matchRemediated = !hideRemediated || !f.is_remediated;
    const matchFalsePos = !hideFalsePositives || !f.is_false_positive;
    return matchSearch && matchSeverity && matchRemediated && matchFalsePos;
  });

  // Styles Definitions for Premium Look
  const glassCardStyle: React.CSSProperties = {
    background: 'rgba(255, 255, 255, 0.025)',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    backdropFilter: 'blur(24px)',
    borderRadius: 16,
    padding: 24,
    boxShadow: '0 12px 32px rgba(0, 0, 0, 0.3)',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'center',
    transition: 'all 0.3s',
  };

  const inputStyle = {
    background: 'rgba(2, 8, 23, 0.8)',
    border: '1px solid #1e293b',
    borderRadius: 10,
    padding: '8px 12px',
    fontSize: 13,
    color: '#e2e8f0',
    outline: 'none',
    transition: 'border-color 0.2s',
    fontFamily: 'Inter, sans-serif',
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 400, flexDirection: 'column', gap: 12 }}>
        <RefreshCw size={32} className="animate-spin" color="#6366f1" />
        <span style={{ fontSize: 14, color: '#64748b', fontWeight: 500 }}>Cargando reporte de auditoría...</span>
      </div>
    );
  }

  if (!audit) return null;

  const isRunning = audit.status === 'running' || audit.status === 'pending';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
      
      {/* Header Navigation */}
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid rgba(99,102,241,0.1)', paddingBottom: 24, gap: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <Link
            href="/dashboard"
            style={{
              padding: 8,
              borderRadius: 12,
              border: '1px solid #1e293b',
              background: 'rgba(255,255,255,0.01)',
              color: '#94a3b8',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.2s',
            }}
            onMouseEnter={e => { e.currentTarget.style.color = 'white'; e.currentTarget.style.background = 'rgba(255,255,255,0.03)'; }}
            onMouseLeave={e => { e.currentTarget.style.color = '#94a3b8'; e.currentTarget.style.background = 'rgba(255,255,255,0.01)'; }}
          >
            <ArrowLeft size={16} />
          </Link>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <h1 style={{ fontSize: 20, fontWeight: 900, color: '#F1F5F9', letterSpacing: '-0.5px', margin: 0 }}>
                {audit.title}
              </h1>
              <span style={{
                fontSize: 10,
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                padding: '2px 8px',
                borderRadius: 6,
                border: audit.status === 'completed' ? '1px solid rgba(16,185,129,0.25)' : '1px solid rgba(99,102,241,0.25)',
                background: audit.status === 'completed' ? 'rgba(16,185,129,0.06)' : 'rgba(99,102,241,0.06)',
                color: audit.status === 'completed' ? '#34d399' : '#818cf8',
              }}>
                {audit.status}
              </span>
            </div>
            <p style={{ fontSize: 12, color: '#64748b', fontFamily: 'monospace', margin: '4px 0 0' }}>{audit.target}</p>
          </div>
        </div>

        {/* Action Buttons Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {isRunning ? (
            <button
              onClick={handleCancelScan}
              style={{
                padding: '8px 16px',
                borderRadius: 10,
                background: 'rgba(239,68,68,0.06)',
                border: '1px solid rgba(239,68,68,0.2)',
                color: '#f87171',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.2s',
              }}
              onMouseEnter={e => e.currentTarget.style.background = 'rgba(239,68,68,0.12)'}
              onMouseLeave={e => e.currentTarget.style.background = 'rgba(239,68,68,0.06)'}
            >
              Cancelar Escaneo
            </button>
          ) : (
            <button
              onClick={handleGeneratePdf}
              disabled={generatingReport}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '10px 18px',
                borderRadius: 12,
                background: 'linear-gradient(135deg, #4f46e5, #6366f1)',
                border: 'none',
                color: 'white',
                fontSize: 13,
                fontWeight: 700,
                cursor: 'pointer',
                boxShadow: '0 4px 16px rgba(79, 70, 229, 0.3)',
                transition: 'all 0.2s',
              }}
              onMouseEnter={e => e.currentTarget.style.boxShadow = '0 8px 24px rgba(79, 70, 229, 0.45)'}
              onMouseLeave={e => e.currentTarget.style.boxShadow = '0 4px 16px rgba(79, 70, 229, 0.3)'}
            >
              <FileDown size={15} />
              <span>Generar Reporte PDF</span>
            </button>
          )}
        </div>
      </div>

      {/* RENDER ACTIVE SCANNING SCREEN */}
      {isRunning ? (
        <AuditProgressLive
          auditId={audit.id}
          target={audit.target}
          modulesEnabled={audit.modules}
          onComplete={handleScanComplete}
        />
      ) : (
        /* RENDER COMPLETED AUDIT RESULTS SCREEN */
        <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
          
          {/* Posture Score & Vulnerability Summary row */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 24, alignItems: 'stretch' }} className="audit-detail-grid">
            
            {/* Circular score gauge */}
            <div style={{ ...glassCardStyle, alignItems: 'center', textAlign: 'center' }}>
              <h4 style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: '#64748b', letterSpacing: '0.08em', margin: '0 0 16px' }}>Clasificación de Seguridad</h4>
              <ScoreGauge score={audit.security_score} letter={audit.score_letter || undefined} size="lg" />
              <p style={{ fontSize: 11, color: '#475569', margin: '20px 0 0', fontWeight: 500 }}>
                Último análisis: {formatDate(audit.completed_at)}
              </p>
            </div>

            {/* Severity stats breakdown cards */}
            <div style={{ ...glassCardStyle, justifyContent: 'space-between' }}>
              <div>
                <h4 style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: '#64748b', letterSpacing: '0.08em', margin: '0 0 16px' }}>Severidad de Vulnerabilidades</h4>
                
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }} className="severity-grid">
                  {/* Críticos */}
                  <div style={{ padding: 16, borderRadius: 12, border: '1px solid rgba(239,68,68,0.15)', background: 'rgba(239,68,68,0.03)', textAlign: 'center' }}>
                    <span style={{ fontSize: 24, fontWeight: 900, color: '#ef4444', display: 'block' }}>{(audit.summary || {}).critical || 0}</span>
                    <span style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', color: '#64748b', letterSpacing: '0.05em', display: 'block', marginTop: 4 }}>Crítico</span>
                  </div>
                  {/* Altos */}
                  <div style={{ padding: 16, borderRadius: 12, border: '1px solid rgba(249,115,22,0.15)', background: 'rgba(249,115,22,0.03)', textAlign: 'center' }}>
                    <span style={{ fontSize: 24, fontWeight: 900, color: '#f97316', display: 'block' }}>{(audit.summary || {}).high || 0}</span>
                    <span style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', color: '#64748b', letterSpacing: '0.05em', display: 'block', marginTop: 4 }}>Alto</span>
                  </div>
                  {/* Medios */}
                  <div style={{ padding: 16, borderRadius: 12, border: '1px solid rgba(234,179,8,0.15)', background: 'rgba(234,179,8,0.03)', textAlign: 'center' }}>
                    <span style={{ fontSize: 24, fontWeight: 900, color: '#eab308', display: 'block' }}>{(audit.summary || {}).medium || 0}</span>
                    <span style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', color: '#64748b', letterSpacing: '0.05em', display: 'block', marginTop: 4 }}>Medio</span>
                  </div>
                  {/* Bajos + Info */}
                  <div style={{ padding: 16, borderRadius: 12, border: '1px solid rgba(59,130,246,0.15)', background: 'rgba(59,130,246,0.03)', textAlign: 'center' }}>
                    <span style={{ fontSize: 24, fontWeight: 900, color: '#3b82f6', display: 'block' }}>
                      {((audit.summary || {}).low || 0) + ((audit.summary || {}).info || 0)}
                    </span>
                    <span style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', color: '#64748b', letterSpacing: '0.05em', display: 'block', marginTop: 4 }}>Bajo/Info</span>
                  </div>
                </div>
              </div>

              {/* Scope/Metodología quick disclaimer */}
              <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 16, marginTop: 24, display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: '#64748b', fontWeight: 500 }}>
                <CheckCircle size={15} color="#10b981" />
                <span>Módulos analizados bajo estándares OWASP Top 10 y CVSS v3.1.</span>
              </div>
            </div>

          </div>

          {/* Findings List Section with interactive Filters */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            
            {/* Filter controls */}
            <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
              <h3 style={{ fontSize: 18, fontWeight: 800, color: '#e2e8f0', margin: 0 }}>Hallazgos ({filteredFindings.length})</h3>
              
              <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 12 }} className="filters-container">
                {/* Search input */}
                <div style={{ position: 'relative' }}>
                  <Search size={14} color="#475569" style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }} />
                  <input
                    type="text"
                    placeholder="Buscar hallazgo..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    style={{ ...inputStyle, paddingLeft: 32 }}
                  />
                </div>

                {/* Severity select filter */}
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  style={inputStyle}
                >
                  <option value="all" style={{ background: '#020817' }}>Severidades: Todas</option>
                  <option value="critical" style={{ background: '#020817' }}>Crítico</option>
                  <option value="high" style={{ background: '#020817' }}>Alto</option>
                  <option value="medium" style={{ background: '#020817' }}>Medio</option>
                  <option value="low" style={{ background: '#020817' }}>Bajo</option>
                  <option value="info" style={{ background: '#020817' }}>Info</option>
                </select>

                {/* Toggle filters */}
                <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: '#64748b', fontWeight: 600, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={hideRemediated}
                    onChange={() => setHideRemediated(!hideRemediated)}
                    style={{ accentColor: '#818cf8' }}
                  />
                  <span>Ocultar resueltos</span>
                </label>
                
                <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: '#64748b', fontWeight: 600, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={hideFalsePositives}
                    onChange={() => setHideFalsePositives(!hideFalsePositives)}
                    style={{ accentColor: '#818cf8' }}
                  />
                  <span>Ocultar Falsos Positivos</span>
                </label>
              </div>
            </div>

            {/* Findings list */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {filteredFindings.length === 0 ? (
                <div style={{
                  background: 'rgba(255,255,255,0.01)',
                  border: '1px dashed #1e293b',
                  borderRadius: 20,
                  padding: 48,
                  textAlign: 'center',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: 12,
                }}>
                  <CheckCircle size={36} color="#10b981" style={{ opacity: 0.3 }} />
                  <div>
                    <p style={{ fontSize: 14, fontWeight: 700, color: '#64748b', margin: 0 }}>Sin hallazgos encontrados</p>
                    <p style={{ fontSize: 12, color: '#475569', marginTop: 4, margin: '4px 0 0' }}>No hay vulnerabilidades que coincidan con la búsqueda.</p>
                  </div>
                </div>
              ) : (
                filteredFindings.map((finding) => (
                  <FindingCard
                    key={finding.id}
                    finding={finding}
                    auditId={audit.id}
                    onUpdate={handleUpdateFinding}
                  />
                ))
              )}
            </div>

          </div>

        </div>
      )}

      <style>{`
        @media (max-width: 1024px) {
          .audit-detail-grid { grid-template-columns: 1fr !important; }
        }
        @media (max-width: 640px) {
          .severity-grid { grid-template-columns: repeat(2, 1fr) !important; }
          .filters-container { flex-direction: column !important; align-items: stretch !important; width: 100% !important; }
          .filters-container > * { width: 100% !important; }
        }
      `}</style>
    </div>
  );
}
