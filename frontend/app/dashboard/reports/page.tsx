'use client';

import React, { useEffect, useState } from 'react';
import { 
  FileDown, 
  Trash2, 
  Plus, 
  FileText,
  X,
  Loader2
} from 'lucide-react';
import { reportsApi, auditsApi, type Report, type Audit } from '@/lib/api';
import { formatDate, formatBytes } from '@/lib/utils';
import toast from 'react-hot-toast';

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([]);
  const [completedAudits, setCompletedAudits] = useState<Audit[]>([]);
  const [loading, setLoading] = useState(true);
  
  // Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [selectedAuditId, setSelectedAuditId] = useState('');
  const [reportType, setReportType] = useState('full');
  const [generating, setGenerating] = useState(false);

  const fetchReportsData = async () => {
    setLoading(true);
    try {
      const [reportsList, auditsList] = await Promise.all([
        reportsApi.list(),
        auditsApi.list()
      ]);
      setReports(reportsList);
      setCompletedAudits(auditsList.filter(a => a.status === 'completed'));
    } catch (error) {
      toast.error('Error al cargar la lista de reportes.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReportsData();
  }, []);

  const handleDownload = async (report: Report) => {
    toast.loading('Descargando PDF...', { id: 'pdf-dl' });
    try {
      const blob = await reportsApi.download(report.id);
      const url = window.URL.createObjectURL(new Blob([blob], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = url;
      
      const filename = `Reporte_AuditShield_${report.audit_id}_${report.report_type.toUpperCase()}.pdf`;
      link.setAttribute('download', filename);
      
      document.body.appendChild(link);
      link.click();
      link.parentNode?.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      toast.success('Descarga completada.', { id: 'pdf-dl' });
    } catch (error) {
      toast.error('Error al descargar el archivo de reporte.', { id: 'pdf-dl' });
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm('¿Seguro que deseas eliminar este reporte de seguridad?')) return;
    try {
      await reportsApi.delete(id);
      toast.success('Reporte eliminado.');
      fetchReportsData();
    } catch (error) {
      toast.error('Error al eliminar el reporte.');
    }
  };

  const handleCreateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAuditId) {
      toast.error('Selecciona una auditoría completada.');
      return;
    }

    setGenerating(true);
    toast.loading('Compilando PDF...', { id: 'pdf-comp' });
    try {
      await reportsApi.generate({
        audit_id: parseInt(selectedAuditId),
        report_type: reportType
      });
      toast.success('Reporte PDF compilado y registrado.', { id: 'pdf-comp' });
      setIsModalOpen(false);
      setSelectedAuditId('');
      fetchReportsData();
    } catch (error) {
      toast.error('Error al compilar el reporte PDF.', { id: 'pdf-comp' });
    } finally {
      setGenerating(false);
    }
  };

  // Shared Styles
  const glassCardStyle: React.CSSProperties = {
    background: 'rgba(255, 255, 255, 0.025)',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    backdropFilter: 'blur(24px)',
    borderRadius: 16,
    padding: 24,
    boxShadow: '0 12px 32px rgba(0, 0, 0, 0.3)',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    transition: 'all 0.3s',
  };

  const inputStyle = {
    width: '100%',
    background: 'rgba(2, 8, 23, 0.8)',
    border: '1px solid #1e293b',
    borderRadius: 12,
    padding: '12px 16px',
    fontSize: 14,
    color: '#e2e8f0',
    outline: 'none',
    transition: 'border-color 0.2s',
    fontFamily: 'Inter, sans-serif',
    boxSizing: 'border-box' as const,
  };

  const labelStyle: React.CSSProperties = {
    fontSize: 11,
    fontWeight: 700,
    letterSpacing: '0.1em',
    textTransform: 'uppercase',
    color: '#64748b',
    display: 'block',
    marginBottom: 6,
  };

  const getBadgeStyle = (type: string) => {
    if (type === 'full') return { border: '1px solid rgba(99,102,241,0.25)', bg: 'rgba(99,102,241,0.06)', color: '#818cf8' };
    if (type === 'executive') return { border: '1px solid rgba(16,185,129,0.25)', bg: 'rgba(16,185,129,0.06)', color: '#34d399' };
    return { border: '1px solid rgba(245,158,11,0.25)', bg: 'rgba(245,158,11,0.06)', color: '#fbbf24' };
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
      
      {/* Header and Add Button */}
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid rgba(99,102,241,0.1)', paddingBottom: 24, gap: 16 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 900, color: '#F1F5F9', letterSpacing: '-0.5px', margin: 0 }}>
            Historial de Reportes PDF
          </h1>
          <p style={{ fontSize: 13, color: '#64748B', marginTop: 4, margin: '4px 0 0' }}>
            Descarga y administra los informes de seguridad listos para presentar.
          </p>
        </div>
        
        <button
          onClick={() => setIsModalOpen(true)}
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
          <Plus size={16} />
          <span>Generar Reporte PDF</span>
        </button>
      </div>

      {loading ? (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 300, flexDirection: 'column', gap: 12 }}>
          <Loader2 size={32} className="animate-spin" color="#6366f1" />
          <span style={{ fontSize: 14, color: '#64748b', fontWeight: 500 }}>Cargando reportes...</span>
        </div>
      ) : reports.length === 0 ? (
        <div style={{
          background: 'rgba(255,255,255,0.01)',
          border: '1px dashed #1e293b',
          borderRadius: 20,
          padding: 48,
          textAlign: 'center',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 16,
        }}>
          <FileText size={48} color="#334155" />
          <div>
            <p style={{ fontSize: 16, fontWeight: 700, color: '#94a3b8', margin: 0 }}>No hay reportes disponibles</p>
            <p style={{ fontSize: 13, color: '#475569', marginTop: 4, margin: '4px 0 0' }}>Genera un PDF técnico o ejecutivo para visualizar los hallazgos sin conexión.</p>
          </div>
          <button
            onClick={() => setIsModalOpen(true)}
            style={{
              padding: '10px 18px',
              borderRadius: 12,
              background: 'rgba(99,102,241,0.1)',
              border: '1px solid rgba(99,102,241,0.25)',
              color: '#818cf8',
              fontSize: 13,
              fontWeight: 700,
              cursor: 'pointer',
              transition: 'all 0.2s',
            }}
          >
            Generar Reporte PDF
          </button>
        </div>
      ) : (
        /* Reports Table */
        <div style={{ ...glassCardStyle, padding: 0, overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', textAlign: 'left', fontSize: 13, borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: 'rgba(15,23,42,0.6)', borderBottom: '1px solid #1e293b' }}>
                  <th style={{ padding: '14px 20px', fontSize: 11, fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.08em' }}>ID Reporte</th>
                  <th style={{ padding: '14px 20px', fontSize: 11, fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Auditoría Relacionada</th>
                  <th style={{ padding: '14px 20px', fontSize: 11, fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.08em', textAlign: 'center' }}>Tipo Reporte</th>
                  <th style={{ padding: '14px 20px', fontSize: 11, fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.08em', textAlign: 'center' }}>Tamaño Archivo</th>
                  <th style={{ padding: '14px 20px', fontSize: 11, fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Fecha de Generación</th>
                  <th style={{ padding: '14px 20px', fontSize: 11, fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.08em', textAlign: 'right' }}>Acciones</th>
                </tr>
              </thead>
              <tbody>
                {reports.map((report) => {
                  const bStyle = getBadgeStyle(report.report_type);
                  return (
                    <tr 
                      key={report.id} 
                      className="table-row"
                      style={{ borderBottom: '1px solid rgba(15,23,42,0.8)', transition: 'background 0.2s' }}
                    >
                      <td style={{ padding: '14px 20px', fontFamily: 'monospace', color: '#64748b', fontSize: 12 }}>
                        REP-{report.id.toString().padStart(4, '0')}
                      </td>
                      <td style={{ padding: '14px 20px' }}>
                        <span style={{ fontWeight: 700, color: '#e2e8f0', display: 'block' }}>Audit ID #{report.audit_id}</span>
                        <span style={{ fontSize: 10, color: '#475569' }}>Asociado a escaneo</span>
                      </td>
                      <td style={{ padding: '14px 20px', textAlign: 'center' }}>
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          fontSize: 10,
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          letterSpacing: '0.05em',
                          padding: '3px 10px',
                          borderRadius: 9999,
                          border: bStyle.border,
                          background: bStyle.bg,
                          color: bStyle.color,
                        }}>
                          {report.report_type}
                        </span>
                      </td>
                      <td style={{ padding: '14px 20px', textAlign: 'center', fontFamily: 'monospace', color: '#94a3b8', fontSize: 12 }}>
                        {formatBytes(report.file_size)}
                      </td>
                      <td style={{ padding: '14px 20px', color: '#94a3b8', fontSize: 12 }}>
                        {formatDate(report.created_at)}
                      </td>
                      <td style={{ padding: '14px 20px', textAlign: 'right' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'end', gap: 12 }}>
                          <button
                            onClick={() => handleDownload(report)}
                            style={{
                              background: 'transparent',
                              border: 'none',
                              cursor: 'pointer',
                              color: '#818cf8',
                              fontSize: 12,
                              fontWeight: 700,
                              display: 'flex',
                              alignItems: 'center',
                              gap: 4,
                            }}
                            onMouseEnter={e => e.currentTarget.style.color = '#c7d2fe'}
                            onMouseLeave={e => e.currentTarget.style.color = '#818cf8'}
                          >
                            <FileDown size={14} />
                            <span>Descargar</span>
                          </button>
                          <button
                            onClick={() => handleDelete(report.id)}
                            style={{
                              background: 'transparent',
                              border: 'none',
                              cursor: 'pointer',
                              color: '#475569',
                              padding: 4,
                              borderRadius: 6,
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              transition: 'all 0.2s',
                            }}
                            onMouseEnter={e => { e.currentTarget.style.color = '#ef4444'; e.currentTarget.style.background = 'rgba(239,68,68,0.1)'; }}
                            onMouseLeave={e => { e.currentTarget.style.color = '#475569'; e.currentTarget.style.background = 'transparent'; }}
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* CREATE MODAL */}
      {isModalOpen && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.6)',
          backdropFilter: 'blur(8px)',
          zIndex: 50,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: 16,
        }}>
          <div style={{
            ...glassCardStyle,
            width: '100%',
            maxWidth: 440,
            padding: 0,
            overflow: 'hidden',
          }}>
            {/* Modal Header */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '16px 24px',
              background: 'rgba(255,255,255,0.02)',
              borderBottom: '1px solid rgba(255,255,255,0.06)',
            }}>
              <h3 style={{ fontSize:15, fontWeight:800, color:'#f1f5f9', display:'flex', alignItems:'center', gap:8, margin:0 }}>
                <FileText size={18} color="#818cf8" />
                <span>Generar Reporte PDF</span>
              </h3>
              <button 
                onClick={() => setIsModalOpen(false)}
                style={{ background:'none', border:'none', cursor:'pointer', color:'#475569', display:'flex', padding:0 }}
                onMouseEnter={e => e.currentTarget.style.color = '#f1f5f9'}
                onMouseLeave={e => e.currentTarget.style.color = '#475569'}
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Form */}
            <form onSubmit={handleCreateReport} style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
              
              {/* Seleccionar Auditoría */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <label style={labelStyle}>Auditoría Completada *</label>
                <select
                  required
                  value={selectedAuditId}
                  onChange={(e) => setSelectedAuditId(e.target.value)}
                  style={inputStyle}
                  onFocus={e => e.target.style.borderColor = '#818cf8'}
                  onBlur={e => e.target.style.borderColor = '#1e293b'}
                >
                  <option value="" style={{ background: '#020817' }}>-- Selecciona una auditoría --</option>
                  {completedAudits.map((audit) => (
                    <option key={audit.id} value={audit.id} style={{ background: '#020817' }}>
                      #{audit.id} - {audit.title} ({audit.target})
                    </option>
                  ))}
                </select>
              </div>

              {/* Seleccionar Tipo Reporte */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <label style={labelStyle}>Tipo de Reporte *</label>
                <select
                  value={reportType}
                  onChange={(e) => setReportType(e.target.value)}
                  style={inputStyle}
                  onFocus={e => e.target.style.borderColor = '#818cf8'}
                  onBlur={e => e.target.style.borderColor = '#1e293b'}
                >
                  <option value="full" style={{ background: '#020817' }}>Reporte Completo (Ejecutivo + Técnico)</option>
                  <option value="executive" style={{ background: '#020817' }}>Reporte Ejecutivo (Resumen para directivos)</option>
                  <option value="technical" style={{ background: '#020817' }}>Reporte Técnico (Detalles para administradores)</option>
                </select>
              </div>

              {/* Actions */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'end', gap: 12, borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 20, marginTop: 12 }}>
                <button
                  type="button" onClick={() => setIsModalOpen(false)}
                  style={{
                    padding: '8px 16px',
                    borderRadius: 10,
                    background: 'transparent',
                    border: '1px solid #1e293b',
                    color: '#64748b',
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                  onMouseEnter={e => e.currentTarget.style.color = '#f1f5f9'}
                  onMouseLeave={e => e.currentTarget.style.color = '#64748b'}
                >
                  Cancelar
                </button>
                <button
                  type="submit" disabled={generating}
                  style={{
                    padding: '8px 16px',
                    borderRadius: 10,
                    background: 'linear-gradient(135deg, #4f46e5, #6366f1)',
                    border: 'none',
                    color: 'white',
                    fontSize: 12,
                    fontWeight: 700,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    boxShadow: '0 4px 16px rgba(79, 70, 229, 0.3)',
                  }}
                >
                  {generating && <Loader2 size={12} className="animate-spin" />}
                  <span>Compilar PDF</span>
                </button>
              </div>

            </form>
          </div>
        </div>
      )}

      {/* CSS Hover Classes Fallback */}
      <style>{`
        .table-row:hover {
          background: rgba(255, 255, 255, 0.015) !important;
        }
      `}</style>
    </div>
  );
}
