'use client';

import React, { useState } from 'react';
import { 
  ChevronDown, 
  ChevronUp, 
  AlertTriangle, 
  CheckCircle2, 
  EyeOff, 
  ShieldAlert, 
  ExternalLink,
  Terminal,
  RefreshCw
} from 'lucide-react';
import { cn, getSeverityColor, formatDate } from '@/lib/utils';
import type { Finding } from '@/lib/api';
import { auditsApi } from '@/lib/api';
import toast from 'react-hot-toast';

interface FindingCardProps {
  finding: Finding;
  auditId: number;
  onUpdate: (updated: Finding) => void;
}

export default function FindingCard({ finding, auditId, onUpdate }: FindingCardProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [loading, setLoading] = useState(false);

  const severityLabels: Record<string, string> = {
    critical: 'CRÍTICO',
    high: 'ALTO',
    medium: 'MEDIO',
    low: 'BAJO',
    info: 'INFO'
  };

  const severityBadgeClass = getSeverityColor(finding.severity);

  const handleToggleStatus = async (type: 'remediated' | 'false_positive') => {
    setLoading(true);
    try {
      const isRemediated = type === 'remediated' ? !finding.is_remediated : finding.is_remediated;
      const isFalsePositive = type === 'false_positive' ? !finding.is_false_positive : finding.is_false_positive;
      const newStatus = isRemediated ? 'remediated' : isFalsePositive ? 'false_positive' : 'open';
      const payload: { status: string; is_remediated?: boolean; is_false_positive?: boolean } = {
        status: newStatus,
        is_remediated: isRemediated,
        is_false_positive: isFalsePositive,
      };
      
      const updated = await auditsApi.updateFinding(auditId, finding.id, payload);
      onUpdate(updated);
      toast.success(
        type === 'remediated' 
          ? (updated.is_remediated ? 'Vulnerabilidad marcada como remediada' : 'Vulnerabilidad reabierta')
          : (updated.is_false_positive ? 'Marcado como Falso Positivo' : 'Falso Positivo removido')
      );
    } catch (error) {
      toast.error('Error al actualizar el estado del hallazgo');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className={cn(
        'card border border-[#1E293B] overflow-hidden transition-all duration-300',
        finding.is_false_positive && 'opacity-65 border-dashed border-slate-700 bg-slate-900/10',
        finding.is_remediated && 'border-emerald-500/20 bg-emerald-950/5'
      )}
    >
      {/* Header */}
      <div
        className="p-4 flex items-center justify-between cursor-pointer hover:bg-[var(--bg-elevated)]/30 transition-colors"
        onClick={() => setIsOpen(!isOpen)}
      >
        <div className="flex items-center space-x-3 flex-1 min-w-0">
          <span className={cn('badge font-bold text-xs uppercase px-2.5 py-1', severityBadgeClass)}>
            {severityLabels[finding.severity.toLowerCase()] ?? finding.severity.toUpperCase()}
          </span>
          <span className="text-xs font-mono text-slate-500 select-all hidden sm:inline-block">
            {finding.finding_id}
          </span>
          <h4 className="font-semibold text-sm sm:text-base text-[var(--text-primary)] truncate flex-1 pr-4">
            {finding.title}
          </h4>
        </div>
        
        <div className="flex items-center space-x-3">
          {finding.cvss_score != null && (
            <span className={cn(
              "text-xs font-bold px-2 py-0.5 rounded",
              finding.cvss_score >= 7.0 ? "bg-rose-500/10 text-rose-400" :
              finding.cvss_score >= 4.0 ? "bg-amber-500/10 text-amber-400" :
              "bg-blue-500/10 text-blue-400"
            )}>
              CVSS {finding.cvss_score.toFixed(1)}
            </span>
          )}
          {finding.cve_id && (
            <span className="text-xs font-mono bg-[#1E293B] text-indigo-400 px-2 py-0.5 rounded select-all hidden md:inline-block">
              {finding.cve_id}
            </span>
          )}
          {finding.is_remediated && (
            <span className="text-emerald-400 text-xs font-medium flex items-center space-x-1 bg-emerald-500/10 px-2 py-0.5 rounded">
              <CheckCircle2 className="w-3 h-3" />
              <span>Remediado</span>
            </span>
          )}
          {finding.is_false_positive && (
            <span className="text-slate-400 text-xs font-medium flex items-center space-x-1 bg-slate-500/10 px-2 py-0.5 rounded">
              <EyeOff className="w-3 h-3" />
              <span>Falso Positivo</span>
            </span>
          )}
          {isOpen ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
        </div>
      </div>

      {/* Expanded Content */}
      {isOpen && (
        <div className="border-t border-[#1E293B] p-5 space-y-5 bg-[var(--bg-surface)]/40">
          
          {/* Metadata Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs font-medium text-[var(--text-secondary)]">
            <div>
              <span className="block text-slate-500 text-[10px] uppercase font-bold tracking-wider">Módulo Escáner</span>
              <span className="text-slate-300">{finding.module}</span>
            </div>
            {finding.cve_id && (
              <div>
                <span className="block text-slate-500 text-[10px] uppercase font-bold tracking-wider">CVE Asociado</span>
                <a 
                  href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-indigo-400 hover:underline inline-flex items-center space-x-1"
                >
                  <span>{finding.cve_id}</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            )}
            {finding.cvss_vector && (
              <div className="col-span-1 md:col-span-2">
                <span className="block text-slate-500 text-[10px] uppercase font-bold tracking-wider">CVSS Vector String</span>
                <span className="font-mono text-slate-400 text-[11px] block truncate select-all">{finding.cvss_vector}</span>
              </div>
            )}
            {finding.is_remediated && (
              <div>
                <span className="block text-slate-500 text-[10px] uppercase font-bold tracking-wider">Estado</span>
                <span className="text-emerald-400">Remediado</span>
              </div>
            )}
          </div>

          <div className="space-y-4 text-sm leading-relaxed">
            {/* Descripción */}
            <div>
              <h5 className="font-semibold text-slate-300 text-xs uppercase tracking-wider mb-1">Descripción</h5>
              <p className="text-slate-300">{finding.description}</p>
            </div>

            {/* Impacto */}
            {finding.impact && (
              <div>
                <h5 className="font-semibold text-slate-300 text-xs uppercase tracking-wider mb-1">Impacto Potencial</h5>
                <p className="text-slate-300 text-rose-400/90">{finding.impact}</p>
              </div>
            )}

            {/* Recomendación */}
            {finding.recommendation && (
              <div className="bg-indigo-950/10 border border-indigo-900/30 rounded-xl p-4">
                <h5 className="font-bold text-indigo-400 text-xs uppercase tracking-wider mb-1.5 flex items-center space-x-1.5">
                  <ShieldAlert className="w-4 h-4" />
                  <span>Recomendación de Mitigación</span>
                </h5>
                <p className="text-slate-300 whitespace-pre-line">{finding.recommendation}</p>
              </div>
            )}

            {/* Evidencia (Terminal style) */}
            {finding.evidence && (
              <div>
                <h5 className="font-semibold text-slate-300 text-xs uppercase tracking-wider mb-1.5 flex items-center space-x-1">
                  <Terminal className="w-3.5 h-3.5 text-slate-400" />
                  <span>Evidencia del Hallazgo</span>
                </h5>
                <pre className="bg-black/40 border border-slate-800 rounded-xl p-4 font-mono text-xs text-slate-400 overflow-x-auto max-h-60 whitespace-pre-wrap select-all">
                  {finding.evidence}
                </pre>
              </div>
            )}

            {/* Referencias */}
            {finding.references && finding.references.length > 0 && (
              <div>
                <h5 className="font-semibold text-slate-300 text-xs uppercase tracking-wider mb-1.5">Referencias externas</h5>
                <ul className="list-disc list-inside space-y-1 text-xs text-indigo-400">
                  {finding.references.map((ref, idx) => (
                    <li key={idx}>
                      <a href={ref} target="_blank" rel="noreferrer" className="hover:underline inline-flex items-center space-x-1">
                        <span>{ref}</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center justify-end gap-3 pt-3 border-t border-[#1E293B]">
            <button
              onClick={() => handleToggleStatus('false_positive')}
              disabled={loading}
              className={cn(
                'btn text-xs px-3 py-1.5 flex items-center space-x-1.5 border border-[#1E293B] hover:bg-slate-800',
                finding.is_false_positive ? 'text-slate-300 bg-slate-800' : 'text-slate-400'
              )}
            >
              {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <EyeOff className="w-3.5 h-3.5" />}
              <span>{finding.is_false_positive ? 'Remover Falso Positivo' : 'Marcar Falso Positivo'}</span>
            </button>
            <button
              onClick={() => handleToggleStatus('remediated')}
              disabled={loading}
              className={cn(
                'btn text-xs px-3 py-1.5 flex items-center space-x-1.5 border',
                finding.is_remediated 
                  ? 'border-indigo-500/30 bg-indigo-500/10 text-indigo-300 hover:bg-indigo-500/20' 
                  : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20'
              )}
            >
              {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
              <span>{finding.is_remediated ? 'Reabrir Vulnerabilidad' : 'Marcar como Resuelto'}</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
