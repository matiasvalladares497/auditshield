/**
 * AuditShield — Generador de Informes de Seguridad Profesionales
 * Genera un informe HTML completo que se abre en una nueva ventana para impresión/PDF
 */

export interface ReportAudit {
  id: number;
  title: string;
  target: string;
  target_type: string;
  status: string;
  profile: string;
  security_score?: number | null;
  score_letter?: string | null;
  created_at: string;
  completed_at?: string | null;
  duration?: number | null;
  findings_count?: number;
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  info_count?: number;
  modules?: string[] | Record<string, boolean>;
  notes?: string | null;
}

export interface ReportFinding {
  id: number;
  finding_id?: string | null;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  module: string;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  cve_id?: string | null;
  evidence?: string | null;
  impact?: string | null;
  recommendation?: string | null;
  references?: string[];
  status: string;
  is_remediated?: boolean;
  is_false_positive?: boolean;
}

export interface HistoricalAudit {
  id: number;
  title: string;
  target: string;
  security_score: number | null;
  score_letter: string | null;
  created_at: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const SEV_COLORS: Record<string, { bg: string; text: string; border: string; hex: string }> = {
  critical: { bg: '#FEF2F2', text: '#991B1B', border: '#FCA5A5', hex: '#DC2626' },
  high:     { bg: '#FFF7ED', text: '#9A3412', border: '#FDBA74', hex: '#EA580C' },
  medium:   { bg: '#FEFCE8', text: '#854D0E', border: '#FDE047', hex: '#CA8A04' },
  low:      { bg: '#EFF6FF', text: '#1E40AF', border: '#93C5FD', hex: '#2563EB' },
  info:     { bg: '#F8FAFC', text: '#475569', border: '#CBD5E1', hex: '#64748B' },
};

const SEV_LABELS: Record<string, string> = {
  critical: 'CRÍTICO', high: 'ALTO', medium: 'MEDIO', low: 'BAJO', info: 'INFO'
};

const RISK_LEVEL: Record<string, { label: string; color: string }> = {
  critical: { label: 'Riesgo Crítico', color: '#DC2626' },
  high:     { label: 'Riesgo Alto',    color: '#EA580C' },
  medium:   { label: 'Riesgo Medio',   color: '#CA8A04' },
  low:      { label: 'Riesgo Bajo',    color: '#2563EB' },
  info:     { label: 'Informativo',    color: '#64748B' },
};

const MODULE_LABELS: Record<string, string> = {
  osint: 'OSINT / Reconocimiento', ssl: 'SSL/TLS', web: 'Cabeceras Web', ports: 'Escaneo de Puertos',
  dns: 'DNS / Email Security', cve: 'CVE Matcher', waf: 'WAF Detection', compliance: 'Compliance'
};

function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('es-CL', { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function formatDateShort(iso: string | null | undefined): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('es-CL', { year: 'numeric', month: 'short', day: 'numeric' });
}

function formatDuration(secs: number | null | undefined): string {
  if (!secs) return '—';
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

function getScoreGrade(score: number | null | undefined): string {
  if (score == null) return '—';
  if (score >= 90) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 70) return 'B';
  if (score >= 60) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

function getScoreColor(score: number | null | undefined): string {
  if (score == null) return '#64748B';
  if (score >= 80) return '#16A34A';
  if (score >= 60) return '#CA8A04';
  return '#DC2626';
}

function getImprovementBadge(prev: number | null, curr: number | null): string {
  if (prev == null || curr == null) return '';
  const diff = curr - prev;
  if (diff > 0) return `<span style="color:#16A34A;font-weight:700">▲ +${diff} pts mejora</span>`;
  if (diff < 0) return `<span style="color:#DC2626;font-weight:700">▼ ${diff} pts regresión</span>`;
  return `<span style="color:#64748B;font-weight:700">= Sin cambio</span>`;
}

// ─── SVG Chart Generators ────────────────────────────────────────────────────

function generateSeverityDonut(critical: number, high: number, medium: number, low: number, info: number): string {
  const total = critical + high + medium + low + info;
  if (total === 0) return '<div style="text-align:center;color:#94A3B8;padding:20px;font-size:13px;">Sin hallazgos</div>';

  const data = [
    { v: critical, color: '#DC2626', label: 'Crítico' },
    { v: high,     color: '#EA580C', label: 'Alto' },
    { v: medium,   color: '#CA8A04', label: 'Medio' },
    { v: low,      color: '#2563EB', label: 'Bajo' },
    { v: info,     color: '#94A3B8', label: 'Info' },
  ].filter(d => d.v > 0);

  const cx = 80, cy = 80, r = 65, innerR = 42;
  let startAngle = -Math.PI / 2;
  let paths = '';

  for (const seg of data) {
    const angle = (seg.v / total) * 2 * Math.PI;
    const endAngle = startAngle + angle;
    const x1 = cx + r * Math.cos(startAngle);
    const y1 = cy + r * Math.sin(startAngle);
    const x2 = cx + r * Math.cos(endAngle);
    const y2 = cy + r * Math.sin(endAngle);
    const xi1 = cx + innerR * Math.cos(startAngle);
    const yi1 = cy + innerR * Math.sin(startAngle);
    const xi2 = cx + innerR * Math.cos(endAngle);
    const yi2 = cy + innerR * Math.sin(endAngle);
    const large = angle > Math.PI ? 1 : 0;
    paths += `<path d="M${xi1},${yi1} L${x1},${y1} A${r},${r} 0 ${large} 1 ${x2},${y2} L${xi2},${yi2} A${innerR},${innerR} 0 ${large} 0 ${xi1},${yi1}" fill="${seg.color}" opacity="0.9"/>`;
    startAngle = endAngle;
  }

  return `
    <div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap">
      <svg width="160" height="160" viewBox="0 0 160 160">
        ${paths}
        <text x="${cx}" y="${cy - 5}" text-anchor="middle" font-size="22" font-weight="800" fill="#1E293B">${total}</text>
        <text x="${cx}" y="${cy + 14}" text-anchor="middle" font-size="10" fill="#64748B" font-weight="600">TOTAL</text>
      </svg>
      <div style="display:flex;flex-direction:column;gap:8px">
        ${data.map(d => `
          <div style="display:flex;align-items:center;gap:8px">
            <div style="width:12px;height:12px;border-radius:3px;background:${d.color};flex-shrink:0"></div>
            <span style="font-size:12px;color:#374151;font-weight:500">${d.label}</span>
            <span style="font-size:13px;font-weight:800;color:${d.color};margin-left:auto">${d.v}</span>
          </div>`).join('')}
      </div>
    </div>`;
}

function generateHistoryChart(history: HistoricalAudit[]): string {
  if (history.length < 2) return '';

  const sorted = [...history].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
  const w = 560, h = 200, padL = 50, padR = 20, padT = 20, padB = 40;
  const chartW = w - padL - padR;
  const chartH = h - padT - padB;
  const n = sorted.length;

  // Grid lines
  let grid = '';
  for (let i = 0; i <= 4; i++) {
    const y = padT + (chartH / 4) * i;
    const val = Math.round(100 - (100 / 4) * i);
    grid += `<line x1="${padL}" y1="${y}" x2="${w - padR}" y2="${y}" stroke="#E2E8F0" stroke-width="1"/>`;
    grid += `<text x="${padL - 6}" y="${y + 4}" text-anchor="end" font-size="10" fill="#94A3B8">${val}</text>`;
  }

  // Score line and dots
  const pts = sorted.map((a, i) => {
    const score = a.security_score ?? 0;
    const x = padL + (n === 1 ? chartW / 2 : (chartW / (n - 1)) * i);
    const y = padT + chartH - (score / 100) * chartH;
    return { x, y, score, date: a.created_at, label: a.title };
  });

  const linePath = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x},${p.y}`).join(' ');
  const areaPath = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x},${p.y}`).join(' ')
    + ` L${pts[pts.length - 1].x},${padT + chartH} L${pts[0].x},${padT + chartH} Z`;

  // Gradient fill
  const gradId = `grad_${Math.random().toString(36).slice(2)}`;

  // Date labels
  const labels = pts.map(p => `
    <text x="${p.x}" y="${padT + chartH + 16}" text-anchor="middle" font-size="9" fill="#94A3B8">
      ${formatDateShort(p.date)}
    </text>`).join('');

  // Dots with score labels
  const dots = pts.map((p, i) => {
    const prev = i > 0 ? pts[i - 1].score : null;
    const diff = prev != null ? p.score - prev : null;
    const color = p.score >= 80 ? '#16A34A' : p.score >= 60 ? '#CA8A04' : '#DC2626';
    return `
      <circle cx="${p.x}" cy="${p.y}" r="5" fill="${color}" stroke="white" stroke-width="2"/>
      <text x="${p.x}" y="${p.y - 10}" text-anchor="middle" font-size="10" font-weight="700" fill="${color}">${p.score}%</text>
      ${diff != null ? `<text x="${p.x}" y="${p.y - 22}" text-anchor="middle" font-size="9" fill="${diff >= 0 ? '#16A34A' : '#DC2626'}">${diff >= 0 ? '+' : ''}${diff}%</text>` : ''}
    `;
  }).join('');

  return `
    <svg width="100%" viewBox="0 0 ${w} ${h}" style="max-width:${w}px">
      <defs>
        <linearGradient id="${gradId}" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#6366F1" stop-opacity="0.15"/>
          <stop offset="100%" stop-color="#6366F1" stop-opacity="0"/>
        </linearGradient>
      </defs>
      ${grid}
      <path d="${areaPath}" fill="url(#${gradId})"/>
      <path d="${linePath}" fill="none" stroke="#6366F1" stroke-width="2.5" stroke-linejoin="round"/>
      ${dots}
      ${labels}
    </svg>`;
}

function generateRiskMatrix(findings: ReportFinding[]): string {
  // Risk matrix: Likelihood (Low/Med/High) x Impact (Low/Med/High/Critical)
  // Based on CVSS score → Likelihood and severity → Impact
  const cells: Record<string, number> = {};
  const matrix = ['high', 'medium', 'low'];
  const impacts = ['critical', 'high', 'medium', 'low'];
  
  for (const f of findings.filter(f => !f.is_false_positive)) {
    const impact = f.severity;
    const likelihood = (f.cvss_score ?? 0) >= 7 ? 'high' : (f.cvss_score ?? 0) >= 4 ? 'medium' : 'low';
    const key = `${likelihood}_${impact}`;
    cells[key] = (cells[key] || 0) + 1;
  }

  const cellColor = (likelihood: string, impact: string): string => {
    const riskScore = (matrix.length - matrix.indexOf(likelihood)) * (impacts.length - impacts.indexOf(impact));
    if (riskScore >= 9) return '#FEE2E2';
    if (riskScore >= 6) return '#FEF3C7';
    if (riskScore >= 3) return '#FEF9C3';
    return '#ECFDF5';
  };

  const cellTextColor = (likelihood: string, impact: string): string => {
    const riskScore = (matrix.length - matrix.indexOf(likelihood)) * (impacts.length - impacts.indexOf(impact));
    if (riskScore >= 9) return '#991B1B';
    if (riskScore >= 6) return '#92400E';
    if (riskScore >= 3) return '#713F12';
    return '#065F46';
  };

  const cellBorder = (likelihood: string, impact: string): string => {
    const riskScore = (matrix.length - matrix.indexOf(likelihood)) * (impacts.length - impacts.indexOf(impact));
    if (riskScore >= 9) return '#FCA5A5';
    if (riskScore >= 6) return '#FDE68A';
    if (riskScore >= 3) return '#FEF08A';
    return '#A7F3D0';
  };

  return `
    <table style="width:100%;border-collapse:collapse;font-size:11px">
      <thead>
        <tr>
          <th style="padding:8px;background:#F8FAFC;border:1px solid #E2E8F0;text-align:center;font-size:10px;color:#64748B;font-weight:700">PROBABILIDAD<br>↕ IMPACTO →</th>
          ${impacts.map(i => `<th style="padding:8px;background:#F8FAFC;border:1px solid #E2E8F0;text-align:center;font-size:10px;color:${SEV_COLORS[i].text};font-weight:700">${SEV_LABELS[i]}</th>`).join('')}
        </tr>
      </thead>
      <tbody>
        ${matrix.map(l => `
          <tr>
            <td style="padding:8px;background:#F8FAFC;border:1px solid #E2E8F0;text-align:center;font-size:10px;font-weight:700;color:#64748B">${l === 'high' ? 'ALTA' : l === 'medium' ? 'MEDIA' : 'BAJA'}</td>
            ${impacts.map(i => {
              const cnt = cells[`${l}_${i}`] || 0;
              const bg = cellColor(l, i);
              const txt = cellTextColor(l, i);
              const bd = cellBorder(l, i);
              return `<td style="padding:10px;border:1px solid ${bd};background:${bg};text-align:center;font-weight:${cnt > 0 ? 800 : 400};color:${cnt > 0 ? txt : '#CBD5E1'};font-size:${cnt > 0 ? '15px' : '11px'}">${cnt > 0 ? cnt : '·'}</td>`;
            }).join('')}
          </tr>`).join('')}
      </tbody>
    </table>`;
}

function generateImprovementPlan(findings: ReportFinding[]): string {
  const open = findings.filter(f => !f.is_remediated && !f.is_false_positive);
  const byPriority = [...open].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  
  const phases = [
    { label: 'Fase 1 — Inmediato (0–7 días)', filter: (f: ReportFinding) => f.severity === 'critical', color: '#DC2626', bg: '#FEF2F2', border: '#FCA5A5' },
    { label: 'Fase 2 — Urgente (7–30 días)', filter: (f: ReportFinding) => f.severity === 'high', color: '#EA580C', bg: '#FFF7ED', border: '#FDBA74' },
    { label: 'Fase 3 — Planificado (1–3 meses)', filter: (f: ReportFinding) => f.severity === 'medium', color: '#CA8A04', bg: '#FEFCE8', border: '#FDE047' },
    { label: 'Fase 4 — Mejora continua (3–6 meses)', filter: (f: ReportFinding) => f.severity === 'low' || f.severity === 'info', color: '#2563EB', bg: '#EFF6FF', border: '#93C5FD' },
  ];

  return phases.filter(p => byPriority.some(f => p.filter(f))).map((phase, idx) => {
    const items = byPriority.filter(f => phase.filter(f));
    if (items.length === 0) return '';
    return `
      <div style="margin-bottom:20px;border:1px solid ${phase.border};border-radius:10px;overflow:hidden">
        <div style="background:${phase.bg};padding:12px 16px;border-bottom:1px solid ${phase.border};display:flex;align-items:center;gap:8px">
          <div style="width:24px;height:24px;border-radius:50%;background:${phase.color};color:white;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:800;flex-shrink:0">${idx + 1}</div>
          <span style="font-weight:700;font-size:13px;color:${phase.color}">${phase.label}</span>
          <span style="margin-left:auto;font-size:11px;font-weight:600;color:${phase.color};background:white;padding:2px 8px;border-radius:99px;border:1px solid ${phase.border}">${items.length} hallazgo${items.length !== 1 ? 's' : ''}</span>
        </div>
        <div style="padding:0">
          ${items.map((f, i) => `
            <div style="padding:12px 16px;border-bottom:${i < items.length - 1 ? '1px solid #F1F5F9' : 'none'};display:flex;align-items:flex-start;gap:12px">
              <div style="width:20px;height:20px;border-radius:4px;background:${phase.color}15;border:1px solid ${phase.border};display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:2px">
                <span style="font-size:9px;font-weight:700;color:${phase.color}">${i + 1}</span>
              </div>
              <div style="flex:1">
                <div style="font-size:12px;font-weight:700;color:#1E293B;margin-bottom:3px">${f.title}</div>
                <div style="font-size:11px;color:#64748B;line-height:1.5">${f.recommendation || 'Revisar y aplicar las mejores prácticas de seguridad correspondientes.'}</div>
                <div style="margin-top:6px;display:flex;gap:8px;flex-wrap:wrap">
                  <span style="font-size:10px;background:#F8FAFC;border:1px solid #E2E8F0;padding:2px 8px;border-radius:99px;color:#64748B">Módulo: ${MODULE_LABELS[f.module] || f.module}</span>
                  ${f.cvss_score ? `<span style="font-size:10px;background:#F8FAFC;border:1px solid #E2E8F0;padding:2px 8px;border-radius:99px;color:#64748B">CVSS: ${f.cvss_score.toFixed(1)}</span>` : ''}
                  ${f.cve_id ? `<span style="font-size:10px;background:#EEF2FF;border:1px solid #C7D2FE;padding:2px 8px;border-radius:99px;color:#4338CA">CVE: ${f.cve_id}</span>` : ''}
                </div>
              </div>
            </div>`).join('')}
        </div>
      </div>`;
  }).join('');
}

// ─── Main Report Generator ────────────────────────────────────────────────────

export function generateProfessionalReport(
  audit: ReportAudit,
  findings: ReportFinding[],
  history: HistoricalAudit[] = []
): string {
  const score = audit.security_score ?? null;
  const scoreColor = getScoreColor(score);
  const scoreLetter = audit.score_letter ?? getScoreGrade(score);
  
  const activeFindings = findings.filter(f => !f.is_false_positive);
  const sortedFindings = [...activeFindings].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  
  const critical = findings.filter(f => f.severity === 'critical' && !f.is_false_positive);
  const high     = findings.filter(f => f.severity === 'high'     && !f.is_false_positive);
  const medium   = findings.filter(f => f.severity === 'medium'   && !f.is_false_positive);
  const low      = findings.filter(f => f.severity === 'low'      && !f.is_false_positive);
  const info     = findings.filter(f => f.severity === 'info'     && !f.is_false_positive);
  const remediated = findings.filter(f => f.is_remediated);
  const falsePos   = findings.filter(f => f.is_false_positive);

  // Determine historical context for same target
  const sameTargetHistory = history
    .filter(h => h.target === audit.target && h.id !== audit.id && h.security_score != null)
    .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
  
  const prevAudit = sameTargetHistory.length > 0 ? sameTargetHistory[sameTargetHistory.length - 1] : null;
  const hasHistory = sameTargetHistory.length > 0;
  
  // Full history for chart (include current audit)
  const chartHistory: HistoricalAudit[] = [
    ...sameTargetHistory,
    {
      id: audit.id,
      title: audit.title,
      target: audit.target,
      security_score: score,
      score_letter: scoreLetter,
      created_at: audit.completed_at || audit.created_at,
      critical_count: critical.length,
      high_count: high.length,
      medium_count: medium.length,
      low_count: low.length,
    }
  ];

  const reportDate = new Date().toLocaleDateString('es-CL', { year: 'numeric', month: 'long', day: 'numeric' });
  const execSummary = generateExecutiveSummary(audit, findings, score, prevAudit);
  const moduleList = getModulesList(audit.modules);

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Informe de Seguridad — ${audit.target} — AuditShield</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap');
    
    * { box-sizing: border-box; margin: 0; padding: 0; }
    
    body {
      font-family: 'Inter', -apple-system, sans-serif;
      color: #1E293B;
      background: white;
      font-size: 13px;
      line-height: 1.6;
      -webkit-font-smoothing: antialiased;
    }

    .page { max-width: 860px; margin: 0 auto; padding: 0; }

    /* ─── Cover Page ─── */
    .cover {
      background: linear-gradient(145deg, #0F172A 0%, #1E293B 60%, #0F172A 100%);
      color: white;
      padding: 60px 60px 50px;
      min-height: 400px;
      position: relative;
      overflow: hidden;
      page-break-after: always;
    }
    .cover::before {
      content: '';
      position: absolute;
      top: -80px;
      right: -80px;
      width: 350px;
      height: 350px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(99,102,241,0.3), transparent 70%);
    }
    .cover::after {
      content: '';
      position: absolute;
      bottom: -60px;
      left: -60px;
      width: 280px;
      height: 280px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(16,185,129,0.15), transparent 70%);
    }
    .cover-logo {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 50px;
    }
    .cover-logo-icon {
      width: 44px;
      height: 44px;
      background: linear-gradient(135deg, rgba(99,102,241,0.4), rgba(129,140,248,0.2));
      border: 1px solid rgba(99,102,241,0.5);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 22px;
    }
    .cover-logo-text {
      font-size: 20px;
      font-weight: 800;
      background: linear-gradient(135deg, #e0e7ff, #818CF8);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -0.5px;
    }
    .cover-type {
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.2em;
      text-transform: uppercase;
      color: rgba(129,140,248,0.9);
      margin-bottom: 16px;
    }
    .cover-title {
      font-size: 36px;
      font-weight: 900;
      line-height: 1.1;
      letter-spacing: -1px;
      color: white;
      margin-bottom: 12px;
    }
    .cover-target {
      font-family: 'JetBrains Mono', monospace;
      font-size: 16px;
      color: rgba(148,163,184,0.9);
      margin-bottom: 40px;
      background: rgba(255,255,255,0.05);
      display: inline-block;
      padding: 6px 14px;
      border-radius: 8px;
      border: 1px solid rgba(255,255,255,0.08);
    }
    .cover-score-area {
      display: flex;
      align-items: center;
      gap: 24px;
      margin-bottom: 40px;
    }
    .cover-score-circle {
      width: 90px;
      height: 90px;
      border-radius: 50%;
      border: 3px solid ${scoreColor};
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      background: rgba(255,255,255,0.04);
      box-shadow: 0 0 30px ${scoreColor}40;
    }
    .cover-score-num {
      font-size: 24px;
      font-weight: 900;
      color: ${scoreColor};
      line-height: 1;
    }
    .cover-score-pct {
      font-size: 11px;
      color: rgba(148,163,184,0.7);
      font-weight: 600;
    }
    .cover-grade {
      font-size: 44px;
      font-weight: 900;
      color: ${scoreColor};
      line-height: 1;
    }
    .cover-grade-label {
      font-size: 12px;
      color: rgba(148,163,184,0.7);
      font-weight: 600;
    }
    .cover-meta {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
      padding: 24px;
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 12px;
    }
    .cover-meta-item { }
    .cover-meta-label {
      font-size: 9px;
      font-weight: 700;
      color: rgba(100,116,139,0.9);
      text-transform: uppercase;
      letter-spacing: 0.1em;
      margin-bottom: 4px;
    }
    .cover-meta-value {
      font-size: 12px;
      font-weight: 600;
      color: rgba(226,232,240,0.9);
    }

    /* ─── Content Sections ─── */
    .section {
      padding: 36px 60px;
      border-bottom: 1px solid #F1F5F9;
    }
    .section:last-child { border-bottom: none; }
    .section-title {
      font-size: 18px;
      font-weight: 800;
      color: #0F172A;
      margin-bottom: 6px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .section-title::after {
      content: '';
      flex: 1;
      height: 2px;
      background: linear-gradient(90deg, #6366F1, transparent);
    }
    .section-subtitle {
      font-size: 12px;
      color: #94A3B8;
      margin-bottom: 24px;
      font-weight: 500;
    }
    .section-num {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 26px;
      height: 26px;
      border-radius: 7px;
      background: #6366F1;
      color: white;
      font-size: 11px;
      font-weight: 800;
      flex-shrink: 0;
    }

    /* ─── Stats Grid ─── */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 12px;
      margin-bottom: 24px;
    }
    .stat-card {
      border-radius: 10px;
      padding: 16px 12px;
      text-align: center;
      border: 1px solid;
    }
    .stat-count {
      font-size: 28px;
      font-weight: 900;
      line-height: 1;
      margin-bottom: 4px;
    }
    .stat-label {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    /* ─── Improvement Banner ─── */
    .improvement-banner {
      padding: 16px 20px;
      border-radius: 12px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      gap: 14px;
    }

    /* ─── Finding Cards ─── */
    .finding-card {
      border: 1px solid;
      border-radius: 10px;
      margin-bottom: 14px;
      overflow: hidden;
      page-break-inside: avoid;
    }
    .finding-header {
      padding: 12px 16px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .finding-badge {
      padding: 3px 10px;
      border-radius: 99px;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      flex-shrink: 0;
    }
    .finding-id {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      color: #94A3B8;
      flex-shrink: 0;
    }
    .finding-title {
      font-weight: 700;
      font-size: 13px;
      color: #1E293B;
      flex: 1;
    }
    .finding-cvss {
      font-size: 11px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 6px;
      flex-shrink: 0;
    }
    .finding-body {
      padding: 14px 16px;
      background: #FAFAFA;
      border-top: 1px solid #F1F5F9;
    }
    .finding-section-label {
      font-size: 9px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: #94A3B8;
      margin-bottom: 4px;
    }
    .finding-section-content {
      font-size: 12px;
      color: #334155;
      line-height: 1.6;
      margin-bottom: 12px;
    }
    .finding-rec {
      background: #EEF2FF;
      border: 1px solid #C7D2FE;
      border-radius: 8px;
      padding: 10px 14px;
      font-size: 12px;
      color: #3730A3;
      line-height: 1.6;
    }
    .evidence-block {
      background: #F8FAFC;
      border: 1px solid #E2E8F0;
      border-radius: 6px;
      padding: 10px 12px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      color: #64748B;
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 120px;
      overflow: hidden;
    }

    /* ─── Print ─── */
    @media print {
      .no-print { display: none !important; }
      .cover { page-break-after: always; }
      .section { page-break-inside: avoid; }
      body { font-size: 12px; }
    }

    /* ─── Print button ─── */
    .print-bar {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      background: linear-gradient(135deg, #0F172A, #1E293B);
      padding: 12px 32px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      z-index: 1000;
      box-shadow: 0 2px 20px rgba(0,0,0,0.3);
    }
    .print-bar-logo {
      font-size: 14px;
      font-weight: 800;
      color: #818CF8;
      letter-spacing: -0.3px;
    }
    .print-bar-actions { display: flex; gap: 10px; }
    .btn-print {
      padding: 8px 20px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      border: none;
      background: linear-gradient(135deg, #4F46E5, #6366F1);
      color: white;
      box-shadow: 0 2px 12px rgba(99,102,241,0.4);
    }
    .btn-close {
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      border: 1px solid rgba(255,255,255,0.1);
      background: rgba(255,255,255,0.05);
      color: #94A3B8;
    }
    .print-spacer { height: 56px; }

    table { border-collapse: collapse; }
  </style>
</head>
<body>
  <!-- Print/Close Bar -->
  <div class="print-bar no-print">
    <span class="print-bar-logo">🛡 AuditShield — Informe de Seguridad</span>
    <div class="print-bar-actions">
      <button class="btn-close" onclick="window.close()">✕ Cerrar</button>
      <button class="btn-print" onclick="window.print()">🖨 Imprimir / Guardar PDF</button>
    </div>
  </div>
  <div class="print-spacer no-print"></div>

  <div class="page">

    <!-- ═══════════════════════════════════════════════════ -->
    <!-- PORTADA                                            -->
    <!-- ═══════════════════════════════════════════════════ -->
    <div class="cover">
      <div class="cover-logo">
        <div class="cover-logo-icon">🛡</div>
        <div>
          <div class="cover-logo-text">AuditShield</div>
          <div style="font-size:9px;color:rgba(148,163,184,0.6);letter-spacing:0.1em;text-transform:uppercase">Security Platform</div>
        </div>
      </div>

      <div class="cover-type">Informe de Auditoría de Ciberseguridad</div>
      <div class="cover-title">${audit.title}</div>
      <div class="cover-target">${audit.target}</div>

      ${score != null ? `
      <div class="cover-score-area">
        <div class="cover-score-circle">
          <div class="cover-score-num">${Math.round(score)}</div>
          <div class="cover-score-pct">/ 100</div>
        </div>
        <div>
          <div class="cover-grade">${scoreLetter}</div>
          <div class="cover-grade-label">Clasificación</div>
        </div>
        <div style="flex:1;padding-left:10px">
          <div style="font-size:13px;color:rgba(148,163,184,0.8);font-weight:500;line-height:1.7">
            Postura de seguridad <strong style="color:${scoreColor}">${score >= 80 ? 'Buena' : score >= 60 ? 'Regular' : 'Deficiente'}</strong>.<br>
            Se identificaron <strong style="color:#FCA5A5">${critical.length} vulnerabilidades críticas</strong>
            ${prevAudit != null ? `<br>${getImprovementBadge(prevAudit.security_score, score)} vs. auditoría anterior.` : '.'}
          </div>
        </div>
      </div>` : `
      <div style="padding:20px 0;color:rgba(148,163,184,0.6)">Score no disponible para esta auditoría.</div>`}

      <div class="cover-meta">
        <div class="cover-meta-item">
          <div class="cover-meta-label">Objetivo</div>
          <div class="cover-meta-value" style="font-family:monospace">${audit.target}</div>
        </div>
        <div class="cover-meta-item">
          <div class="cover-meta-label">Tipo de Perfil</div>
          <div class="cover-meta-value">${audit.profile || 'Completo'}</div>
        </div>
        <div class="cover-meta-item">
          <div class="cover-meta-label">Fecha Inicio</div>
          <div class="cover-meta-value">${formatDate(audit.created_at)}</div>
        </div>
        <div class="cover-meta-item">
          <div class="cover-meta-label">Fecha Finalización</div>
          <div class="cover-meta-value">${formatDate(audit.completed_at)}</div>
        </div>
        <div class="cover-meta-item">
          <div class="cover-meta-label">Duración</div>
          <div class="cover-meta-value">${formatDuration(audit.duration)}</div>
        </div>
        <div class="cover-meta-item">
          <div class="cover-meta-label">Fecha del Informe</div>
          <div class="cover-meta-value">${reportDate}</div>
        </div>
      </div>
    </div>

    <!-- ═══════════════════════════════════════════════════ -->
    <!-- 1. RESUMEN EJECUTIVO                               -->
    <!-- ═══════════════════════════════════════════════════ -->
    <div class="section">
      <div class="section-title"><span class="section-num">1</span> Resumen Ejecutivo</div>
      <div class="section-subtitle">Visión general del estado de seguridad del activo auditado</div>

      ${hasHistory && prevAudit ? `
      <div class="improvement-banner" style="background:${prevAudit.security_score != null && score != null && score > prevAudit.security_score ? '#F0FDF4' : score != null && prevAudit.security_score != null && score < prevAudit.security_score ? '#FEF2F2' : '#F8FAFC'};border:1px solid ${prevAudit.security_score != null && score != null && score > prevAudit.security_score ? '#86EFAC' : '#FCA5A5'}">
        <div style="font-size:26px">
          ${prevAudit.security_score != null && score != null && score > prevAudit.security_score ? '📈' : score != null && prevAudit.security_score != null && score < prevAudit.security_score ? '📉' : '📊'}
        </div>
        <div style="flex:1">
          <div style="font-weight:700;font-size:13px;color:#0F172A;margin-bottom:3px">
            ${prevAudit.security_score != null && score != null && score > prevAudit.security_score
              ? `✅ ¡Mejora detectada! El score subió de ${prevAudit.security_score}% a ${score}% (+${score - prevAudit.security_score} puntos)`
              : score != null && prevAudit.security_score != null && score < prevAudit.security_score
              ? `⚠️ Regresión detectada. El score bajó de ${prevAudit.security_score}% a ${score}% (${score - prevAudit.security_score} puntos)`
              : '📊 Sin cambios detectados respecto a la auditoría anterior'}
          </div>
          <div style="font-size:12px;color:#64748B">
            Comparado con auditoría anterior del ${formatDateShort(prevAudit.created_at)} — Score: ${prevAudit.security_score}% (${prevAudit.score_letter ?? '?'})
          </div>
        </div>
      </div>` : ''}

      ${execSummary}

      <!-- Stats -->
      <div class="stats-grid" style="margin-top:24px">
        <div class="stat-card" style="background:${SEV_COLORS.critical.bg};border-color:${SEV_COLORS.critical.border}">
          <div class="stat-count" style="color:${SEV_COLORS.critical.hex}">${critical.length}</div>
          <div class="stat-label" style="color:${SEV_COLORS.critical.text}">Crítico</div>
        </div>
        <div class="stat-card" style="background:${SEV_COLORS.high.bg};border-color:${SEV_COLORS.high.border}">
          <div class="stat-count" style="color:${SEV_COLORS.high.hex}">${high.length}</div>
          <div class="stat-label" style="color:${SEV_COLORS.high.text}">Alto</div>
        </div>
        <div class="stat-card" style="background:${SEV_COLORS.medium.bg};border-color:${SEV_COLORS.medium.border}">
          <div class="stat-count" style="color:${SEV_COLORS.medium.hex}">${medium.length}</div>
          <div class="stat-label" style="color:${SEV_COLORS.medium.text}">Medio</div>
        </div>
        <div class="stat-card" style="background:${SEV_COLORS.low.bg};border-color:${SEV_COLORS.low.border}">
          <div class="stat-count" style="color:${SEV_COLORS.low.hex}">${low.length}</div>
          <div class="stat-label" style="color:${SEV_COLORS.low.text}">Bajo</div>
        </div>
        <div class="stat-card" style="background:#F8FAFC;border-color:#E2E8F0">
          <div class="stat-count" style="color:#64748B">${info.length}</div>
          <div class="stat-label" style="color:#94A3B8">Info</div>
        </div>
      </div>
      
      ${remediated.length > 0 ? `
      <div style="margin-top:12px;padding:12px 16px;background:#F0FDF4;border:1px solid #86EFAC;border-radius:8px;display:flex;align-items:center;gap:10px">
        <span style="font-size:16px">✅</span>
        <div>
          <span style="font-weight:700;color:#16A34A;font-size:12px">${remediated.length} vulnerabilidad${remediated.length !== 1 ? 'es' : ''} ya remediada${remediated.length !== 1 ? 's' : ''}</span>
          <span style="color:#4ADE80;font-size:12px"> — Buen trabajo en las correcciones aplicadas.</span>
        </div>
      </div>` : ''}
    </div>

    <!-- ═══════════════════════════════════════════════════ -->
    <!-- 2. DISTRIBUCIÓN DE VULNERABILIDADES                -->
    <!-- ═══════════════════════════════════════════════════ -->
    <div class="section">
      <div class="section-title"><span class="section-num">2</span> Distribución de Vulnerabilidades</div>
      <div class="section-subtitle">Desglose visual por severidad y módulos de escaneo</div>
      
      <div style="display:flex;gap:32px;align-items:flex-start;flex-wrap:wrap;margin-bottom:28px">
        <div>
          <div style="font-size:11px;font-weight:700;color:#64748B;margin-bottom:12px;text-transform:uppercase;letter-spacing:0.08em">Por Severidad</div>
          ${generateSeverityDonut(critical.length, high.length, medium.length, low.length, info.length)}
        </div>
        <div style="flex:1;min-width:200px">
          <div style="font-size:11px;font-weight:700;color:#64748B;margin-bottom:12px;text-transform:uppercase;letter-spacing:0.08em">Por Módulo</div>
          ${generateModuleBreakdown(activeFindings)}
        </div>
      </div>

      <!-- Modules used -->
      <div style="margin-top:8px">
        <div style="font-size:11px;font-weight:700;color:#64748B;margin-bottom:10px;text-transform:uppercase;letter-spacing:0.08em">Módulos Ejecutados</div>
        <div style="display:flex;flex-wrap:wrap;gap:8px">
          ${moduleList.map(m => `<span style="padding:4px 12px;border-radius:99px;background:#EEF2FF;border:1px solid #C7D2FE;font-size:11px;font-weight:600;color:#4338CA">${MODULE_LABELS[m] || m}</span>`).join('')}
        </div>
      </div>
    </div>

    <!-- ═══════════════════════════════════════════════════ -->
    <!-- 3. HISTÓRICO DE MEJORA                             -->
    <!-- ═══════════════════════════════════════════════════ -->
    ${chartHistory.length >= 2 ? `
    <div class="section">
      <div class="section-title"><span class="section-num">3</span> Evolución Histórica de Seguridad</div>
      <div class="section-subtitle">Progreso del score de seguridad a lo largo de las auditorías para ${audit.target}</div>
      
      <div style="margin-bottom:20px">
        ${generateHistoryChart(chartHistory)}
      </div>

      <table style="width:100%;border-collapse:collapse;font-size:11px">
        <thead>
          <tr style="background:#F8FAFC;border-bottom:2px solid #E2E8F0">
            <th style="padding:10px 12px;text-align:left;font-weight:700;color:#64748B">Fecha</th>
            <th style="padding:10px 12px;text-align:left;font-weight:700;color:#64748B">Título</th>
            <th style="padding:10px 12px;text-align:center;font-weight:700;color:#64748B">Score</th>
            <th style="padding:10px 12px;text-align:center;font-weight:700;color:#64748B">Crít</th>
            <th style="padding:10px 12px;text-align:center;font-weight:700;color:#64748B">Alto</th>
            <th style="padding:10px 12px;text-align:center;font-weight:700;color:#64748B">Variación</th>
          </tr>
        </thead>
        <tbody>
          ${chartHistory.map((h, i) => {
            const prev = i > 0 ? chartHistory[i-1] : null;
            const isCurrent = h.id === audit.id;
            const sc = h.security_score;
            const scColor = getScoreColor(sc);
            return `
            <tr style="border-bottom:1px solid #F1F5F9;background:${isCurrent ? '#EEF2FF' : 'white'}">
              <td style="padding:10px 12px;color:#64748B;font-size:11px">${formatDateShort(h.created_at)}</td>
              <td style="padding:10px 12px;font-weight:${isCurrent ? 700 : 500};color:${isCurrent ? '#4338CA' : '#1E293B'};font-size:11px">
                ${h.title}${isCurrent ? ' <span style="font-size:9px;background:#4338CA;color:white;padding:1px 6px;border-radius:99px;font-weight:700">ACTUAL</span>' : ''}
              </td>
              <td style="padding:10px 12px;text-align:center;font-weight:800;color:${scColor}">${sc != null ? sc + '%' : '—'}</td>
              <td style="padding:10px 12px;text-align:center;font-weight:700;color:${(h.critical_count || 0) > 0 ? '#DC2626' : '#94A3B8'}">${h.critical_count || 0}</td>
              <td style="padding:10px 12px;text-align:center;font-weight:700;color:${(h.high_count || 0) > 0 ? '#EA580C' : '#94A3B8'}">${h.high_count || 0}</td>
              <td style="padding:10px 12px;text-align:center">
                ${prev?.security_score != null && sc != null ? getImprovementBadge(prev.security_score, sc) : '<span style="color:#CBD5E1">—</span>'}
              </td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>` : ''}

    <!-- ═══════════════════════════════════════════════════ -->
    <!-- 4. MATRIZ DE RIESGO                                -->
    <!-- ═══════════════════════════════════════════════════ -->
    <div class="section">
      <div class="section-title"><span class="section-num">${chartHistory.length >= 2 ? '4' : '3'}</span> Matriz de Riesgo</div>
      <div class="section-subtitle">Clasificación de vulnerabilidades según probabilidad de explotación e impacto en el negocio</div>

      ${generateRiskMatrix(findings)}

      <div style="margin-top:16px;display:flex;gap:12px;flex-wrap:wrap">
        <div style="display:flex;align-items:center;gap:6px;font-size:11px;color:#64748B">
          <div style="width:12px;height:12px;background:#FEE2E2;border:1px solid #FCA5A5;border-radius:2px"></div> Riesgo Crítico (acción inmediata)
        </div>
        <div style="display:flex;align-items:center;gap:6px;font-size:11px;color:#64748B">
          <div style="width:12px;height:12px;background:#FEF3C7;border:1px solid #FDE68A;border-radius:2px"></div> Riesgo Alto (acción urgente)
        </div>
        <div style="display:flex;align-items:center;gap:6px;font-size:11px;color:#64748B">
          <div style="width:12px;height:12px;background:#FEF9C3;border:1px solid #FEF08A;border-radius:2px"></div> Riesgo Medio (planificado)
        </div>
        <div style="display:flex;align-items:center;gap:6px;font-size:11px;color:#64748B">
          <div style="width:12px;height:12px;background:#ECFDF5;border:1px solid #A7F3D0;border-radius:2px"></div> Riesgo Bajo (mejora continua)
        </div>
      </div>
    </div>

    <!-- ═══════════════════════════════════════════════════ -->
    <!-- 5. PLAN DE MEJORA                                  -->
    <!-- ═══════════════════════════════════════════════════ -->
    <div class="section">
      <div class="section-title"><span class="section-num">${chartHistory.length >= 2 ? '5' : '4'}</span> Plan de Mejora por Fases</div>
      <div class="section-subtitle">Roadmap de remediación priorizado por criticidad y esfuerzo estimado</div>
      
      ${generateImprovementPlan(findings)}

      ${activeFindings.filter(f => !f.is_remediated).length === 0 ? `
      <div style="text-align:center;padding:32px;background:#F0FDF4;border:1px solid #86EFAC;border-radius:10px">
        <div style="font-size:32px;margin-bottom:8px">🎉</div>
        <div style="font-weight:700;color:#16A34A;font-size:15px">¡Todas las vulnerabilidades han sido remediadas!</div>
        <div style="color:#4ADE80;font-size:12px;margin-top:4px">Se recomienda realizar una nueva auditoría de verificación.</div>
      </div>` : ''}
    </div>

    <!-- ═══════════════════════════════════════════════════ -->
    <!-- 6. HALLAZGOS DETALLADOS                            -->
    <!-- ═══════════════════════════════════════════════════ -->
    <div class="section">
      <div class="section-title"><span class="section-num">${chartHistory.length >= 2 ? '6' : '5'}</span> Hallazgos Detallados</div>
      <div class="section-subtitle">${sortedFindings.length} vulnerabilidades identificadas, ordenadas por severidad</div>

      ${sortedFindings.map((f, i) => {
        const sc = SEV_COLORS[f.severity];
        return `
        <div class="finding-card" style="border-color:${sc.border}">
          <div class="finding-header" style="background:${sc.bg}">
            <span style="width:20px;height:20px;border-radius:5px;background:${sc.hex};color:white;font-size:10px;font-weight:800;display:flex;align-items:center;justify-content:center;flex-shrink:0">${i + 1}</span>
            <span class="finding-badge" style="background:${sc.hex};color:white">${SEV_LABELS[f.severity]}</span>
            ${f.finding_id ? `<span class="finding-id">${f.finding_id}</span>` : ''}
            <span class="finding-title">${f.title}</span>
            ${f.cvss_score != null ? `<span class="finding-cvss" style="background:${f.cvss_score >= 7 ? '#FEE2E2' : f.cvss_score >= 4 ? '#FEF3C7' : '#F0FDF4'};color:${f.cvss_score >= 7 ? '#DC2626' : f.cvss_score >= 4 ? '#CA8A04' : '#16A34A'};border:1px solid ${f.cvss_score >= 7 ? '#FCA5A5' : f.cvss_score >= 4 ? '#FDE68A' : '#86EFAC'}">CVSS ${f.cvss_score.toFixed(1)}</span>` : ''}
            ${f.is_remediated ? `<span style="font-size:10px;background:#F0FDF4;border:1px solid #86EFAC;padding:2px 8px;border-radius:99px;color:#16A34A;font-weight:700">✓ REMEDIADO</span>` : ''}
          </div>
          <div class="finding-body">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:12px">
              <div>
                <div class="finding-section-label">Descripción</div>
                <div class="finding-section-content">${f.description}</div>
              </div>
              <div>
                <div class="finding-section-label">Impacto Potencial</div>
                <div class="finding-section-content" style="color:#991B1B">${f.impact || 'No especificado'}</div>
              </div>
            </div>
            ${f.evidence ? `
            <div style="margin-bottom:12px">
              <div class="finding-section-label">Evidencia Técnica</div>
              <div class="evidence-block">${f.evidence.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>
            </div>` : ''}
            ${f.recommendation ? `
            <div class="finding-rec">
              <div style="font-size:10px;font-weight:700;color:#4338CA;margin-bottom:4px;text-transform:uppercase;letter-spacing:0.08em">🛡 Recomendación de Mitigación</div>
              ${f.recommendation}
            </div>` : ''}
            <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
              <span style="font-size:10px;background:#F8FAFC;border:1px solid #E2E8F0;padding:2px 8px;border-radius:99px;color:#64748B">Módulo: ${MODULE_LABELS[f.module] || f.module}</span>
              ${f.cve_id ? `<a href="https://nvd.nist.gov/vuln/detail/${f.cve_id}" style="font-size:10px;background:#EEF2FF;border:1px solid #C7D2FE;padding:2px 8px;border-radius:99px;color:#4338CA;text-decoration:none">${f.cve_id}</a>` : ''}
              ${f.cvss_vector ? `<span style="font-size:10px;background:#F8FAFC;border:1px solid #E2E8F0;padding:2px 8px;border-radius:99px;color:#64748B;font-family:monospace">${f.cvss_vector}</span>` : ''}
            </div>
          </div>
        </div>`;
      }).join('')}

      ${sortedFindings.length === 0 ? `
      <div style="text-align:center;padding:40px;background:#F8FAFC;border:1px dashed #E2E8F0;border-radius:10px">
        <div style="font-size:28px;margin-bottom:8px">✅</div>
        <div style="font-weight:700;color:#16A34A">No se encontraron vulnerabilidades activas</div>
      </div>` : ''}
    </div>

    <!-- ═══════════════════════════════════════════════════ -->
    <!-- FOOTER                                             -->
    <!-- ═══════════════════════════════════════════════════ -->
    <div style="padding:24px 60px;background:#0F172A;color:rgba(148,163,184,0.7);font-size:11px;display:flex;align-items:center;justify-content:space-between">
      <div>
        <strong style="color:#818CF8">AuditShield</strong> — Plataforma de Auditoría de Ciberseguridad<br>
        Informe generado el ${reportDate} · Confidencial
      </div>
      <div style="text-align:right">
        Auditoría ID: #${audit.id}<br>
        Objetivo: ${audit.target}
      </div>
    </div>

  </div><!-- .page -->
</body>
</html>`;
}

// ─── Helpers for report ─────────────────────────────────────────────────────

function generateExecutiveSummary(
  audit: ReportAudit,
  findings: ReportFinding[],
  score: number | null,
  prevAudit: HistoricalAudit | null
): string {
  const critical = findings.filter(f => f.severity === 'critical' && !f.is_false_positive);
  const open = findings.filter(f => !f.is_remediated && !f.is_false_positive);
  const totalActive = findings.filter(f => !f.is_false_positive).length;

  const riskLevel = score == null ? 'No evaluado' :
    score >= 80 ? 'Bajo' : score >= 60 ? 'Moderado' : score >= 40 ? 'Alto' : 'Crítico';
  const riskColor = score == null ? '#64748B' :
    score >= 80 ? '#16A34A' : score >= 60 ? '#CA8A04' : '#DC2626';

  return `
    <div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:12px;padding:20px 24px;margin-bottom:20px">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
        <div>
          <div style="font-size:11px;font-weight:700;color:#64748B;margin-bottom:10px;text-transform:uppercase;letter-spacing:0.08em">Conclusiones Principales</div>
          <div style="font-size:13px;color:#334155;line-height:1.8">
            La auditoría de seguridad sobre <strong style="font-family:monospace">${audit.target}</strong> arrojó 
            <strong>${totalActive} hallazgos</strong> activos, de los cuales 
            <strong style="color:${critical.length > 0 ? '#DC2626' : '#16A34A'}">${critical.length} son de nivel crítico</strong>.
            ${open.length > 0 ? `Se requiere atención inmediata en <strong>${open.length} vulnerabilidades pendientes de remediación</strong>.` : 'Todas las vulnerabilidades han sido remediadas exitosamente.'}
            ${prevAudit?.security_score != null && score != null ? `<br><br>Respecto a la auditoría anterior (${formatDateShort(prevAudit.created_at)}), el score de seguridad ha <strong style="color:${score >= prevAudit.security_score ? '#16A34A' : '#DC2626'}">${score >= prevAudit.security_score ? 'mejorado' : 'disminuido'} ${Math.abs(score - prevAudit.security_score)} puntos</strong>.` : ''}
          </div>
        </div>
        <div>
          <div style="font-size:11px;font-weight:700;color:#64748B;margin-bottom:10px;text-transform:uppercase;letter-spacing:0.08em">Indicadores Clave</div>
          <div style="display:flex;flex-direction:column;gap:8px">
            <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:white;border-radius:8px;border:1px solid #F1F5F9">
              <span style="font-size:12px;color:#64748B">Nivel de Riesgo Global</span>
              <span style="font-weight:700;color:${riskColor};font-size:12px">${riskLevel}</span>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:white;border-radius:8px;border:1px solid #F1F5F9">
              <span style="font-size:12px;color:#64748B">Score de Seguridad</span>
              <span style="font-weight:700;color:${getScoreColor(score)};font-size:12px">${score != null ? score + '/100 (' + audit.score_letter + ')' : 'N/A'}</span>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:white;border-radius:8px;border:1px solid #F1F5F9">
              <span style="font-size:12px;color:#64748B">Hallazgos Totales</span>
              <span style="font-weight:700;color:#1E293B;font-size:12px">${totalActive}</span>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:white;border-radius:8px;border:1px solid #F1F5F9">
              <span style="font-size:12px;color:#64748B">Pendientes de Remediar</span>
              <span style="font-weight:700;color:${open.length > 0 ? '#DC2626' : '#16A34A'};font-size:12px">${open.length}</span>
            </div>
          </div>
        </div>
      </div>
    </div>`;
}

function generateModuleBreakdown(findings: ReportFinding[]): string {
  const byModule: Record<string, number> = {};
  for (const f of findings) {
    byModule[f.module] = (byModule[f.module] || 0) + 1;
  }
  const total = findings.length;
  const sorted = Object.entries(byModule).sort((a, b) => b[1] - a[1]);
  
  if (sorted.length === 0) return '<div style="color:#94A3B8;font-size:12px">Sin hallazgos</div>';

  return sorted.map(([mod, count]) => `
    <div style="margin-bottom:8px">
      <div style="display:flex;justify-content:space-between;margin-bottom:3px">
        <span style="font-size:11px;font-weight:500;color:#334155">${MODULE_LABELS[mod] || mod}</span>
        <span style="font-size:11px;font-weight:700;color:#64748B">${count}</span>
      </div>
      <div style="height:5px;background:#F1F5F9;border-radius:99px;overflow:hidden">
        <div style="height:100%;width:${total > 0 ? (count / total) * 100 : 0}%;background:linear-gradient(90deg,#6366F1,#818CF8);border-radius:99px"></div>
      </div>
    </div>`).join('');
}

function getModulesList(modules?: string[] | Record<string, boolean>): string[] {
  if (!modules) return [];
  if (Array.isArray(modules)) return modules;
  return Object.entries(modules).filter(([, v]) => v).map(([k]) => k);
}

// ─── Download / Open Report ──────────────────────────────────────────────────

export function openProfessionalReport(html: string): void {
  const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const win = window.open(url, '_blank');
  if (win) {
    win.focus();
    // Cleanup after a while
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  } else {
    // Fallback: download as HTML
    const a = document.createElement('a');
    a.href = url;
    a.download = `AuditShield_Reporte_${Date.now()}.html`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }
}
