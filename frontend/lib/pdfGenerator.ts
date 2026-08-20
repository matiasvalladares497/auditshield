import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

interface Audit {
  id: number;
  title: string;
  target: string;
  target_type: string;
  status: string;
  profile: string;
  score: number | null;
  security_score?: number | null;
  score_letter: string | null;
  created_at: string;
  completed_at: string | null;
  duration: number | null;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  summary?: any;
}

interface Finding {
  id: number;
  audit_id: number;
  finding_id: string | null;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  module: string;
  cvss_score: number | null;
  cvss_vector?: string | null;
  cve_id: string | null;
  evidence: string | null;
  impact: string | null;
  recommendation: string | null;
  references: string[];
}

export const generateClientPdf = (
  audit: Audit,
  findings: Finding[],
  previousAudits: Audit[]
): Blob => {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'pt',
    format: 'a4',
  });

  const width = doc.internal.pageSize.getWidth(); // 595.28
  const height = doc.internal.pageSize.getHeight(); // 841.89
  const score = audit.security_score ?? audit.score ?? 0;
  const letter = audit.score_letter ?? 'F';

  // Helper colors
  const colors = {
    bgDark: '#020817',
    bgSurface: '#0F172A',
    border: '#334155',
    textPrimary: '#0F172A',
    textSecondary: '#64748B',
    brand: '#6366F1',
    critical: '#EF4444',
    high: '#F97316',
    medium: '#F59E0B',
    low: '#3B82F6',
    info: '#6B7280',
    success: '#10B981',
  };

  const getSeverityColor = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical': return colors.critical;
      case 'high': return colors.high;
      case 'medium': return colors.medium;
      case 'low': return colors.low;
      case 'info': return colors.info;
      default: return colors.brand;
    }
  };

  const getSeverityLabel = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical': return 'CRÍTICO';
      case 'high': return 'ALTO';
      case 'medium': return 'MEDIO';
      case 'low': return 'BAJO';
      case 'info': return 'INFO';
      default: return sev.toUpperCase();
    }
  };

  // ---------------------------------------------------------------------------
  // PÁGINA 1: PORTADA
  // ---------------------------------------------------------------------------
  // Dibujar fondo oscuro para la portada
  doc.setFillColor(2, 8, 23); // #020817
  doc.rect(0, 0, width, height, 'F');

  // Gradiente simulado (pequeño fondo decorativo)
  doc.setFillColor(15, 23, 42); // #0F172A
  doc.rect(0, 500, width, height - 500, 'F');

  // Logo
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(28);
  doc.setFont('helvetica', 'bold');
  doc.text('AuditShield', 60, 100);

  // Badge tipo reporte
  doc.setFillColor(99, 102, 241, 0.15); // rgba(99,102,241,0.15)
  doc.setDrawColor(99, 102, 241);
  doc.setLineWidth(1);
  doc.roundedRect(60, 160, 200, 24, 12, 12, 'D');
  doc.setFontSize(9);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(129, 140, 248);
  doc.text('AUDITORÍA DE CIBERSEGURIDAD', 75, 175);

  // Título
  doc.setFontSize(36);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(255, 255, 255);
  const splitTitle = doc.splitTextToSize(audit.title, width - 120);
  doc.text(splitTitle, 60, 240);

  // Subtítulo
  const titleHeight = splitTitle.length * 40;
  doc.setFontSize(16);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(148, 163, 184);
  doc.text('Informe Profesional de Evaluación de Seguridad', 60, 250 + titleHeight);

  // Cuadro de Puntuación
  const scoreY = 320 + titleHeight;
  doc.setFillColor(15, 23, 42);
  doc.setDrawColor(51, 65, 85);
  doc.roundedRect(60, scoreY, 475, 100, 8, 8, 'FD');

  // Puntaje texto
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(148, 163, 184);
  doc.text('POSTURA GLOBAL DE SEGURIDAD', 85, scoreY + 30);

  // Puntaje número
  doc.setFontSize(44);
  let scoreColorRGB = [16, 185, 129]; // green
  if (score < 40) scoreColorRGB = [239, 68, 68]; // red
  else if (score < 60) scoreColorRGB = [249, 115, 22]; // orange
  else if (score < 80) scoreColorRGB = [245, 158, 11]; // yellow
  
  doc.setTextColor(scoreColorRGB[0], scoreColorRGB[1], scoreColorRGB[2]);
  doc.setFont('helvetica', 'bold');
  doc.text(String(score), 85, scoreY + 75);

  doc.setFontSize(28);
  doc.text(letter, 180, scoreY + 70);

  doc.setFontSize(12);
  doc.setTextColor(148, 163, 184);
  doc.setFont('helvetica', 'normal');
  doc.text('/ 100', 140, scoreY + 70);

  let ratingLabel = 'EXCELENTE';
  if (score < 40) ratingLabel = 'CRÍTICO';
  else if (score < 60) ratingLabel = 'DEFICIENTE';
  else if (score < 80) ratingLabel = 'ACEPTABLE';
  doc.text(`NIVEL ${ratingLabel}`, 230, scoreY + 65);

  // Metadatos
  const metaY = scoreY + 140;
  doc.setFontSize(10);
  doc.setTextColor(148, 163, 184);
  
  doc.setFont('helvetica', 'bold');
  doc.text('OBJETIVO AUDITADO:', 60, metaY);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(255, 255, 255);
  doc.text(audit.target, 220, metaY);

  doc.setTextColor(148, 163, 184);
  doc.setFont('helvetica', 'bold');
  doc.text('FECHA DE GENERACIÓN:', 60, metaY + 25);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(255, 255, 255);
  doc.text(new Date(audit.created_at).toLocaleDateString('es-ES', { day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' }), 220, metaY + 25);

  doc.setTextColor(148, 163, 184);
  doc.setFont('helvetica', 'bold');
  doc.text('TOTAL DE HALLAZGOS:', 60, metaY + 50);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(255, 255, 255);
  doc.text(`${findings.length} vulnerabilidades detectadas`, 220, metaY + 50);

  doc.setTextColor(148, 163, 184);
  doc.setFont('helvetica', 'bold');
  doc.text('TIPO DE REPORTE:', 60, metaY + 75);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(255, 255, 255);
  doc.text('Reporte Completo (Ejecutivo + Técnico)', 220, metaY + 75);

  // Footer confidencial
  doc.setFontSize(8);
  doc.setTextColor(239, 68, 68);
  doc.setFont('helvetica', 'bold');
  doc.text('CONFIDENCIAL - AUDITSHIELD REPORT ENGINE', 60, height - 40);

  // ---------------------------------------------------------------------------
  // PÁGINA 2: RESUMEN EJECUTIVO Y MATRIZ DE RIESGO
  // ---------------------------------------------------------------------------
  doc.addPage();
  
  // Dibujar header
  doc.setFillColor(248, 250, 252); // light background
  doc.rect(0, 0, width, height, 'F');

  // Header decorativo
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, width, 50, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('AuditShield - Reporte de Auditoría de Ciberseguridad', 60, 30);
  doc.setFontSize(9);
  doc.setTextColor(148, 163, 184);
  doc.text(audit.target, width - 60 - doc.getTextWidth(audit.target), 30);

  let currentY = 90;
  
  // Título Sección 1
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('1. Resumen Ejecutivo', 60, currentY);
  currentY += 15;

  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(51, 65, 85);
  const summaryText = `El presente informe consolida los hallazgos identificados durante la auditoría de seguridad realizada sobre el activo "${audit.target}". El análisis evaluó los vectores de exposición a nivel OSINT, DNS, puertos expuestos, criptografía SSL/TLS, cabeceras de seguridad y vulnerabilidades comunes OWASP. Con un score final de ${score}/100 (Clasificación ${letter}), el objetivo requiere medidas de mitigación para resolver las vulnerabilidades críticas detalladas a continuación.`;
  const splitSummary = doc.splitTextToSize(summaryText, width - 120);
  doc.text(splitSummary, 60, currentY);
  currentY += splitSummary.length * 15 + 15;

  // Cuadrícula de Severidades
  const boxWidth = 90;
  const boxHeight = 45;
  const startX = 60;
  const severities = [
    { label: 'CRÍTICO', count: audit.critical_count ?? findings.filter(f => f.severity === 'critical').length, color: colors.critical },
    { label: 'ALTO', count: audit.high_count ?? findings.filter(f => f.severity === 'high').length, color: colors.high },
    { label: 'MEDIO', count: audit.medium_count ?? findings.filter(f => f.severity === 'medium').length, color: colors.medium },
    { label: 'BAJO', count: audit.low_count ?? findings.filter(f => f.severity === 'low').length, color: colors.low },
    { label: 'INFO', count: audit.info_count ?? findings.filter(f => f.severity === 'info').length, color: colors.info },
  ];

  severities.forEach((sev, idx) => {
    const x = startX + idx * (boxWidth + 6);
    doc.setFillColor(255, 255, 255);
    doc.setDrawColor(203, 213, 225);
    doc.roundedRect(x, currentY, boxWidth, boxHeight, 6, 6, 'FD');
    
    // Linea superior del badge
    doc.setFillColor(sev.color);
    doc.rect(x + 1, currentY + 1, boxWidth - 2, 4, 'F');

    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(71, 85, 105);
    doc.text(sev.label, x + boxWidth / 2 - doc.getTextWidth(sev.label) / 2, currentY + 20);

    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(sev.color);
    doc.text(String(sev.count), x + boxWidth / 2 - doc.getTextWidth(String(sev.count)) / 2, currentY + 38);
  });
  currentY += boxHeight + 40;

  // Título Sección 2: Matriz de Riesgos
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('2. Matriz de Riesgo (Probabilidad vs Impacto)', 60, currentY);
  currentY += 25;

  // Generar conteos para matriz
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const mediumCount = findings.filter(f => f.severity === 'medium').length;
  const lowCount = findings.filter(f => f.severity === 'low').length;
  const infoCount = findings.filter(f => f.severity === 'info').length;

  // Dibujar Matriz
  // Celdas: (alto, alta) = critical, (medio, alta) = high, (medio, media) = medium, (medio, baja) = low, (bajo, baja) = info
  const cellW = 70;
  const cellH = 30;
  const matrixStartX = 180;
  
  // Etiquetas superiores
  doc.setFontSize(9);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(100, 116, 139);
  doc.text('Probabilidad (Likelihood)', matrixStartX + cellW * 1.5, currentY - 20, { align: 'center' });
  doc.text('Baja', matrixStartX + cellW * 0.5, currentY - 5, { align: 'center' });
  doc.text('Media', matrixStartX + cellW * 1.5, currentY - 5, { align: 'center' });
  doc.text('Alta', matrixStartX + cellW * 2.5, currentY - 5, { align: 'center' });

  // Etiquetas laterales
  doc.text('Impacto', matrixStartX - 70, currentY + cellH * 1.5, { align: 'center', angle: 90 });
  doc.text('Alto', matrixStartX - 15, currentY + cellH * 0.5 + 5, { align: 'right' });
  doc.text('Medio', matrixStartX - 15, currentY + cellH * 1.5 + 5, { align: 'right' });
  doc.text('Bajo', matrixStartX - 15, currentY + cellH * 2.5 + 5, { align: 'right' });

  // Fila Alto
  // (Alto, Baja) -> Amarillo
  doc.setFillColor(254, 240, 138); // Yellow 100
  doc.rect(matrixStartX, currentY, cellW, cellH, 'F');
  doc.setTextColor(133, 77, 14);
  doc.text('0', matrixStartX + cellW/2, currentY + cellH/2 + 4, { align: 'center' });

  // (Alto, Media) -> Naranja
  doc.setFillColor(255, 237, 213); // Orange 100
  doc.rect(matrixStartX + cellW, currentY, cellW, cellH, 'F');
  doc.setTextColor(194, 65, 12);
  doc.text('0', matrixStartX + cellW * 1.5, currentY + cellH/2 + 4, { align: 'center' });

  // (Alto, Alta) -> Rojo (Critical)
  doc.setFillColor(254, 226, 226); // Red 100
  doc.rect(matrixStartX + cellW * 2, currentY, cellW, cellH, 'F');
  doc.setTextColor(185, 28, 28);
  doc.setFont('helvetica', 'bold');
  doc.text(String(criticalCount), matrixStartX + cellW * 2.5, currentY + cellH/2 + 4, { align: 'center' });
  doc.setFont('helvetica', 'normal');

  // Fila Medio
  currentY += cellH;
  // (Medio, Baja) -> Verde (Low)
  doc.setFillColor(209, 250, 229); // Green 100
  doc.rect(matrixStartX, currentY, cellW, cellH, 'F');
  doc.setTextColor(4, 120, 87);
  doc.text(String(lowCount), matrixStartX + cellW/2, currentY + cellH/2 + 4, { align: 'center' });

  // (Medio, Media) -> Amarillo (Medium)
  doc.setFillColor(254, 240, 138);
  doc.rect(matrixStartX + cellW, currentY, cellW, cellH, 'F');
  doc.setTextColor(133, 77, 14);
  doc.text(String(mediumCount), matrixStartX + cellW * 1.5, currentY + cellH/2 + 4, { align: 'center' });

  // (Medio, Alta) -> Naranja (High)
  doc.setFillColor(255, 237, 213);
  doc.rect(matrixStartX + cellW * 2, currentY, cellW, cellH, 'F');
  doc.setTextColor(194, 65, 12);
  doc.setFont('helvetica', 'bold');
  doc.text(String(highCount), matrixStartX + cellW * 2.5, currentY + cellH/2 + 4, { align: 'center' });
  doc.setFont('helvetica', 'normal');

  // Fila Bajo
  currentY += cellH;
  // (Bajo, Baja) -> Verde (Info)
  doc.setFillColor(209, 250, 229);
  doc.rect(matrixStartX, currentY, cellW, cellH, 'F');
  doc.setTextColor(4, 120, 87);
  doc.text(String(infoCount), matrixStartX + cellW/2, currentY + cellH/2 + 4, { align: 'center' });

  // (Bajo, Media) -> Verde
  doc.setFillColor(209, 250, 229);
  doc.rect(matrixStartX + cellW, currentY, cellW, cellH, 'F');
  doc.setTextColor(4, 120, 87);
  doc.text('0', matrixStartX + cellW * 1.5, currentY + cellH/2 + 4, { align: 'center' });

  // (Bajo, Alta) -> Amarillo
  doc.setFillColor(254, 240, 138);
  doc.rect(matrixStartX + cellW * 2, currentY, cellW, cellH, 'F');
  doc.setTextColor(133, 77, 14);
  doc.text('0', matrixStartX + cellW * 2.5, currentY + cellH/2 + 4, { align: 'center' });

  // Bordes de la cuadrícula
  doc.setDrawColor(203, 213, 225);
  for (let r = 0; r <= 3; r++) {
    doc.line(matrixStartX, currentY - cellH * (3 - r), matrixStartX + cellW * 3, currentY - cellH * (3 - r));
  }
  for (let c = 0; c <= 3; c++) {
    doc.line(matrixStartX + cellW * c, currentY - cellH * 3, matrixStartX + cellW * c, currentY);
  }

  currentY += 40;

  // Explicación de Matriz
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);
  doc.text('Explicación del riesgo:', 60, currentY);
  doc.text('- Crítico (Rojo): Explotación inmediata probable con impacto severo.', 70, currentY + 15);
  doc.text('- Alto (Naranja): Alto riesgo, vulnerabilidades que deben mitigarse prioritariamente.', 70, currentY + 28);
  doc.text('- Medio (Amarillo): Riesgo moderado, requiere mitigación programada.', 70, currentY + 41);
  doc.text('- Bajo (Verde): Bajo impacto técnico, medidas preventivas recomendadas.', 70, currentY + 54);

  // Footer
  doc.setFontSize(8);
  doc.setTextColor(148, 163, 184);
  doc.text(`Generado por AuditShield v1.0.0 — Página 2`, 60, height - 30);

  // ---------------------------------------------------------------------------
  // PÁGINA 3: PLAN DE ACCIÓN Y EVOLUCIÓN HISTÓRICA
  // ---------------------------------------------------------------------------
  doc.addPage();
  doc.setFillColor(248, 250, 252);
  doc.rect(0, 0, width, height, 'F');

  // Header decorativo
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, width, 50, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('AuditShield - Reporte de Auditoría de Ciberseguridad', 60, 30);
  doc.setFontSize(9);
  doc.setTextColor(148, 163, 184);
  doc.text(audit.target, width - 60 - doc.getTextWidth(audit.target), 30);

  currentY = 80;

  // Comparación histórica (si existe)
  if (previousAudits && previousAudits.length > 0) {
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('3. Evolución de Seguridad e Historial', 60, currentY);
    currentY += 15;

    // Obtener la auditoría anterior inmediata
    const sortedHistory = [...previousAudits].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
    const lastAudit = sortedHistory[sortedHistory.length - 1];
    const lastScore = lastAudit.security_score ?? lastAudit.score ?? 0;
    const diff = score - lastScore;

    let bannerColor = colors.success;
    let bannerText = `La postura de seguridad ha MEJORADO en +${diff} puntos!`;
    if (diff < 0) {
      bannerColor = colors.critical;
      bannerText = `Atencion: La postura de seguridad ha DEGRADADO en ${diff} puntos.`;
    } else if (diff === 0) {
      bannerColor = colors.medium;
      bannerText = `La postura de seguridad se mantiene IGUAL en ${score} puntos.`;
    }

    doc.setFillColor(255, 255, 255);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(60, currentY, 475, 45, 6, 6, 'FD');
    doc.setFillColor(bannerColor);
    doc.rect(61, currentY + 1, 4, 43, 'F');

    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(bannerColor);
    doc.text(bannerText, 80, currentY + 18);

    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text(`Score Anterior: ${lastScore} (${lastAudit.score_letter || 'F'})  ->  Score Actual: ${score} (${letter})`, 80, currentY + 34);
    
    currentY += 65;

    // Tabla de Historial
    const historyRows = sortedHistory.map((item, index) => [
      `Auditoría #${index + 1} (${item.title})`,
      new Date(item.created_at).toLocaleDateString('es-ES'),
      String(item.security_score ?? item.score ?? 0),
      item.score_letter ?? 'N/A'
    ]);
    historyRows.push([
      `Auditoría Actual (Evaluación de hoy)`,
      new Date(audit.created_at).toLocaleDateString('es-ES'),
      String(score),
      letter
    ]);

    autoTable(doc, {
      startY: currentY,
      head: [['Auditoría Realizada', 'Fecha', 'Puntaje', 'Clase']],
      body: historyRows,
      theme: 'grid',
      headStyles: { fillColor: [15, 23, 42], fontSize: 9 },
      styles: { fontSize: 8 },
      margin: { left: 60, right: 60 }
    });

    currentY = (doc as any).lastAutoTable.finalY + 30;
  }

  // Título: Plan de Acción
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('4. Plan de Acción y Mejora', 60, currentY);
  currentY += 15;

  // Mapear findings para la tabla de remediación
  const remediationRows = findings.map(f => {
    let esfuerzo = 'Bajo';
    if (f.severity === 'critical' || f.severity === 'high') {
      esfuerzo = f.module === 'web' || f.module === 'port_scan' ? 'Alto' : 'Medio';
    } else if (f.severity === 'medium') {
      esfuerzo = 'Medio';
    }

    let plazo = 'Largo Plazo (30d)';
    if (f.severity === 'critical') plazo = 'Inmediato (24h)';
    else if (f.severity === 'high') plazo = 'Corto Plazo (72h)';
    else if (f.severity === 'medium') plazo = 'Medio Plazo (15d)';

    return [
      f.finding_id ?? 'AS-FIND',
      f.title,
      getSeverityLabel(f.severity),
      esfuerzo,
      plazo,
      f.recommendation ?? 'Ver detalle técnico.'
    ];
  });

  autoTable(doc, {
    startY: currentY,
    head: [['ID', 'Vulnerabilidad', 'Prioridad', 'Esfuerzo', 'Plazo Sugerido', 'Acción de Mitigación']],
    body: remediationRows,
    theme: 'striped',
    headStyles: { fillColor: [15, 23, 42], fontSize: 8, halign: 'center' },
    columnStyles: {
      0: { cellWidth: 50, fontStyle: 'bold' },
      1: { cellWidth: 100 },
      2: { cellWidth: 60, halign: 'center' },
      3: { cellWidth: 50, halign: 'center' },
      4: { cellWidth: 70, halign: 'center' },
      5: { cellWidth: 145 },
    },
    styles: { fontSize: 7.5 },
    margin: { left: 60, right: 60 }
  });

  // Footer
  doc.setFontSize(8);
  doc.setTextColor(148, 163, 184);
  doc.text(`Generado por AuditShield v1.0.0 — Página 3`, 60, height - 30);

  // ---------------------------------------------------------------------------
  // PÁGINAS 4+: DETALLES TÉCNICOS DE HALLAZGOS
  // ---------------------------------------------------------------------------
  doc.addPage();
  doc.setFillColor(248, 250, 252);
  doc.rect(0, 0, width, height, 'F');

  // Header decorativo
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, width, 50, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('AuditShield - Reporte de Auditoría de Ciberseguridad', 60, 30);
  doc.setFontSize(9);
  doc.setTextColor(148, 163, 184);
  doc.text(audit.target, width - 60 - doc.getTextWidth(audit.target), 30);

  currentY = 80;

  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('5. Hallazgos Técnicos Detallados', 60, currentY);
  currentY += 25;

  findings.forEach((finding, index) => {
    // Comprobar desbordamiento de página
    if (currentY > height - 150) {
      doc.addPage();
      doc.setFillColor(248, 250, 252);
      doc.rect(0, 0, width, height, 'F');

      doc.setFillColor(15, 23, 42);
      doc.rect(0, 0, width, 50, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(12);
      doc.setFont('helvetica', 'bold');
      doc.text('AuditShield - Reporte de Auditoría de Ciberseguridad', 60, 30);

      currentY = 80;
    }

    const startFindingY = currentY;
    const sevColor = getSeverityColor(finding.severity);

    // Caja contenedora
    doc.setFillColor(255, 255, 255);
    doc.setDrawColor(226, 232, 240);
    // Dibujamos caja base (calculamos altura aproximada antes de pintar texto largo)
    // Para simplificar, pintamos línea lateral de color
    doc.rect(60, currentY, 475, 5, 'F');
    doc.setFillColor(sevColor);
    doc.rect(60, currentY, 4, 110, 'F');

    // ID del Hallazgo y Severidad
    doc.setFontSize(8.5);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(129, 140, 248);
    doc.text(finding.finding_id ?? `AS-FIND-${index + 1}`, 75, currentY + 15);

    doc.setFillColor(sevColor);
    doc.rect(170, currentY + 6, 60, 12, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(7.5);
    doc.text(getSeverityLabel(finding.severity), 200, currentY + 14, { align: 'center' });

    if (finding.cvss_score) {
      doc.setFillColor(15, 23, 42);
      doc.rect(235, currentY + 6, 65, 12, 'F');
      doc.setTextColor(255, 255, 255);
      doc.text(`CVSS: ${finding.cvss_score.toFixed(1)}`, 267, currentY + 14, { align: 'center' });
    }

    // Título
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text(finding.title, 75, currentY + 34);

    // Descripción
    doc.setFontSize(8.5);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(100, 116, 139);
    doc.text('DESCRIPCIÓN:', 75, currentY + 48);
    
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    const splitDesc = doc.splitTextToSize(finding.description, 450);
    doc.text(splitDesc, 75, currentY + 58);

    let descOffset = splitDesc.length * 11;
    
    // Recomendación
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(100, 116, 139);
    doc.text('RECOMENDACIÓN:', 75, currentY + 68 + descOffset);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(4, 120, 87); // Greenish text
    const splitRec = doc.splitTextToSize(finding.recommendation ?? 'No hay recomendación disponible.', 450);
    doc.text(splitRec, 75, currentY + 78 + descOffset);

    let recOffset = splitRec.length * 11;

    // Evidencia si existe
    let evOffset = 0;
    if (finding.evidence) {
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(100, 116, 139);
      doc.text('EVIDENCIA / PRUEBA:', 75, currentY + 88 + descOffset + recOffset);

      doc.setFont('courier', 'normal');
      doc.setTextColor(71, 85, 105);
      doc.setFontSize(7.5);
      const splitEv = doc.splitTextToSize(finding.evidence, 450);
      doc.text(splitEv, 75, currentY + 98 + descOffset + recOffset);
      doc.setFont('helvetica', 'normal');
      evOffset = splitEv.length * 10 + 10;
    }

    // Dibujar borde inferior de la caja
    const cardHeight = 90 + descOffset + recOffset + evOffset;
    // Redibujar la línea lateral para ajustarse al tamaño dinámico
    doc.setFillColor(sevColor);
    doc.rect(60, startFindingY, 4, cardHeight, 'F');
    // Línea inferior separatoria
    doc.setDrawColor(226, 232, 240);
    doc.line(60, startFindingY + cardHeight, 535, startFindingY + cardHeight);

    currentY += cardHeight + 20;
  });

  // Convertir a Blob y retornar
  return doc.output('blob');
};
