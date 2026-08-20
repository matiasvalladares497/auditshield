"""
Motor de Generación de Reportes PDF Profesionales - AuditShield
Genera reportes ejecutivos, técnicos y completos en PDF.
"""
import os
import json
import base64
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from io import BytesIO

logger = logging.getLogger(__name__)

REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "/reports"))
TEMPLATES_DIR = Path(os.getenv("TEMPLATES_DIR", "/reports/templates"))

SEVERITY_COLORS = {
    "critical": "#DC2626",
    "high": "#EA580C",
    "medium": "#D97706",
    "low": "#2563EB",
    "info": "#6B7280",
}

SEVERITY_LABELS_ES = {
    "critical": "Crítico",
    "high": "Alto",
    "medium": "Medio",
    "low": "Bajo",
    "info": "Informativo",
}

MODULE_NAMES_ES = {
    "osint": "Reconocimiento OSINT",
    "port_scan": "Escaneo de Puertos",
    "ssl": "SSL/TLS",
    "web": "Auditoría Web (OWASP)",
    "dns": "Seguridad DNS",
    "email_security": "Seguridad de Email",
    "info_exposure": "Exposición de Información",
    "cve_matching": "Vulnerabilidades CVE",
    "waf_detection": "Detección WAF",
    "compliance": "Cumplimiento Normativo",
}


def generate_donut_chart(summary: Dict) -> str:
    """Genera gráfico donut de distribución de vulnerabilidades. Retorna base64."""
    severities = ["critical", "high", "medium", "low", "info"]
    values = [summary.get(s, 0) for s in severities]
    colors = [SEVERITY_COLORS[s] for s in severities]
    labels = [f"{SEVERITY_LABELS_ES[s]}: {summary.get(s, 0)}" for s in severities]

    # Filtra ceros
    filtered = [(v, c, l) for v, c, l in zip(values, colors, labels) if v > 0]
    if not filtered:
        filtered = [(1, "#6B7280", "Sin hallazgos: 0")]

    values_f, colors_f, labels_f = zip(*filtered)

    fig, ax = plt.subplots(figsize=(6, 4), facecolor='#0F172A')
    ax.set_facecolor('#0F172A')
    wedges, texts = ax.pie(
        values_f,
        colors=colors_f,
        startangle=90,
        wedgeprops=dict(width=0.5, edgecolor='#1E293B', linewidth=2),
    )
    ax.legend(
        wedges,
        labels_f,
        loc="center left",
        bbox_to_anchor=(1, 0, 0.5, 1),
        fontsize=8,
        labelcolor='white',
        facecolor='#1E293B',
        edgecolor='#334155',
    )
    plt.tight_layout()

    buf = BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=150, facecolor='#0F172A')
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


def generate_score_gauge(score: float, letter: str) -> str:
    """Genera gráfico gauge del score de seguridad. Retorna base64."""
    fig, ax = plt.subplots(figsize=(5, 3), facecolor='#0F172A')
    ax.set_facecolor('#0F172A')

    # Colores del gauge
    if score >= 80:
        color = "#10B981"
    elif score >= 60:
        color = "#F59E0B"
    elif score >= 40:
        color = "#F97316"
    else:
        color = "#EF4444"

    # Semicírculo de fondo
    theta = [i for i in range(0, 181)]
    bg_x = [0.5 + 0.4 * __import__('math').cos(__import__('math').radians(t)) for t in theta]
    bg_y = [0.2 + 0.4 * __import__('math').sin(__import__('math').radians(t)) for t in theta]

    # Score arc
    score_angle = int(score * 1.8)  # 0-100 → 0-180 degrees
    score_theta = [i for i in range(0, score_angle + 1)]
    sc_x = [0.5 + 0.38 * __import__('math').cos(__import__('math').radians(t)) for t in score_theta]
    sc_y = [0.2 + 0.38 * __import__('math').sin(__import__('math').radians(t)) for t in score_theta]

    ax.plot(bg_x, bg_y, color='#334155', linewidth=20, solid_capstyle='round')
    ax.plot(sc_x, sc_y, color=color, linewidth=18, solid_capstyle='round')

    ax.text(0.5, 0.35, f"{score:.0f}", fontsize=32, fontweight='bold',
            color=color, ha='center', va='center', transform=ax.transAxes)
    ax.text(0.5, 0.12, f"Score: {letter}", fontsize=14, color='white',
            ha='center', va='center', transform=ax.transAxes)
    ax.text(0.5, 0.0, "Seguridad Global", fontsize=9, color='#94A3B8',
            ha='center', va='center', transform=ax.transAxes)

    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off')
    plt.tight_layout()

    buf = BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=150, facecolor='#0F172A')
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


def generate_bar_chart(findings_by_module: Dict) -> str:
    """Gráfico de barras de hallazgos por módulo. Retorna base64."""
    modules = list(findings_by_module.keys())
    counts = list(findings_by_module.values())
    labels = [MODULE_NAMES_ES.get(m, m)[:20] for m in modules]

    fig, ax = plt.subplots(figsize=(8, 4), facecolor='#0F172A')
    ax.set_facecolor('#1E293B')
    bars = ax.barh(labels, counts, color='#6366F1', edgecolor='#818CF8', linewidth=0.5)

    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                str(count), va='center', fontsize=8, color='white')

    ax.set_xlabel('Hallazgos', color='#94A3B8')
    ax.tick_params(colors='#94A3B8', labelsize=7)
    ax.spines['bottom'].set_color('#334155')
    ax.spines['left'].set_color('#334155')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout()

    buf = BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=150, facecolor='#0F172A')
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


def generate_history_chart(history_data: List[Dict]) -> str:
    """Genera gráfico de línea de evolución de score de seguridad. Retorna base64."""
    if len(history_data) < 2:
        return ""
    
    dates = []
    scores = []
    for item in history_data:
        dt_str = item.get("completed_at")
        if dt_str:
            try:
                dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
                dates.append(dt.strftime("%d/%m/%y"))
            except Exception:
                dates.append(str(dt_str)[:10])
        else:
            dates.append("N/A")
        scores.append(item.get("security_score", 0) or 0)
        
    fig, ax = plt.subplots(figsize=(6, 2.2), facecolor='#0F172A')
    ax.set_facecolor('#1E293B')
    
    ax.plot(dates, scores, color='#6366F1', marker='o', linewidth=2.5, markersize=5, label="Score")
    ax.fill_between(dates, scores, color='#6366F1', alpha=0.15)
    
    for i, score in enumerate(scores):
        ax.text(dates[i], score + 4, f"{score:.0f}", color='white', ha='center', va='bottom', fontsize=8, fontweight='bold')
        
    ax.set_ylim(0, 115)
    ax.spines['bottom'].set_color('#334155')
    ax.spines['left'].set_color('#334155')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.tick_params(colors='#94A3B8', labelsize=8)
    ax.grid(True, linestyle='--', alpha=0.1, color='#94A3B8')
    plt.tight_layout()
    
    buf = BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=150, facecolor='#0F172A')
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


def prepare_report_context(
    audit_data: Dict, 
    findings: List[Dict], 
    report_type: str,
    previous_audits: Optional[List[Dict]] = None
) -> Dict:
    """Prepara el contexto completo para el template Jinja2."""
    summary = audit_data.get("summary", {}) or {}
    score = audit_data.get("security_score", 0) or 0
    letter = audit_data.get("score_letter", "F") or "F"

    # Organizar findings por módulo
    findings_by_module = {}
    for f in findings:
        mod = f.get("module", "other")
        if mod not in findings_by_module:
            findings_by_module[mod] = []
        findings_by_module[mod].append(f)

    # Findings por módulo (conteo para gráfico)
    module_counts = {mod: len(flist) for mod, flist in findings_by_module.items()}

    # Generar gráficos
    donut_chart = generate_donut_chart(summary)
    gauge_chart = generate_score_gauge(score, letter)
    bar_chart = generate_bar_chart(module_counts) if module_counts else None

    # Top 5 críticos
    critical_findings = [f for f in findings if f.get("severity") == "critical"][:5]
    high_findings = [f for f in findings if f.get("severity") == "high"][:10]

    # Calcular duración del escaneo
    started = audit_data.get("started_at")
    completed = audit_data.get("completed_at")
    duration = "N/A"
    if started and completed:
        if isinstance(started, str):
            try:
                started = datetime.fromisoformat(started.replace("Z", "+00:00"))
            except Exception:
                pass
        if isinstance(completed, str):
            try:
                completed = datetime.fromisoformat(completed.replace("Z", "+00:00"))
            except Exception:
                pass
        if isinstance(started, datetime) and isinstance(completed, datetime):
            delta = completed - started
            mins = int(delta.total_seconds() // 60)
            secs = int(delta.total_seconds() % 60)
            duration = f"{mins}m {secs}s"

    # Matriz de Riesgo 3x3
    matrix_counts = {
        "alto_alta": sum(1 for f in findings if f.get("severity") == "critical"),
        "alto_media": 0,
        "alto_baja": 0,
        "medio_alta": sum(1 for f in findings if f.get("severity") == "high"),
        "medio_media": sum(1 for f in findings if f.get("severity") == "medium"),
        "medio_baja": sum(1 for f in findings if f.get("severity") == "low"),
        "bajo_alta": 0,
        "bajo_media": 0,
        "bajo_baja": sum(1 for f in findings if f.get("severity") == "info"),
    }

    # Plan de Remediación Priorizado
    remediation_findings = []
    for f in findings:
        sev = f.get("severity", "info").lower()
        mod = f.get("module", "other")
        
        if sev in ["critical", "high"]:
            effort = "Alto" if mod in ["web", "port_scan"] else "Medio"
        elif sev == "medium":
            effort = "Medio"
        else:
            effort = "Bajo"

        if sev == "critical":
            plazo = "Inmediato (< 24 horas)"
            priority_label = "Urgente"
        elif sev == "high":
            plazo = "Corto Plazo (< 72 horas)"
            priority_label = "Alta"
        elif sev == "medium":
            plazo = "Medio Plazo (< 15 días)"
            priority_label = "Media"
        else:
            plazo = "Largo Plazo (< 30 días)"
            priority_label = "Baja"
            
        remediation_findings.append({
            **f,
            "remediation_priority": priority_label,
            "remediation_effort": effort,
            "remediation_deadline": plazo
        })

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    remediation_findings.sort(key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5))

    # Historial y Comparativa de Auditorías
    history_chart = None
    has_history = False
    improvement_banner = None
    last_audit_data = None
    
    if previous_audits and len(previous_audits) > 0:
        has_history = True
        history_list = list(previous_audits)
        history_list.sort(key=lambda x: x.get("completed_at") or "")
        
        last_audit_data = history_list[-1]
        last_score = last_audit_data.get("security_score", 0) or 0
        diff = score - last_score
        
        if diff > 0:
            improvement_banner = {
                "status": "improved",
                "text": f"¡La postura de seguridad ha MEJORADO en {diff:.0f} puntos!",
                "diff": f"+{diff:.0f}",
                "color": "#10B981"
            }
        elif diff == 0:
            improvement_banner = {
                "status": "same",
                "text": "La postura de seguridad se mantiene igual respecto al escaneo anterior.",
                "diff": "0",
                "color": "#F59E0B"
            }
        else:
            improvement_banner = {
                "status": "worsened",
                "text": f"¡Atención! La postura de seguridad ha EMPEORADO en {abs(diff):.0f} puntos.",
                "diff": f"-{abs(diff):.0f}",
                "color": "#EF4444"
            }
            
        full_history = history_list + [{
            "security_score": score,
            "completed_at": audit_data.get("completed_at")
        }]
        history_chart = generate_history_chart(full_history)

    return {
        "report_type": report_type,
        "report_type_label": {"executive": "Ejecutivo", "technical": "Técnico", "full": "Completo"}.get(report_type, "Completo"),
        "generated_at": datetime.now().strftime("%d de %B de %Y, %H:%M UTC"),
        "audit": audit_data,
        "target": audit_data.get("target", ""),
        "title": audit_data.get("title", ""),
        "score": score,
        "letter": letter,
        "summary": summary,
        "findings": findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "findings_by_module": findings_by_module,
        "module_counts": module_counts,
        "module_names": MODULE_NAMES_ES,
        "severity_colors": SEVERITY_COLORS,
        "severity_labels": SEVERITY_LABELS_ES,
        "donut_chart_b64": donut_chart,
        "gauge_chart_b64": gauge_chart,
        "bar_chart_b64": bar_chart,
        "duration": duration,
        "total_findings": sum(summary.values()) if summary else len(findings),
        "matrix_counts": matrix_counts,
        "remediation_findings": remediation_findings,
        "has_history": has_history,
        "last_audit": last_audit_data,
        "improvement_banner": improvement_banner,
        "history_chart_b64": history_chart,
    }


async def generate_pdf_report(
    audit_data: Dict,
    findings: List[Dict],
    report_type: str = "full",
    output_path: Optional[str] = None,
    previous_audits: Optional[List[Dict]] = None,
) -> str:
    """
    Genera el reporte PDF completo.
    Retorna la ruta del archivo PDF generado.
    """
    try:
        from weasyprint import HTML, CSS
        from weasyprint.text.fonts import FontConfiguration

        # Preparar contexto
        context = prepare_report_context(audit_data, findings, report_type, previous_audits)

        # Cargar template
        templates_path = TEMPLATES_DIR
        if not templates_path.exists():
            templates_path = Path(__file__).parent.parent.parent.parent / "reports" / "templates"

        env = Environment(
            loader=FileSystemLoader(str(templates_path), encoding="utf-8"),
            autoescape=select_autoescape(['html', 'xml'])
        )
        template = env.get_template("report_full.html")
        html_content = template.render(**context)

        # Definir ruta de salida
        if not output_path:
            REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            audit_id = audit_data.get("id", "0")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(REPORTS_DIR / f"report_{audit_id}_{report_type}_{timestamp}.pdf")

        # Generar PDF
        font_config = FontConfiguration()
        html = HTML(string=html_content, base_url=str(templates_path))
        html.write_pdf(output_path, font_config=font_config)

        logger.info(f"Reporte PDF generado: {output_path}")
        return output_path

    except ImportError:
        logger.warning("WeasyPrint no disponible. Generando HTML en su lugar.")
        # Fallback: guardar HTML
        output_path = output_path.replace(".pdf", ".html") if output_path else "/tmp/report.html"
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return output_path
    except Exception as e:
        logger.error(f"Error generando reporte: {e}")
        raise
