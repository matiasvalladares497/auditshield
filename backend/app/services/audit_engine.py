"""
Motor de Auditoría Central - AuditShield
Calcula scores de seguridad y coordina el flujo de auditoría.
"""
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

# Pesos de severidad para el cálculo del score
SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}

# Configuración de perfiles de escaneo predefinidos
SCAN_PROFILES = {
    "basic": {
        "osint": True,
        "ssl": True,
        "web": True,
        "dns": True,
        "port_scan": False,
        "email_security": True,
        "info_exposure": True,
        "cve_matching": False,
        "waf_detection": False,
        "compliance": False,
    },
    "web": {
        "osint": True,
        "ssl": True,
        "web": True,
        "dns": True,
        "port_scan": False,
        "email_security": True,
        "info_exposure": True,
        "cve_matching": True,
        "waf_detection": True,
        "compliance": True,
    },
    "infrastructure": {
        "osint": True,
        "ssl": True,
        "web": False,
        "dns": True,
        "port_scan": True,
        "email_security": True,
        "info_exposure": False,
        "cve_matching": True,
        "waf_detection": False,
        "compliance": True,
    },
    "full": {
        "osint": True,
        "ssl": True,
        "web": True,
        "dns": True,
        "port_scan": True,
        "email_security": True,
        "info_exposure": True,
        "cve_matching": True,
        "waf_detection": True,
        "compliance": True,
    },
    "email_dns": {
        "osint": True,
        "ssl": False,
        "web": False,
        "dns": True,
        "port_scan": False,
        "email_security": True,
        "info_exposure": False,
        "cve_matching": False,
        "waf_detection": False,
        "compliance": False,
    },
    "osint_leak": {
        "osint": True,
        "ssl": False,
        "web": False,
        "dns": True,
        "port_scan": False,
        "email_security": False,
        "info_exposure": True,
        "cve_matching": False,
        "waf_detection": False,
        "compliance": False,
    },
    "compliance_chk": {
        "osint": True,
        "ssl": True,
        "web": True,
        "dns": True,
        "port_scan": False,
        "email_security": True,
        "info_exposure": True,
        "cve_matching": True,
        "waf_detection": False,
        "compliance": True,
    },
    "lan_internal": {
        "osint": False,
        "ssl": True,
        "web": False,
        "dns": False,
        "port_scan": True,
        "email_security": False,
        "info_exposure": False,
        "cve_matching": True,
        "waf_detection": False,
        "compliance": False,
    },
}


def calculate_security_score(findings: List[Dict]) -> float:
    """
    Calcula el score de seguridad (0-100) basado en los hallazgos.
    Empieza en 100 y descuenta por cada hallazgo según su severidad.
    """
    score = 100.0
    penalty_cap = {
        "critical": 80,  # máximo descuento por criticals
        "high": 50,
        "medium": 30,
        "low": 15,
    }
    penalties = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for finding in findings:
        severity = finding.get("severity", "info").lower()
        weight = SEVERITY_WEIGHTS.get(severity, 0)
        penalties[severity] = min(penalties.get(severity, 0) + weight, penalty_cap.get(severity, 100))

    total_penalty = sum(penalties.values())
    score = max(0.0, min(100.0, score - total_penalty))
    return round(score, 1)


def get_score_letter(score: float) -> str:
    """Convierte el score numérico en letra de clasificación."""
    if score >= 90:
        return "A+"
    elif score >= 80:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 50:
        return "D"
    else:
        return "F"


def get_score_color(score: float) -> str:
    """Retorna color hex para el score (para reportes PDF)."""
    if score >= 80:
        return "#10B981"  # verde
    elif score >= 60:
        return "#F59E0B"  # amarillo
    elif score >= 40:
        return "#F97316"  # naranja
    else:
        return "#EF4444"  # rojo


def create_finding_id(audit_id: int, index: int) -> str:
    """Genera un ID único para cada hallazgo: AS-{AUDIT_ID}-{INDEX:03d}"""
    return f"AS-{audit_id:04d}-{index:03d}"


def summarize_findings(findings: List[Dict]) -> Dict:
    """Cuenta hallazgos por severidad."""
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    for finding in findings:
        sev = finding.get("severity", "info").lower()
        if sev in summary:
            summary[sev] += 1
        summary["total"] += 1
    return summary


def get_modules_for_profile(profile: str) -> Dict:
    """Retorna la configuración de módulos para un perfil dado."""
    return SCAN_PROFILES.get(profile, SCAN_PROFILES["full"])


def prioritize_findings(findings: List[Dict]) -> List[Dict]:
    """Ordena hallazgos por severidad (critical primero)."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda f: severity_order.get(f.get("severity", "info").lower(), 5))


def get_remediation_priority(findings: List[Dict]) -> List[Dict]:
    """
    Clasifica hallazgos en quick wins y largo plazo.
    Quick wins: Low/Medium sin dependencias complejas.
    Largo plazo: Critical/High que requieren cambios arquitectónicos.
    """
    quick_wins = []
    long_term = []

    for finding in findings:
        severity = finding.get("severity", "info").lower()
        if severity in ["low", "medium"]:
            quick_wins.append(finding)
        elif severity in ["critical", "high"]:
            long_term.append(finding)

    return {"quick_wins": quick_wins, "long_term": long_term}
