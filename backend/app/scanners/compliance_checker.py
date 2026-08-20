"""
Módulo Compliance Checker para AuditShield.
Evalúa los hallazgos consolidados contra estándares internacionales:
- OWASP ASVS (Application Security Verification Standard) Nivel 1
- ISO 27001 (Controles seleccionados)
- NIST Cybersecurity Framework (CSF)
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _build_finding(
    severity: str,
    title: str,
    description: str,
    evidence: str = "",
    impact: str = "",
    recommendation: str = "",
    references: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation,
        "references": references or [],
    }


def run_compliance_scan(target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Evalúa el cumplimiento de controles basado en los findings de seguridad del escaneo.
    """
    logger.info(f"Evaluando cumplimiento de normas para {target} basado en {len(findings)} hallazgos")
    
    # 1. Definir controles
    # OWASP ASVS Nivel 1
    asvs_controls = {
        "V1. Architecture": {"desc": "Arquitectura segura y superficie de ataque minimizada", "passed": True, "detail": "Superficie de puertos minimizada."},
        "V2. Authentication": {"desc": "Políticas seguras de contraseñas y logins", "passed": True, "detail": "Sin formularios vulnerables expuestos."},
        "V3. Session Management": {"desc": "Sesiones seguras y atributos HttpOnly/Secure", "passed": True, "detail": "Cookies configuradas correctamente."},
        "V6. Cryptography": {"desc": "Protocolos SSL/TLS seguros y cipher suites fuertes", "passed": True, "detail": "Cifrado TLS configurado de forma óptima."},
        "V14. Configuration": {"desc": "Cabeceras de seguridad HTTP y hardening", "passed": True, "detail": "Cabeceras de seguridad e interfaces limpias."}
    }

    # ISO 27001:2022
    iso_controls = {
        "A.5.15 Access control": {"desc": "Políticas de control de acceso en puertos y SSH", "passed": True, "detail": "Sin puertos de administración críticos expuestos."},
        "A.8.12 Data leakage prevention": {"desc": "Protección contra fuga de archivos sensibles (.env, copias)", "passed": True, "detail": "Sin exposición de archivos sensibles detectada."},
        "A.8.24 Use of cryptography": {"desc": "Uso correcto de criptografía (HTTPS y TLS)", "passed": True, "detail": "TLS y HTTPS habilitados correctamente."},
        "A.8.20 Network security": {"desc": "Seguridad en comunicaciones y registros SPF/DMARC", "passed": True, "detail": "Políticas de correo SPF/DMARC habilitadas."}
    }

    # NIST CSF v1.1
    nist_controls = {
        "PR.AC-4 Access Control": {"desc": "Acceso restringido en puertos y servicios peligrosos", "passed": True, "detail": "Servicios obsoletos (telnet/ftp) cerrados."},
        "PR.DS-1 Data at Rest/Transit": {"desc": "Cifrado en tránsito (SSL/TLS)", "passed": True, "detail": "Protocolos HTTPS obligatorios habilitados."},
        "PR.DS-2 Data Loss Prevention": {"desc": "Prevención de fuga de información técnica (.env, git)", "passed": True, "detail": "Sin archivos de desarrollo expuestos."},
        "PR.IP-1 Baseline Configuration": {"desc": "Hardening y cabeceras de seguridad HTTP", "passed": True, "detail": "Configuración HTTP sin misconfigs críticas."}
    }

    # 2. Mapear hallazgos a fallos de control
    for f in findings:
        title_lower = f.get("title", "").lower()
        module = f.get("module", "").lower()
        severity = f.get("severity", "info").lower()
        
        # Ignorar hallazgos puramente informativos
        if severity == "info":
            continue

        # Evitar fallos falsificados si es Falso Positivo
        if f.get("is_false_positive"):
            continue

        # Fallos SSL/TLS
        if "ssl" in title_lower or module == "ssl":
            asvs_controls["V6. Cryptography"]["passed"] = False
            asvs_controls["V6. Cryptography"]["detail"] = f"Falla por: {f.get('title')}"
            iso_controls["A.8.24 Use of cryptography"]["passed"] = False
            iso_controls["A.8.24 Use of cryptography"]["detail"] = f"Falla por: {f.get('title')}"
            nist_controls["PR.DS-1 Data at Transit"]["passed"] = False
            nist_controls["PR.DS-1 Data at Transit"]["detail"] = f"Falla por: {f.get('title')}"

        # Fallos de archivos expuestos (fuga de información)
        if "expuesto" in title_lower or "exposición" in title_lower or "sensitive" in title_lower or "error" in title_lower:
            asvs_controls["V14. Configuration"]["passed"] = False
            asvs_controls["V14. Configuration"]["detail"] = f"Falla por: {f.get('title')}"
            iso_controls["A.8.12 Data leakage prevention"]["passed"] = False
            iso_controls["A.8.12 Data leakage prevention"]["detail"] = f"Falla por: {f.get('title')}"
            nist_controls["PR.DS-2 Data Loss Prevention"]["passed"] = False
            nist_controls["PR.DS-2 Data Loss Prevention"]["detail"] = f"Falla por: {f.get('title')}"

        # Fallos de cabeceras de seguridad
        if "cabecera" in title_lower or "header" in title_lower or "csp" in title_lower or "x-frame" in title_lower:
            asvs_controls["V14. Configuration"]["passed"] = False
            asvs_controls["V14. Configuration"]["detail"] = f"Falla por: {f.get('title')}"
            nist_controls["PR.IP-1 Baseline Configuration"]["passed"] = False
            nist_controls["PR.IP-1 Baseline Configuration"]["detail"] = f"Falla por: {f.get('title')}"

        # Fallos de cookies (Session Management)
        if "cookie" in title_lower:
            asvs_controls["V3. Session Management"]["passed"] = False
            asvs_controls["V3. Session Management"]["detail"] = f"Falla por: {f.get('title')}"

        # Fallos de puertos / servicios expuestos
        if "servicio peligroso" in title_lower or "puerto" in title_lower:
            asvs_controls["V1. Architecture"]["passed"] = False
            asvs_controls["V1. Architecture"]["detail"] = f"Falla por: {f.get('title')}"
            iso_controls["A.5.15 Access control"]["passed"] = False
            iso_controls["A.5.15 Access control"]["detail"] = f"Falla por: {f.get('title')}"
            nist_controls["PR.AC-4 Access Control"]["passed"] = False
            nist_controls["PR.AC-4 Access Control"]["detail"] = f"Falla por: {f.get('title')}"

        # Fallos SPF/DKIM/DMARC
        if "spf" in title_lower or "dmarc" in title_lower or "dkim" in title_lower or "dns" in title_lower:
            iso_controls["A.8.20 Network security"]["passed"] = False
            iso_controls["A.8.20 Network security"]["detail"] = f"Falla por: {f.get('title')}"

    # 3. Calcular porcentajes
    asvs_passed = sum(1 for c in asvs_controls.values() if c["passed"])
    iso_passed = sum(1 for c in iso_controls.values() if c["passed"])
    nist_passed = sum(1 for c in nist_controls.values() if c["passed"])

    asvs_pct = round((asvs_passed / len(asvs_controls)) * 100)
    iso_pct = round((iso_passed / len(iso_controls)) * 100)
    nist_pct = round((nist_passed / len(nist_controls)) * 100)

    # 4. Formatear evidencia
    evidence_parts = []
    
    evidence_parts.append("=========================================")
    evidence_parts.append("   EVALUACIÓN DE CUMPLIMIENTO NORMATIVO  ")
    evidence_parts.append("=========================================")
    evidence_parts.append(f"OWASP ASVS Nivel 1: {asvs_pct}% de cumplimiento ({asvs_passed}/{len(asvs_controls)} controles)")
    for k, c in asvs_controls.items():
        status = "[PASSED]" if c["passed"] else "[FAILED]"
        evidence_parts.append(f" - {status} {k}: {c['desc']}\n   Detalle: {c['detail']}")
        
    evidence_parts.append("\nISO 27001:2022: {0}% de cumplimiento ({1}/{2} controles)".format(iso_pct, iso_passed, len(iso_controls)))
    for k, c in iso_controls.items():
        status = "[PASSED]" if c["passed"] else "[FAILED]"
        evidence_parts.append(f" - {status} {k}: {c['desc']}\n   Detalle: {c['detail']}")
        
    evidence_parts.append("\nNIST CSF v1.1: {0}% de cumplimiento ({1}/{2} controles)".format(nist_pct, nist_passed, len(nist_controls)))
    for k, c in nist_controls.items():
        status = "[PASSED]" if c["passed"] else "[FAILED]"
        evidence_parts.append(f" - {status} {k}: {c['desc']}\n   Detalle: {c['detail']}")

    evidence = "\n".join(evidence_parts)

    compliance_findings = []
    
    # Agregar un finding general con el resumen de cumplimiento
    avg_pct = round((asvs_pct + iso_pct + nist_pct) / 3)
    severity = "Info" if avg_pct >= 90 else "Low" if avg_pct >= 75 else "Medium"
    
    recommendation = (
        "1. Priorice la corrección de los hallazgos técnicos que causan fallos de controles en ASVS/ISO/NIST.\n"
        "2. Vuelva a ejecutar la auditoría tras aplicar las soluciones para validar de inmediato el aumento en la tasa de cumplimiento."
    )

    compliance_findings.append(_build_finding(
        severity=severity,
        title=f"Resumen de Cumplimiento Normativo (Tasa Media: {avg_pct}%)",
        description=(
            "Se evaluó la postura de ciberseguridad del activo frente a los estándares internacionales "
            "OWASP ASVS Nivel 1, ISO 27001 y NIST CSF. Cada vulnerabilidad técnica detectada en los demás módulos "
            "provoca la caída de uno o más controles organizacionales."
        ),
        evidence=evidence,
        impact="El incumplimiento de estándares internacionales reduce la confianza de los clientes/usuarios e incrementa el riesgo de incidentes de seguridad críticos.",
        recommendation=recommendation,
        references=[
            "https://owasp.org/www-project-application-security-verification-standard/",
            "https://www.iso.org/standard/27001",
            "https://www.nist.gov/cyberframework"
        ]
    ))

    return {
        "status": "completed",
        "data": {
            "asvs_percentage": asvs_pct,
            "iso_percentage": iso_pct,
            "nist_percentage": nist_pct,
            "average_percentage": avg_pct,
            "asvs_controls": asvs_controls,
            "iso_controls": iso_controls,
            "nist_controls": nist_controls
        },
        "findings": compliance_findings
    }
