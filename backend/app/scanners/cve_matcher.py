"""
Módulo CVE Matcher para AuditShield.
Correlaciona tecnologías y versiones detectadas con CVEs (Common Vulnerabilities and Exposures).
Usa la API oficial de la NVD (National Vulnerability Database) v2.0 con fallback local offline.
"""

import logging
import urllib.parse
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger(__name__)

# Base de datos local offline de vulnerabilidades comunes (para cuando la API de NVD no está disponible o falla)
OFFLINE_CVE_DATABASE = {
    "nginx": [
        {
            "version_range": "<1.25.4",
            "cve_id": "CVE-2024-24989",
            "cvss_score": 7.5,
            "description": "Vulnerabilidad en el módulo HTTP/3 de Nginx que permite denegación de servicio (DoS) a través de conexiones HTTP/3 maliciosas.",
            "impact": "Un atacante remoto puede colapsar el servidor Nginx (DoS) enviando peticiones HTTP/3 especialmente diseñadas.",
            "recommendation": "Actualizar Nginx a la versión 1.25.4 o superior, o desactivar HTTP/3 si no es crítico.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-24989"]
        },
        {
            "version_range": "<1.20.1",
            "cve_id": "CVE-2021-23017",
            "cvss_score": 8.1,
            "description": "Error de parseo en el resolvedor DNS de nginx que permite una corrupción de memoria de 1 byte al procesar respuestas DNS.",
            "impact": "Posible ejecución remota de código o caída del servidor nginx (DoS) si un atacante puede suplantar respuestas del servidor DNS.",
            "recommendation": "Actualizar Nginx a la versión 1.20.1, 1.21.0 o superior.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"]
        }
    ],
    "apache": [
        {
            "version_range": "<2.4.59",
            "cve_id": "CVE-2024-27316",
            "cvss_score": 7.5,
            "description": "Vulnerabilidad de denegación de servicio HTTP/2 (petición de reset ilimitada) en Apache HTTP Server.",
            "impact": "Agotamiento de memoria y recursos de CPU en el servidor web (DoS).",
            "recommendation": "Actualizar Apache HTTP Server a la versión 2.4.59 o superior.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-27316"]
        },
        {
            "version_range": "<2.4.52",
            "cve_id": "CVE-2021-44790",
            "cvss_score": 9.8,
            "description": "Desbordamiento de búfer en el analizador de peticiones multipart en mod_lua en Apache HTTP Server.",
            "impact": "Ejecución remota de código (RCE) con privilegios del proceso del servidor web.",
            "recommendation": "Actualizar Apache HTTP Server a la versión 2.4.52 o superior.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44790"]
        }
    ],
    "openssl": [
        {
            "version_range": "3.0.0-3.0.6",
            "cve_id": "CVE-2022-3786",
            "cvss_score": 7.5,
            "description": "Desbordamiento de búfer de lectura en la verificación de direcciones de correo electrónico en OpenSSL.",
            "impact": "Denegación de servicio (DoS) o posible corrupción de memoria.",
            "recommendation": "Actualizar OpenSSL a la versión 3.0.7 o superior.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-3786"]
        },
        {
            "version_range": "1.0.1-1.0.1f",
            "cve_id": "CVE-2014-0160",
            "cvss_score": 7.5,
            "description": "Vulnerabilidad Heartbleed. Fuga de información sensible de la memoria del proceso a través de paquetes Heartbeat maliciosos.",
            "impact": "Lectura no autorizada de la memoria del servidor que podría revelar llaves privadas SSL, tokens de sesión o contraseñas.",
            "recommendation": "Actualizar OpenSSL a la versión 1.0.1g o superior y revocar las llaves SSL anteriores.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160", "http://heartbleed.com"]
        }
    ],
    "php": [
        {
            "version_range": "<8.1.29 || <8.2.20 || <8.3.8",
            "cve_id": "CVE-2024-4577",
            "cvss_score": 9.8,
            "description": "Vulnerabilidad de omisión de escape de argumentos en PHP CGI ejecutándose en sistemas Windows con configuraciones de caracteres locales específicas.",
            "impact": "Ejecución de código remota (RCE) de forma trivial en sistemas Windows.",
            "recommendation": "Actualizar PHP a las versiones oficiales 8.1.29, 8.2.20, 8.3.8 o superior.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-4577"]
        },
        {
            "version_range": "<7.4.21",
            "cve_id": "CVE-2021-21703",
            "cvss_score": 9.8,
            "description": "Inyección de variables en PHP-FPM que puede conducir a la corrupción de memoria y ejecución remota de código.",
            "impact": "Ejecución de código remota con los privilegios de PHP-FPM.",
            "recommendation": "Actualizar PHP a la versión 7.4.21 o superior.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-21703"]
        }
    ],
    "wordpress": [
        {
            "version_range": "<6.4.3",
            "cve_id": "CVE-2024-25600",
            "cvss_score": 9.8,
            "description": "Inyección SQL remota en la API REST de WordPress para ciertos plugins/configuraciones.",
            "impact": "Lectura no autorizada de base de datos, robo de contraseñas de administradores.",
            "recommendation": "Actualizar WordPress a la versión core 6.4.3 o superior.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-25600"]
        }
    ],
    "mysql": [
        {
            "version_range": "<8.0.28",
            "cve_id": "CVE-2022-21245",
            "cvss_score": 8.8,
            "description": "Vulnerabilidad en el componente MySQL Server (Optimizer) que permite a atacantes con privilegios altos provocar la caída del servicio.",
            "impact": "Denegación de servicio (DoS) del motor de base de datos.",
            "recommendation": "Actualizar MySQL Server a la versión 8.0.28 o posterior.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-21245"]
        }
    ]
}


def calculate_cvss_severity(score: float) -> str:
    """Clasifica un score de CVSS en una severidad estándar."""
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score >= 0.1:
        return "low"
    else:
        return "info"


def _compare_versions(detected_ver: str, rule: str) -> bool:
    """
    Compara de manera simplificada la versión detectada con la regla.
    Soporta formatos '<1.2.3', '1.0.1-1.0.1f', etc.
    """
    try:
        # Limpieza básica
        d_ver = detected_ver.strip().lower()
        rule = rule.strip().lower()

        # Caso Rango: 1.0.1-1.0.1f
        if "-" in rule:
            start, end = rule.split("-")
            return start <= d_ver <= end

        # Caso Menor que: <1.25.4
        if rule.startswith("<"):
            ver_lim = rule.replace("<", "").strip()
            # Split por puntos para comparación numérica si es posible
            d_parts = [int(p) for p in d_ver.split(".") if p.isdigit()]
            l_parts = [int(p) for p in ver_lim.split(".") if p.isdigit()]
            return d_parts < l_parts

        # Si hay reglas múltiples como ||
        if "||" in rule:
            parts = rule.split("||")
            return any(_compare_versions(detected_ver, p) for p in parts)

    except Exception:
        # Fallback si falla el parseo
        return detected_ver in rule or rule in detected_ver
    
    return False


def match_offline_cves(tech_name: str, version: str) -> List[Dict[str, Any]]:
    """Busca CVEs en la base de datos offline local."""
    findings = []
    tech_clean = tech_name.strip().lower()
    
    # Buscar coincidencia aproximada de tecnología
    matched_tech = None
    for key in OFFLINE_CVE_DATABASE.keys():
        if key in tech_clean or tech_clean in key:
            matched_tech = key
            break
            
    if matched_tech and version:
        rules = OFFLINE_CVE_DATABASE[matched_tech]
        for rule in rules:
            if _compare_versions(version, rule["version_range"]):
                severity = calculate_cvss_severity(rule["cvss_score"])
                findings.append({
                    "severity": severity,
                    "title": f"Vulnerabilidad conocida en {tech_name.upper()} {version}: {rule['cve_id']}",
                    "description": rule["description"],
                    "evidence": f"Tecnología: {tech_name}\nVersión detectada: {version}\nCVE Asociado: {rule['cve_id']}\nCVSS Score: {rule['cvss_score']}",
                    "impact": rule["impact"],
                    "recommendation": rule["recommendation"],
                    "references": rule["references"],
                    "cvss_score": rule["cvss_score"],
                    "cve_id": rule["cve_id"],
                    "module": "cve_matching"
                })
    return findings


async def query_nvd_api(tech_name: str, version: str, api_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """Consulta la API v2.0 de la NVD para buscar CVEs."""
    findings = []
    
    # Si no hay versión o está muy genérico, la búsqueda es ineficiente y puede bloquear la API.
    if not version or len(version) < 2:
        return findings

    # Query keywords
    keyword = f"{tech_name} {version}"
    encoded_keyword = urllib.parse.quote(keyword)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_keyword}"
    
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
        
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                # Limitamos a 5 resultados para no sobrecargar el reporte
                for item in vulnerabilities[:5]:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id")
                    descriptions = cve.get("descriptions", [])
                    description = next((d.get("value") for d in descriptions if d.get("lang") == "es"), None)
                    if not description:
                        description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "Sin descripción disponible.")
                    
                    # CVSS metrics
                    metrics = cve.get("metrics", {})
                    cvss_score = 0.0
                    cvss_vector = ""
                    
                    # Intentar buscar CVSS v3.1 o v3.0, luego v2.0
                    cvss_data = None
                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    elif "cvssMetricV30" in metrics:
                        cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                    elif "cvssMetricV2" in metrics:
                        cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                        
                    if cvss_data:
                        cvss_score = cvss_data.get("baseScore", 0.0)
                        cvss_vector = cvss_data.get("vectorString", "")
                        
                    severity = calculate_cvss_severity(cvss_score)
                    
                    findings.append({
                        "severity": severity,
                        "title": f"Vulnerabilidad en {tech_name.upper()} {version}: {cve_id}",
                        "description": description,
                        "evidence": f"Tecnología: {tech_name}\nVersión detectada: {version}\nCVE: {cve_id}\nCVSS Score: {cvss_score}\nVector: {cvss_vector}",
                        "impact": "Un atacante podría explotar esta vulnerabilidad para comprometer la confidencialidad, integridad o disponibilidad de la aplicación.",
                        "recommendation": f"Actualice la tecnología {tech_name} a una versión segura no vulnerable.",
                        "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "cve_id": cve_id,
                        "module": "cve_matching"
                    })
            else:
                logger.warning(f"Error consultando NVD API: status_code={response.status_code}")
    except Exception as e:
        logger.error(f"Excepción al conectar con NVD API: {e}")
        
    return findings


async def run_cve_scan(technologies: List[Dict[str, str]], nvd_api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Recibe una lista de tecnologías detectadas, por ejemplo:
    [{'name': 'nginx', 'version': '1.18.0'}, {'name': 'php', 'version': '7.4.3'}]
    Retorna un diccionario con los hallazgos.
    """
    logger.info(f"Iniciando correlación de CVEs para {len(technologies)} tecnologías detectadas")
    findings = []
    
    for tech in technologies:
        name = tech.get("name", "")
        version = tech.get("version", "")
        if not name:
            continue
            
        # 1. Intentar offline matcher local
        offline_findings = match_offline_cves(name, version)
        findings.extend(offline_findings)
        
        # 2. Si no hubo hallazgos locales, intentar online (si la API de NVD está disponible y hay versión)
        if not offline_findings and version:
            online_findings = await query_nvd_api(name, version, nvd_api_key)
            findings.extend(online_findings)

    # Si se corrió pero no se encontró nada
    if not findings:
        findings.append({
            "severity": "info",
            "title": "Sin vulnerabilidades CVE críticas identificadas",
            "description": "No se encontraron CVEs críticos coincidentes en la base de datos local ni en la API de NVD para las tecnologías y versiones detectadas.",
            "evidence": f"Tecnologías analizadas:\n" + "\n".join([f"- {t.get('name')} (versión: {t.get('version', 'unknown')})" for t in technologies]),
            "impact": "Bajo nivel de vulnerabilidades conocidas públicamente para este stack.",
            "recommendation": "Mantener actualizado el inventario de software y realizar escaneos periódicos.",
            "references": [],
            "module": "cve_matching"
        })

    return {
        "status": "completed",
        "data": {
            "technologies_scanned": technologies,
            "total_findings": len(findings)
        },
        "findings": findings
    }
