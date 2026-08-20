"""
Módulo WAF Detector para AuditShield.
Detecta la presencia de un Web Application Firewall (WAF) mediante análisis de cabeceras,
cookies y respuestas a payloads de prueba bloqueados.
"""

import logging
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger(__name__)

# Firmas comunes de WAF en cabeceras o cookies
WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server"],
        "cookies": ["__cfduid", "cf_clearance"],
        "name": "Cloudflare WAF"
    },
    "modsecurity": {
        "headers": ["x-frame-options", "server"],
        "name": "ModSecurity (OWASP CRS)"
    },
    "aws": {
        "headers": ["x-amz-id-2", "x-amz-request-id", "server"],
        "name": "AWS WAF"
    },
    "imperva": {
        "headers": ["x-iinfo", "x-cdn"],
        "cookies": ["visid_incap", "incap_ses"],
        "name": "Imperva Incapsula WAF"
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "name": "Sucuri WAF"
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "server"],
        "name": "Akamai Kona Site Defender"
    },
    "barracuda": {
        "headers": ["x-barra-cookie-info", "server"],
        "name": "Barracuda WAF"
    },
    "f5": {
        "headers": ["x-cray", "server"],
        "name": "F5 BIG-IP ASM"
    }
}


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


def _normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return f"http://{url}"
    return url


async def run_waf_scan(target: str) -> Dict[str, Any]:
    """
    Ejecuta el escaneo de detección de WAF.
    """
    url = _normalize_url(target)
    findings = []
    waf_detected = False
    waf_name = None
    evidence_list = []
    
    logger.info(f"Iniciando escaneo de WAF en: {url}")
    
    try:
        # 1. Petición estándar para analizar headers y cookies normales
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0 AuditShield WAF-Scan"})
            
            # Analizar firmas
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            cookies_lower = [c.name.lower() for c in client.cookies.jar]
            
            for key, sig in WAF_SIGNATURES.items():
                # Comprobar headers
                for h in sig.get("headers", []):
                    if h in headers_lower:
                        val = headers_lower[h]
                        if key in val or ("cloudflare" in val and key == "cloudflare") or ("sucuri" in val and key == "sucuri"):
                            waf_detected = True
                            waf_name = sig["name"]
                            evidence_list.append(f"Header detectado: {h}: {resp.headers.get(h)}")
                            break
                            
                # Comprobar cookies
                for c in sig.get("cookies", []):
                    if c in cookies_lower:
                        waf_detected = True
                        waf_name = sig["name"]
                        evidence_list.append(f"Cookie de WAF detectada: {c}")
                        break
                        
                if waf_detected:
                    break

        # 2. Petición agresiva con payload seguro de XSS para provocar al WAF
        # Si el WAF bloquea, usualmente retorna 403 Forbidden o 406 Not Acceptable
        provocation_url = f"{url}?test=<script>alert('auditshield_waf_test')</script>"
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                resp_block = await client.get(provocation_url)
                if resp_block.status_code in [403, 406, 999]:
                    waf_detected = True
                    evidence_list.append(
                        f"Bloqueo activo detectado. Petición con payload XSS retornó HTTP {resp_block.status_code}."
                    )
                    if not waf_name:
                        waf_name = "WAF Activo (Firma Desconocida / Bloqueo por código)"
        except Exception:
            pass

    except Exception as e:
        logger.error(f"Error detectando WAF para {url}: {e}")
        return {
            "status": "error",
            "error": str(e),
            "findings": []
        }

    if waf_detected:
        evidence = "\n".join(evidence_list)
        findings.append(_build_finding(
            severity="Info",
            title=f"Firewall de Aplicación Web (WAF) Detectado: {waf_name}",
            description=(
                f"Se detectó la presencia activa de un WAF ({waf_name}) protegiendo el sitio web. "
                "El WAF analiza el tráfico entrante y bloquea ataques web comunes como inyecciones SQL y XSS."
            ),
            evidence=evidence,
            impact="Reduce drásticamente la probabilidad de explotación de vulnerabilidades web de día cero y OWASP.",
            recommendation="Asegúrese de mantener las reglas del WAF actualizadas y no dependa únicamente de él para la seguridad (Defense in Depth).",
            references=["https://owasp.org/www-community/Web_Application_Firewall"]
        ))
    else:
        findings.append(_build_finding(
            severity="Medium",
            title="Sin Firewall de Aplicación Web (WAF) Detectado",
            description=(
                "No se pudo identificar un Firewall de Aplicación Web (WAF) protegiendo el objetivo. "
                "Los ataques web dirigidos llegarán directamente al servidor web backend."
            ),
            evidence="Petición con payload XSS no fue bloqueada (código HTTP retornado distinto de 403/406).",
            impact="La aplicación web está expuesta directamente a escaneos automáticos de vulnerabilidades y ataques distribuidos.",
            recommendation=(
                "Se recomienda implementar un WAF frente al servidor web. "
                "Opciones gratuitas o de bajo costo incluyen Cloudflare (plan gratuito), "
                "ModSecurity (Open Source) para servidores Apache/Nginx locales, o AWS WAF si está en la nube."
            ),
            references=["https://owasp.org/www-community/Web_Application_Firewall"]
        ))

    return {
        "status": "completed",
        "data": {
            "waf_detected": waf_detected,
            "waf_name": waf_name,
            "details": evidence_list
        },
        "findings": findings
    }
