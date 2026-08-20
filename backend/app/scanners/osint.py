"""
Módulo OSINT (Open Source Intelligence) para AuditShield.
Reúne información pública sobre el objetivo: WHOIS, DNS, subdominios,
geolocalización de IPs y fingerprinting de tecnologías.
"""

import asyncio
import json
import logging
import re
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# Firmas de tecnologías conocidas (header → tecnología)
TECHNOLOGY_SIGNATURES = {
    "headers": {
        "x-powered-by": {
            "PHP": "PHP",
            "Express": "Express.js",
            "ASP.NET": "ASP.NET",
            "Servlet": "Java Servlet",
            "Next.js": "Next.js",
        },
        "server": {
            "nginx": "Nginx",
            "apache": "Apache",
            "Microsoft-IIS": "IIS",
            "LiteSpeed": "LiteSpeed",
            "cloudflare": "Cloudflare",
            "openresty": "OpenResty",
            "gunicorn": "Gunicorn",
            "uvicorn": "Uvicorn",
        },
        "via": {"varnish": "Varnish Cache", "squid": "Squid"},
        "x-generator": {"WordPress": "WordPress", "Drupal": "Drupal"},
        "x-drupal-cache": {"": "Drupal"},
        "x-wp-total": {"": "WordPress"},
    },
    "html": {
        "wp-content": "WordPress",
        "wp-includes": "WordPress",
        "Joomla": "Joomla",
        "drupal": "Drupal",
        "django": "Django",
        "laravel": "Laravel",
        "__next": "Next.js",
        "react": "React",
        "angular": "Angular",
        "vue": "Vue.js",
        "jquery": "jQuery",
        "bootstrap": "Bootstrap",
        "tailwindcss": "Tailwind CSS",
        "shopify": "Shopify",
        "wix.com": "Wix",
        "squarespace": "Squarespace",
    },
    "cookies": {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java",
        "ASP.NET_SessionId": "ASP.NET",
        "laravel_session": "Laravel",
        "django_session": "Django",
        "_rails": "Ruby on Rails",
        "csrftoken": "Django (CSRF)",
        "wp-settings": "WordPress",
    },
}


# ---------------------------------------------------------------------------
# Helpers internos
# ---------------------------------------------------------------------------


def _extract_domain(target: str) -> str:
    """Extrae el dominio limpio de una URL o string."""
    target = target.strip()
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        return parsed.hostname or target
    return target.split("/")[0]


def _build_finding(
    severity: str,
    title: str,
    description: str,
    evidence: str = "",
    impact: str = "",
    recommendation: str = "",
    references: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Construye un finding con el formato estándar de AuditShield."""
    return {
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation,
        "references": references or [],
    }


# ---------------------------------------------------------------------------
# WHOIS lookup
# ---------------------------------------------------------------------------


async def whois_lookup(target: str) -> Dict[str, Any]:
    """
    Realiza lookup WHOIS consultando la API de IANA y el servidor WHOIS apropiado.
    Intenta primero con python-whois si está disponible, si no usa requests crudos.
    """
    domain = _extract_domain(target)
    findings: List[Dict] = []

    try:
        # Intentar con python-whois (librería opcional)
        try:
            import whois  # type: ignore

            w = whois.whois(domain)
            raw_data = {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "updated_date": str(w.updated_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "dnssec": w.dnssec,
                "country": w.country,
                "org": w.org,
            }

            # Verificar expiración próxima
            exp = w.expiration_date
            if isinstance(exp, list):
                exp = exp[0]
            if exp:
                if hasattr(exp, "tzinfo") and exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                days_left = (exp - datetime.now(timezone.utc)).days
                if days_left < 30:
                    findings.append(
                        _build_finding(
                            severity="High",
                            title="Dominio próximo a expirar",
                            description=f"El dominio expira en {days_left} días ({exp.date()}).",
                            evidence=f"expiration_date: {exp}",
                            impact="El dominio podría ser tomado por un atacante si expira.",
                            recommendation="Renovar el dominio inmediatamente.",
                            references=[
                                "https://www.icann.org/resources/pages/domain-renewal"
                            ],
                        )
                    )
                elif days_left < 90:
                    findings.append(
                        _build_finding(
                            severity="Medium",
                            title="Dominio expira en menos de 90 días",
                            description=f"El dominio expira en {days_left} días.",
                            evidence=f"expiration_date: {exp}",
                            impact="Riesgo de pérdida de dominio si no se renueva a tiempo.",
                            recommendation="Programar renovación del dominio.",
                        )
                    )

            # Verificar privacidad WHOIS
            registrar_str = str(raw_data.get("registrar", "")).lower()
            if not any(
                kw in registrar_str
                for kw in ["privacy", "protect", "whoisguard", "private"]
            ):
                findings.append(
                    _build_finding(
                        severity="Low",
                        title="WHOIS sin privacidad habilitada",
                        description="Los datos del registrante son públicos en WHOIS.",
                        evidence=f"registrar: {raw_data.get('registrar')}",
                        impact="Exposición de información personal del propietario.",
                        recommendation="Activar WHOIS Privacy Protection en el registrador.",
                        references=["https://www.icann.org/resources/pages/privacy-2012-02-25-en"],
                    )
                )

            return {
                "status": "success",
                "data": raw_data,
                "findings": findings,
            }

        except ImportError:
            logger.warning("python-whois no instalado, usando fallback HTTP")

        # Fallback: consultar whois.iana.org via HTTP
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(
                f"https://www.whois.com/whois/{domain}",
                headers=HEADERS,
                follow_redirects=True,
            )
            # Extraer datos básicos del texto HTML (muy simplificado)
            text = resp.text
            raw_data = {
                "domain": domain,
                "raw_response": text[:2000],
                "source": "whois.com HTTP fallback",
            }

            return {
                "status": "partial",
                "data": raw_data,
                "findings": findings,
            }

    except Exception as exc:
        logger.error("whois_lookup error para %s: %s", domain, exc)
        return {
            "status": "error",
            "data": {"error": str(exc)},
            "findings": [],
        }


# ---------------------------------------------------------------------------
# DNS lookup
# ---------------------------------------------------------------------------


async def dns_lookup(target: str) -> Dict[str, Any]:
    """
    Resuelve múltiples tipos de registros DNS para el dominio:
    A, AAAA, MX, NS, TXT, CNAME, SOA.
    """
    domain = _extract_domain(target)
    findings: List[Dict] = []
    records: Dict[str, Any] = {}

    try:
        import dns.resolver  # type: ignore
        import dns.exception  # type: ignore

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 8.0

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except dns.resolver.NoAnswer:
                records[rtype] = []
            except dns.resolver.NXDOMAIN:
                records[rtype] = None
            except dns.exception.DNSException as e:
                records[rtype] = f"error: {e}"

        # Analizar hallazgos DNS
        # Verificar si hay registros A
        if not records.get("A"):
            findings.append(
                _build_finding(
                    severity="Info",
                    title="Sin registros A",
                    description="No se encontraron registros A para el dominio.",
                    evidence=f"Dominio: {domain}",
                    impact="El dominio no resuelve a una dirección IP.",
                    recommendation="Verificar la configuración DNS.",
                )
            )

        # Verificar múltiples servidores NS (resiliencia)
        ns_records = records.get("NS", [])
        if isinstance(ns_records, list) and len(ns_records) < 2:
            findings.append(
                _build_finding(
                    severity="Medium",
                    title="Pocos servidores de nombres (NS)",
                    description=f"Solo {len(ns_records)} servidor(es) NS encontrados. Se recomiendan al menos 2.",
                    evidence=f"NS records: {ns_records}",
                    impact="Punto único de falla en la resolución DNS.",
                    recommendation="Configurar al menos 2 servidores de nombres redundantes.",
                    references=["https://www.rfc-editor.org/rfc/rfc1034"],
                )
            )

        return {
            "status": "success",
            "data": {"domain": domain, "records": records},
            "findings": findings,
        }

    except ImportError:
        logger.warning("dnspython no instalado, usando socket fallback")
        # Fallback con socket
        try:
            a_records = socket.getaddrinfo(domain, None)
            ips = list({r[4][0] for r in a_records})
            return {
                "status": "partial",
                "data": {"domain": domain, "records": {"A": ips}},
                "findings": findings,
            }
        except Exception as exc:
            return {
                "status": "error",
                "data": {"error": str(exc)},
                "findings": [],
            }
    except Exception as exc:
        logger.error("dns_lookup error para %s: %s", domain, exc)
        return {
            "status": "error",
            "data": {"error": str(exc)},
            "findings": [],
        }


# ---------------------------------------------------------------------------
# Subdomain discovery via crt.sh
# ---------------------------------------------------------------------------


async def subdomain_discovery(target: str) -> Dict[str, Any]:
    """
    Descubre subdominios usando Certificate Transparency Logs via crt.sh.
    Consulta: https://crt.sh/?q=%.{domain}&output=json
    """
    domain = _extract_domain(target)
    findings: List[Dict] = []
    subdomains: List[str] = []

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = await client.get(url, headers=HEADERS, follow_redirects=True)
            resp.raise_for_status()

            certs = resp.json()

            # Extraer subdominios únicos
            seen: set = set()
            for cert in certs:
                name_value = cert.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    # Eliminar wildcards y duplicados
                    if name.startswith("*."):
                        name = name[2:]
                    if name.endswith(f".{domain}") or name == domain:
                        if name not in seen:
                            seen.add(name)
                            subdomains.append(name)

            subdomains.sort()

            # Analizar hallazgos
            if len(subdomains) > 50:
                findings.append(
                    _build_finding(
                        severity="Info",
                        title="Gran superficie de ataque: muchos subdominios",
                        description=f"Se encontraron {len(subdomains)} subdominios únicos.",
                        evidence=f"Subdominios encontrados: {len(subdomains)}",
                        impact="Una mayor cantidad de subdominios incrementa la superficie de ataque.",
                        recommendation=(
                            "Revisar y desactivar subdominios no utilizados. "
                            "Implementar inventario de activos digitales."
                        ),
                    )
                )

            # Detectar subdominios sospechosos
            suspicious_keywords = ["dev", "test", "staging", "qa", "old", "backup", "admin", "beta"]
            suspicious_found = [
                s for s in subdomains
                if any(kw in s.split(".")[0] for kw in suspicious_keywords)
            ]
            if suspicious_found:
                findings.append(
                    _build_finding(
                        severity="Medium",
                        title="Subdominios de entorno no-productivo expuestos",
                        description=(
                            "Se detectaron subdominios que podrían corresponder a entornos "
                            "de desarrollo o prueba expuestos en Internet."
                        ),
                        evidence=", ".join(suspicious_found[:10]),
                        impact=(
                            "Los entornos de desarrollo suelen tener menor seguridad "
                            "y pueden revelar información sensible."
                        ),
                        recommendation=(
                            "Restringir acceso a subdominios dev/test/staging. "
                            "Usar VPN o IP allowlist para acceder a estos entornos."
                        ),
                    )
                )

            return {
                "status": "success",
                "data": {
                    "domain": domain,
                    "subdomains": subdomains,
                    "total": len(subdomains),
                    "suspicious": suspicious_found,
                },
                "findings": findings,
            }

    except httpx.HTTPError as exc:
        logger.error("subdomain_discovery HTTP error: %s", exc)
        return {
            "status": "error",
            "data": {"error": str(exc)},
            "findings": [],
        }
    except Exception as exc:
        logger.error("subdomain_discovery error para %s: %s", domain, exc)
        return {
            "status": "error",
            "data": {"error": str(exc)},
            "findings": [],
        }


# ---------------------------------------------------------------------------
# IP Geolocation
# ---------------------------------------------------------------------------


async def get_ip_info(ip: str) -> Dict[str, Any]:
    """
    Obtiene información de geolocalización para una IP usando ipapi.co.
    Endpoint: https://ipapi.co/{ip}/json/
    """
    findings: List[Dict] = []

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(
                f"https://ipapi.co/{ip}/json/",
                headers=HEADERS,
                follow_redirects=True,
            )
            resp.raise_for_status()
            data = resp.json()

            # Detectar IP de hosting / datacenter
            org = data.get("org", "").lower()
            hosting_keywords = [
                "amazon", "google", "microsoft", "digitalocean", "linode",
                "vultr", "hetzner", "ovh", "cloudflare", "fastly", "akamai",
            ]
            is_hosting = any(kw in org for kw in hosting_keywords)
            if is_hosting:
                findings.append(
                    _build_finding(
                        severity="Info",
                        title="IP en infraestructura de cloud/hosting",
                        description=f"La IP {ip} pertenece a {data.get('org')}.",
                        evidence=f"org: {data.get('org')}, country: {data.get('country_name')}",
                        impact="La IP es de un proveedor cloud conocido.",
                        recommendation=(
                            "Verificar que el proveedor cloud esté correctamente configurado "
                            "con las políticas de seguridad apropiadas."
                        ),
                    )
                )

            return {
                "status": "success",
                "data": {
                    "ip": ip,
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country_name"),
                    "country_code": data.get("country_code"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                    "org": data.get("org"),
                    "asn": data.get("asn"),
                    "timezone": data.get("timezone"),
                    "is_hosting": is_hosting,
                },
                "findings": findings,
            }

    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 429:
            logger.warning("ipapi.co rate limit alcanzado para %s", ip)
            return {
                "status": "rate_limited",
                "data": {"ip": ip, "error": "Rate limit exceeded"},
                "findings": [],
            }
        logger.error("get_ip_info HTTP error para %s: %s", ip, exc)
        return {"status": "error", "data": {"error": str(exc)}, "findings": []}
    except Exception as exc:
        logger.error("get_ip_info error para %s: %s", ip, exc)
        return {"status": "error", "data": {"error": str(exc)}, "findings": []}


# ---------------------------------------------------------------------------
# Technology Fingerprinting
# ---------------------------------------------------------------------------


async def fingerprint_technologies(url: str) -> Dict[str, Any]:
    """
    Detecta tecnologías usadas por el sitio web analizando:
    - Headers HTTP (Server, X-Powered-By, etc.)
    - Contenido HTML (meta tags, scripts, links)
    - Cookies
    """
    findings: List[Dict] = []
    technologies: Dict[str, str] = {}

    # Asegurar que la URL tiene esquema
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT,
            follow_redirects=True,
            verify=False,  # Algunos sitios tienen cert inválido
        ) as client:
            resp = await client.get(url, headers=HEADERS)

        headers = dict(resp.headers)
        html = resp.text.lower()
        cookies = {c.name: c.value for c in resp.cookies.jar}

        # --- Analizar headers ---
        for header_name, signature_map in TECHNOLOGY_SIGNATURES["headers"].items():
            header_val = headers.get(header_name, "")
            if header_val:
                for keyword, tech_name in signature_map.items():
                    if not keyword or keyword.lower() in header_val.lower():
                        technologies[tech_name] = header_val
                        break

        # --- Analizar HTML ---
        for pattern, tech_name in TECHNOLOGY_SIGNATURES["html"].items():
            if pattern in html:
                technologies.setdefault(tech_name, "detected in HTML")

        # --- Analizar cookies ---
        for cookie_name, tech_name in TECHNOLOGY_SIGNATURES["cookies"].items():
            if cookie_name in cookies:
                technologies.setdefault(tech_name, f"cookie: {cookie_name}")

        # --- Generar hallazgos de seguridad basados en tecnologías ---

        # Versión de servidor expuesta
        server_header = headers.get("server", "")
        server_version_pattern = re.compile(r"[\d.]+")
        if server_header and server_version_pattern.search(server_header):
            findings.append(
                _build_finding(
                    severity="Low",
                    title="Versión del servidor expuesta en header",
                    description=(
                        f"El header 'Server' revela la versión exacta: '{server_header}'. "
                        "Esto facilita la búsqueda de vulnerabilidades específicas."
                    ),
                    evidence=f"Server: {server_header}",
                    impact=(
                        "Un atacante puede buscar CVEs específicos para la versión "
                        "exacta del servidor."
                    ),
                    recommendation=(
                        "Configurar el servidor para no exponer la versión. "
                        "En Nginx: 'server_tokens off'. En Apache: 'ServerTokens Prod'."
                    ),
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/"
                        "latest/4-Web_Application_Security_Testing/01-Information_Gathering/"
                        "02-Fingerprint_Web_Server"
                    ],
                )
            )

        # X-Powered-By expuesto
        x_powered = headers.get("x-powered-by", "")
        if x_powered:
            findings.append(
                _build_finding(
                    severity="Low",
                    title="Header X-Powered-By expuesto",
                    description=(
                        f"El header 'X-Powered-By: {x_powered}' revela la tecnología backend."
                    ),
                    evidence=f"X-Powered-By: {x_powered}",
                    impact="Facilita el fingerprinting y búsqueda de vulnerabilidades.",
                    recommendation=(
                        "Eliminar o falsificar el header X-Powered-By. "
                        "En Express.js: 'app.disable(\"x-powered-by\")'. "
                        "En PHP: 'expose_php = Off' en php.ini."
                    ),
                    references=["https://owasp.org/www-community/attacks/Fingerprinting"],
                )
            )

        return {
            "status": "success",
            "data": {
                "url": url,
                "technologies": technologies,
                "headers_analyzed": list(headers.keys()),
                "cookies_found": list(cookies.keys()),
                "status_code": resp.status_code,
            },
            "findings": findings,
        }

    except httpx.ConnectError:
        return {
            "status": "error",
            "data": {"error": f"No se puede conectar a {url}"},
            "findings": [],
        }
    except Exception as exc:
        logger.error("fingerprint_technologies error para %s: %s", url, exc)
        return {
            "status": "error",
            "data": {"error": str(exc)},
            "findings": [],
        }


# ---------------------------------------------------------------------------
# Función principal: run_osint_scan
# ---------------------------------------------------------------------------


async def run_osint_scan(target: str) -> Dict[str, Any]:
    """
    Ejecuta el escaneo OSINT completo sobre el objetivo.
    Combina: WHOIS, DNS, subdominios, geolocalización e IP y fingerprinting.

    Args:
        target: URL, dominio o IP del objetivo.

    Returns:
        Dict con módulos de resultados y findings consolidados.
    """
    domain = _extract_domain(target)
    all_findings: List[Dict] = []
    start_time = time.time()

    logger.info("Iniciando escaneo OSINT para: %s", domain)

    # Ejecutar todos los módulos en paralelo
    whois_task = whois_lookup(domain)
    dns_task = dns_lookup(domain)
    subdomain_task = subdomain_discovery(domain)
    tech_task = fingerprint_technologies(target)

    (whois_result, dns_result, subdomain_result, tech_result) = await asyncio.gather(
        whois_task, dns_task, subdomain_task, tech_task, return_exceptions=True
    )

    # Convertir excepciones en errores
    def safe_result(r, module_name: str) -> Dict:
        if isinstance(r, Exception):
            logger.error("Error en módulo %s: %s", module_name, r)
            return {"status": "error", "data": {"error": str(r)}, "findings": []}
        return r

    whois_result = safe_result(whois_result, "whois")
    dns_result = safe_result(dns_result, "dns")
    subdomain_result = safe_result(subdomain_result, "subdomain")
    tech_result = safe_result(tech_result, "tech")

    # Obtener IP principal para geolocalización
    ip_result = {"status": "skipped", "data": {}, "findings": []}
    a_records = dns_result.get("data", {}).get("records", {}).get("A", [])
    if isinstance(a_records, list) and a_records:
        ip_result = await get_ip_info(a_records[0])

    # Consolidar findings
    for module_result in [whois_result, dns_result, subdomain_result, tech_result, ip_result]:
        all_findings.extend(module_result.get("findings", []))

    elapsed = round(time.time() - start_time, 2)

    return {
        "status": "completed",
        "module": "osint",
        "target": target,
        "domain": domain,
        "scan_duration_seconds": elapsed,
        "modules": {
            "whois": whois_result,
            "dns": dns_result,
            "subdomains": subdomain_result,
            "ip_geolocation": ip_result,
            "technologies": tech_result,
        },
        "findings": all_findings,
        "summary": {
            "total_findings": len(all_findings),
            "by_severity": {
                sev: sum(1 for f in all_findings if f["severity"] == sev)
                for sev in ["Critical", "High", "Medium", "Low", "Info"]
            },
        },
    }
