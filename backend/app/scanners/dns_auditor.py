"""
Módulo DNS Auditor para AuditShield.
Audita la configuración de seguridad del DNS:
- SPF (Sender Policy Framework)
- DKIM (DomainKeys Identified Mail)
- DMARC (Domain-based Message Authentication)
- DNSSEC
- Zone Transfer (AXFR)
- Open Resolver
"""

import asyncio
import logging
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

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


def _get_txt_records(domain: str, record_type: str = "TXT") -> List[str]:
    """Obtiene registros TXT/DNS usando dnspython o socket fallback."""
    records = []
    try:
        import dns.resolver  # type: ignore
        import dns.exception  # type: ignore

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 8.0
        answers = resolver.resolve(domain, record_type)
        for r in answers:
            records.append(str(r).strip('"'))
    except ImportError:
        # Fallback básico usando socket (solo para A records)
        logger.warning("dnspython no disponible, funcionalidad DNS limitada")
    except Exception as exc:
        logger.debug("Error obteniendo %s records para %s: %s", record_type, domain, exc)
    return records


# ---------------------------------------------------------------------------
# SPF Check
# ---------------------------------------------------------------------------


def check_spf(domain: str) -> Dict[str, Any]:
    """
    Verifica el registro SPF del dominio.
    - Existencia del registro
    - Sintaxis válida
    - Política (+all, ~all, -all, ?all)
    - Número de DNS lookups (límite: 10)
    """
    findings: List[Dict] = []

    try:
        txt_records = _get_txt_records(domain, "TXT")
        spf_records = [r for r in txt_records if r.startswith("v=spf1")]

        if not spf_records:
            findings.append(
                _build_finding(
                    severity="High",
                    title="Registro SPF ausente",
                    description=(
                        f"No se encontró registro SPF para '{domain}'. "
                        "Sin SPF, cualquier servidor puede enviar correos falsificando este dominio."
                    ),
                    evidence=f"No se encontró registro TXT con v=spf1 para {domain}",
                    impact=(
                        "El dominio es vulnerable a email spoofing. "
                        "Atacantes pueden enviar phishing haciéndose pasar por este dominio."
                    ),
                    recommendation=(
                        "Crear un registro TXT SPF. Ejemplo: "
                        "'v=spf1 include:_spf.google.com ~all' para Google Workspace. "
                        "Usar '-all' para política estricta."
                    ),
                    references=[
                        "https://dmarcian.com/spf-syntax-table/",
                        "https://www.rfc-editor.org/rfc/rfc7208",
                    ],
                )
            )
            return {
                "status": "success",
                "data": {"domain": domain, "spf_present": False, "spf_record": None},
                "findings": findings,
            }

        if len(spf_records) > 1:
            findings.append(
                _build_finding(
                    severity="High",
                    title="Múltiples registros SPF detectados",
                    description=(
                        f"Se encontraron {len(spf_records)} registros SPF para '{domain}'. "
                        "Solo debe existir un registro SPF por dominio."
                    ),
                    evidence="\n".join(spf_records),
                    impact="Registros SPF múltiples causan validación incierta.",
                    recommendation="Consolidar en un único registro SPF.",
                    references=["https://www.rfc-editor.org/rfc/rfc7208#section-3.2"],
                )
            )

        spf = spf_records[0]

        # Analizar la política de all
        spf_data: Dict[str, Any] = {
            "domain": domain,
            "spf_present": True,
            "spf_record": spf,
            "policy": None,
            "includes": [],
            "dns_lookups": 0,
        }

        # Contar mecanismos que requieren DNS lookups
        lookup_mechanisms = re.findall(r"(?:include|a|mx|ptr|exists):[^\s]+", spf, re.I)
        spf_data["dns_lookups"] = len(lookup_mechanisms)
        spf_data["includes"] = re.findall(r"include:([^\s]+)", spf, re.I)

        if spf_data["dns_lookups"] > 10:
            findings.append(
                _build_finding(
                    severity="Medium",
                    title="SPF excede el límite de 10 DNS lookups",
                    description=(
                        f"El registro SPF requiere {spf_data['dns_lookups']} DNS lookups. "
                        "El RFC 7208 limita a 10 lookups."
                    ),
                    evidence=f"SPF: {spf}\nLookups: {spf_data['dns_lookups']}",
                    impact="La validación SPF puede fallar con PermError, causando que emails legítimos sean rechazados.",
                    recommendation=(
                        "Reducir los includes y mecanismos. "
                        "Usar herramientas como SPF Flattening."
                    ),
                    references=["https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4"],
                )
            )

        # Analizar política
        if "+all" in spf or " all" in spf.replace("+all", ""):
            spf_data["policy"] = "+all"
            findings.append(
                _build_finding(
                    severity="High",
                    title="SPF con política '+all' (permite cualquier servidor)",
                    description=(
                        "La política '+all' permite que CUALQUIER servidor envíe correos "
                        "como si fuera este dominio, invalidando SPF completamente."
                    ),
                    evidence=f"SPF: {spf}",
                    impact="SPF inefectivo. Email spoofing posible.",
                    recommendation="Cambiar a '-all' (reject) o '~all' (softfail).",
                    references=["https://dmarcian.com/spf-syntax-table/#all"],
                )
            )
        elif "~all" in spf:
            spf_data["policy"] = "~all"
            findings.append(
                _build_finding(
                    severity="Low",
                    title="SPF con política softfail (~all)",
                    description=(
                        "La política '~all' marca emails no autorizados como 'softfail' "
                        "pero no los rechaza. Depende del comportamiento del receptor."
                    ),
                    evidence=f"SPF: {spf}",
                    impact="Emails de servidores no autorizados pueden llegar a inbox.",
                    recommendation=(
                        "Considerar cambiar a '-all' cuando se confirme que todos los "
                        "servidores legítimos están en el registro SPF."
                    ),
                )
            )
        elif "-all" in spf:
            spf_data["policy"] = "-all"
            # Política correcta, no generar finding
        elif "?all" in spf:
            spf_data["policy"] = "?all"
            findings.append(
                _build_finding(
                    severity="Medium",
                    title="SPF con política neutral (?all)",
                    description="La política '?all' es neutral, no proporciona protección real.",
                    evidence=f"SPF: {spf}",
                    impact="Sin protección efectiva contra spoofing.",
                    recommendation="Cambiar a '-all' para política estricta.",
                )
            )

        return {"status": "success", "data": spf_data, "findings": findings}

    except Exception as exc:
        logger.error("check_spf error para %s: %s", domain, exc)
        return {"status": "error", "data": {"error": str(exc)}, "findings": []}


# ---------------------------------------------------------------------------
# DKIM Check
# ---------------------------------------------------------------------------


def check_dkim(domain: str, selector: str = "default") -> Dict[str, Any]:
    """
    Verifica registros DKIM probando selectores comunes.
    Selectores a probar: default, mail, google, k1, smtp, selector1, selector2, dkim, email
    """
    findings: List[Dict] = []
    common_selectors = [selector, "mail", "google", "k1", "smtp", "selector1",
                        "selector2", "dkim", "email", "s1", "s2", "pm", "mandrill",
                        "mailgun", "sendgrid"]

    dkim_found: List[Dict] = []
    dkim_missing_selectors: List[str] = []

    for sel in common_selectors:
        dkim_domain = f"{sel}._domainkey.{domain}"
        txt_records = _get_txt_records(dkim_domain, "TXT")

        dkim_records = [r for r in txt_records if "v=DKIM1" in r or "k=rsa" in r or "p=" in r]

        if dkim_records:
            # Analizar el registro DKIM
            record = dkim_records[0]
            
            # Verificar si la clave está revocada (p= vacío)
            revoked = bool(re.search(r"\bp=\s*;", record)) or bool(re.search(r"\bp=\s*$", record))
            
            # Extraer tamaño de clave si es posible
            key_match = re.search(r"p=([A-Za-z0-9+/=]+)", record)
            key_info = {
                "selector": sel,
                "record": record[:200],
                "is_revoked": revoked,
                "dkim_domain": dkim_domain,
            }
            dkim_found.append(key_info)

            if revoked:
                findings.append(
                    _build_finding(
                        severity="Medium",
                        title=f"Registro DKIM revocado: selector '{sel}'",
                        description=(
                            f"El registro DKIM con selector '{sel}' tiene la clave pública vacía (revocada). "
                            "Emails firmados con este selector serán rechazados."
                        ),
                        evidence=f"{dkim_domain} TXT: {record[:100]}",
                        impact="Emails legítimos pueden ser rechazados.",
                        recommendation=(
                            "Si el selector ya no se usa, eliminarlo. "
                            "Si está activo, generar un nuevo par de claves."
                        ),
                    )
                )
        else:
            dkim_missing_selectors.append(sel)

    if not dkim_found:
        findings.append(
            _build_finding(
                severity="High",
                title="Sin registros DKIM detectados",
                description=(
                    f"No se encontraron registros DKIM para '{domain}' "
                    f"con los selectores probados: {', '.join(common_selectors[:5])}..."
                ),
                evidence=f"Dominio: {domain}, selectores probados: {len(common_selectors)}",
                impact=(
                    "Sin DKIM, los emails no tienen firma criptográfica. "
                    "Mayor probabilidad de ser marcados como spam o spoofing."
                ),
                recommendation=(
                    "Configurar DKIM en el servidor de correo. "
                    "La mayoría de proveedores (Google Workspace, Microsoft 365) "
                    "proveen instrucciones para configurar DKIM."
                ),
                references=[
                    "https://dmarc.org/wiki/FAQ",
                    "https://www.rfc-editor.org/rfc/rfc6376",
                ],
            )
        )

    return {
        "status": "success",
        "data": {
            "domain": domain,
            "dkim_found": dkim_found,
            "selectors_found": [d["selector"] for d in dkim_found],
            "selectors_tested": common_selectors,
        },
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# DMARC Check
# ---------------------------------------------------------------------------


def check_dmarc(domain: str) -> Dict[str, Any]:
    """
    Verifica el registro DMARC y su política.
    """
    findings: List[Dict] = []
    dmarc_domain = f"_dmarc.{domain}"

    try:
        txt_records = _get_txt_records(dmarc_domain, "TXT")
        dmarc_records = [r for r in txt_records if r.startswith("v=DMARC1")]

        if not dmarc_records:
            findings.append(
                _build_finding(
                    severity="High",
                    title="Registro DMARC ausente",
                    description=(
                        f"No se encontró registro DMARC para '{domain}'. "
                        "Sin DMARC, no hay política de manejo de correos no autenticados."
                    ),
                    evidence=f"No TXT record en {dmarc_domain}",
                    impact=(
                        "El dominio es más vulnerable al spoofing. "
                        "Sin DMARC, los receptores no saben qué hacer con emails que fallan SPF/DKIM."
                    ),
                    recommendation=(
                        "Crear registro DMARC: '_dmarc.{domain} TXT \"v=DMARC1; p=quarantine; "
                        "rua=mailto:dmarc-reports@{domain}\"'"
                    ),
                    references=[
                        "https://dmarc.org/overview/",
                        "https://www.rfc-editor.org/rfc/rfc7489",
                    ],
                )
            )
            return {
                "status": "success",
                "data": {"domain": domain, "dmarc_present": False, "dmarc_record": None},
                "findings": findings,
            }

        dmarc = dmarc_records[0]

        # Parsear directivas DMARC
        directives: Dict[str, str] = {}
        for part in dmarc.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                directives[k.strip().lower()] = v.strip()

        policy = directives.get("p", "none").lower()
        sp_policy = directives.get("sp", policy).lower()  # Subdomain policy
        rua = directives.get("rua", "")  # Aggregate reports
        ruf = directives.get("ruf", "")  # Forensic reports
        pct = int(directives.get("pct", "100"))

        dmarc_data = {
            "domain": domain,
            "dmarc_present": True,
            "dmarc_record": dmarc,
            "policy": policy,
            "subdomain_policy": sp_policy,
            "aggregate_reports_uri": rua,
            "forensic_reports_uri": ruf,
            "percentage": pct,
        }

        # Evaluar política
        if policy == "none":
            findings.append(
                _build_finding(
                    severity="Medium",
                    title="DMARC con política 'none' (solo monitoreo)",
                    description=(
                        "La política DMARC es 'p=none', que solo monitorea sin acción. "
                        "Los emails que fallan SPF/DKIM no son rechazados ni cuarentenados."
                    ),
                    evidence=f"DMARC: {dmarc}",
                    impact="Sin protección real contra email spoofing.",
                    recommendation=(
                        "Progresivamente endurecer la política: "
                        "none → quarantine → reject. "
                        "Usar 'p=quarantine' como primer paso, luego 'p=reject'."
                    ),
                    references=["https://dmarc.org/2016/01/about-dmarc-policy-none/"],
                )
            )
        elif policy == "quarantine":
            findings.append(
                _build_finding(
                    severity="Low",
                    title="DMARC con política 'quarantine' (moderada)",
                    description=(
                        "La política DMARC es 'p=quarantine'. "
                        "Los emails no autenticados van a carpeta de spam/cuarentena."
                    ),
                    evidence=f"DMARC: {dmarc}",
                    impact="Emails falsos van a spam, pero no son rechazados definitivamente.",
                    recommendation=(
                        "Considerar escalar a 'p=reject' para máxima protección "
                        "una vez verificado que todos los sistemas de correo están correctamente configurados."
                    ),
                )
            )
        # policy == "reject" es el estado ideal, no genera finding

        # Verificar si hay URIs de reportes
        if not rua:
            findings.append(
                _build_finding(
                    severity="Low",
                    title="DMARC sin URI de reportes agregados (rua)",
                    description="No se configuró 'rua' en DMARC para recibir reportes.",
                    evidence=f"DMARC: {dmarc}",
                    impact="No hay visibilidad sobre intentos de spoofing o fallos de autenticación.",
                    recommendation=(
                        "Agregar 'rua=mailto:dmarc@{domain}' para recibir reportes. "
                        "Usar servicios como dmarcian.com o Postmark para analizar reportes."
                    ),
                )
            )

        # Verificar porcentaje
        if pct < 100:
            findings.append(
                _build_finding(
                    severity="Low",
                    title=f"DMARC con pct={pct}% (política parcial)",
                    description=(
                        f"DMARC solo aplica al {pct}% del tráfico. "
                        "El {100 - pct}% restante no es procesado."
                    ),
                    evidence=f"DMARC: {dmarc}",
                    impact="Protección DMARC incompleta.",
                    recommendation="Incrementar pct=100 cuando la configuración esté estabilizada.",
                )
            )

        return {"status": "success", "data": dmarc_data, "findings": findings}

    except Exception as exc:
        logger.error("check_dmarc error para %s: %s", domain, exc)
        return {"status": "error", "data": {"error": str(exc)}, "findings": []}


# ---------------------------------------------------------------------------
# DNSSEC Check
# ---------------------------------------------------------------------------


def check_dnssec(domain: str) -> Dict[str, Any]:
    """
    Verifica si DNSSEC está configurado para el dominio.
    Busca registros DNSKEY y RRSIG.
    """
    findings: List[Dict] = []
    dnssec_data: Dict[str, Any] = {
        "domain": domain,
        "dnssec_enabled": False,
        "dnskey_records": [],
        "ds_records": [],
    }

    try:
        import dns.resolver  # type: ignore
        import dns.dnssec  # type: ignore
        import dns.exception  # type: ignore

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 8.0

        # Buscar DNSKEY
        try:
            answers = resolver.resolve(domain, "DNSKEY")
            dnssec_data["dnskey_records"] = [str(r)[:100] for r in answers]
            dnssec_data["dnssec_enabled"] = bool(dnssec_data["dnskey_records"])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            pass

        # Buscar DS en el dominio padre
        try:
            parent_domain = ".".join(domain.split(".")[1:])
            answers = resolver.resolve(domain, "DS")
            dnssec_data["ds_records"] = [str(r)[:100] for r in answers]
        except Exception:
            pass

        if not dnssec_data["dnssec_enabled"]:
            findings.append(
                _build_finding(
                    severity="Low",
                    title="DNSSEC no configurado",
                    description=(
                        f"El dominio '{domain}' no tiene DNSSEC habilitado. "
                        "DNSSEC protege contra DNS spoofing y cache poisoning."
                    ),
                    evidence=f"No se encontraron registros DNSKEY para {domain}",
                    impact=(
                        "Sin DNSSEC, las respuestas DNS pueden ser falsificadas "
                        "(DNS cache poisoning/Kaminsky attack)."
                    ),
                    recommendation=(
                        "Habilitar DNSSEC en el registrador del dominio y en el servidor DNS. "
                        "La mayoría de registradores modernos ofrecen DNSSEC como opción."
                    ),
                    references=[
                        "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en",
                        "https://www.cloudflare.com/dns/dnssec/how-dnssec-works/",
                    ],
                )
            )

    except ImportError:
        logger.warning("dnspython no disponible para check_dnssec")
        dnssec_data["error"] = "dnspython no disponible"
    except Exception as exc:
        logger.error("check_dnssec error para %s: %s", domain, exc)
        return {"status": "error", "data": {"error": str(exc)}, "findings": []}

    return {"status": "success", "data": dnssec_data, "findings": findings}


# ---------------------------------------------------------------------------
# Zone Transfer Check
# ---------------------------------------------------------------------------


def check_zone_transfer(domain: str) -> Dict[str, Any]:
    """
    Intenta realizar una transferencia de zona DNS (AXFR) a todos los servidores NS.
    Un AXFR exitoso expone todos los registros DNS del dominio.
    """
    findings: List[Dict] = []
    ns_servers: List[str] = []
    transfer_results: Dict[str, Any] = {}

    try:
        import dns.resolver  # type: ignore
        import dns.zone  # type: ignore
        import dns.query  # type: ignore
        import dns.exception  # type: ignore

        # Obtener servidores NS
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 8.0
            ns_answers = resolver.resolve(domain, "NS")
            ns_servers = [str(ns).rstrip(".") for ns in ns_answers]
        except Exception:
            pass

        for ns in ns_servers:
            try:
                # Resolver IP del NS
                ns_ip = socket.gethostbyname(ns)
                
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, domain, lifetime=10)
                )
                
                # Si llegamos aquí, la transferencia fue exitosa
                records_count = len(list(zone.nodes.keys()))
                transfer_results[ns] = {
                    "allowed": True,
                    "records_count": records_count,
                    "ns_ip": ns_ip,
                }

                findings.append(
                    _build_finding(
                        severity="Critical",
                        title=f"Zone Transfer (AXFR) permitido en {ns}",
                        description=(
                            f"El servidor DNS '{ns}' ({ns_ip}) permite transferencias de zona. "
                            f"Se obtuvieron {records_count} registros DNS completos."
                        ),
                        evidence=(
                            f"AXFR exitoso desde {ns} ({ns_ip})\n"
                            f"Registros obtenidos: {records_count}"
                        ),
                        impact=(
                            "Un atacante obtiene el mapa completo de la infraestructura DNS: "
                            "subdominios internos, IPs de servidores, configuraciones de red."
                        ),
                        recommendation=(
                            "Restringir AXFR solo a servidores DNS secundarios autorizados. "
                            "En BIND: usar 'allow-transfer { trusted_ns_ips; };'. "
                            "En PowerDNS: configurar 'allow-axfr-ips'."
                        ),
                        references=[
                            "https://www.rfc-editor.org/rfc/rfc5936",
                            "https://owasp.org/www-project-web-security-testing-guide/"
                            "latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"
                            "10-Test_for_Subdomain_Takeover",
                        ],
                    )
                )

            except (dns.exception.FormError, dns.exception.DNSException):
                transfer_results[ns] = {"allowed": False}
            except Exception as e:
                transfer_results[ns] = {"allowed": False, "error": str(e)}

    except ImportError:
        logger.warning("dnspython no disponible para check_zone_transfer")
        return {
            "status": "skipped",
            "data": {"domain": domain, "reason": "dnspython no disponible"},
            "findings": [],
        }
    except Exception as exc:
        logger.error("check_zone_transfer error para %s: %s", domain, exc)
        return {"status": "error", "data": {"error": str(exc)}, "findings": []}

    return {
        "status": "success",
        "data": {
            "domain": domain,
            "ns_servers": ns_servers,
            "transfer_results": transfer_results,
            "vulnerable": any(r.get("allowed") for r in transfer_results.values()),
        },
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Open Resolver Check
# ---------------------------------------------------------------------------


def check_open_resolver(ip: str) -> Dict[str, Any]:
    """
    Verifica si el servidor DNS en la IP dada es un open resolver.
    Un open resolver responde consultas DNS de cualquier fuente.
    """
    findings: List[Dict] = []
    is_open = False

    try:
        import dns.resolver  # type: ignore
        import dns.exception  # type: ignore

        # Crear resolver apuntando al IP del objetivo
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [ip]
        resolver.lifetime = 5.0

        # Intentar resolver un dominio externo
        try:
            answers = resolver.resolve("google.com", "A")
            if answers:
                is_open = True
                findings.append(
                    _build_finding(
                        severity="High",
                        title="Open DNS Resolver detectado",
                        description=(
                            f"El servidor DNS en {ip} responde consultas para dominios externos "
                            "(open resolver). Puede ser abusado en ataques DNS Amplification."
                        ),
                        evidence=(
                            f"Consulta: google.com A → {[str(r) for r in answers]}\n"
                            f"DNS Server: {ip}"
                        ),
                        impact=(
                            "El servidor puede ser usado en ataques DDoS de amplificación DNS. "
                            "Factor de amplificación de hasta 50x."
                        ),
                        recommendation=(
                            "Restringir el resolver para responder solo consultas "
                            "de redes internas autorizadas. "
                            "En BIND: 'allow-recursion { trusted_networks; };'. "
                            "En Unbound: 'access-control: 0.0.0.0/0 refuse;'"
                        ),
                        references=[
                            "https://www.cloudflare.com/learning/ddos/dns-amplification-ddos-attack/",
                            "https://www.rfc-editor.org/rfc/rfc5358",
                        ],
                    )
                )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # El resolver respondió pero no encontró el dominio: igual es open
            is_open = True
        except dns.exception.DNSException:
            is_open = False

    except ImportError:
        logger.warning("dnspython no disponible para check_open_resolver")
        return {
            "status": "skipped",
            "data": {"ip": ip, "reason": "dnspython no disponible"},
            "findings": [],
        }
    except Exception as exc:
        logger.error("check_open_resolver error para %s: %s", ip, exc)
        return {"status": "error", "data": {"error": str(exc)}, "findings": []}

    return {
        "status": "success",
        "data": {"ip": ip, "is_open_resolver": is_open},
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Función principal: run_dns_scan
# ---------------------------------------------------------------------------


async def run_dns_scan(target: str) -> Dict[str, Any]:
    """
    Ejecuta el análisis de seguridad DNS completo.

    Args:
        target: Dominio o URL del objetivo.

    Returns:
        Dict con resultados de todos los módulos DNS y findings consolidados.
    """
    # Extraer dominio
    from urllib.parse import urlparse
    if target.startswith(("http://", "https://")):
        domain = urlparse(target).hostname or target
    else:
        domain = target.split("/")[0]

    all_findings: List[Dict] = []
    start_time = time.time()

    logger.info("Iniciando análisis DNS para: %s", domain)

    loop = asyncio.get_event_loop()

    # Ejecutar módulos síncronos en thread pool
    (
        spf_result,
        dkim_result,
        dmarc_result,
        dnssec_result,
        zone_result,
    ) = await asyncio.gather(
        loop.run_in_executor(None, check_spf, domain),
        loop.run_in_executor(None, check_dkim, domain),
        loop.run_in_executor(None, check_dmarc, domain),
        loop.run_in_executor(None, check_dnssec, domain),
        loop.run_in_executor(None, check_zone_transfer, domain),
    )

    # Open resolver check con la IP del dominio
    open_resolver_result = {"status": "skipped", "data": {}, "findings": []}
    try:
        ip = socket.gethostbyname(domain)
        open_resolver_result = await loop.run_in_executor(None, check_open_resolver, ip)
    except Exception:
        pass

    def safe(r, name):
        if isinstance(r, Exception):
            logger.error("Error en módulo DNS %s: %s", name, r)
            return {"status": "error", "data": {"error": str(r)}, "findings": []}
        return r

    modules = {
        "spf": safe(spf_result, "spf"),
        "dkim": safe(dkim_result, "dkim"),
        "dmarc": safe(dmarc_result, "dmarc"),
        "dnssec": safe(dnssec_result, "dnssec"),
        "zone_transfer": safe(zone_result, "zone_transfer"),
        "open_resolver": open_resolver_result,
    }

    for module_result in modules.values():
        all_findings.extend(module_result.get("findings", []))

    elapsed = round(time.time() - start_time, 2)

    return {
        "status": "completed",
        "module": "dns_security",
        "target": target,
        "domain": domain,
        "scan_duration_seconds": elapsed,
        "modules": modules,
        "findings": all_findings,
        "summary": {
            "total_findings": len(all_findings),
            "by_severity": {
                sev: sum(1 for f in all_findings if f["severity"] == sev)
                for sev in ["Critical", "High", "Medium", "Low", "Info"]
            },
        },
    }
