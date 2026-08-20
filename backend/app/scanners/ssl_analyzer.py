"""
Módulo SSL/TLS Analyzer para AuditShield.
Verifica certificados, protocolos soportados, cipher suites y configuración HSTS.
Calcula una calificación de seguridad SSL similar a Qualys SSL Labs.
"""

import asyncio
import json
import logging
import re
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

# Cipher suites considerados débiles o inseguros
WEAK_CIPHERS = {
    # RC4 es completamente roto
    "RC4": "Critical",
    "RC4-SHA": "Critical",
    "RC4-MD5": "Critical",
    # Export ciphers (FREAK)
    "EXP-": "Critical",
    "EXPORT": "Critical",
    # DES y Triple-DES
    "DES-CBC": "High",
    "DES-CBC3-SHA": "High",
    "3DES": "High",
    "DES": "High",
    # NULL ciphers
    "NULL": "Critical",
    "eNULL": "Critical",
    "aNULL": "Critical",
    # MD5 como MAC
    "-MD5": "Medium",
    # Anon DH (sin autenticación)
    "ADH": "High",
    "AECDH": "High",
}

# Protocolos y su estado de seguridad
PROTOCOL_SECURITY = {
    "SSLv2": {"secure": False, "severity": "Critical"},
    "SSLv3": {"secure": False, "severity": "Critical"},
    "TLSv1.0": {"secure": False, "severity": "High"},
    "TLSv1.1": {"secure": False, "severity": "Medium"},
    "TLSv1.2": {"secure": True, "severity": None},
    "TLSv1.3": {"secure": True, "severity": None},
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
# Verificación de Certificado SSL
# ---------------------------------------------------------------------------


def check_certificate(host: str, port: int = 443) -> Dict[str, Any]:
    """
    Verifica el certificado SSL/TLS del servidor:
    - Validez y expiración
    - Common Name (CN) y Subject Alternative Names (SAN)
    - Issuer (CA)
    - Self-signed detection
    - Weak key size
    """
    findings: List[Dict] = []

    try:
        # Crear contexto SSL para obtener el certificado
        context = ssl.create_default_context()

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cert_bin = ssock.getpeercert(binary_form=True)
                cipher_used = ssock.cipher()
                protocol_used = ssock.version()

        # Analizar certificado con cryptography si está disponible
        cert_details: Dict[str, Any] = {}
        try:
            from cryptography import x509  # type: ignore
            from cryptography.hazmat.primitives import hashes  # type: ignore
            from cryptography.hazmat.backends import default_backend  # type: ignore

            cert_obj = x509.load_der_x509_certificate(cert_bin, default_backend())

            # Fechas
            not_before = cert_obj.not_valid_before_utc
            not_after = cert_obj.not_valid_after_utc
            now = datetime.now(timezone.utc)
            days_left = (not_after - now).days
            is_expired = now > not_after

            # Subject
            subject = {attr.oid._name: attr.value for attr in cert_obj.subject}
            issuer = {attr.oid._name: attr.value for attr in cert_obj.issuer}

            # SANs
            try:
                san_ext = cert_obj.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
                sans = san_ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                sans = []

            # Tamaño de clave
            public_key = cert_obj.public_key()
            key_size = getattr(public_key, "key_size", None)

            # Self-signed: issuer == subject
            is_self_signed = cert_obj.issuer == cert_obj.subject

            cert_details = {
                "subject": subject,
                "issuer": issuer,
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_until_expiry": days_left,
                "is_expired": is_expired,
                "serial_number": str(cert_obj.serial_number),
                "signature_algorithm": cert_obj.signature_algorithm_oid.dotted_string,
                "subject_alternative_names": sans,
                "key_size": key_size,
                "is_self_signed": is_self_signed,
                "cipher_suite": cipher_used,
                "protocol_version": protocol_used,
            }

            # --- Generar findings ---

            if is_expired:
                findings.append(
                    _build_finding(
                        severity="Critical",
                        title="Certificado SSL expirado",
                        description=f"El certificado expiró el {not_after.date()}.",
                        evidence=f"not_after: {not_after.isoformat()}",
                        impact="Navegadores mostrarán advertencia de seguridad. Conexiones pueden fallar.",
                        recommendation="Renovar el certificado inmediatamente.",
                        references=["https://letsencrypt.org/"],
                    )
                )
            elif days_left < 14:
                findings.append(
                    _build_finding(
                        severity="High",
                        title="Certificado SSL expira muy pronto",
                        description=f"El certificado expira en {days_left} días.",
                        evidence=f"not_after: {not_after.isoformat()}",
                        impact="Interrupción inminente del servicio HTTPS.",
                        recommendation="Renovar el certificado inmediatamente.",
                    )
                )
            elif days_left < 30:
                findings.append(
                    _build_finding(
                        severity="Medium",
                        title="Certificado SSL expira en menos de 30 días",
                        description=f"El certificado expira en {days_left} días.",
                        evidence=f"not_after: {not_after.isoformat()}",
                        impact="El servicio HTTPS dejará de funcionar pronto.",
                        recommendation="Programar renovación del certificado.",
                    )
                )

            if is_self_signed:
                findings.append(
                    _build_finding(
                        severity="High",
                        title="Certificado auto-firmado detectado",
                        description="El certificado no está firmado por una Autoridad Certificadora (CA) confiable.",
                        evidence=f"issuer == subject: {issuer}",
                        impact="Navegadores mostrarán advertencias de seguridad. Vulnerable a MITM.",
                        recommendation=(
                            "Obtener un certificado firmado por una CA reconocida. "
                            "Let's Encrypt ofrece certificados gratuitos y automatizados."
                        ),
                        references=["https://letsencrypt.org/getting-started/"],
                    )
                )

            if key_size and key_size < 2048:
                findings.append(
                    _build_finding(
                        severity="High",
                        title="Tamaño de clave insuficiente",
                        description=f"La clave RSA tiene {key_size} bits. Se requieren mínimo 2048 bits.",
                        evidence=f"key_size: {key_size}",
                        impact="Clave vulnerable a ataques de factorización.",
                        recommendation="Generar un nuevo certificado con clave RSA de 2048+ bits o ECDSA P-256.",
                        references=["https://www.keylength.com/en/4/"],
                    )
                )

            # Verificar algoritmo de firma débil
            sig_alg = cert_obj.signature_algorithm_oid.dotted_string
            # SHA1 OID: 1.2.840.113549.1.1.5
            if "1.2.840.113549.1.1.5" in sig_alg or "sha1" in str(cert_obj.signature_hash_algorithm).lower():
                findings.append(
                    _build_finding(
                        severity="High",
                        title="Algoritmo de firma SHA-1 deprecado",
                        description="El certificado usa SHA-1 como algoritmo de firma, que está deprecado.",
                        evidence=f"signature_algorithm: {sig_alg}",
                        impact="SHA-1 es vulnerable a ataques de colisión.",
                        recommendation="Re-emitir el certificado con SHA-256 o superior.",
                        references=["https://shattered.io/"],
                    )
                )

        except ImportError:
            # Fallback sin cryptography: usar datos del dict de ssl
            logger.warning("cryptography no instalado, usando datos básicos de ssl")
            not_after_str = cert.get("notAfter", "")
            cert_details = {
                "raw_cert": cert,
                "not_after_raw": not_after_str,
                "cipher_suite": cipher_used,
                "protocol_version": protocol_used,
            }

        return {
            "status": "success",
            "data": cert_details,
            "findings": findings,
        }

    except ssl.SSLCertVerificationError as exc:
        findings.append(
            _build_finding(
                severity="High",
                title="Error de verificación del certificado SSL",
                description=f"El certificado no pudo ser verificado: {exc}",
                evidence=str(exc),
                impact="Posible ataque Man-in-the-Middle o configuración incorrecta.",
                recommendation="Verificar la cadena de certificación y la validez del certificado.",
            )
        )
        return {"status": "error", "data": {"error": str(exc)}, "findings": findings}
    except (socket.timeout, ConnectionRefusedError) as exc:
        return {
            "status": "error",
            "data": {"error": f"No se puede conectar a {host}:{port} - {exc}"},
            "findings": [],
        }
    except Exception as exc:
        logger.error("check_certificate error para %s:%s: %s", host, port, exc)
        return {"status": "error", "data": {"error": str(exc)}, "findings": []}


# ---------------------------------------------------------------------------
# Verificación de Protocolos SSL/TLS
# ---------------------------------------------------------------------------


def check_protocols(host: str, port: int = 443) -> Dict[str, Any]:
    """
    Prueba qué protocolos SSL/TLS soporta el servidor.
    Usa el módulo ssl de Python para probar TLS 1.0, 1.1, 1.2, 1.3.
    Para SSLv2/SSLv3 usa subprocess con openssl si está disponible.
    """
    findings: List[Dict] = []
    supported_protocols: Dict[str, bool] = {}

    # Mapeo de versiones TLS disponibles en el módulo ssl de Python
    tls_versions_to_test = []

    for attr in ["PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1", "PROTOCOL_TLSv1_2"]:
        if hasattr(ssl, attr):
            tls_versions_to_test.append(attr)

    # Probar TLS 1.0
    for protocol_name, min_ver, max_ver in [
        ("TLSv1.0", ssl.TLSVersion.TLSv1 if hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1") else None, None),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_1") else None, None),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2 if hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_2") else None, None),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3 if hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_3") else None, None),
    ]:
        if min_ver is None:
            supported_protocols[protocol_name] = None  # type: ignore
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = min_ver
            ctx.maximum_version = min_ver
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    actual_version = ssock.version()
                    supported_protocols[protocol_name] = True
        except ssl.SSLError:
            supported_protocols[protocol_name] = False
        except Exception:
            supported_protocols[protocol_name] = False

    # Intentar detectar SSLv3 con openssl CLI
    for old_proto in ["SSLv2", "SSLv3"]:
        flag = "-ssl2" if old_proto == "SSLv2" else "-ssl3"
        try:
            result = subprocess.run(
                ["openssl", "s_client", flag, "-connect", f"{host}:{port}"],
                input=b"",
                capture_output=True,
                timeout=5,
            )
            output = result.stdout.decode("utf-8", errors="ignore")
            supported_protocols[old_proto] = "CONNECTED" in output
        except (FileNotFoundError, subprocess.TimeoutExpired):
            supported_protocols[old_proto] = False
        except Exception:
            supported_protocols[old_proto] = False

    # Generar findings para protocolos inseguros
    for proto, is_supported in supported_protocols.items():
        if is_supported and not PROTOCOL_SECURITY.get(proto, {}).get("secure", True):
            severity = PROTOCOL_SECURITY.get(proto, {}).get("severity", "Medium")
            findings.append(
                _build_finding(
                    severity=severity,
                    title=f"Protocolo inseguro soportado: {proto}",
                    description=(
                        f"El servidor acepta conexiones {proto}, "
                        "un protocolo con vulnerabilidades conocidas."
                    ),
                    evidence=f"{proto}: soportado en {host}:{port}",
                    impact=(
                        f"{'SSLv2/SSLv3' if 'SSL' in proto else proto} es vulnerable a "
                        "ataques como POODLE, BEAST o DROWN que permiten descifrar el tráfico."
                    ),
                    recommendation=(
                        f"Deshabilitar {proto} en la configuración del servidor. "
                        "Solo habilitar TLS 1.2 y TLS 1.3."
                    ),
                    references=[
                        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566",  # POODLE
                        "https://bettercrypto.org/",
                    ],
                )
            )

    # Verificar que al menos TLS 1.2 o 1.3 esté habilitado
    if not supported_protocols.get("TLSv1.2") and not supported_protocols.get("TLSv1.3"):
        findings.append(
            _build_finding(
                severity="Critical",
                title="Sin soporte para TLS moderno",
                description="El servidor no soporta TLS 1.2 ni TLS 1.3.",
                evidence=str(supported_protocols),
                impact="Las conexiones seguras modernas no son posibles.",
                recommendation="Actualizar la configuración SSL para soportar TLS 1.2 y TLS 1.3.",
            )
        )

    return {
        "status": "success",
        "data": {"host": host, "port": port, "protocols": supported_protocols},
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Verificación de Cipher Suites
# ---------------------------------------------------------------------------


def check_cipher_suites(host: str, port: int = 443) -> Dict[str, Any]:
    """
    Detecta cipher suites soportados usando openssl s_client.
    Identifica ciphers débiles (RC4, DES, NULL, EXPORT, etc.)
    """
    findings: List[Dict] = []
    detected_ciphers: List[str] = []
    weak_detected: Dict[str, str] = {}  # cipher → severidad

    # Obtener ciphers usando el SSL context de Python
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        available_ciphers = [c[0] for c in ctx.get_ciphers()]

        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                negotiated = ssock.cipher()
                if negotiated:
                    detected_ciphers.append(negotiated[0])

    except Exception as exc:
        logger.debug("check_cipher_suites SSL error: %s", exc)

    # Intentar enumerar ciphers con openssl si está disponible
    try:
        result = subprocess.run(
            ["openssl", "ciphers", "ALL:eNULL"],
            capture_output=True,
            timeout=5,
        )
        all_ciphers = result.stdout.decode().strip().split(":")
        
        for cipher in all_ciphers[:50]:  # Limitar para no tardar demasiado
            try:
                result = subprocess.run(
                    ["openssl", "s_client", "-cipher", cipher, "-connect", f"{host}:{port}"],
                    input=b"",
                    capture_output=True,
                    timeout=3,
                )
                output = result.stdout.decode("utf-8", errors="ignore")
                if "CONNECTED" in output and "Cipher is" in output:
                    detected_ciphers.append(cipher)
            except Exception:
                pass

    except FileNotFoundError:
        logger.debug("openssl CLI no disponible para enumerar ciphers")
    except Exception as exc:
        logger.debug("Error enumerando ciphers con openssl: %s", exc)

    # Analizar ciphers detectados
    for cipher in detected_ciphers:
        for weak_pattern, severity in WEAK_CIPHERS.items():
            if weak_pattern in cipher:
                weak_detected[cipher] = severity
                break

    # Generar findings para ciphers débiles
    for cipher, severity in weak_detected.items():
        findings.append(
            _build_finding(
                severity=severity,
                title=f"Cipher suite débil soportado: {cipher}",
                description=(
                    f"El servidor acepta el cipher suite '{cipher}', "
                    "que presenta vulnerabilidades de seguridad conocidas."
                ),
                evidence=f"Cipher detectado: {cipher}",
                impact="Posibilidad de descifrado de tráfico por ataques criptográficos.",
                recommendation=(
                    "Deshabilitar cipher suites débiles. "
                    "Usar configuración recomendada por Mozilla: "
                    "https://ssl-config.mozilla.org/"
                ),
                references=[
                    "https://ssl-config.mozilla.org/",
                    "https://www.ssllabs.com/ssltest/",
                ],
            )
        )

    return {
        "status": "success",
        "data": {
            "host": host,
            "port": port,
            "detected_ciphers": list(set(detected_ciphers)),
            "weak_ciphers": weak_detected,
        },
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Verificación HSTS
# ---------------------------------------------------------------------------


async def check_hsts(host: str) -> Dict[str, Any]:
    """
    Verifica si el servidor implementa HSTS (HTTP Strict Transport Security)
    y evalúa su configuración (max-age, includeSubDomains, preload).
    """
    findings: List[Dict] = []

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            follow_redirects=False,
            verify=False,
        ) as client:
            resp = await client.get(f"https://{host}", headers={
                "User-Agent": "Mozilla/5.0 AuditShield/1.0"
            })

        hsts_header = resp.headers.get("strict-transport-security", "")

        if not hsts_header:
            findings.append(
                _build_finding(
                    severity="Medium",
                    title="HSTS no implementado",
                    description=(
                        "El servidor no envía el header 'Strict-Transport-Security'. "
                        "HSTS protege contra ataques de downgrade y session hijacking."
                    ),
                    evidence="Header 'Strict-Transport-Security' ausente",
                    impact=(
                        "Sin HSTS, los navegadores pueden ser redirigidos a HTTP. "
                        "Vulnerable a ataques SSL Stripping."
                    ),
                    recommendation=(
                        "Implementar HSTS: "
                        "'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'"
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
                    ],
                )
            )
            return {
                "status": "success",
                "data": {"host": host, "hsts_present": False, "hsts_header": None},
                "findings": findings,
            }

        # Parsear directivas HSTS
        directives = {d.strip().lower() for d in hsts_header.split(";")}
        max_age_val = 0
        for d in directives:
            if d.startswith("max-age="):
                try:
                    max_age_val = int(d.split("=")[1])
                except ValueError:
                    pass

        has_include_subdomains = "includesubdomains" in directives
        has_preload = "preload" in directives

        hsts_data = {
            "host": host,
            "hsts_present": True,
            "hsts_header": hsts_header,
            "max_age_seconds": max_age_val,
            "max_age_days": max_age_val // 86400,
            "include_subdomains": has_include_subdomains,
            "preload": has_preload,
        }

        # Verificar max-age mínimo (OWASP recomienda 1 año = 31536000)
        if max_age_val < 31536000:
            findings.append(
                _build_finding(
                    severity="Low",
                    title="HSTS max-age insuficiente",
                    description=(
                        f"El HSTS max-age es {max_age_val} segundos ({max_age_val // 86400} días). "
                        "OWASP recomienda al menos 31536000 segundos (1 año)."
                    ),
                    evidence=f"Strict-Transport-Security: {hsts_header}",
                    impact="Una duración corta reduce la protección contra SSL Stripping.",
                    recommendation="Aumentar max-age a 31536000 o más.",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
                    ],
                )
            )

        if not has_include_subdomains:
            findings.append(
                _build_finding(
                    severity="Low",
                    title="HSTS sin includeSubDomains",
                    description="La directiva includeSubDomains no está presente en HSTS.",
                    evidence=f"Strict-Transport-Security: {hsts_header}",
                    impact="Los subdominios no están protegidos por HSTS.",
                    recommendation="Agregar 'includeSubDomains' a la directiva HSTS.",
                )
            )

        return {"status": "success", "data": hsts_data, "findings": findings}

    except Exception as exc:
        logger.error("check_hsts error para %s: %s", host, exc)
        return {"status": "error", "data": {"error": str(exc)}, "findings": []}


# ---------------------------------------------------------------------------
# Cálculo de Grade SSL
# ---------------------------------------------------------------------------


def calculate_ssl_grade(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calcula una calificación SSL similar a Qualys SSL Labs:
    A+ → Sin issues críticos/altos + HSTS + TLS1.3
    A  → Sin issues críticos/altos
    B  → Issues medios
    C  → Issues importantes
    D  → Issues serios
    F  → Issues críticos (cert expirado, SSLv2/SSLv3, etc.)
    """
    score = 100
    all_findings: List[Dict] = []

    # Consolidar findings de todos los módulos
    for module_name in ["certificate", "protocols", "cipher_suites", "hsts"]:
        module_result = results.get(module_name, {})
        all_findings.extend(module_result.get("findings", []))

    # Deducciones por severidad
    deductions = {"Critical": 30, "High": 15, "Medium": 5, "Low": 2, "Info": 0}
    for finding in all_findings:
        score -= deductions.get(finding.get("severity", "Info"), 0)

    score = max(0, min(100, score))

    # Calcular letra
    if score >= 90:
        # Verificar si merece A+
        hsts_data = results.get("hsts", {}).get("data", {})
        has_tls13 = results.get("protocols", {}).get("data", {}).get(
            "protocols", {}
        ).get("TLSv1.3", False)
        if hsts_data.get("hsts_present") and hsts_data.get("preload") and has_tls13:
            grade = "A+"
        else:
            grade = "A"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    return {
        "grade": grade,
        "score": score,
        "total_findings": len(all_findings),
        "by_severity": {
            sev: sum(1 for f in all_findings if f.get("severity") == sev)
            for sev in ["Critical", "High", "Medium", "Low", "Info"]
        },
    }


# ---------------------------------------------------------------------------
# Función principal: run_ssl_scan
# ---------------------------------------------------------------------------


async def run_ssl_scan(target: str) -> Dict[str, Any]:
    """
    Ejecuta el análisis SSL/TLS completo:
    certificado, protocolos, cipher suites y HSTS.

    Args:
        target: Hostname o URL del objetivo.

    Returns:
        Dict con resultados detallados y calificación SSL.
    """
    # Extraer host
    if target.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.hostname or target
        port = parsed.port or 443
    else:
        host = target.split(":")[0]
        port = int(target.split(":")[1]) if ":" in target else 443

    logger.info("Iniciando análisis SSL para: %s:%s", host, port)
    start_time = time.time()

    # Ejecutar módulos en paralelo donde sea posible
    # check_certificate y check_protocols/cipher_suites son síncronos (blocking socket)
    # Los ejecutamos en un thread pool para no bloquear el event loop

    loop = asyncio.get_event_loop()

    cert_result, proto_result, cipher_result = await asyncio.gather(
        loop.run_in_executor(None, check_certificate, host, port),
        loop.run_in_executor(None, check_protocols, host, port),
        loop.run_in_executor(None, check_cipher_suites, host, port),
    )
    hsts_result = await check_hsts(host)

    all_results = {
        "certificate": cert_result,
        "protocols": proto_result,
        "cipher_suites": cipher_result,
        "hsts": hsts_result,
    }

    grade_info = calculate_ssl_grade(all_results)

    # Consolidar todos los findings
    all_findings: List[Dict] = []
    for module_result in all_results.values():
        all_findings.extend(module_result.get("findings", []))

    elapsed = round(time.time() - start_time, 2)

    return {
        "status": "completed",
        "module": "ssl_tls",
        "target": target,
        "host": host,
        "port": port,
        "scan_duration_seconds": elapsed,
        "grade": grade_info,
        "modules": all_results,
        "findings": all_findings,
        "summary": {
            "total_findings": len(all_findings),
            "by_severity": {
                sev: sum(1 for f in all_findings if f["severity"] == sev)
                for sev in ["Critical", "High", "Medium", "Low", "Info"]
            },
        },
    }
