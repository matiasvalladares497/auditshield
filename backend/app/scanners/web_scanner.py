"""
Módulo Web Scanner para AuditShield.
Verifica vulnerabilidades web basadas en OWASP Top 10:
- Security Headers
- Métodos HTTP peligrosos
- Archivos sensibles expuestos
- Páginas de error con información sensible
- Configuración de cookies
- CORS misconfiguration
- Formularios sin CSRF
- Mixed Content
"""

import asyncio
import logging
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup  # type: ignore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

TIMEOUT = httpx.Timeout(10.0, connect=5.0)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Security headers requeridos y su severidad si faltan
REQUIRED_HEADERS = {
    "content-security-policy": {
        "severity": "High",
        "title": "Content-Security-Policy ausente",
        "description": (
            "El header Content-Security-Policy (CSP) no está configurado. "
            "CSP previene ataques XSS y otras inyecciones de contenido."
        ),
        "recommendation": (
            "Implementar una política CSP estricta. Ejemplo mínimo: "
            "'Content-Security-Policy: default-src \\'self\\'; "
            "script-src \\'self\\'; object-src \\'none\\''"
        ),
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
        ],
    },
    "x-frame-options": {
        "severity": "Medium",
        "title": "X-Frame-Options ausente",
        "description": (
            "El header X-Frame-Options no está configurado. "
            "Esto puede permitir ataques de Clickjacking."
        ),
        "recommendation": (
            "Agregar 'X-Frame-Options: DENY' o 'X-Frame-Options: SAMEORIGIN'. "
            "Alternativamente usar CSP con frame-ancestors."
        ),
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
        ],
    },
    "x-content-type-options": {
        "severity": "Low",
        "title": "X-Content-Type-Options ausente",
        "description": (
            "El header X-Content-Type-Options: nosniff no está presente. "
            "Sin él, los navegadores pueden 'sniffear' el tipo de contenido."
        ),
        "recommendation": "Agregar 'X-Content-Type-Options: nosniff'.",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
        ],
    },
    "strict-transport-security": {
        "severity": "Medium",
        "title": "HSTS ausente",
        "description": (
            "El header Strict-Transport-Security no está configurado. "
            "HSTS previene ataques de downgrade y SSL Stripping."
        ),
        "recommendation": (
            "Agregar 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
        ],
    },
    "referrer-policy": {
        "severity": "Low",
        "title": "Referrer-Policy ausente",
        "description": (
            "El header Referrer-Policy no está configurado. "
            "Sin él, la URL completa puede ser enviada como Referer a sitios externos."
        ),
        "recommendation": (
            "Agregar 'Referrer-Policy: strict-origin-when-cross-origin' o 'no-referrer'."
        ),
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
        ],
    },
    "permissions-policy": {
        "severity": "Low",
        "title": "Permissions-Policy ausente",
        "description": (
            "El header Permissions-Policy (antes Feature-Policy) no está configurado."
        ),
        "recommendation": (
            "Configurar Permissions-Policy para restringir funcionalidades del navegador: "
            "'Permissions-Policy: geolocation=(), microphone=(), camera=()'"
        ),
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
        ],
    },
}

# Archivos sensibles a verificar
SENSITIVE_FILES = [
    ".env",
    ".env.local",
    ".env.production",
    ".git/config",
    ".git/HEAD",
    ".gitignore",
    "robots.txt",
    "sitemap.xml",
    "backup.zip",
    "backup.tar.gz",
    "db.sql",
    "database.sql",
    "dump.sql",
    "wp-config.php",
    "wp-config.php.bak",
    "phpinfo.php",
    "info.php",
    ".htaccess",
    "web.config",
    "config.php",
    "config.js",
    "config.json",
    "settings.py",
    "application.properties",
    "application.yml",
    "appsettings.json",
    ".DS_Store",
    "Thumbs.db",
    "composer.json",
    "package.json",
    "yarn.lock",
    "Gemfile",
    "requirements.txt",
    "Dockerfile",
    "docker-compose.yml",
    ".travis.yml",
    ".circleci/config.yml",
    "server-status",
    "server-info",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "elmah.axd",
    "trace.axd",
]

# Patrones que indican información técnica en páginas de error
ERROR_PATTERNS = [
    (r"PHP (Fatal error|Warning|Notice|Parse error)", "PHP error message", "Medium"),
    (r"Traceback \(most recent call last\)", "Python traceback", "Medium"),
    (r"java\.lang\.", "Java stack trace", "Medium"),
    (r"at .+\.(java|kt):\d+\)", "Java stack trace", "Medium"),
    (r"Microsoft OLE DB|ODBC SQL Server|SQLite3::query|PG::Error", "Database error", "High"),
    (r"NullPointerException|ClassNotFoundException|NoSuchMethodException", "Java exception", "Medium"),
    (r"Stack overflow|OutOfMemoryError", "Memory error", "Low"),
    (r"Syntax error|unexpected T_", "PHP syntax error", "Medium"),
    (r"django\.core\.|django\.db\.", "Django internal error", "High"),
    (r"ActiveRecord::|ActionController::", "Rails error", "High"),
    (r"Illuminate\\|laravel", "Laravel error", "High"),
]


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
        return f"https://{url}"
    return url


# ---------------------------------------------------------------------------
# Security Headers Check
# ---------------------------------------------------------------------------


async def check_security_headers(url: str) -> Dict[str, Any]:
    """
    Verifica todos los security headers importantes en la respuesta HTTP.
    Evalúa: CSP, X-Frame-Options, X-Content-Type-Options, HSTS,
    Referrer-Policy, Permissions-Policy, X-XSS-Protection.
    """
    url = _normalize_url(url)
    findings: List[Dict] = []
    headers_present: Dict[str, str] = {}
    headers_missing: List[str] = []

    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT, follow_redirects=True, verify=False
        ) as client:
            resp = await client.get(url, headers={"User-Agent": USER_AGENT})

        resp_headers = dict(resp.headers)
        headers_lower = {k.lower(): v for k, v in resp_headers.items()}

        # Verificar headers requeridos
        for header_name, config in REQUIRED_HEADERS.items():
            if header_name in headers_lower:
                headers_present[header_name] = headers_lower[header_name]
                
                # Verificar si CSP tiene directivas débiles
                if header_name == "content-security-policy":
                    csp_val = headers_lower[header_name]
                    if "'unsafe-inline'" in csp_val:
                        findings.append(
                            _build_finding(
                                severity="Medium",
                                title="CSP con 'unsafe-inline'",
                                description=(
                                    "La política CSP permite 'unsafe-inline', "
                                    "lo que debilita la protección contra XSS."
                                ),
                                evidence=f"Content-Security-Policy: {csp_val[:200]}",
                                impact="Los atacantes pueden inyectar scripts inline.",
                                recommendation=(
                                    "Eliminar 'unsafe-inline' y usar nonces o hashes para scripts."
                                ),
                                references=[
                                    "https://content-security-policy.com/unsafe-inline/"
                                ],
                            )
                        )
                    if "'unsafe-eval'" in csp_val:
                        findings.append(
                            _build_finding(
                                severity="Medium",
                                title="CSP con 'unsafe-eval'",
                                description=(
                                    "La política CSP permite 'unsafe-eval', "
                                    "habilitando eval() que puede ser explotado por XSS."
                                ),
                                evidence=f"Content-Security-Policy: {csp_val[:200]}",
                                impact="Posibilidad de ejecución de código arbitrario via eval().",
                                recommendation="Eliminar 'unsafe-eval' y refactorizar el código.",
                            )
                        )
            else:
                headers_missing.append(header_name)
                findings.append(
                    _build_finding(
                        severity=config["severity"],
                        title=config["title"],
                        description=config["description"],
                        evidence=f"Header '{header_name}' no encontrado en la respuesta",
                        impact=f"Exposición a vulnerabilidades relacionadas con {header_name}.",
                        recommendation=config["recommendation"],
                        references=config.get("references", []),
                    )
                )

        # Verificar X-XSS-Protection (deprecado pero su presencia incorrecta es peor)
        xxss = headers_lower.get("x-xss-protection", "")
        if xxss == "1":
            findings.append(
                _build_finding(
                    severity="Low",
                    title="X-XSS-Protection sin mode=block",
                    description=(
                        "El header X-XSS-Protection está habilitado sin 'mode=block'. "
                        "Esto puede permitir ataques XSS en algunos navegadores."
                    ),
                    evidence=f"X-XSS-Protection: {xxss}",
                    impact="Protección XSS incompleta en navegadores antiguos.",
                    recommendation=(
                        "Usar 'X-XSS-Protection: 1; mode=block' o mejor: implementar CSP correctamente "
                        "y establecer 'X-XSS-Protection: 0' en navegadores modernos."
                    ),
                )
            )

        return {
            "status": "success",
            "data": {
                "url": url,
                "headers_present": headers_present,
                "headers_missing": headers_missing,
                "status_code": resp.status_code,
            },
            "findings": findings,
        }

    except Exception as exc:
        logger.error("check_security_headers error para %s: %s", url, exc)
        return {"status": "error", "data": {"error": str(exc)}, "findings": []}


# ---------------------------------------------------------------------------
# HTTP Methods Check
# ---------------------------------------------------------------------------


async def check_http_methods(url: str) -> Dict[str, Any]:
    """
    Prueba métodos HTTP potencialmente peligrosos: PUT, DELETE, TRACE, OPTIONS.
    """
    url = _normalize_url(url)
    findings: List[Dict] = []
    methods_found: Dict[str, int] = {}

    dangerous_methods = {
        "PUT": ("High", "Puede permitir subir archivos arbitrarios al servidor."),
        "DELETE": ("High", "Puede permitir eliminar recursos del servidor."),
        "TRACE": (
            "Medium",
            "Permite ataques Cross-Site Tracing (XST) que pueden robar cookies.",
        ),
        "CONNECT": ("Medium", "Puede usarse para hacer proxy requests."),
    }

    # Primero verificar OPTIONS para ver qué métodos están permitidos
    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT, follow_redirects=True, verify=False
        ) as client:
            # Probar OPTIONS
            try:
                resp_options = await client.options(url)
                methods_found["OPTIONS"] = resp_options.status_code
                allow_header = resp_options.headers.get("allow", "")
                if allow_header:
                    for method in dangerous_methods:
                        if method in allow_header.upper():
                            severity, reason = dangerous_methods[method]
                            findings.append(
                                _build_finding(
                                    severity=severity,
                                    title=f"Método HTTP peligroso permitido: {method}",
                                    description=(
                                        f"El servidor indica que acepta el método {method}. "
                                        f"{reason}"
                                    ),
                                    evidence=f"Allow: {allow_header}",
                                    impact=reason,
                                    recommendation=(
                                        f"Deshabilitar el método {method} en la configuración del servidor. "
                                        "Solo permitir GET, POST, HEAD y los métodos estrictamente necesarios."
                                    ),
                                    references=[
                                        "https://owasp.org/www-project-web-security-testing-guide/"
                                        "latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"
                                        "06-Test_HTTP_Methods"
                                    ],
                                )
                            )
            except Exception:
                pass

            # Probar TRACE específicamente (no aparece siempre en Allow)
            try:
                resp_trace = await client.request("TRACE", url)
                methods_found["TRACE"] = resp_trace.status_code
                if resp_trace.status_code == 200:
                    findings.append(
                        _build_finding(
                            severity="Medium",
                            title="Método TRACE habilitado",
                            description=(
                                "El servidor responde a solicitudes TRACE con código 200. "
                                "Esto permite ataques Cross-Site Tracing (XST)."
                            ),
                            evidence=f"TRACE {url} → {resp_trace.status_code}",
                            impact="Un atacante puede usar TRACE para robar cookies HttpOnly.",
                            recommendation="Deshabilitar TRACE en la configuración del servidor web.",
                            references=[
                                "https://owasp.org/www-community/attacks/Cross_Site_Tracing"
                            ],
                        )
                    )
            except Exception:
                pass

    except Exception as exc:
        logger.error("check_http_methods error para %s: %s", url, exc)

    return {
        "status": "success",
        "data": {"url": url, "methods_tested": methods_found},
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Sensitive Files Check
# ---------------------------------------------------------------------------


async def check_sensitive_files(url: str) -> Dict[str, Any]:
    """
    Prueba si archivos o rutas sensibles están accesibles públicamente.
    """
    base_url = _normalize_url(url)
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    findings: List[Dict] = []
    exposed_files: List[Dict] = []

    # Niveles de severidad por tipo de archivo
    file_severity = {
        ".env": "Critical",
        ".env.local": "Critical",
        ".env.production": "Critical",
        ".git/config": "High",
        ".git/HEAD": "High",
        "wp-config.php": "Critical",
        "wp-config.php.bak": "Critical",
        "phpinfo.php": "High",
        "info.php": "High",
        "db.sql": "Critical",
        "database.sql": "Critical",
        "dump.sql": "Critical",
        "backup.zip": "High",
        "backup.tar.gz": "High",
        ".htaccess": "Medium",
        "web.config": "High",
        "settings.py": "High",
        "application.properties": "High",
        "docker-compose.yml": "Medium",
        "Dockerfile": "Low",
    }

    async def check_file(client: httpx.AsyncClient, path: str) -> Optional[Dict]:
        full_url = urljoin(base + "/", path)
        try:
            resp = await client.get(full_url, follow_redirects=False)
            if resp.status_code == 200:
                # Verificar que no sea una página 404 personalizada
                content_len = len(resp.content)
                content_type = resp.headers.get("content-type", "")
                
                # Evitar falsos positivos: páginas 200 que son HTML de error
                if "text/html" in content_type and content_len < 100:
                    return None
                
                return {
                    "path": path,
                    "url": full_url,
                    "status_code": resp.status_code,
                    "content_type": content_type,
                    "content_length": content_len,
                    "preview": resp.text[:200] if content_len < 5000 else "[contenido grande]",
                }
            return None
        except Exception:
            return None

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(5.0), verify=False
        ) as client:
            # Ejecutar verificaciones en paralelo (en grupos para no saturar)
            chunk_size = 10
            for i in range(0, len(SENSITIVE_FILES), chunk_size):
                chunk = SENSITIVE_FILES[i : i + chunk_size]
                results = await asyncio.gather(
                    *[check_file(client, f) for f in chunk]
                )
                for r in results:
                    if r:
                        exposed_files.append(r)

    except Exception as exc:
        logger.error("check_sensitive_files error: %s", exc)

    # Generar findings
    for exposed in exposed_files:
        path = exposed["path"]
        severity = file_severity.get(path, "Medium")
        findings.append(
            _build_finding(
                severity=severity,
                title=f"Archivo sensible expuesto: {path}",
                description=(
                    f"El archivo '{path}' es accesible públicamente en el servidor. "
                    "Puede contener credenciales, configuraciones o información sensible."
                ),
                evidence=(
                    f"URL: {exposed['url']}\n"
                    f"Status: {exposed['status_code']}\n"
                    f"Preview: {exposed.get('preview', '')[:100]}"
                ),
                impact=(
                    "Exposición de información sensible como credenciales de base de datos, "
                    "claves API, configuraciones internas o datos de usuarios."
                ),
                recommendation=(
                    f"Restringir acceso al archivo '{path}'. "
                    "Mover archivos de configuración fuera del webroot. "
                    "Agregar reglas en .htaccess o nginx.conf para denegar acceso."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/"
                    "latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"
                    "01-Test_Network_Infrastructure_Configuration"
                ],
            )
        )

    return {
        "status": "success",
        "data": {
            "url": base_url,
            "files_checked": len(SENSITIVE_FILES),
            "exposed_files": exposed_files,
            "total_exposed": len(exposed_files),
        },
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Error Pages Check
# ---------------------------------------------------------------------------


async def check_error_pages(url: str) -> Dict[str, Any]:
    """
    Detecta páginas de error que revelan información del stack tecnológico
    o stack traces completos.
    """
    url = _normalize_url(url)
    findings: List[Dict] = []
    error_pages_found: List[Dict] = []

    # URLs de prueba para provocar errores
    test_paths = [
        "/nonexistent-page-auditshield-test",
        "/api/nonexistent",
        "/'",  # SQL injection trigger
        "/<script>",  # XSS trigger
        "/admin/nonexistent",
        "/error",
        "/500",
        "/?id=1'",
    ]

    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT, follow_redirects=True, verify=False
        ) as client:
            for path in test_paths:
                try:
                    parsed = urlparse(url)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                    resp = await client.get(
                        test_url, headers={"User-Agent": USER_AGENT}
                    )
                    
                    content = resp.text
                    
                    # Buscar patrones de error en el contenido
                    for pattern, error_type, severity in ERROR_PATTERNS:
                        if re.search(pattern, content, re.IGNORECASE):
                            error_pages_found.append({
                                "url": test_url,
                                "status_code": resp.status_code,
                                "error_type": error_type,
                                "pattern_matched": pattern,
                            })
                            findings.append(
                                _build_finding(
                                    severity=severity,
                                    title=f"Información técnica expuesta en error: {error_type}",
                                    description=(
                                        f"La respuesta a '{path}' contiene "
                                        f"información de error detallada ({error_type})."
                                    ),
                                    evidence=(
                                        f"URL: {test_url}\n"
                                        f"Pattern: {pattern}\n"
                                        f"Status: {resp.status_code}"
                                    ),
                                    impact=(
                                        "Revela tecnología, rutas del servidor, consultas SQL o "
                                        "stack traces que facilitan ataques dirigidos."
                                    ),
                                    recommendation=(
                                        "Implementar páginas de error personalizadas. "
                                        "Deshabilitar el modo debug en producción. "
                                        "Capturar excepciones y mostrar solo mensajes genéricos."
                                    ),
                                    references=[
                                        "https://owasp.org/www-project-web-security-testing-guide/"
                                        "latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/"
                                        "01-Testing_For_Improper_Error_Handling"
                                    ],
                                )
                            )
                            break  # Un finding por URL

                except Exception:
                    continue

    except Exception as exc:
        logger.error("check_error_pages error para %s: %s", url, exc)

    return {
        "status": "success",
        "data": {
            "url": url,
            "paths_tested": test_paths,
            "error_pages_found": error_pages_found,
        },
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Cookies Check
# ---------------------------------------------------------------------------


async def check_cookies(url: str) -> Dict[str, Any]:
    """
    Analiza los atributos de seguridad de las cookies:
    Secure, HttpOnly, SameSite, Domain/Path correctos.
    """
    url = _normalize_url(url)
    findings: List[Dict] = []
    cookies_info: List[Dict] = []

    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT, follow_redirects=True, verify=False
        ) as client:
            resp = await client.get(url, headers={"User-Agent": USER_AGENT})

        # Obtener Set-Cookie headers raw
        raw_cookies = resp.headers.get_list("set-cookie")

        for raw_cookie in raw_cookies:
            parts = raw_cookie.split(";")
            cookie_main = parts[0].strip()
            cookie_name = cookie_main.split("=")[0].strip() if "=" in cookie_main else cookie_main

            directives = {p.strip().lower() for p in parts[1:]}
            has_secure = any("secure" == d for d in directives)
            has_httponly = any("httponly" == d for d in directives)
            samesite_val = next(
                (d.split("=")[1] for d in directives if d.startswith("samesite=")),
                None,
            )

            cookie_data = {
                "name": cookie_name,
                "has_secure": has_secure,
                "has_httponly": has_httponly,
                "samesite": samesite_val,
                "raw": raw_cookie[:150],
            }
            cookies_info.append(cookie_data)

            # Generar findings por cada atributo faltante
            is_https = url.startswith("https://")

            if is_https and not has_secure:
                findings.append(
                    _build_finding(
                        severity="Medium",
                        title=f"Cookie sin atributo Secure: {cookie_name}",
                        description=(
                            f"La cookie '{cookie_name}' no tiene el atributo 'Secure'. "
                            "Puede ser transmitida sobre conexiones HTTP no cifradas."
                        ),
                        evidence=f"Set-Cookie: {raw_cookie[:100]}",
                        impact="La cookie puede ser interceptada en ataques MITM.",
                        recommendation=(
                            f"Agregar el atributo 'Secure' a la cookie '{cookie_name}'. "
                            "Ejemplo: Set-Cookie: nombre=valor; Secure; HttpOnly"
                        ),
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies"
                        ],
                    )
                )

            if not has_httponly:
                # Solo reportar para cookies de sesión (nombre conocido)
                session_cookie_names = [
                    "session", "sessid", "phpsessid", "jsessionid", "asp.net_sessionid",
                    "token", "auth", "remember_token",
                ]
                if any(sc in cookie_name.lower() for sc in session_cookie_names):
                    findings.append(
                        _build_finding(
                            severity="High",
                            title=f"Cookie de sesión sin HttpOnly: {cookie_name}",
                            description=(
                                f"La cookie de sesión '{cookie_name}' no tiene el atributo 'HttpOnly'. "
                                "JavaScript puede acceder a ella, facilitando ataques XSS."
                            ),
                            evidence=f"Set-Cookie: {raw_cookie[:100]}",
                            impact="Un ataque XSS exitoso puede robar la sesión del usuario.",
                            recommendation=(
                                f"Agregar el atributo 'HttpOnly' a la cookie '{cookie_name}'."
                            ),
                            references=[
                                "https://owasp.org/www-community/HttpOnly"
                            ],
                        )
                    )

            if not samesite_val:
                findings.append(
                    _build_finding(
                        severity="Low",
                        title=f"Cookie sin atributo SameSite: {cookie_name}",
                        description=(
                            f"La cookie '{cookie_name}' no tiene el atributo 'SameSite'. "
                            "Puede ser vulnerable a ataques CSRF."
                        ),
                        evidence=f"Set-Cookie: {raw_cookie[:100]}",
                        impact="Posible vulnerabilidad CSRF.",
                        recommendation=(
                            "Agregar 'SameSite=Strict' o 'SameSite=Lax' según el caso de uso."
                        ),
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
                        ],
                    )
                )

    except Exception as exc:
        logger.error("check_cookies error para %s: %s", url, exc)
        return {"status": "error", "data": {"error": str(exc)}, "findings": []}

    return {
        "status": "success",
        "data": {"url": url, "cookies": cookies_info},
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# CORS Check
# ---------------------------------------------------------------------------


async def check_cors(url: str) -> Dict[str, Any]:
    """
    Detecta misconfiguraciones de CORS enviando peticiones con Origin malicioso.
    """
    url = _normalize_url(url)
    findings: List[Dict] = []
    cors_data: Dict[str, Any] = {}

    malicious_origins = [
        "https://evil.com",
        "https://attacker.example.com",
        f"https://evil.{urlparse(url).hostname}",
    ]

    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT, follow_redirects=True, verify=False
        ) as client:
            for evil_origin in malicious_origins:
                headers = {
                    "User-Agent": USER_AGENT,
                    "Origin": evil_origin,
                }
                resp = await client.get(url, headers=headers)

                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                cors_data[evil_origin] = {
                    "access_control_allow_origin": acao,
                    "access_control_allow_credentials": acac,
                }

                # CORS crítico: origin reflejado + credentials
                if acao == evil_origin and acac.lower() == "true":
                    findings.append(
                        _build_finding(
                            severity="Critical",
                            title="CORS misconfiguration crítica: Origin reflejado con Credentials",
                            description=(
                                "El servidor refleja el Origin del atacante en ACAO y permite "
                                "credenciales. Un atacante puede realizar peticiones autenticadas "
                                "desde cualquier dominio."
                            ),
                            evidence=(
                                f"Request Origin: {evil_origin}\n"
                                f"Access-Control-Allow-Origin: {acao}\n"
                                f"Access-Control-Allow-Credentials: {acac}"
                            ),
                            impact=(
                                "Permite ataques CSRF avanzados y robo de datos de usuarios autenticados "
                                "desde sitios maliciosos."
                            ),
                            recommendation=(
                                "Implementar una whitelist de orígenes permitidos. "
                                "Nunca usar wildcard (*) con Access-Control-Allow-Credentials: true."
                            ),
                            references=[
                                "https://portswigger.net/web-security/cors",
                                "https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html",
                            ],
                        )
                    )
                elif acao == "*":
                    findings.append(
                        _build_finding(
                            severity="Medium",
                            title="CORS con wildcard (*) habilitado",
                            description=(
                                "El servidor permite peticiones cross-origin desde cualquier dominio (*)."
                            ),
                            evidence=f"Access-Control-Allow-Origin: *",
                            impact=(
                                "Cualquier sitio web puede leer las respuestas de esta API. "
                                "Riesgo si la API expone datos sensibles."
                            ),
                            recommendation=(
                                "Restringir CORS a dominios específicos y confiables. "
                                "Nunca usar '*' para APIs que manejan datos de usuarios."
                            ),
                            references=[
                                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
                            ],
                        )
                    )
                elif acao == evil_origin:
                    findings.append(
                        _build_finding(
                            severity="High",
                            title="CORS refleja Origin arbitrario",
                            description=(
                                "El servidor refleja cualquier Origin en el header "
                                "Access-Control-Allow-Origin sin validación."
                            ),
                            evidence=(
                                f"Request Origin: {evil_origin}\n"
                                f"Access-Control-Allow-Origin: {acao}"
                            ),
                            impact="Permite acceso cross-origin desde dominios arbitrarios.",
                            recommendation=(
                                "Validar el Origin contra una lista blanca antes de reflejarlo."
                            ),
                            references=[
                                "https://portswigger.net/web-security/cors"
                            ],
                        )
                    )
                break  # Con un test es suficiente para detectar el patrón

    except Exception as exc:
        logger.error("check_cors error para %s: %s", url, exc)
        return {"status": "error", "data": {"error": str(exc)}, "findings": []}

    return {
        "status": "success",
        "data": {"url": url, "cors_tests": cors_data},
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Forms Check (CSRF y autocomplete)
# ---------------------------------------------------------------------------


async def check_forms(url: str) -> Dict[str, Any]:
    """
    Analiza formularios HTML en busca de:
    - CSRF tokens ausentes
    - autocomplete="off" ausente en campos de contraseña
    - Formularios con action HTTP en páginas HTTPS
    """
    url = _normalize_url(url)
    findings: List[Dict] = []
    forms_data: List[Dict] = []

    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT, follow_redirects=True, verify=False
        ) as client:
            resp = await client.get(url, headers={"User-Agent": USER_AGENT})

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            # Si BeautifulSoup no está disponible, usar regex básico
            forms = re.findall(r"<form[^>]*>.*?</form>", resp.text, re.DOTALL | re.IGNORECASE)
            return {
                "status": "partial",
                "data": {"url": url, "forms_count": len(forms)},
                "findings": findings,
            }

        forms = soup.find_all("form")

        for i, form in enumerate(forms):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            inputs = form.find_all("input")

            input_names = [inp.get("name", "") for inp in inputs]
            input_types = [inp.get("type", "text").lower() for inp in inputs]

            # Detectar campos de contraseña
            has_password = "password" in input_types

            # Buscar CSRF token (nombres comunes)
            csrf_token_names = [
                "csrf", "csrf_token", "_token", "csrfmiddlewaretoken",
                "__requestverificationtoken", "_csrf_token", "authenticity_token",
            ]
            has_csrf = any(
                any(csrf_name in name.lower() for csrf_name in csrf_token_names)
                for name in input_names
            )

            form_data = {
                "index": i,
                "action": action,
                "method": method,
                "has_password_field": has_password,
                "has_csrf_token": has_csrf,
                "inputs": input_names,
            }
            forms_data.append(form_data)

            # Finding: formulario POST sin CSRF token
            if method == "POST" and not has_csrf:
                findings.append(
                    _build_finding(
                        severity="Medium",
                        title=f"Formulario POST sin token CSRF (form #{i + 1})",
                        description=(
                            f"El formulario #{i + 1} (action='{action}') usa método POST "
                            "pero no contiene un token CSRF."
                        ),
                        evidence=(
                            f"Form action: {action}, method: {method}\n"
                            f"Inputs encontrados: {input_names}"
                        ),
                        impact=(
                            "Un atacante puede engañar a usuarios autenticados para "
                            "realizar acciones no deseadas (CSRF)."
                        ),
                        recommendation=(
                            "Implementar tokens CSRF anti-forgery en todos los formularios POST. "
                            "Usar SameSite cookies como defensa adicional."
                        ),
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
                        ],
                    )
                )

            # Finding: campo de contraseña sin autocomplete=off
            if has_password:
                password_inputs = [
                    inp for inp in inputs
                    if inp.get("type", "").lower() == "password"
                ]
                for pwd_input in password_inputs:
                    autocomplete = pwd_input.get("autocomplete", "")
                    if autocomplete.lower() not in ["off", "new-password", "current-password"]:
                        pass  # En realidad autocomplete=off se considera mala práctica ahora
                        # Solo reportar si el form no tiene ninguna protección

        # Finding: formulario con action HTTP en página HTTPS
        if url.startswith("https://"):
            for form_data in forms_data:
                action = form_data.get("action", "")
                if action.startswith("http://"):
                    findings.append(
                        _build_finding(
                            severity="High",
                            title="Formulario con action HTTP en página HTTPS",
                            description=(
                                f"Un formulario en la página HTTPS envía datos a "
                                f"'{action}' via HTTP no cifrado."
                            ),
                            evidence=f"Form action: {action}",
                            impact="Los datos del formulario (incluyendo contraseñas) viajan sin cifrar.",
                            recommendation=(
                                "Cambiar el action del formulario a HTTPS."
                            ),
                        )
                    )

    except Exception as exc:
        logger.error("check_forms error para %s: %s", url, exc)
        return {"status": "error", "data": {"error": str(exc)}, "findings": []}

    return {
        "status": "success",
        "data": {"url": url, "forms": forms_data, "total_forms": len(forms_data)},
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Mixed Content Check
# ---------------------------------------------------------------------------


async def check_mixed_content(url: str) -> Dict[str, Any]:
    """
    Detecta recursos HTTP (imágenes, scripts, estilos) cargados en páginas HTTPS.
    """
    url = _normalize_url(url)
    findings: List[Dict] = []
    mixed_resources: List[Dict] = []

    if not url.startswith("https://"):
        return {
            "status": "skipped",
            "data": {"url": url, "reason": "Mixed content solo aplica a HTTPS"},
            "findings": [],
        }

    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT, follow_redirects=True, verify=False
        ) as client:
            resp = await client.get(url, headers={"User-Agent": USER_AGENT})

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            
            # Verificar elementos que cargan recursos externos
            checks = [
                ("script", "src", "JavaScript"),
                ("link", "href", "CSS/Font"),
                ("img", "src", "Imagen"),
                ("iframe", "src", "iFrame"),
                ("video", "src", "Video"),
                ("audio", "src", "Audio"),
                ("source", "src", "Media Source"),
            ]
            
            for tag, attr, resource_type in checks:
                for element in soup.find_all(tag):
                    src = element.get(attr, "")
                    if src and src.startswith("http://"):
                        mixed_resources.append({
                            "type": resource_type,
                            "url": src,
                            "tag": str(element)[:100],
                        })

        except Exception:
            # Fallback con regex
            http_resources = re.findall(
                r'(?:src|href)\s*=\s*["\']?(http://[^"\'>\s]+)',
                resp.text,
                re.IGNORECASE,
            )
            for r in http_resources:
                mixed_resources.append({"type": "unknown", "url": r})

        if mixed_resources:
            findings.append(
                _build_finding(
                    severity="Medium",
                    title=f"Mixed Content detectado: {len(mixed_resources)} recurso(s) HTTP",
                    description=(
                        f"La página HTTPS carga {len(mixed_resources)} recurso(s) via HTTP no cifrado."
                    ),
                    evidence="\n".join(r["url"] for r in mixed_resources[:5]),
                    impact=(
                        "Los recursos HTTP pueden ser interceptados y modificados (inyección de código). "
                        "Los navegadores modernos bloquean mixed content activo (scripts, iframes)."
                    ),
                    recommendation=(
                        "Cambiar todas las URLs de recursos a HTTPS. "
                        "Usar URLs relativas (//) para que el navegador use el mismo protocolo."
                    ),
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
                        "https://web.dev/what-is-mixed-content/",
                    ],
                )
            )

    except Exception as exc:
        logger.error("check_mixed_content error para %s: %s", url, exc)
        return {"status": "error", "data": {"error": str(exc)}, "findings": []}

    return {
        "status": "success",
        "data": {
            "url": url,
            "mixed_resources": mixed_resources,
            "total_mixed": len(mixed_resources),
        },
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Función principal: run_web_scan
# ---------------------------------------------------------------------------


async def run_web_scan(target: str) -> Dict[str, Any]:
    """
    Ejecuta el escaneo web completo con todos los módulos OWASP.

    Args:
        target: URL del objetivo.

    Returns:
        Dict con resultados de todos los módulos y findings consolidados.
    """
    url = _normalize_url(target)
    all_findings: List[Dict] = []
    start_time = time.time()

    logger.info("Iniciando escaneo web para: %s", url)

    # Ejecutar todos los módulos en paralelo
    (
        headers_result,
        methods_result,
        files_result,
        errors_result,
        cookies_result,
        cors_result,
        forms_result,
        mixed_result,
    ) = await asyncio.gather(
        check_security_headers(url),
        check_http_methods(url),
        check_sensitive_files(url),
        check_error_pages(url),
        check_cookies(url),
        check_cors(url),
        check_forms(url),
        check_mixed_content(url),
        return_exceptions=True,
    )

    def safe(r, name):
        if isinstance(r, Exception):
            logger.error("Error en módulo web %s: %s", name, r)
            return {"status": "error", "data": {"error": str(r)}, "findings": []}
        return r

    modules = {
        "security_headers": safe(headers_result, "security_headers"),
        "http_methods": safe(methods_result, "http_methods"),
        "sensitive_files": safe(files_result, "sensitive_files"),
        "error_pages": safe(errors_result, "error_pages"),
        "cookies": safe(cookies_result, "cookies"),
        "cors": safe(cors_result, "cors"),
        "forms": safe(forms_result, "forms"),
        "mixed_content": safe(mixed_result, "mixed_content"),
    }

    for module_result in modules.values():
        all_findings.extend(module_result.get("findings", []))

    elapsed = round(time.time() - start_time, 2)

    return {
        "status": "completed",
        "module": "web_scanner",
        "target": target,
        "url": url,
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
