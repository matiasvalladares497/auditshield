"""
Módulo Port Scanner para AuditShield.
Escanea puertos y servicios del target y detecta servicios peligrosos expuestos.
Usa nmap como motor principal y socket-scanner como fallback de respaldo.
"""

import asyncio
import logging
import socket
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Puertos y servicios comunes para banner grabbing y análisis
COMMON_PORTS = {
    21: {"service": "ftp", "dangerous": True, "description": "Protocolo de transferencia de archivos inseguro (FTP). Las credenciales se transmiten en texto plano."},
    22: {"service": "ssh", "dangerous": False, "description": "Secure Shell para acceso remoto cifrado."},
    23: {"service": "telnet", "dangerous": True, "description": "Protocolo de acceso remoto obsoleto e inseguro (Telnet). Transmite todo en texto plano."},
    25: {"service": "smtp", "dangerous": False, "description": "Servidor de correo (Simple Mail Transfer Protocol)."},
    53: {"service": "dns", "dangerous": False, "description": "Servidor de nombres de dominio (DNS)."},
    80: {"service": "http", "dangerous": False, "description": "Servidor web sin cifrar (HTTP)."},
    110: {"service": "pop3", "dangerous": False, "description": "Protocolo de descarga de correos (POP3) sin cifrar."},
    135: {"service": "msrpc", "dangerous": True, "description": "Microsoft RPC Endpoint Mapper. Altamente expuesto a ataques de enumeración."},
    139: {"service": "netbios-ssn", "dangerous": True, "description": "NetBIOS Session Service. Expone detalles de red interna."},
    143: {"service": "imap", "dangerous": False, "description": "Protocolo de acceso a correos (IMAP) sin cifrar."},
    443: {"service": "https", "dangerous": False, "description": "Servidor web cifrado (HTTPS)."},
    445: {"service": "microsoft-ds", "dangerous": True, "description": "Servicio Microsoft SMB (Server Message Block). Altamente vulnerable a exploits como EternalBlue."},
    1433: {"service": "mssql", "dangerous": True, "description": "Microsoft SQL Server. Base de datos expuesta directamente a Internet."},
    3306: {"service": "mysql", "dangerous": True, "description": "MySQL Database Server. Base de datos expuesta directamente a Internet."},
    3389: {"service": "ms-wbt-server", "dangerous": True, "description": "Microsoft Remote Desktop (RDP). Blanco constante de ataques de fuerza bruta."},
    5432: {"service": "postgresql", "dangerous": True, "description": "PostgreSQL Database Server. Base de datos expuesta directamente a Internet."},
    8080: {"service": "http-proxy", "dangerous": False, "description": "Servidor web alternativo o proxy."},
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


async def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Intenta obtener el banner de bienvenida del puerto enviando una solicitud básica."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        # Algunos servicios requieren que enviemos algo para responder (HTTP, etc.)
        if port in [80, 8080]:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
        
        banner_data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        
        banner = banner_data.decode("utf-8", errors="ignore").strip()
        # Truncar banners gigantescos
        return banner[:150]
    except Exception:
        return "No banner available (Connection reset or timeout)"


async def _fallback_socket_scan(target_ip: str, ports: List[int]) -> Dict[int, Dict[str, Any]]:
    """Escaneo básico y asíncrono usando socket fallback cuando nmap no está."""
    open_ports = {}
    
    async def scan_single_port(port: int):
        try:
            # Intentar conexión TCP rápida
            conn = asyncio.open_connection(target_ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1.0)
            writer.close()
            await writer.wait_closed()
            
            # Obtener banner e info por defecto
            banner = await _grab_banner(target_ip, port)
            info = COMMON_PORTS.get(port, {"service": "unknown", "dangerous": False, "description": "Servicio desconocido"})
            
            open_ports[port] = {
                "port": port,
                "name": info["service"],
                "product": "",
                "version": "",
                "extrainfo": banner,
                "reason": "syn-ack",
                "state": "open"
            }
        except Exception:
            pass

    # Ejecutar tareas concurrentemente con límite de concurrencia
    sem = asyncio.Semaphore(50)  # límite de 50 puertos a la vez
    
    async def worker(port):
        async with sem:
            await scan_single_port(port)

    await asyncio.gather(*(worker(p) for p in ports))
    return open_ports


def _parse_port_range(port_range_str: str) -> List[int]:
    """Parsea un rango de puertos como '1-1000' o '80,443' en una lista de enteros."""
    ports = []
    try:
        if "," in port_range_str:
            return [int(p.strip()) for p in port_range_str.split(",") if p.strip().isdigit()]
        
        if "-" in port_range_str:
            start_str, end_str = port_range_str.split("-")
            start, end = int(start_str), int(end_str)
            return list(range(max(1, start), min(65535, end) + 1))
        
        if port_range_str.isdigit():
            return [int(port_range_str)]
    except Exception as e:
        logger.warning(f"Error parsing port range '{port_range_str}': {e}. Using default range.")
    
    return list(range(1, 1001))  # Default top 1000


def scan_ports(target: str, port_range: str = "1-1000", scan_type: str = "normal") -> Dict[str, Any]:
    """
    Función principal de escaneo de puertos.
    Usa python-nmap si está disponible y funciona, de lo contrario cae a socket fallback.
    """
    results = {}
    scanner_type = "socket-fallback"
    ports_to_scan = _parse_port_range(port_range)
    
    try:
        # Resolver host por si es un nombre de dominio
        target_ip = socket.gethostbyname(target)
    except Exception as e:
        return {
            "status": "failed",
            "error": f"No se pudo resolver el host '{target}': {e}",
            "data": {},
            "findings": []
        }

    try:
        import nmap  # type: ignore
        nm = nmap.PortScanner()
        
        # Opciones de nmap
        # -sV: Detección de versiones de servicios
        # -T4: Intensidad/velocidad rápida
        arguments = "-sV -T4"
        if scan_type == "stealth":
            arguments = "-sS -T2 -f"  # Escaneo stealth con fragmentación
        elif scan_type == "aggressive":
            arguments = "-sV -sC -O -T4"  # Escaneo agresivo con scripts y OS detection

        logger.info(f"Lanzando escaneo nmap en {target_ip} (puertos {port_range}) con argumentos: {arguments}")
        nm.scan(target_ip, port_range, arguments=arguments)
        
        if target_ip in nm.all_hosts():
            host_info = nm[target_ip]
            scanner_type = "nmap"
            
            for proto in host_info.all_protocols():
                if proto == "tcp":
                    port_list = host_info["tcp"].keys()
                    for port in port_list:
                        port_data = host_info["tcp"][port]
                        if port_data["state"] == "open":
                            results[port] = {
                                "port": port,
                                "name": port_data.get("name", "unknown"),
                                "product": port_data.get("product", ""),
                                "version": port_data.get("version", ""),
                                "extrainfo": port_data.get("extrainfo", ""),
                                "reason": port_data.get("reason", "syn-ack"),
                                "state": "open"
                            }
    except Exception as e:
        logger.warning(f"Nmap scanner falló o no está instalado ({e}). Cambiando a socket fallback.")

    # Si nmap falló o no devolvió resultados, usar fallback asíncrono
    if not results:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Crear nueva tarea si estamos en loop asíncrono (FastAPI)
            future = asyncio.run_coroutine_threadsafe(_fallback_socket_scan(target_ip, ports_to_scan), loop)
            results = future.result()
        else:
            results = asyncio.run(_fallback_socket_scan(target_ip, ports_to_scan))

    return {
        "status": "completed",
        "scanner_used": scanner_type,
        "target_ip": target_ip,
        "data": results
    }


def check_dangerous_services(open_ports: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analiza los puertos abiertos en busca de servicios peligrosos expuestos."""
    findings = []
    
    for port, info in open_ports.items():
        port_info = COMMON_PORTS.get(port)
        if port_info and port_info["dangerous"]:
            service_name = info.get("name") or port_info["service"]
            product = info.get("product", "")
            version = info.get("version", "")
            
            evidence = f"Puerto: {port}/TCP\nServicio detectado: {service_name}"
            if product:
                evidence += f"\nSoftware: {product} {version}"
            
            severity = "High"
            # Servicios extremadamente críticos si están directamente en internet
            if port in [445, 135, 139]:
                severity = "Critical"
            elif port in [23, 21]:
                severity = "High"
            else:
                severity = "Medium"

            recommendation = (
                f"1. Deshabilite o restrinja el acceso al puerto {port}.\n"
                f"2. Si requiere el servicio, colóquelo detrás de una VPN corporativa.\n"
                f"3. Si el puerto debe permanecer público, configure firewalls para limitar las IPs autorizadas "
                f"y asegúrese de que el software esté actualizado y use contraseñas robustas."
            )
            
            findings.append(_build_finding(
                severity=severity,
                title=f"Servicio peligroso expuesto: {service_name.upper()} (Puerto {port})",
                description=port_info["description"],
                evidence=evidence,
                impact="Un atacante puede intentar explotar vulnerabilidades conocidas en el servicio expuesto o realizar ataques de fuerza bruta para obtener acceso no autorizado.",
                recommendation=recommendation,
                references=[
                    f"https://cwe.mitre.org/data/definitions/284.html",
                    f"https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_Security_Cheat_Sheet.html"
                ]
            ))
            
    return findings


def run_port_scan(target: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
    """Punto de entrada del módulo de escaneo de puertos."""
    port_range = options.get("port_range", "1-1000")
    intensity = options.get("intensity", "normal")
    
    logger.info(f"Iniciando auditoría de puertos sobre {target} (Puertos: {port_range})")
    
    scan_res = scan_ports(target, port_range, intensity)
    if scan_res["status"] == "failed":
        return scan_res
        
    open_ports = scan_res["data"]
    findings = check_dangerous_services(open_ports)
    
    # Agregar un hallazgo informativo que lista todos los puertos TCP abiertos
    if open_ports:
        open_list = [f"{p}/tcp ({info['name']}) {info['product']} {info['version']}".strip() for p, info in open_ports.items()]
        evidence = "\n".join(open_list)
        findings.append(_build_finding(
            severity="Info",
            title="Puertos TCP Abiertos Detectados",
            description="Se detectaron los siguientes puertos TCP abiertos en el host remoto durante el escaneo.",
            evidence=evidence,
            impact="La exposición de puertos incrementa la superficie de ataque del sistema remoto.",
            recommendation="Cierre los puertos expuestos que no sean estrictamente necesarios para la operación del sistema.",
            references=["https://nmap.org/book/man.html"]
        ))
    else:
        findings.append(_build_finding(
            severity="Info",
            title="Sin puertos abiertos detectados",
            description="El escaneo de puertos no arrojó ningún puerto TCP abierto en el rango especificado.",
            evidence="Rango analizado: " + port_range,
            impact="Superficie de ataque minimizada por bloqueo/firewall.",
            recommendation="Mantener la política de firewall actual y realizar auditorías periódicas.",
            references=[]
        ))
        
    return {
        "status": "completed",
        "data": {
            "scanner_used": scan_res["scanner_used"],
            "target_ip": scan_res["target_ip"],
            "open_ports": open_ports
        },
        "findings": findings
    }
