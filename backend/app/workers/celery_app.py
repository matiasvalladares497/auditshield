"""
Worker Celery para AuditShield.
Maneja la ejecución asíncrona de las tareas de auditoría de seguridad.
"""

import asyncio
import logging
import json
import time
from datetime import datetime
from celery import Celery
import redis

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.audit import Audit, AuditStatus, Finding, Asset
from app.models.user import Organization
from app.services.audit_engine import (
    calculate_security_score,
    get_score_letter,
    create_finding_id,
    summarize_findings
)
from app.services.report_engine import generate_pdf_report

# Scanners
from app.scanners.osint import run_osint_scan
from app.scanners.port_scanner import run_port_scan
from app.scanners.ssl_analyzer import run_ssl_scan
from app.scanners.web_scanner import run_web_scan
from app.scanners.dns_auditor import run_dns_scan
from app.scanners.cve_matcher import run_cve_scan
from app.scanners.waf_detector import run_waf_scan
from app.scanners.compliance_checker import run_compliance_scan

logger = logging.getLogger(__name__)

# Configuración de Celery
_REDIS_AVAILABLE = True
try:
    _test_redis = redis.from_url(settings.REDIS_URL)
    _test_redis.ping()
except Exception:
    _REDIS_AVAILABLE = False
    logger.warning("Redis no disponible — modo desarrollo sin cola de tareas.")

celery_app = Celery(
    "auditshield_tasks",
    broker=settings.REDIS_URL if _REDIS_AVAILABLE else "memory://",
    backend=settings.REDIS_URL if _REDIS_AVAILABLE else "cache+memory://"
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # En modo dev sin Redis, ejecutar tareas de forma síncrona
    task_always_eager=not _REDIS_AVAILABLE,
)

# Conexión Redis directa para mensajería pub/sub WebSocket (opcional)
_redis_client = None
if _REDIS_AVAILABLE:
    try:
        _redis_client = redis.from_url(settings.REDIS_URL)
    except Exception as e:
        logger.warning(f"No se pudo conectar a Redis para pub/sub: {e}")


def publish_audit_log(audit_id: int, log_type: str, message: str, progress: int, data: dict = None):
    """Publica un mensaje de log/progreso a Redis Pub/Sub (opcional en dev)."""
    payload = {
        "type": log_type,  # progress, log, finding, complete, error
        "audit_id": audit_id,
        "message": message,
        "progress": progress,
        "timestamp": datetime.utcnow().isoformat(),
        "data": data or {}
    }
    channel = f"audit_channel_{audit_id}"
    if _redis_client:
        try:
            _redis_client.publish(channel, json.dumps(payload))
        except Exception as e:
            logger.warning(f"No se pudo publicar a Redis: {e}")
    logger.info(f"[Audit {audit_id}] [{log_type.upper()}] ({progress}%): {message}")


async def execute_audit(audit_id: int):
    """
    Función interna asíncrona que ejecuta el flujo completo del escaneo.
    Reutiliza la base de datos async.
    """
    async with AsyncSessionLocal() as db:
        # Obtener auditoría
        audit = await db.get(Audit, audit_id)
        if not audit:
            logger.error(f"Auditoría {audit_id} no encontrada en la base de datos.")
            return
        
        # Validar estado inicial
        if audit.status == AuditStatus.RUNNING:
            logger.warning(f"Auditoría {audit_id} ya se está ejecutando.")
            return

        # Actualizar a Running
        audit.status = AuditStatus.RUNNING
        audit.started_at = datetime.utcnow()
        audit.progress = 5
        audit.current_module = "Reconocimiento Inicial"
        await db.commit()
        
        publish_audit_log(audit_id, "progress", "Iniciando escaneo...", 5)
        
        target = audit.target
        modules = audit.modules  # dict: {module_name: bool}
        scan_options = audit.scan_options
        
        all_findings = []
        raw_results = {}
        detected_technologies = []
        
        # 1. OSINT / Reconocimiento (Siempre corre o es prerrequisito para cve/web)
        if modules.get("osint", True):
            publish_audit_log(audit_id, "log", "Ejecutando módulo OSINT y Reconocimiento...", 10)
            audit.current_module = "OSINT"
            audit.progress = 10
            await db.commit()
            
            try:
                osint_res = await run_osint_scan(target)
                raw_results["osint"] = osint_res
                
                # Extraer hallazgos
                module_findings = osint_res.get("findings", [])
                all_findings.extend(module_findings)
                
                # Extraer tecnologías para CVE matcher
                techs = osint_res.get("data", {}).get("fingerprint", {}).get("technologies", [])
                for t in techs:
                    detected_technologies.append({"name": t, "version": ""})
                
                publish_audit_log(
                    audit_id,
                    "log",
                    f"OSINT completado. Hallazgos: {len(module_findings)}. Tecnologías detectadas: {len(techs)}",
                    25
                )
            except Exception as e:
                logger.error(f"Error en módulo OSINT: {e}")
                publish_audit_log(audit_id, "log", f"Módulo OSINT falló: {str(e)}", 25)
                raw_results["osint"] = {"status": "error", "error": str(e)}

        # 2. Seguridad DNS
        if modules.get("dns", True) or modules.get("email_security", True):
            publish_audit_log(audit_id, "log", "Ejecutando auditoría de seguridad DNS y SPF/DMARC...", 30)
            audit.current_module = "DNS & Email"
            audit.progress = 30
            await db.commit()
            
            try:
                dns_res = await run_dns_scan(target)
                raw_results["dns"] = dns_res
                
                module_findings = dns_res.get("findings", [])
                all_findings.extend(module_findings)
                publish_audit_log(audit_id, "log", f"Seguridad DNS completada. Hallazgos: {len(module_findings)}", 45)
            except Exception as e:
                logger.error(f"Error en módulo DNS: {e}")
                publish_audit_log(audit_id, "log", f"Módulo DNS/Email falló: {str(e)}", 45)
                raw_results["dns"] = {"status": "error", "error": str(e)}

        # 3. Escaneo de Puertos
        if modules.get("port_scan", True):
            publish_audit_log(audit_id, "log", "Ejecutando escaneo de puertos TCP...", 50)
            audit.current_module = "Port Scan"
            audit.progress = 50
            await db.commit()
            
            try:
                loop = asyncio.get_event_loop()
                port_res = await loop.run_in_executor(None, run_port_scan, target, scan_options)
                raw_results["port_scan"] = port_res
                
                module_findings = port_res.get("findings", [])
                all_findings.extend(module_findings)
                
                # Extraer tecnologías de banners de puertos
                open_ports = port_res.get("data", {}).get("open_ports", {})
                for p, info in open_ports.items():
                    prod = info.get("product")
                    ver = info.get("version")
                    if prod:
                        detected_technologies.append({"name": prod, "version": ver})
                        
                publish_audit_log(audit_id, "log", f"Escaneo de puertos completado. Hallazgos: {len(module_findings)}", 65)
            except Exception as e:
                logger.error(f"Error en módulo Port Scan: {e}")
                publish_audit_log(audit_id, "log", f"Módulo Port Scan falló: {str(e)}", 65)
                raw_results["port_scan"] = {"status": "error", "error": str(e)}

        # 4. SSL/TLS Analyzer
        if modules.get("ssl", True):
            publish_audit_log(audit_id, "log", "Analizando configuración SSL/TLS...", 70)
            audit.current_module = "SSL/TLS"
            audit.progress = 70
            await db.commit()
            
            try:
                ssl_res = await run_ssl_scan(target)
                raw_results["ssl"] = ssl_res
                
                module_findings = ssl_res.get("findings", [])
                all_findings.extend(module_findings)
                publish_audit_log(audit_id, "log", f"Análisis SSL completado. Hallazgos: {len(module_findings)}", 80)
            except Exception as e:
                logger.error(f"Error en módulo SSL: {e}")
                publish_audit_log(audit_id, "log", f"Módulo SSL falló: {str(e)}", 80)
                raw_results["ssl"] = {"status": "error", "error": str(e)}

        # 5. Auditoría Web (OWASP Top 10)
        if modules.get("web", True) or modules.get("info_exposure", True):
            publish_audit_log(audit_id, "log", "Realizando escaneo web de vulnerabilidades OWASP...", 82)
            audit.current_module = "OWASP Web Scan"
            audit.progress = 82
            await db.commit()
            
            try:
                # Asegurar formato URL para el scanner web
                web_target = target
                if not web_target.startswith(("http://", "https://")):
                    web_target = f"http://{web_target}"
                
                web_res = await run_web_scan(web_target)
                raw_results["web"] = web_res
                
                module_findings = web_res.get("findings", [])
                all_findings.extend(module_findings)
                
                # Extraer tecnologías detectadas por cabeceras HTTP o cookies
                server = web_res.get("data", {}).get("headers", {}).get("server")
                if server:
                    detected_technologies.append({"name": server, "version": ""})
                
                publish_audit_log(audit_id, "log", f"Auditoría web completada. Hallazgos: {len(module_findings)}", 90)
            except Exception as e:
                logger.error(f"Error en módulo Web: {e}")
                publish_audit_log(audit_id, "log", f"Módulo Web falló: {str(e)}", 90)
                raw_results["web"] = {"status": "error", "error": str(e)}

        # 6. CVE Matching
        if modules.get("cve_matching", True) and detected_technologies:
            publish_audit_log(audit_id, "log", f"Correlacionando {len(detected_technologies)} tecnologías con base de datos CVE...", 92)
            audit.current_module = "CVE Matcher"
            audit.progress = 92
            await db.commit()
            
            try:
                cve_res = await run_cve_scan(detected_technologies, settings.NVD_API_KEY)
                raw_results["cve_matching"] = cve_res
                
                module_findings = cve_res.get("findings", [])
                all_findings.extend(module_findings)
                publish_audit_log(audit_id, "log", f"Correlación de CVEs completada. Hallazgos: {len(module_findings)}", 93)
            except Exception as e:
                logger.error(f"Error en módulo CVE matcher: {e}")
                publish_audit_log(audit_id, "log", f"Módulo CVE Matcher falló: {str(e)}", 93)
                raw_results["cve_matching"] = {"status": "error", "error": str(e)}

        # 6.5. WAF Detection
        if modules.get("waf_detection", True):
            publish_audit_log(audit_id, "log", "Ejecutando detección de Firewall de Aplicación Web (WAF)...", 94)
            audit.current_module = "WAF Detection"
            audit.progress = 94
            await db.commit()
            
            try:
                waf_res = await run_waf_scan(target)
                raw_results["waf_detection"] = waf_res
                module_findings = waf_res.get("findings", [])
                all_findings.extend(module_findings)
                publish_audit_log(audit_id, "log", f"Detección de WAF completada. Hallazgos: {len(module_findings)}", 95)
            except Exception as e:
                logger.error(f"Error en WAF detection: {e}")
                publish_audit_log(audit_id, "log", f"Módulo WAF detector falló: {str(e)}", 95)
                raw_results["waf_detection"] = {"status": "error", "error": str(e)}

        # 6.6. Compliance Evaluation
        if modules.get("compliance", True):
            publish_audit_log(audit_id, "log", "Evaluando cumplimiento normativo (ASVS / ISO / NIST)...", 96)
            audit.current_module = "Compliance Checker"
            audit.progress = 96
            await db.commit()
            
            try:
                loop = asyncio.get_event_loop()
                compliance_res = await loop.run_in_executor(None, run_compliance_scan, target, all_findings)
                raw_results["compliance"] = compliance_res
                module_findings = compliance_res.get("findings", [])
                all_findings.extend(module_findings)
                publish_audit_log(audit_id, "log", f"Evaluación de cumplimiento completada. Hallazgos: {len(module_findings)}", 97)
            except Exception as e:
                logger.error(f"Error en compliance check: {e}")
                publish_audit_log(audit_id, "log", f"Módulo Compliance falló: {str(e)}", 97)
                raw_results["compliance"] = {"status": "error", "error": str(e)}

        # 7. Post-procesamiento y almacenamiento de hallazgos
        publish_audit_log(audit_id, "log", "Consolidando hallazgos y calculando score final...", 96)
        
        # Eliminar duplicados o formatear hallazgos
        final_findings = []
        for idx, f in enumerate(all_findings):
            # Asegurar estructura del hallazgo
            severity = f.get("severity", "Info").lower()
            title = f.get("title", "Hallazgo sin título")
            description = f.get("description", "")
            evidence = f.get("evidence", "")
            impact = f.get("impact", "")
            recommendation = f.get("recommendation", "")
            references = f.get("references", [])
            
            # Generar ID
            f_id = create_finding_id(audit_id, idx + 1)
            
            db_finding = Finding(
                audit_id=audit_id,
                finding_id=f_id,
                title=title,
                severity=severity,
                module=f.get("module", audit.current_module or "General"),
                cvss_score=f.get("cvss_score"),
                cvss_vector=f.get("cvss_vector"),
                cve_id=f.get("cve_id"),
                cwe_id=f.get("cwe_id"),
                description=description,
                evidence=evidence,
                impact=impact,
                recommendation=recommendation,
                references=references,
            )
            db.add(db_finding)
            final_findings.append({
                "severity": severity,
                "title": title,
                "description": description,
                "evidence": evidence,
                "impact": impact,
                "recommendation": recommendation,
                "references": references,
            })

        # Calcular scores
        score = calculate_security_score(final_findings)
        letter = get_score_letter(score)
        summary = summarize_findings(final_findings)
        
        audit.security_score = score
        audit.score_letter = letter
        audit.summary = summary
        audit.raw_results = raw_results
        audit.status = AuditStatus.COMPLETED
        audit.completed_at = datetime.utcnow()
        audit.progress = 98
        audit.current_module = "Generación de Reporte PDF"
        await db.commit()
        
        # Si tiene un asset asociado, actualizar historial de ese asset
        if audit.asset_id:
            asset = await db.get(Asset, audit.asset_id)
            if asset:
                asset.last_audited = audit.completed_at
                asset.last_score = score
                await db.commit()

        # 8. Reportes PDF opcionales
        pdf_generated = False
        pdf_path = None
        
        if audit.scan_options.get("auto_generate_pdf", True):
            publish_audit_log(audit_id, "log", "Generando reporte ejecutivo PDF profesional...", 98)
            try:
                # Convertir objeto SQLAlchemy a dict para el report engine
                audit_dict = {
                    "id": audit.id,
                    "title": audit.title,
                    "target": audit.target,
                    "target_type": audit.target_type,
                    "profile": audit.profile,
                    "status": audit.status,
                    "security_score": audit.security_score,
                    "score_letter": audit.score_letter,
                    "summary": audit.summary,
                    "started_at": audit.started_at.isoformat() if audit.started_at else None,
                    "completed_at": audit.completed_at.isoformat() if audit.completed_at else None,
                }
                
                # Generar PDF
                pdf_path = await generate_pdf_report(audit_dict, final_findings, "full")
                pdf_generated = True
                publish_audit_log(audit_id, "log", f"Reporte PDF guardado exitosamente en {pdf_path}", 99)
            except Exception as e:
                logger.error(f"Error generando reporte PDF: {e}")
                publish_audit_log(audit_id, "log", f"No se pudo generar el reporte PDF: {str(e)}", 99)

        # Finalizar auditoría
        audit.progress = 100
        audit.current_module = None
        await db.commit()
        
        # Publicar completado al WS
        publish_audit_log(audit_id, "complete", "Auditoría de ciberseguridad completada con éxito.", 100, {
            "score": score,
            "letter": letter,
            "summary": summary,
            "pdf_generated": pdf_generated,
            "pdf_path": pdf_path
        })


@celery_app.task(name="app.workers.celery_app.run_audit_task")
def run_audit_task(audit_id: int):
    """
    Tarea Celery expuesta para ejecutar la auditoría de forma asíncrona.
    """
    logger.info(f"Iniciando tarea Celery para auditoría ID: {audit_id}")
    try:
        # Ejecutar en el event loop
        asyncio.run(execute_audit(audit_id))
    except Exception as e:
        logger.error(f"Error fatal en tarea Celery de auditoría {audit_id}: {e}", exc_info=True)
        # Intentar marcar la auditoría como fallida en DB
        try:
            async def mark_failed():
                async with AsyncSessionLocal() as db:
                    audit = await db.get(Audit, audit_id)
                    if audit:
                        audit.status = AuditStatus.FAILED
                        audit.error_message = str(e)
                        audit.completed_at = datetime.utcnow()
                        await db.commit()
                        publish_audit_log(audit_id, "error", f"Error fatal: {str(e)}", 100)
            asyncio.run(mark_failed())
        except Exception as db_err:
            logger.error(f"No se pudo guardar el estado de error de la auditoría en la DB: {db_err}")
