"""
Rutas de Gestión de Auditorías para AuditShield.
Permite programar, ejecutar, cancelar y listar auditorías de seguridad.
"""

import json
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User, UserRole
from app.models.audit import Audit, AuditStatus, Finding, Asset
from app.schemas.audit import AuditCreate, AuditResponse, AuditListResponse, FindingResponse, FindingUpdate
from app.workers.celery_app import run_audit_task, celery_app

router = APIRouter()


@router.get("", response_model=List[AuditListResponse])
async def list_audits(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lista todas las auditorías de la organización del usuario actual."""
    if current_user.role == UserRole.SUPERADMIN.value:
        query = select(Audit).order_by(desc(Audit.created_at))
    else:
        query = select(Audit).where(
            Audit.organization_id == current_user.organization_id
        ).order_by(desc(Audit.created_at))
        
    result = await db.execute(query)
    return result.scalars().all()


@router.post("", response_model=AuditResponse, status_code=status.HTTP_201_CREATED)
async def create_audit(
    audit_in: AuditCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Crea una nueva auditoría e inicia la tarea asíncrona en Celery."""
    # Verificar si el asset existe y pertenece a la misma organización
    if audit_in.asset_id:
        asset = await db.get(Asset, audit_in.asset_id)
        if not asset or (current_user.role != UserRole.SUPERADMIN.value and asset.organization_id != current_user.organization_id):
            raise HTTPException(status_code=404, detail="El activo especificado no fue encontrado.")

    # Módulos por defecto si es un perfil predefinido
    from app.services.audit_engine import get_modules_for_profile
    modules = audit_in.modules
    if audit_in.profile != "custom":
        modules = get_modules_for_profile(audit_in.profile)

    new_audit = Audit(
        title=audit_in.title,
        target=audit_in.target,
        target_type=audit_in.target_type,
        profile=audit_in.profile,
        modules=modules,
        status=AuditStatus.PENDING.value,
        progress=0,
        summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
        scan_options={
            **audit_in.scan_options,
            "auto_generate_pdf": audit_in.scan_options.get("auto_generate_pdf", True)
        },
        organization_id=current_user.organization_id,
        created_by=current_user.id,
        asset_id=audit_in.asset_id,
    )
    
    db.add(new_audit)
    await db.commit()
    await db.refresh(new_audit)

    # Lanzar tarea de auditoría
    from app.workers.celery_app import _REDIS_AVAILABLE
    if _REDIS_AVAILABLE:
        # Modo producción: cola Celery con Redis
        run_audit_task.delay(new_audit.id)
    else:
        # Modo desarrollo: ejecutar en background thread para no bloquear la respuesta
        import threading
        import asyncio
        from app.workers.celery_app import execute_audit

        def run_in_thread(audit_id: int):
            asyncio.run(execute_audit(audit_id))

        thread = threading.Thread(target=run_in_thread, args=(new_audit.id,), daemon=True)
        thread.start()

    return AuditResponse.model_validate(new_audit.__dict__)


@router.get("/{audit_id}", response_model=AuditResponse)
async def get_audit(
    audit_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Obtiene el detalle completo de una auditoría, incluyendo sus hallazgos."""
    query = select(Audit).where(Audit.id == audit_id).options(
        selectinload(Audit.findings)
    )
    result = await db.execute(query)
    audit = result.scalar_one_or_none()

    if not audit:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada.")

    # Permisos
    if current_user.role != UserRole.SUPERADMIN.value and audit.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Acceso denegado a esta auditoría.")

    return audit


@router.delete("/{audit_id}", status_code=status.HTTP_200_OK)
async def delete_audit(
    audit_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Elimina una auditoría y todos sus hallazgos asociados (Cascade)."""
    audit = await db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada.")

    if current_user.role != UserRole.SUPERADMIN.value and audit.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Permisos insuficientes.")

    await db.delete(audit)
    await db.commit()
    return {"message": "Auditoría eliminada correctamente."}


@router.get("/{audit_id}/findings", response_model=List[FindingResponse])
async def list_findings(
    audit_id: int,
    severity: Optional[str] = Query(None, description="Filtrar por severidad: critical, high, medium, low, info"),
    module: Optional[str] = Query(None, description="Filtrar por módulo"),
    is_remediated: Optional[bool] = Query(None, description="Filtrar por vulnerabilidades resueltas"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lista los hallazgos de una auditoría con filtros."""
    # Validar acceso
    audit = await db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada.")
        
    if current_user.role != UserRole.SUPERADMIN.value and audit.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Acceso denegado.")

    # Construir query de hallazgos
    query = select(Finding).where(Finding.audit_id == audit_id)
    if severity:
        query = query.where(Finding.severity == severity.lower())
    if module:
        query = query.where(Finding.module == module)
    if is_remediated is not None:
        query = query.where(Finding.is_remediated == is_remediated)

    query = query.order_by(Finding.id)
    result = await db.execute(query)
    return result.scalars().all()


@router.put("/{audit_id}/findings/{finding_id}", response_model=FindingResponse)
async def update_finding(
    audit_id: int,
    finding_id: int,
    finding_in: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Permite marcar un hallazgo como Falso Positivo o Remediado/Solucionado."""
    # Validar acceso
    audit = await db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada.")
        
    if current_user.role != UserRole.SUPERADMIN.value and audit.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Acceso denegado.")

    finding = await db.get(Finding, finding_id)
    if not finding or finding.audit_id != audit_id:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado.")

    # Aplicar cambios
    if finding_in.is_false_positive is not None:
        finding.is_false_positive = finding_in.is_false_positive
    
    if finding_in.is_remediated is not None:
        finding.is_remediated = finding_in.is_remediated
        if finding_in.is_remediated:
            finding.remediated_at = datetime.utcnow()
        else:
            finding.remediated_at = None

    await db.commit()
    await db.refresh(finding)
    return finding


@router.post("/{audit_id}/cancel")
async def cancel_audit(
    audit_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Cancela una auditoría activa en curso."""
    audit = await db.get(Audit, audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada.")

    if current_user.role != UserRole.SUPERADMIN.value and audit.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Permisos insuficientes.")

    if audit.status != AuditStatus.RUNNING.value and audit.status != AuditStatus.PENDING.value:
        raise HTTPException(
            status_code=400,
            detail=f"No se puede cancelar una auditoría con estado: {audit.status}"
        )

    # Actualizar estado en la base de datos
    audit.status = AuditStatus.CANCELLED.value
    audit.completed_at = datetime.utcnow()
    await db.commit()

    # Opcional: Cancelar la tarea Celery si es posible
    # Dado que no tenemos guardado el celery_task_id en la base de datos de manera estricta,
    # el cambio de estado en la base de datos detendrá futuros módulos en la ejecución.
    # Si deseamos revocar en celery de todas formas, podemos notificar al worker por canal Redis
    import redis
    redis_client = redis.from_url(settings.REDIS_URL)
    channel = f"audit_channel_{audit_id}"
    redis_client.publish(channel, json.dumps({
        "type": "error",
        "audit_id": audit_id,
        "message": "Auditoría cancelada por el usuario.",
        "progress": audit.progress
    }))

    return {"message": "Solicitud de cancelación enviada correctamente."}
