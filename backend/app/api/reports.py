"""
Rutas de Gestión de Reportes para AuditShield.
Permite listar, generar y descargar los reportes ejecutivos/técnicos en PDF.
"""

import os
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User, UserRole
from app.models.audit import Audit, Report, AuditStatus, Finding
from app.schemas.audit import ReportResponse, ReportCreate
from app.services.report_engine import generate_pdf_report

router = APIRouter()


@router.get("", response_model=List[ReportResponse])
async def list_reports(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lista todos los reportes PDF generados de la organización."""
    if current_user.role == UserRole.SUPERADMIN.value:
        query = select(Report).order_by(desc(Report.created_at))
    else:
        # Unir con Audit para filtrar por organización del usuario
        query = select(Report).join(Audit).where(
            Audit.organization_id == current_user.organization_id
        ).order_by(desc(Report.created_at))
        
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/generate", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def generate_report(
    report_in: ReportCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Genera manualmente un nuevo reporte PDF para una auditoría finalizada."""
    # Buscar la auditoría y validar pertenencia
    audit = await db.get(Audit, report_in.audit_id)
    if not audit or (current_user.role != UserRole.SUPERADMIN.value and audit.organization_id != current_user.organization_id):
        raise HTTPException(status_code=404, detail="La auditoría especificada no existe.")

    if audit.status != AuditStatus.COMPLETED.value:
        raise HTTPException(
            status_code=400,
            detail="Solo se pueden generar reportes para auditorías con estado 'completed'."
        )

    # Obtener los hallazgos asociados
    result = await db.execute(select(Finding).where(Finding.audit_id == audit.id))
    findings = result.scalars().all()
    
    # Convertir hallazgos a formato dict para el motor de reportes
    findings_list = []
    for f in findings:
        findings_list.append({
            "severity": f.severity,
            "title": f.title,
            "module": f.module,
            "cvss_score": f.cvss_score,
            "cvss_vector": f.cvss_vector,
            "cve_id": f.cve_id,
            "cwe_id": f.cwe_id,
            "description": f.description,
            "evidence": f.evidence,
            "impact": f.impact,
            "recommendation": f.recommendation,
            "references": f.references
        })

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

    # Obtener historial de auditorías previas del mismo target
    prev_query = select(Audit).where(
        Audit.target == audit.target,
        Audit.status == AuditStatus.COMPLETED.value,
        Audit.id != audit.id,
        Audit.completed_at <= audit.completed_at
    ).order_by(desc(Audit.completed_at))
    prev_result = await db.execute(prev_query)
    prev_audits = prev_result.scalars().all()
    
    prev_audits_list = []
    for pa in prev_audits:
        prev_audits_list.append({
            "id": pa.id,
            "title": pa.title,
            "security_score": pa.security_score,
            "score_letter": pa.score_letter,
            "completed_at": pa.completed_at.isoformat() if pa.completed_at else None,
            "summary": pa.summary
        })

    try:
        # Generar el archivo físico PDF
        pdf_path = await generate_pdf_report(
            audit_dict, 
            findings_list, 
            report_in.report_type,
            previous_audits=prev_audits_list
        )
        
        # Calcular tamaño del archivo
        file_size = os.path.getsize(pdf_path) if os.path.exists(pdf_path) else 0

        # Registrar el reporte en base de datos
        new_report = Report(
            audit_id=audit.id,
            report_type=report_in.report_type,
            file_path=pdf_path,
            file_size=file_size,
            generated_by=current_user.id
        )
        
        db.add(new_report)
        await db.commit()
        await db.refresh(new_report)
        return new_report
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al generar el reporte PDF: {str(e)}"
        )


@router.get("/{report_id}/download")
async def download_report(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Descarga el archivo PDF de un reporte específico."""
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Reporte no encontrado.")

    # Validar permisos (Unir con Audit)
    audit = await db.get(Audit, report.audit_id)
    if current_user.role != UserRole.SUPERADMIN.value and audit.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Acceso denegado a este reporte.")

    if not report.file_path or not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="El archivo PDF físico no existe en el servidor.")

    filename = os.path.basename(report.file_path)
    return FileResponse(
        path=report.file_path,
        media_type="application/pdf",
        filename=filename
    )


@router.delete("/{report_id}", status_code=status.HTTP_200_OK)
async def delete_report(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Elimina el registro de un reporte en DB y su archivo PDF del disco."""
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Reporte no encontrado.")

    # Validar permisos
    audit = await db.get(Audit, report.audit_id)
    if current_user.role != UserRole.SUPERADMIN.value and audit.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Permisos insuficientes.")

    # Eliminar archivo físico
    if report.file_path and os.path.exists(report.file_path):
        try:
            os.remove(report.file_path)
        except Exception as e:
            # Continuar aunque no se pueda borrar de disco
            pass

    await db.delete(report)
    await db.commit()
    return {"message": "Reporte eliminado correctamente."}
