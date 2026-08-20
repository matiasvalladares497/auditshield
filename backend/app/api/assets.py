"""
Rutas de Gestión de Activos (Assets) para AuditShield.
Permite registrar y monitorear dominios, subdominios, IPs y rangos de red.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User, UserRole
from app.models.audit import Asset, Audit
from app.schemas.audit import AssetCreate, AssetResponse, AuditListResponse

router = APIRouter()


@router.get("", response_model=List[AssetResponse])
async def list_assets(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lista todos los activos registrados de la organización del usuario actual."""
    if current_user.role == UserRole.SUPERADMIN.value:
        query = select(Asset).order_by(desc(Asset.created_at))
    else:
        query = select(Asset).where(
            Asset.organization_id == current_user.organization_id,
            Asset.is_active == True
        ).order_by(desc(Asset.created_at))
        
    result = await db.execute(query)
    return result.scalars().all()


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    asset_in: AssetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Registra un nuevo activo en la plataforma."""
    new_asset = Asset(
        name=asset_in.name,
        target=asset_in.target,
        asset_type=asset_in.asset_type,
        description=asset_in.description,
        tags=asset_in.tags,
        organization_id=current_user.organization_id,
        is_active=True
    )
    db.add(new_asset)
    await db.commit()
    await db.refresh(new_asset)
    return new_asset


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Obtiene el detalle de un activo específico."""
    asset = await db.get(Asset, asset_id)
    if not asset or (current_user.role != UserRole.SUPERADMIN.value and asset.organization_id != current_user.organization_id):
        raise HTTPException(status_code=404, detail="Activo no encontrado.")
    return asset


@router.get("/{asset_id}/audits", response_model=List[AuditListResponse])
async def get_asset_audits(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Obtiene el historial de auditorías ejecutadas sobre un activo específico."""
    asset = await db.get(Asset, asset_id)
    if not asset or (current_user.role != UserRole.SUPERADMIN.value and asset.organization_id != current_user.organization_id):
        raise HTTPException(status_code=404, detail="Activo no encontrado.")

    query = select(Audit).where(Audit.asset_id == asset_id).order_by(desc(Audit.created_at))
    result = await db.execute(query)
    return result.scalars().all()


@router.put("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: int,
    asset_in: AssetCreate,  # Reusar campos de creación
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Actualiza la información de un activo registrado."""
    asset = await db.get(Asset, asset_id)
    if not asset or (current_user.role != UserRole.SUPERADMIN.value and asset.organization_id != current_user.organization_id):
        raise HTTPException(status_code=404, detail="Activo no encontrado.")

    asset.name = asset_in.name
    asset.target = asset_in.target
    asset.asset_type = asset_in.asset_type
    asset.description = asset_in.description
    asset.tags = asset_in.tags

    await db.commit()
    await db.refresh(asset)
    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_200_OK)
async def delete_asset(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Desactiva un activo (Soft Delete)."""
    asset = await db.get(Asset, asset_id)
    if not asset or (current_user.role != UserRole.SUPERADMIN.value and asset.organization_id != current_user.organization_id):
        raise HTTPException(status_code=404, detail="Activo no encontrado.")

    asset.is_active = False
    await db.commit()
    return {"message": "Activo eliminado correctamente."}
