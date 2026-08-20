"""
Rutas de Gestión de Usuarios para AuditShield.
Maneja operaciones CRUD sobre usuarios de la organización.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user, get_password_hash, get_current_active_admin
from app.models.user import User, UserRole
from app.schemas.user import UserResponse, UserCreate, UserUpdate

router = APIRouter()


@router.get("", response_model=List[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_admin)
):
    """Lista todos los usuarios pertenecientes a la misma organización (Solo admins)."""
    # Si es SuperAdmin, puede ver todos los usuarios del sistema.
    if current_user.role == UserRole.SUPERADMIN.value:
        result = await db.execute(select(User))
    else:
        result = await db.execute(
            select(User).where(User.organization_id == current_user.organization_id)
        )
    return result.scalars().all()


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_admin)
):
    """Crea un nuevo usuario dentro de la organización (Solo admins)."""
    # Validar que el admin no intente crear un usuario en otra organización
    org_id = current_user.organization_id
    if current_user.role == UserRole.SUPERADMIN.value and user_in.organization_id:
        org_id = user_in.organization_id

    # Verificar si el correo electrónico ya existe
    result = await db.execute(select(User).where(User.email == user_in.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="El correo electrónico ya está registrado.")

    # Verificar si el nombre de usuario ya existe
    result = await db.execute(select(User).where(User.username == user_in.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="El nombre de usuario ya está registrado.")

    new_user = User(
        email=user_in.email,
        username=user_in.username,
        full_name=user_in.full_name,
        hashed_password=get_password_hash(user_in.password),
        role=user_in.role or UserRole.AUDITOR.value,
        organization_id=org_id,
        is_active=True,
        is_verified=True
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Obtiene los detalles de un usuario específico."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")

    # Seguridad: Un auditor/cliente normal solo puede verse a sí mismo.
    # Un admin solo puede ver usuarios de su propia organización.
    if current_user.role != UserRole.SUPERADMIN.value:
        if current_user.id != user.id:
            if current_user.role not in [UserRole.ADMIN.value, UserRole.SUPERADMIN.value]:
                raise HTTPException(status_code=403, detail="Permisos insuficientes.")
            if current_user.organization_id != user.organization_id:
                raise HTTPException(status_code=403, detail="El usuario pertenece a otra organización.")

    return user


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_in: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Actualiza la información de un usuario."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")

    # Permisos
    if current_user.role != UserRole.SUPERADMIN.value:
        if current_user.id != user.id and current_user.role != UserRole.ADMIN.value:
            raise HTTPException(status_code=403, detail="Permisos insuficientes.")
        if current_user.role == UserRole.ADMIN.value and current_user.organization_id != user.organization_id:
            raise HTTPException(status_code=403, detail="El usuario pertenece a otra organización.")

    # Aplicar actualizaciones
    if user_in.full_name is not None:
        user.full_name = user_in.full_name
    if user_in.email is not None:
        # Validar duplicados si cambia
        if user_in.email != user.email:
            email_check = await db.execute(select(User).where(User.email == user_in.email))
            if email_check.scalar_one_or_none():
                raise HTTPException(status_code=400, detail="El correo electrónico ya está en uso.")
            user.email = user_in.email
    if user_in.is_active is not None:
        # Solo admins pueden activar/desactivar
        if current_user.role not in [UserRole.ADMIN.value, UserRole.SUPERADMIN.value]:
            raise HTTPException(status_code=403, detail="Solo administradores pueden cambiar el estado activo.")
        user.is_active = user_in.is_active
    if user_in.role is not None:
        # Solo superadmins o admins (que no se degraden a sí mismos) pueden cambiar roles
        if current_user.role not in [UserRole.ADMIN.value, UserRole.SUPERADMIN.value]:
            raise HTTPException(status_code=403, detail="Solo administradores pueden cambiar roles.")
        if current_user.id == user.id:
            raise HTTPException(status_code=400, detail="No puedes cambiar tu propio rol.")
        user.role = user_in.role

    await db.commit()
    await db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=status.HTTP_200_OK)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_admin)
):
    """Desactiva temporal o permanentemente a un usuario (Soft Delete)."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")

    if current_user.id == user.id:
        raise HTTPException(status_code=400, detail="No puedes desactivarte a ti mismo.")

    if current_user.role != UserRole.SUPERADMIN.value and current_user.organization_id != user.organization_id:
        raise HTTPException(status_code=403, detail="El usuario pertenece a otra organización.")

    user.is_active = False
    await db.commit()
    return {"message": "Usuario desactivado correctamente."}
