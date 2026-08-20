"""
Rutas de Autenticación para AuditShield.
Maneja el registro, inicio de sesión, refresco de tokens y cierre de sesión.
"""

from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    get_current_user
)
from app.models.user import User, Organization, UserRole
from app.schemas.user import UserCreate, Token, UserResponse

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    """Registra un nuevo usuario en la plataforma."""
    # Verificar si el email ya existe
    result = await db.execute(select(User).where(User.email == user_in.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=400,
            detail="El correo electrónico ya está registrado."
        )

    # Verificar si el nombre de usuario ya existe
    result = await db.execute(select(User).where(User.username == user_in.username))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=400,
            detail="El nombre de usuario ya está registrado."
        )

    # Si no se provee organización, crear una por defecto para el usuario
    org_id = user_in.organization_id
    if not org_id:
        new_org = Organization(
            name=f"Organización de {user_in.full_name}",
            description="Organización creada por defecto al registrarse."
        )
        db.add(new_org)
        await db.flush()  # Para obtener el ID autogenerado
        org_id = new_org.id

    # Crear el usuario
    new_user = User(
        email=user_in.email,
        username=user_in.username,
        full_name=user_in.full_name,
        hashed_password=get_password_hash(user_in.password),
        role=user_in.role or UserRole.AUDITOR.value,
        organization_id=org_id,
        is_active=True,
        is_verified=False
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """
    Inicio de sesión estándar de OAuth2.
    Recibe username (que puede ser el email) y password.
    """
    # Buscar por email o username
    result = await db.execute(
        select(User).where(
            (User.email == form_data.username) | 
            (User.username == form_data.username)
        )
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El usuario está inactivo."
        )

    # Crear tokens
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id), "role": user.role},
        expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(data={"sub": str(user.id)})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": user
    }


@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_token: str,
    db: AsyncSession = Depends(get_db)
):
    """Genera un nuevo access token a partir de un refresh token válido."""
    from jose import jwt, JWTError
    try:
        payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if not user_id or token_type != "refresh":
            raise HTTPException(status_code=401, detail="Token de refresco inválido.")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token de refresco inválido o expirado.")

    result = await db.execute(select(User).where(User.id == int(user_id)))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Usuario inactivo o no encontrado.")

    # Generar nuevo access token
    access_token = create_access_token(
        data={"sub": str(user.id), "role": user.role}
    )
    # Reutilizar el refresh token o generar uno nuevo
    new_refresh = create_refresh_token(data={"sub": str(user.id)})

    return {
        "access_token": access_token,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "user": user
    }


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Retorna los detalles del usuario logueado actualmente."""
    return current_user


@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user)):
    """Cierra la sesión del usuario actual."""
    # En arquitecturas puras JWT sin estado, el cliente borra el token.
    # Opcionalmente se puede guardar en una lista negra de Redis si se desea invalidación inmediata.
    return {"message": "Cierre de sesión exitoso."}
