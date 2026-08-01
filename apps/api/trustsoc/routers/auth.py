from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from trustsoc.database import get_db
from trustsoc.dependencies import current_user
from trustsoc.models import User
from trustsoc.schemas import LoginRequest, RefreshRequest, TokenResponse, UserOut
from trustsoc.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def tokens(user: User) -> TokenResponse:
    role = user.role.value
    return TokenResponse(
        access_token=create_access_token(
            str(user.id), str(user.organization_id), role, user.token_version
        ),
        refresh_token=create_refresh_token(
            str(user.id), str(user.organization_id), role, user.token_version
        ),
    )


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    user = await db.scalar(
        select(User).where(User.email == payload.email.lower(), User.active.is_(True))
    )
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return tokens(user)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(payload: RefreshRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    token = None
    user = None
    try:
        token = decode_token(payload.refresh_token, "refresh")
        user = await db.scalar(select(User).where(User.id == token["sub"], User.active.is_(True)))
    except (ValueError, KeyError):
        pass
    if token is None or user is None or user.token_version != int(token.get("ver", -1)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )
    return tokens(user)


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(current_user)) -> User:
    return user
