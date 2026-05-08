from fastapi import APIRouter, HTTPException, Request, status

from app.config import settings
from app.domain.auth.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    MessageResponse,
    TokenResponse,
)
from app.domain.auth.security import get_token_ttl_seconds
from app.domain.auth.service import AuthServiceDep, CurrentAccountDep
<<<<<<< feature/session-per-key-encryption
from app.shared.session import SessionServiceDep
=======
from app.shared.session.repository import SessionRepository
>>>>>>> main

auth_router = APIRouter(prefix="/auth", tags=["Auth"])


@auth_router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, service: AuthServiceDep):
    return service.login(payload)


@auth_router.patch("/change-password", response_model=MessageResponse)
def change_password(
    payload: ChangePasswordRequest,
    service: AuthServiceDep,
    current: CurrentAccountDep,
):
    return service.change_password(current, payload)


@auth_router.post("/logout", response_model=MessageResponse)
async def logout(
<<<<<<< feature/session-per-key-encryption
    current: CurrentAccountDep,
    session_service: SessionServiceDep,
):
    """
    Logout endpoint - Invalidates the user session.
    
    Deletes the session from Valkey, effectively invalidating all
    JWT tokens associated with this user account.
    
    **Flow:**
    1. Validates JWT token from Authorization header
    2. Extracts user account_id from token
    3. Deletes session from Valkey (user_session + refresh_token index)
    4. Returns success message
    
    **After logout:**
    - All access tokens become invalid
    - All refresh tokens become invalid
    - User must call /auth/login again to obtain new tokens
    
    **Note:**
    - This is for human users (Administrator, Manager, User)
    - For entity logout (Device, Application), each domain has its own endpoint
    """
    await session_service.invalidate_user_session(str(current.account_id))
    return MessageResponse(message="Logged out successfully")
=======
    request: Request,
    _current: CurrentAccountDep,
):
    payload = getattr(request.state, "token_payload", None)
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    token_id = payload.get("jti")
    if not token_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token cannot be invalidated because it has no jti",
        )

    ttl_seconds = get_token_ttl_seconds(payload)

    repository = SessionRepository(settings.VALKEY_URL)
    try:
        if ttl_seconds > 0:
            await repository.add_to_blacklist(token_id, ttl_seconds=ttl_seconds)

        return MessageResponse(message="Logged out successfully")
    finally:
        await repository.close()

>>>>>>> main
