from fastapi import APIRouter

from app.domain.auth.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    MessageResponse,
    TokenResponse,
)
from app.domain.auth.service import AuthServiceDep, CurrentAccountDep
from app.shared.session import SessionServiceDep

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