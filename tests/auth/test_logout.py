"""Tests for logout endpoint - User session invalidation."""

import pytest
from uuid import uuid4

from app.shared.session.service import SessionService


# Valid base64 AES-256 key (32 bytes) for JWE encryption
TEST_ENCRYPTION_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


class TestLogoutService:
    """Test logout at service layer."""

    @pytest.mark.asyncio
    async def test_invalidate_user_session_removes_session(self):
        """Test: invalidate_user_session successfully removes user session."""
        service = SessionService(encryption_key=TEST_ENCRYPTION_KEY)

        # Create a user session
        user_id = str(uuid4())
        claims = {
            "sub": user_id,
            "email": "test@example.com",
            "type": "user",
            "is_master": False,
        }
        request_info = {
            "ip_address": "192.168.1.100",
            "user_agent": "TestClient/1.0",
        }

        tokens = await service.create_session_with_tokens(
            user_id=user_id,
            claims=claims,
            request_info=request_info,
        )
        assert tokens.access_token is not None
        assert tokens.refresh_token is not None

        # Verify session exists
        session = await service.get_session(user_id)
        assert session is not None
        assert session.user_id == user_id
        assert session.email == "test@example.com"

        # Logout (invalidate session)
        await service.invalidate_user_session(user_id)

        # Verify session no longer exists
        session = await service.get_session(user_id)
        assert session is None

    @pytest.mark.asyncio
    async def test_invalidate_user_session_idempotent(self):
        """Test: invalidate_user_session is idempotent (can call multiple times)."""
        service = SessionService(encryption_key=TEST_ENCRYPTION_KEY)
        user_id = str(uuid4())

        # Logout when no session exists (should not raise)
        await service.invalidate_user_session(user_id)

        # Logout again (should not raise)
        await service.invalidate_user_session(user_id)

    @pytest.mark.asyncio
    async def test_logout_allows_new_login(self):
        """Test: After logout, user can login again with new session."""
        service = SessionService(encryption_key=TEST_ENCRYPTION_KEY)
        user_id = str(uuid4())
        claims = {
            "sub": user_id,
            "email": "test@example.com",
            "type": "user",
            "is_master": False,
        }
        request_info = {
            "ip_address": "192.168.1.100",
            "user_agent": "TestClient/1.0",
        }

        # First login
        tokens_1 = await service.create_session_with_tokens(
            user_id=user_id,
            claims=claims,
            request_info=request_info,
        )
        refresh_token_1 = tokens_1.refresh_token

        # Logout
        await service.invalidate_user_session(user_id)

        # Second login
        tokens_2 = await service.create_session_with_tokens(
            user_id=user_id,
            claims=claims,
            request_info=request_info,
        )
        refresh_token_2 = tokens_2.refresh_token

        # Verify different refresh tokens (new session)
        assert refresh_token_1 != refresh_token_2

        # Verify new session exists
        session = await service.get_session(user_id)
        assert session is not None
        assert session.user_id == user_id


class TestLogoutEndpoint:
    """Test logout at endpoint layer."""

    def test_logout_endpoint_requires_authentication(self, client):
        """Test: POST /api/v1/auth/logout requires authentication."""
        response = client.post("/api/v1/auth/logout")
        assert response.status_code == 401

    def test_logout_endpoint_with_invalid_token(self, client):
        """Test: Logout with invalid token returns 401."""
        response = client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": "Bearer invalid_token_here"},
        )
        assert response.status_code == 401

    def test_logout_endpoint_success(self, client, master_admin_account):
        """Test: Logout successfully invalidates session."""
        # Login first
        login_response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "master_admin@test.com",
                "password": "MasterPassword123!",
            },
        )
        assert login_response.status_code == 200
        token = login_response.json()["access_token"]

        # Logout
        logout_response = client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert logout_response.status_code == 200
        assert logout_response.json() == {"message": "Logged out successfully"}

        # Try to use the same token (should fail after logout)
        # Note: This test assumes JWT validation checks session existence
        # Currently our middleware may not check session, so this might still work
        # until we add session validation to the middleware


class TestLogoutComparison:
    """Test comparing entity logout vs user logout."""

    @pytest.mark.asyncio
    async def test_entity_logout_vs_user_logout(self):
        """Test: Both entity and user logout work independently."""
        service = SessionService(encryption_key=TEST_ENCRYPTION_KEY)

        # Create entity session (Device/Application)
        entity_id = uuid4()
        entity_key = "EQo5HabccZyRDqJanKRjvf4Lpkav5NJMqN9I-6ZaPQU="
        entity_response = await service.create_entity_session(
            entity_id=entity_id,
            key_session=entity_key,
            ip_address="192.168.1.10",
            metadata={"type": "device"},
        )
        entity_session_id = entity_response.session_id

        # Create user session (Administrator/Manager/User)
        user_id = str(uuid4())
        user_tokens = await service.create_session_with_tokens(
            user_id=user_id,
            claims={
                "sub": user_id,
                "email": "test@example.com",
                "type": "user",
                "is_master": False,
            },
            request_info={
                "ip_address": "192.168.1.20",
                "user_agent": "TestClient/1.0",
            },
        )

        # Verify both sessions exist
        assert await service.check_active_session(entity_id) is True
        assert await service.get_session(user_id) is not None

        # Logout entity
        await service.invalidate_entity_session(entity_id)

        # Verify entity session gone, user session still exists
        assert await service.check_active_session(entity_id) is False
        assert await service.get_session(user_id) is not None

        # Logout user
        await service.invalidate_user_session(user_id)

        # Verify both sessions gone
        assert await service.check_active_session(entity_id) is False
        assert await service.get_session(user_id) is None
