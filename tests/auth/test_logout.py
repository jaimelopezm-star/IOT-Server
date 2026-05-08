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

        user_id = str(uuid4())
        tokens = await service.create_session_with_tokens(
            user_id=user_id,
            claims={
                "sub": user_id,
                "email": "test@example.com",
                "type": "user",
                "is_master": False,
            },
            request_info={
                "ip_address": "192.168.1.10",
                "user_agent": "TestClient/1.0",
            },
        )

        assert tokens.access_token is not None
        assert tokens.refresh_token is not None
        assert await service.get_session(user_id) is not None

        await service.invalidate_user_session(user_id)

        assert await service.get_session(user_id) is None


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
