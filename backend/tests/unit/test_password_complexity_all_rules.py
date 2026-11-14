"""Password complexity reports every unmet rule at once (fork #9)."""

import pytest
from pydantic import ValidationError

from backend.app.schemas.auth import (
    ChangePasswordRequest,
    UserCreate,
    UserUpdate,
    password_complexity_message,
    unmet_password_rules,
)


class TestUnmetPasswordRules:
    def test_all_rules_listed_for_empty_password(self):
        assert unmet_password_rules("") == ["min_length", "uppercase", "lowercase", "digit", "special"]

    def test_only_the_failing_rules_are_listed(self):
        assert unmet_password_rules("abcdefgh") == ["uppercase", "digit", "special"]
        assert unmet_password_rules("Aa1!") == ["min_length"]

    def test_valid_password_has_no_unmet_rules(self):
        assert unmet_password_rules("Aa1!aaaa") == []

    def test_length_counts_code_points_and_digits_are_unicode(self):
        # The frontend checklist mirrors these two behaviours (fork #9 review).
        assert unmet_password_rules("Aa1!ab😀") == ["min_length"]
        assert unmet_password_rules("Aa!aaaa١") == []

    def test_message_names_every_unmet_rule(self):
        message = password_complexity_message(["uppercase", "digit"])
        assert message == "Password must contain an uppercase letter and contain a digit"


class TestMultiRuleValidationError:
    @pytest.mark.parametrize(
        ("model", "payload", "field"),
        [
            (UserCreate, {"username": "u", "password": "abc"}, "password"),
            (UserUpdate, {"password": "abc"}, "password"),
            (ChangePasswordRequest, {"current_password": "x", "new_password": "abc"}, "new_password"),
        ],
    )
    def test_single_error_carries_all_rules_in_ctx(self, model, payload, field):
        with pytest.raises(ValidationError) as exc_info:
            model(**payload)
        errors = exc_info.value.errors()
        assert len(errors) == 1
        err = errors[0]
        assert err["loc"] == (field,)
        assert err["type"] == "password_complexity"
        assert err["ctx"]["rules"] == ["min_length", "uppercase", "digit", "special"]
        for text in ("8 characters", "uppercase", "digit", "special"):
            assert text in err["msg"]


@pytest.mark.asyncio
@pytest.mark.integration
class TestMultiRule422:
    async def test_users_create_returns_one_422_with_all_rules(self, async_client):
        await async_client.post(
            "/api/v1/auth/setup",
            json={"auth_enabled": True, "admin_username": "rules_admin", "admin_password": "AdminPass1!"},
        )
        login = await async_client.post(
            "/api/v1/auth/login", json={"username": "rules_admin", "password": "AdminPass1!"}
        )
        token = login.json()["access_token"]

        response = await async_client.post(
            "/api/v1/users/",
            headers={"Authorization": f"Bearer {token}"},
            json={"username": "weakling", "password": "abcdefgh"},
        )

        assert response.status_code == 422
        detail = response.json()["detail"]
        assert len(detail) == 1
        assert detail[0]["type"] == "password_complexity"
        assert detail[0]["ctx"]["rules"] == ["uppercase", "digit", "special"]
        assert "uppercase" in detail[0]["msg"] and "digit" in detail[0]["msg"]

    async def test_setup_400_message_names_every_unmet_rule(self, async_client):
        response = await async_client.post(
            "/api/v1/auth/setup",
            json={"auth_enabled": True, "admin_username": "weak_setup", "admin_password": "12345"},
        )

        assert response.status_code == 400
        message = response.json()["detail"]
        for text in ("8 characters", "uppercase", "lowercase", "special"):
            assert text in message
