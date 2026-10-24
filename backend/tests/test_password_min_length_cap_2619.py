"""#2619 — the Password Policy minimum may not exceed what a password can be.

Every path that sets a password refuses one over 72 bytes, so a saved minimum
above 72 would be a policy nobody can meet.
"""

import pytest
from pydantic import ValidationError

from app.api.v1.settings.router import SettingsUpdate
from app.services.password_policy import MAX_PASSWORD_BYTES


def test_cap_matches_the_byte_ceiling() -> None:
    SettingsUpdate(password_min_length=MAX_PASSWORD_BYTES)


@pytest.mark.parametrize("n", [73, 100, 128])
def test_minimum_above_the_byte_ceiling_is_refused(n: int) -> None:
    with pytest.raises(ValidationError):
        SettingsUpdate(password_min_length=n)


@pytest.mark.parametrize("n", [5, 0])
def test_floor_still_applies(n: int) -> None:
    with pytest.raises(ValidationError):
        SettingsUpdate(password_min_length=n)
