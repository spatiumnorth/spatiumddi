"""Password-policy messages built from a count agree in number (#4688)."""

from app.services.password_policy import PasswordPolicy, history_error, validate


def _policy(**kw: int) -> PasswordPolicy:
    base = dict(
        min_length=12,
        require_uppercase=False,
        require_lowercase=False,
        require_digit=False,
        require_symbol=False,
        history_count=1,
        max_age_days=0,
    )
    base.update(kw)
    return PasswordPolicy(**base)  # type: ignore[arg-type]


def test_history_error_singular_and_plural() -> None:
    assert history_error(1) == "Password matches your last password; choose a new one."
    assert history_error(5) == "Password matches one of the last 5 passwords; choose a new one."


def test_min_length_message_singular_and_plural() -> None:
    assert validate("", _policy(min_length=1)).errors == ["Password must be at least 1 character"]
    assert validate("a", _policy(min_length=2)).errors == ["Password must be at least 2 characters"]
