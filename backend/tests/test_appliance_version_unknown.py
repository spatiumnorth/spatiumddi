"""#2004: an unknown appliance version is None on every surface, never "dev"."""

from app.config import settings
from app.services.appliance.system import get_system_info


def test_system_info_reports_none_when_unset(monkeypatch) -> None:
    monkeypatch.setattr(settings, "appliance_version", "")
    assert get_system_info().appliance_version is None


def test_system_info_reports_the_stamped_version(monkeypatch) -> None:
    monkeypatch.setattr(settings, "appliance_version", "2026.10.16-1")
    assert get_system_info().appliance_version == "2026.10.16-1"
