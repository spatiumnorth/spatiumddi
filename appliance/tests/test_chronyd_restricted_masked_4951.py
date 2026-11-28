"""chronyd-restricted.service is masked so chrony.service runs at boot (#4951)."""

from pathlib import Path

POSTINST = Path(__file__).resolve().parents[1] / "mkosi.postinst"


def test_chronyd_restricted_masked() -> None:
    post = POSTINST.read_text()
    assert 'ln -sfn /dev/null "$BUILDROOT/etc/systemd/system/chronyd-restricted.service"' in post


def test_chrony_service_still_enabled() -> None:
    assert "for unit in chrony.service" in POSTINST.read_text()
