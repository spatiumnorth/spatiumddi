"""#4836: refusals/warnings name the real place (Features & Integrations is a footer page)."""

from pathlib import Path

_APP = Path(__file__).resolve().parents[1] / "app"
_FILES = ("api/v1/appliance/supervisor.py", "services/ai/operations.py")


def test_no_administration_prefix_before_features_page() -> None:
    for rel in _FILES:
        src = (_APP / rel).read_text()
        flat = " ".join(src.replace('"', " ").split())
        assert "Enable it under Features & Integrations" in flat, rel
        assert "Administration > Features" not in flat, rel
