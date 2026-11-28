"""Hand-typed console place names must name places that exist (#4614)."""

from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"

# (file under app/, stale phrase, phrase that must be there instead)
CASES = [
    (
        "services/ai/tools/support_bundle.py",
        "System > Support bundle",
        "Diagnostics → Support bundle",
    ),
    ("services/ai/tools/certificates.py", "Certificates tab's", "Fleet → Web UI Certificate"),
    ("services/ai/tools/certificates.py", "Fleet → Web UI Certificate.", "'TLS "),  # #4687
    ("api/v1/admin/feature_modules.py", "Settings → Security", "Account → Two-factor"),
    ("services/backup/archive.py", "Platform -> Backup", "Administration -> Backup"),
    ("api/v1/auth/router.py", "Settings > General", "Branding & URL"),
]


def test_stale_place_names_gone() -> None:
    for rel, stale, fresh in CASES:
        text = (APP / rel).read_text(encoding="utf-8")
        assert stale not in text, f"{rel} still says {stale!r}"
        assert fresh in text, f"{rel} should name {fresh!r}"
