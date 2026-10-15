"""named's resolver cache is bounded by the container's memory limit (#1725).

``max-cache-size`` defaults to 90 % of PHYSICAL memory per view, and named
reads the host's RAM, not the cgroup. A pod that also holds a ~580k-entry RPZ
in memory has nothing left for a cache allowed to grow to nine tenths of the
node. The renderer therefore writes an explicit ceiling.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spatium_dns_agent import oom_watch
from spatium_dns_agent.drivers import bind9
from spatium_dns_agent.drivers.bind9 import Bind9Driver, _render_max_cache_size

GIB = 1 << 30


def test_a_quarter_of_the_cgroup_limit() -> None:
    assert _render_max_cache_size({}, 2 * GIB) == "    max-cache-size 512m;\n"


def test_a_tiny_limit_still_gets_a_usable_cache() -> None:
    assert _render_max_cache_size({}, 64 * 1024 * 1024) == "    max-cache-size 32m;\n"


def test_env_override_wins_and_is_validated() -> None:
    assert _render_max_cache_size({"NAMED_MAX_CACHE_SIZE": "256m"}, 2 * GIB) == (
        "    max-cache-size 256m;\n"
    )
    # A value that is not a BIND size must never reach named.conf: the agent
    # would decline the whole bundle (named-checkconf).
    assert _render_max_cache_size({"NAMED_MAX_CACHE_SIZE": "1g; };"}, 2 * GIB) == (
        "    max-cache-size 512m;\n"
    )


@pytest.mark.parametrize(
    "content,expected",
    [
        ("max\n", None),
        ("2147483648\n", 2 * GIB),
        ("9223372036854771712\n", None),
        ("junk", None),
    ],
)
def test_cgroup_file_parsing(tmp_path: Path, content: str, expected: int | None) -> None:
    f = tmp_path / "memory.max"
    f.write_text(content)
    assert oom_watch.cgroup_memory_limit_bytes((str(f),)) == expected


def _bundle() -> dict:
    return {
        "server": {"name": "s1", "driver": "bind9"},
        "options": {},
        "acls": [],
        "views": [],
        "zones": [],
        "blocklists": [],
        "tsig_keys": [],
        "pending_ops": [],
    }


def test_the_rendered_named_conf_carries_the_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("NAMED_MAX_CACHE_SIZE", raising=False)
    monkeypatch.setattr(bind9, "_cgroup_memory_limit_bytes", lambda *a, **k: 2 * GIB)
    Bind9Driver(state_dir=tmp_path).render(_bundle())
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    opts = conf[conf.index("options {") : conf.index("\n};\n", conf.index("options {"))]
    assert "max-cache-size 512m;" in opts


def test_no_limit_renders_no_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NAMED_MAX_CACHE_SIZE", raising=False)
    monkeypatch.setattr(bind9, "_cgroup_memory_limit_bytes", lambda *a, **k: None)
    Bind9Driver(state_dir=tmp_path).render(_bundle())
    assert "max-cache-size" not in (tmp_path / "rendered.new" / "named.conf").read_text()


def test_the_budget_is_split_across_recursive_views() -> None:
    """``max-cache-size`` in ``options {}`` sizes EACH view's cache (BIND ARM),
    so three recursive views on a 2 GiB limit get a third of the quarter each,
    not 512m apiece (1.5 GiB of cache in a 2 GiB pod)."""
    assert _render_max_cache_size({}, 2 * GIB, caches=3) == "    max-cache-size 170m;\n"


def test_views_with_recursion_off_take_no_share(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("NAMED_MAX_CACHE_SIZE", raising=False)
    monkeypatch.setattr(bind9, "_cgroup_memory_limit_bytes", lambda *a, **k: 2 * GIB)
    bundle = _bundle()
    bundle["views"] = [
        {"name": "internal", "match_clients": ["10.0.0.0/8"], "recursion": True},
        {"name": "guest", "match_clients": ["192.168.0.0/16"], "recursion": True},
        {"name": "external", "match_clients": ["any"], "recursion": False},
    ]
    Bind9Driver(state_dir=tmp_path).render(bundle)
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert "max-cache-size 256m;" in conf
    assert conf.count("max-cache-size") == 1  # options-level, inherited per view
