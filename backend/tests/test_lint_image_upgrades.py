"""The shipped-image package-upgrade guard (#1088).

``scripts/lint_image_upgrades.py`` refuses a published image whose package
layer can never be patched — no ``apk upgrade`` / ``apt-get upgrade``, or no
cache-busting snapshot ARG for the nightly to bust the layer with.

Every case below was a real property of the tree when the linter was written,
or a way the linter could have looked like it passed while checking nothing:

  * the api image had neither half, and shipped 34 HIGH/CRITICAL findings;
  * the Dockerfiles carry long rationale comments that NAME the commands
    being looked for, so a linter matching raw text would pass an image whose
    comments merely describe an upgrade it does not perform;
  * an ``ARG`` never referenced in the RUN text does not change that text, so
    it changes no cache key and busts nothing;
  * and if the nightly's images heredoc is ever restructured, the linter must
    say so rather than find zero images and report success — the failure mode
    this whole class of guard keeps producing.

#1226 added the release workflow's own copy of the list, which it builds,
scans and pushes from; an image that drops off it keeps building every night
and silently stops being released, so the two must match entry for entry.
"""

from __future__ import annotations

import importlib.util
import pathlib
import textwrap
import types

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "lint_image_upgrades.py"

pytestmark = pytest.mark.skipif(
    not _SCRIPT.exists(),
    reason="image-upgrade linter not present in this checkout",
)

_NIGHTLY_TEMPLATE = """\
jobs:
  gate:
    steps:
      - run: |
          cat > /tmp/images.json <<'IMAGES_EOF'
          [
            {"image": "an-image", "context": ".", "file": "./Dockerfile", "target": "runtime"}
          ]
          IMAGES_EOF
"""

_GOOD_DOCKERFILE = """\
FROM alpine:3.24 AS runtime
ARG APK_SNAPSHOT=dev
RUN echo "apk snapshot ${APK_SNAPSHOT}" >/dev/null \\
 && apk upgrade --no-cache \\
 && apk add --no-cache tini
"""


@pytest.fixture(scope="module")
def lint() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("lint_image_upgrades", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(
    lint: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    dockerfile: str | None,
    nightly: str = _NIGHTLY_TEMPLATE,
    release: str | None = None,
) -> int:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "nightly.yml").write_text(nightly)
    (workflows / "release.yml").write_text(nightly if release is None else release)
    if dockerfile is not None:
        (tmp_path / "Dockerfile").write_text(dockerfile)
    monkeypatch.setattr(lint, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(lint, "NIGHTLY", workflows / "nightly.yml")
    monkeypatch.setattr(lint, "RELEASE", workflows / "release.yml")
    return lint.main()


def test_a_well_formed_image_passes(
    lint: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    assert _run(lint, monkeypatch, tmp_path, _GOOD_DOCKERFILE) == 0


def test_an_apt_image_passes(
    lint: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """The Debian half of #1088 — the shape backend/Dockerfile now has."""
    body = textwrap.dedent("""\
        FROM python:3.12-slim AS runtime
        ARG APT_SNAPSHOT=dev
        RUN echo "apt snapshot ${APT_SNAPSHOT}" >/dev/null \\
            && apt-get update \\
            && apt-get upgrade -y \\
            && apt-get install -y --no-install-recommends ca-certificates
        """)
    assert _run(lint, monkeypatch, tmp_path, body) == 0


def test_install_alone_is_not_an_upgrade(
    lint: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """The exact pre-fix api image: it installed packages and upgraded none."""
    body = textwrap.dedent("""\
        FROM python:3.12-slim AS runtime
        ARG APT_SNAPSHOT=dev
        RUN echo "${APT_SNAPSHOT}" >/dev/null \\
            && apt-get update \\
            && apt-get install -y --no-install-recommends ca-certificates
        """)
    assert _run(lint, monkeypatch, tmp_path, body) == 1


def test_a_missing_snapshot_arg_is_reported(
    lint: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    body = "FROM alpine:3.24\nRUN apk upgrade --no-cache && apk add --no-cache tini\n"
    assert _run(lint, monkeypatch, tmp_path, body) == 1


def test_an_unreferenced_snapshot_arg_is_reported(
    lint: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Declared but never interpolated: the RUN text is unchanged, so the
    nightly's date tag changes no cache key and the upgrade still never runs."""
    body = "FROM alpine:3.24\nARG APK_SNAPSHOT=dev\nRUN apk upgrade --no-cache\n"
    assert _run(lint, monkeypatch, tmp_path, body) == 1


def test_an_upgrade_only_in_a_comment_does_not_count(
    lint: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Load-bearing: these Dockerfiles explain at length why `apk upgrade`
    matters, so raw-text matching would pass a file that only talks about it."""
    body = textwrap.dedent("""\
        FROM alpine:3.24
        # We deliberately do not run `apk upgrade` here, and APK_SNAPSHOT
        # would be the knob if we did: ARG APK_SNAPSHOT=dev
        RUN apk add --no-cache tini
        """)
    assert _run(lint, monkeypatch, tmp_path, body) == 1


def test_an_upgrade_in_a_discarded_builder_stage_does_not_count(
    lint: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Builder stages are thrown away — their packages never ship, and
    ``COPY --from`` brings files, not a package database. Checking the whole
    file passes an image whose only upgrade is in a stage nobody runs, which
    is the shape most of these Dockerfiles actually have."""
    body = textwrap.dedent("""\
        FROM alpine:3.24 AS builder
        ARG APK_SNAPSHOT=dev
        RUN echo "${APK_SNAPSHOT}" >/dev/null && apk upgrade --no-cache

        FROM alpine:3.24 AS runtime
        RUN apk add --no-cache tini
        COPY --from=builder /out /out
        """)
    assert _run(lint, monkeypatch, tmp_path, body) == 1


def test_a_stage_inherits_its_local_parent(
    lint: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """The other direction: ``FROM base AS runtime`` DOES inherit base's
    layers, so an upgrade there ships and must count."""
    body = textwrap.dedent("""\
        FROM alpine:3.24 AS base
        ARG APK_SNAPSHOT=dev
        RUN echo "${APK_SNAPSHOT}" >/dev/null && apk upgrade --no-cache

        FROM base AS runtime
        RUN apk add --no-cache tini
        """)
    assert _run(lint, monkeypatch, tmp_path, body) == 0


def test_a_trailing_comment_does_not_count(
    lint: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """A ``#`` mid-line is a comment to the shell too, so the command is
    named and not performed. The whole-line case has its own test above;
    this is the half the first cut's docstring wrongly claimed was safe."""
    body = textwrap.dedent("""\
        FROM alpine:3.24 AS runtime
        ARG APK_SNAPSHOT=dev
        RUN echo "${APK_SNAPSHOT}" >/dev/null \\
         && apk add --no-cache tini   # we deliberately do not apk upgrade here
        """)
    assert _run(lint, monkeypatch, tmp_path, body) == 1


def test_a_quoted_hash_is_data_not_a_comment(
    lint: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Truncating at every ``#`` would silently discard real commands."""
    body = textwrap.dedent("""\
        FROM alpine:3.24 AS runtime
        ARG APK_SNAPSHOT=dev
        RUN echo "snapshot ${APK_SNAPSHOT} #1" >/dev/null && apk upgrade --no-cache
        """)
    assert _run(lint, monkeypatch, tmp_path, body) == 0


def test_a_target_the_dockerfile_does_not_define_is_reported(
    lint: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Better than silently checking whichever stage happens to be last."""
    body = (
        "FROM alpine:3.24 AS other\nARG APK_SNAPSHOT=dev\nRUN echo ${APK_SNAPSHOT} && apk upgrade\n"
    )
    assert _run(lint, monkeypatch, tmp_path, body) == 1


def test_an_image_missing_from_disk_is_reported(
    lint: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    assert _run(lint, monkeypatch, tmp_path, None) == 1


def test_a_restructured_heredoc_raises_rather_than_passing(
    lint: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Finding zero images must not read as success. A guard that evaluates
    nothing looks exactly like one that passed — which is the failure this
    repo keeps rediscovering (#1030 most recently)."""
    with pytest.raises(SystemExit):
        _run(
            lint,
            monkeypatch,
            tmp_path,
            _GOOD_DOCKERFILE,
            nightly="jobs:\n  gate:\n    steps:\n      - run: echo no heredoc here\n",
        )


_SECOND_IMAGE = (
    '{"image": "an-image", "context": ".", "file": "./Dockerfile", "target": "runtime"},\n'
    '            {"image": "other", "context": ".", "file": "./Dockerfile", "target": "runtime"}'
)
_ONE_IMAGE = '{"image": "an-image", "context": ".", "file": "./Dockerfile", "target": "runtime"}'


@pytest.mark.parametrize(
    ("nightly", "release"),
    [
        # An image the nightly builds and the release no longer publishes.
        (_NIGHTLY_TEMPLATE.replace(_ONE_IMAGE, _SECOND_IMAGE), _NIGHTLY_TEMPLATE),
        # The other direction: published by a release, never built nightly,
        # so a regression in it surfaces only when a release is cut.
        (_NIGHTLY_TEMPLATE, _NIGHTLY_TEMPLATE.replace(_ONE_IMAGE, _SECOND_IMAGE)),
        # Same name, different build: the #732 shape, a release that drops
        # the api's ``target: runtime`` and ships the dev stage.
        (_NIGHTLY_TEMPLATE, _NIGHTLY_TEMPLATE.replace('"target": "runtime"', '"target": ""')),
    ],
    ids=["missing-from-release", "missing-from-nightly", "different-target"],
)
def test_the_release_list_must_match_the_nightly_list(
    lint: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    nightly: str,
    release: str,
) -> None:
    (tmp_path / "Dockerfile").write_text(_GOOD_DOCKERFILE)
    assert _run(lint, monkeypatch, tmp_path, None, nightly=nightly, release=release) == 1


def test_a_release_without_the_heredoc_raises(
    lint: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    with pytest.raises(SystemExit):
        _run(
            lint,
            monkeypatch,
            tmp_path,
            _GOOD_DOCKERFILE,
            release="jobs:\n  meta:\n    steps:\n      - run: echo no heredoc here\n",
        )


def test_the_real_tree_passes(lint: types.ModuleType) -> None:
    """The linter against the repo it ships in — every image the nightly
    builds. Skipped in the dev container, which copies only backend/."""
    if not (_REPO_ROOT / ".github" / "workflows" / "nightly.yml").is_file():
        pytest.skip("full checkout not present in this image")
    assert lint.main() == 0
