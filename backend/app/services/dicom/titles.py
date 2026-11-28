"""DICOM AE Title validation — issue #723.

The AE Value Representation is defined in PS3.5, and getting it wrong in
either direction has a real cost:

* Too permissive and the registry accepts a title a device will reject,
  so the plan fails at commissioning — which is the exact failure this
  whole registry exists to prevent.
* Too strict and the registry rejects titles real devices already use,
  which is worse: it makes the tool unusable at the sites that most need
  it, and the operator's fix is to stop using the tool.

The rules, verbatim from the specification rather than from folklore:

* maximum length **16 characters**. The repertoire below is ASCII only,
  so characters and bytes are the same count.
* the default character repertoire — ISO-IR 6, printable ASCII
  ``0x20``-``0x7E`` — **excluding backslash** (``0x5C``, which is the
  DICOM multi-value delimiter). Everything else is refused, and the
  message names it by code point: control characters (C0, DEL and the
  C1 range ``U+0080``-``U+009F``), no-break and other Unicode spaces, and
  look-alikes such as a Cyrillic ``А``. A look-alike is the dangerous
  case: it is invisible in the UI and makes a title that cannot match
  the device it was typed for.
* **spaces are legal.** They are non-significant padding — a title is
  padded with trailing spaces to an even length on the wire — so leading
  and trailing ASCII space is trimmed on the way in and internal spaces are
  kept.
* an **all-space value is forbidden**, which after trimming is the same
  statement as "must not be empty".

Note what is *not* a rule: there is no alphanumeric-only restriction and
no case requirement. Titles like ``CT_1``, ``PACS-ARCHIVE`` and
``MR SCANNER 2`` are all valid, and case is significant to peers — an AE
configured as ``CT_ONE`` does not answer to ``ct_one``. So titles are
stored as given and matched exactly; only the *default-title* advisory
check compares case-insensitively, because that is asking "did anyone
change this from the box" rather than "do these two match".
"""

from __future__ import annotations

from app.models.dicom import DICOM_AE_TITLE_MAX_BYTES, DICOM_DEFAULT_AE_TITLES

# 0x5C is the DICOM multi-value delimiter, so it can never appear inside
# a single value. Control characters are excluded by the VR definition.
_BACKSLASH = "\\"


class AETitleError(ValueError):
    """An AE Title violates the PS3.5 ``AE`` value representation.

    Carries a message naming the specific rule broken, because "invalid
    AE title" tells an operator nothing about whether their problem is
    length, a stray tab pasted out of a spreadsheet, or the backslash a
    vendor put in their conformance statement by mistake.
    """


def normalize_ae_title(raw: str) -> str:
    """Trim padding and return the canonical stored form.

    Spaces are non-significant padding per the VR, so trimming them is
    normalization, not mutation of operator intent. Nothing else is
    changed — in particular case is preserved, because peers match
    titles exactly. Only ``0x20`` is trimmed: ``str.strip()`` would also
    eat a tab or a no-break space, silently repairing a value that
    :func:`validate_ae_title` must refuse. This is the one form stored
    and compared for uniqueness.
    """
    return (raw or "").strip(" ")


def validate_ae_title(raw: str) -> str:
    """Return the normalized title, or raise :class:`AETitleError`.

    Checks are ordered so the message names the most specific problem:
    empty first (which also covers the forbidden all-space value), then
    backslash, then the rest of the repertoire, then length. Length is checked last so a
    title that is both too long *and* contains a backslash reports the
    backslash — the operator can shorten a name themselves, but a
    forbidden character usually means the value was mis-transcribed.
    """
    title = normalize_ae_title(raw)
    if not title:
        # Also the all-space case, which the specification forbids
        # explicitly: after trimming padding there is nothing left.
        raise AETitleError("AE Title must not be empty or all spaces")

    if _BACKSLASH in title:
        raise AETitleError(
            "AE Title must not contain a backslash — it is the DICOM "
            "multi-value delimiter and cannot appear inside a single value"
        )

    bad = sorted({ch for ch in title if not 0x20 <= ord(ch) <= 0x7E})
    if bad:
        found = ", ".join(f"U+{ord(ch):04X}" for ch in bad)
        raise AETitleError(
            "AE Title may only contain printable ASCII characters "
            f"(found {found}) — control characters, no-break spaces and "
            "look-alike letters usually mean the value was pasted out of a "
            "document or spreadsheet"
        )

    if len(title) > DICOM_AE_TITLE_MAX_BYTES:
        raise AETitleError(
            f"AE Title must be at most {DICOM_AE_TITLE_MAX_BYTES} characters "
            f"(this one is {len(title)})"
        )
    return title


def is_vendor_default(title: str) -> bool:
    """Is this a known out-of-the-box vendor default?

    Compared case-insensitively on the trimmed value, because the
    question is "did anyone change this from the box", and a device
    shipped as ``ANY-SCP`` that someone re-typed as ``Any-SCP`` is
    equally un-changed.

    Advisory by design: a default title is not invalid, it is just the
    single most common cause of the estate-wide collisions this registry
    exists to prevent — two vendors' defaults collide long before anyone
    runs out of names.
    """
    return normalize_ae_title(title).lower() in DICOM_DEFAULT_AE_TITLES


__all__ = [
    "AETitleError",
    "is_vendor_default",
    "normalize_ae_title",
    "validate_ae_title",
]
