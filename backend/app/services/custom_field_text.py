"""One text form for a custom field value (#4421).

The API stores any JSON in ``custom_fields``. Wherever text is built from a
value (the PDF export, the label of a search hit, the CSV / XLSX cell) a list
or an object reads as compact JSON, never Python's repr (``{'k': 'v'}``).
The console's twin is ``customFieldDisplay`` in ``frontend/src/lib/customFieldValues.ts``.
"""

from __future__ import annotations

import json
from typing import Any


def custom_field_json(value: Any) -> str:
    """Compact JSON text for a list or object."""
    return json.dumps(value, separators=(",", ":"), default=str)


def custom_field_text(value: Any) -> str:
    """A custom field value as text: JSON for a list or object, ``str`` otherwise."""
    if isinstance(value, (list, dict)):
        return custom_field_json(value)
    return str(value)
