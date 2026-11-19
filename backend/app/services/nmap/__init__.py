"""Nmap on-demand scanning service.

Public surface:

* :data:`PRESETS` — canonical flag bundles keyed by preset name.
* :func:`build_argv` — assemble + sanitise the nmap argv from operator
  inputs.
* :func:`run_scan` — async coroutine that drives one scan to
  completion, line-buffering stdout into the row's ``raw_stdout`` so
  the SSE endpoint can replay it.
* :func:`parse_nmap_xml` — best-effort parser of nmap's ``-oX -``
  output into a compact ``summary_json`` shape.
"""

from app.services.nmap.runner import (
    PRESETS,
    NmapArgError,
    build_argv,
    parse_nmap_xml,
    resolve_target,
    run_scan,
)

__all__ = [
    "PRESETS",
    "NmapArgError",
    "build_argv",
    "parse_nmap_xml",
    "resolve_target",
    "run_scan",
]
