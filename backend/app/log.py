import logging
from typing import TextIO

import structlog

from app.config import settings

#: Marks the root handler ``configure_logging`` installed, so a second call
#: (a test re-running the lifespan, a Celery ``setup_logging`` after an
#: import-time call) replaces it instead of stacking a duplicate — and
#: leaves any handler it did not install, such as pytest's ``caplog``, alone.
_HANDLER_FLAG = "_spatium_structlog"


def _service_adder(service: str) -> structlog.types.Processor:
    """Stamp ``service`` on every line that does not already carry one.

    Non-negotiable #7 wants ``service`` on every line, but the api bound it
    only inside ``RequestContextMiddleware`` — so startup lines, lifespan
    tasks and every worker / beat line went out without it (#1246).
    ``setdefault`` keeps an explicit ``service=`` on a call site working.
    """

    def _add(
        _logger: object, _method: str, event_dict: structlog.types.EventDict
    ) -> structlog.types.EventDict:
        event_dict.setdefault("service", service)
        return event_dict

    return _add


def _level_number(value: int | str, default: int) -> int:
    if isinstance(value, int):
        return value
    return int(getattr(logging, str(value).upper(), default))


def configure_logging(
    service: str = "api",
    *,
    stream: TextIO | None = None,
    level: int | str | None = None,
    logfile: str | None = None,
) -> None:
    """Configure structlog for JSON output per the observability spec.

    One pipeline for both kinds of line. structlog loggers render through
    ``structlog.configure``; stdlib records — Celery's own ``Task … received``
    / ``succeeded`` lines, SQLAlchemy, httpx — render through the same
    processors via ``ProcessorFormatter`` on the root handler, so a worker's
    output is one JSON stream rather than JSON interleaved with Celery's
    ``[2026-09-28 20:44:59,719: INFO/MainProcess]`` text (#1246).

    ``stream`` sends both to one file object; the default is the process's
    stdout for structlog lines and stderr for stdlib records, as before.
    ``logfile`` (Celery's ``--logfile``) sends both to that file instead,
    through a ``FileHandler`` — so the logging module owns the handle and
    closes it when this handler is replaced or at shutdown.
    ``level`` (Celery's ``--loglevel``) applies only when it is MORE verbose
    than ``LOG_LEVEL``, so neither a command-line default nor the setting
    can hide what the other asked to see.
    """
    level_no = _level_number(settings.log_level, logging.INFO)
    if level is not None:
        level_no = min(level_no, _level_number(level, level_no))
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _service_adder(service),
    ]

    renderer: structlog.types.Processor
    if settings.log_format == "json":
        exc_processors: list[structlog.types.Processor] = [structlog.processors.dict_tracebacks]
        renderer = structlog.processors.JSONRenderer()
    else:
        exc_processors = []
        renderer = structlog.dev.ConsoleRenderer()

    handler: logging.StreamHandler[TextIO]
    if logfile:
        handler = logging.FileHandler(logfile, encoding="utf-8")
        struct_file: TextIO | None = handler.stream
    else:
        handler = logging.StreamHandler(stream)
        struct_file = stream

    structlog.configure(
        processors=shared_processors + exc_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level_no),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=struct_file),
        cache_logger_on_first_use=True,
    )

    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=[*shared_processors, structlog.stdlib.add_logger_name],
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                *exc_processors,
                renderer,
            ],
        )
    )
    setattr(handler, _HANDLER_FLAG, True)

    root = logging.getLogger()
    for existing in list(root.handlers):
        if getattr(existing, _HANDLER_FLAG, False):
            root.removeHandler(existing)
            existing.close()
    root.addHandler(handler)
    root.setLevel(level_no)
