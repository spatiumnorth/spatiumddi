"""Unauthenticated third-party notices for the About page (#2895).

The Apache-2.0 NOTICE text and the MIT / BSD / ISC notices of everything we
redistribute have to reach whoever receives the software, not only an admin
who can log in — so this router has no auth dependency, like the About page
that links to it.

It serves ONE static file, baked into the image at build time by the builder
stage of ``backend/Dockerfile`` (``pip-licenses`` over the packages the runtime
stage receives). Nothing here reads the database or the request, and the body
is the same for every caller: it names Python packages and their licences,
which are the image's own contents and carry no install detail. The matching
npm list, ``NOTICE`` and ``LICENSE`` are static files in the web tier.

A checkout run outside the image (``make dev`` hot-reload) has no baked file;
that is a 404 naming the reason, not an empty 200, so the page can say
"not available in this build" rather than show a blank list as if it were the
real one.
"""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.core.responses import PlainTextStreamResponse

router = APIRouter(tags=["about"])

# ``COPY --from=builder /install /usr/local`` lands the builder's
# ``/install/share/spatiumddi`` here.
THIRD_PARTY_PYTHON = Path(sys.prefix) / "share" / "spatiumddi" / "third-party-python.txt"


@router.get(
    "/third-party/python",
    response_class=PlainTextStreamResponse,
    summary="Python third-party licence list (plain text)",
)
async def python_third_party_licenses() -> FileResponse:
    path = THIRD_PARTY_PYTHON
    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail="The Python third-party list is generated when the image is built "
            "and is not present in this build.",
        )
    return FileResponse(
        path,
        media_type="text/plain",
        # Content only changes with the image, and a stale copy for an hour
        # after an upgrade is harmless.
        headers={"Cache-Control": "public, max-age=3600"},
    )
