"""The About page's data sources, signed-in callers only (#2895).

The About page carries the licence, the NOTICE and the third-party notice
lists. All of it is behind a session: someone probing the server from outside
must not learn which version, libraries or third-party tools it runs. So every
source the page reads needs a signed-in user:

* ``GET /about/third-party/python`` — the Python list, one static file baked
  into the image at build time by the builder stage of ``backend/Dockerfile``
  (``pip-licenses`` over the packages the runtime stage receives).
* ``GET /about/session`` — 204 for a signed-in caller, 401 otherwise. It
  carries no data. The web tier's nginx calls it as an ``auth_request`` before
  serving the other three files (NOTICE, LICENSE and the npm list), which the
  Vite build generates and the frontend image keeps outside its web root. That
  keeps the files where they are produced and still refuses them to anyone
  without a session, on every deployment shape: compose and the Helm chart
  both route browser traffic through that nginx.

A checkout run outside the image (``make dev`` hot-reload) has no baked Python
list; that is a 404 naming the reason, not an empty 200, so the page can say
"not available in this build" rather than show a blank list as if it were the
real one.
"""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException, Response, status
from fastapi.responses import FileResponse

from app.api.deps import CurrentUser
from app.core.responses import PlainTextStreamResponse

router = APIRouter(tags=["about"])

# ``COPY --from=builder /install /usr/local`` lands the builder's
# ``/install/share/spatiumddi`` here.
THIRD_PARTY_PYTHON = Path(sys.prefix) / "share" / "spatiumddi" / "third-party-python.txt"


@router.get(
    "/session",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Whether the caller is signed in (the web tier's gate for the About files)",
)
async def about_session(_: CurrentUser) -> Response:
    # ``CurrentUser`` does the work: no credential or a bad one is a 401, a
    # disabled account or a pending password change a 403. nginx passes
    # either straight back to the browser and serves the file only on a 2xx.
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/third-party/python",
    response_class=PlainTextStreamResponse,
    summary="Python third-party licence list (plain text)",
)
async def python_third_party_licenses(_: CurrentUser) -> FileResponse:
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
        # Content only changes with the image, so a browser may keep it for an
        # hour. ``private``: it is an authenticated response, and a shared
        # cache must not hand it to the next, anonymous, caller.
        headers={"Cache-Control": "private, max-age=3600"},
    )
