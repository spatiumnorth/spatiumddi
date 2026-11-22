### Fixed

- Docs: `DOCKER.md` and the agent compose files now say that agents on another host must use the frontend URL (or a reverse proxy) as `CONTROL_PLANE_URL` / `SPATIUM_API_URL`, because the Compose API listens on `127.0.0.1:8000` only (#4662).
