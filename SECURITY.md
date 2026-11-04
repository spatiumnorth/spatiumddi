# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| Previous release | Security fixes only |
| Older releases | No |

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Please report security vulnerabilities by opening a [GitHub Security Advisory](https://github.com/spatiumnorth/spatiumddi/security/advisories/new) on the repository.

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Affected component(s) and version(s)
- Potential impact assessment
- Any suggested remediation (optional)

We aim to acknowledge reports within **two business days** and provide an initial assessment within **five business days**. If the issue is confirmed, we will work toward a fix and coordinated disclosure.

## Security Design Principles

- **All auth enforced server-side** — the API validates every request independently of the UI
- **Passwords hashed with bcrypt** — never stored in plaintext
- **JWT access tokens** — short-lived (configurable, default 15 min); refresh tokens hashed before storage
- **Append-only audit log** — every mutation is recorded before the response is returned
- **No hardcoded secrets** — all credentials via environment variables or mounted secrets
- **API tokens hashed with SHA-256** — only the prefix is stored for identification
- **RBAC with group-scoped permissions** — roles are assigned to groups, groups to users

## Known Security Considerations

- The default admin password is `admin` with `force_password_change=True`. Change it immediately on first login.
- The API is unauthenticated internally on the Docker bridge network — do not expose PostgreSQL or Redis ports externally.
- TLS termination should be handled by a reverse proxy (nginx, Caddy) or load balancer in front of the frontend container.

## Dependency Scanning

We use GitHub Dependabot for automated dependency updates. Critical security patches are applied as soon as feasible.
