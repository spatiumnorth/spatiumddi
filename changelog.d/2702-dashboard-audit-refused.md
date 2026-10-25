### Fixed

- **The Dashboard no longer polls the audit log for a user who may not read
  it (#2702).** Live Activity asked `GET /audit` every 15 s whatever the
  user's role; each refusal wrote a `denied` audit row (about 5,760 a day for
  one open tab) and the card read "No recent activity". It now asks only
  with read on `audit_log`, stops after a refusal, and says the user may not
  see the log. The certificates card likewise says it is withheld instead of
  "0 of 0 monitored".
