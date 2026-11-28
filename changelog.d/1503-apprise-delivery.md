### Added

- **Alerts and audit events through Apprise: Telegram, ntfy, Pushover,
  Matrix and more (#1503).** Webhook forward targets get an `apprise`
  flavor. Its URL is one [Apprise](https://github.com/caronc/apprise)
  service URL, e.g. `tgram://<bot_token>/<chat_id>` or
  `ntfys://<user>:<password>@<host>/<topic>`, and Apprise formats the
  message for that service. It is a webhook target, so an alert rule's
  existing webhook channel, `min_severity` and resource filters apply
  unchanged. The URL is stored like every webhook URL since #1502:
  Fernet-encrypted, write-only, shown only as its scheme (`tgram://…`).
  Saving checks that Apprise can read the URL, without sending anything
  and without echoing it in the 422. Delivery and the Test button run on a
  small thread pool, off the event loop, with Apprise's per-request
  timeouts and a 20-second deadline per message. The Test button now
  reports the service's own reason ("Bad Request: chat not found"), with
  the URL's token and credentials redacted. Apprise's log lines are kept
  out of the api and worker logs, and the URL's parts are scrubbed from
  any library's log line written during a send; the support-bundle
  scrubber recognises the common Apprise URL shapes and Telegram bot
  tokens. New dependency: `apprise` 2.x (BSD 2-Clause), which brings
  `requests-oauthlib`, `oauthlib` and `Markdown`; see NOTICE and
  `docs/THIRD_PARTY.md`. `docs/PRIVACY.md` lists Apprise destinations as
  an operator-configured connection. Apprise also reaches Microsoft Teams
  through Power Automate Workflows (`workflows://…`, or the workflow's
  HTTPS URL as is).

