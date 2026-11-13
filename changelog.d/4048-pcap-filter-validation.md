### Security

- **Stricter packet-capture filter validation.** The capture filter is
  now refused when it starts with `-`, and tcpdump is told where its
  options end so the filter is only ever read as an expression. Capture
  failures no longer return raw tcpdump output to the caller: the API
  shows a fixed message and the details stay in the server log.
