### Added

- Logs → DNS Queries now shows how a query was answered. The details modal has an "Answered by" row and the filter bar an "Answered by" filter (authoritative, cache, forwarded, recursion, not reported). PowerDNS Authoritative reports it per query (packet-cache hit, or a non-empty answer from its own zones). BIND9's query log carries no such signal, so its rows read "not reported" rather than a guess; upstream attribution for forwarded queries needs dnstap (#3580).
