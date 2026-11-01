### Fixed

- An open alert no longer shows a rule's edited threshold (or its free-address floor) as its current reading (`[now: 73%]` on a subnet that still reads 71.4%): the event's message restates the new threshold in place, and `[now: …]` carries only readings (#3233). The seeded `/var` rule's description now says it resolves once usage is 5 points below the threshold, as it does, and existing untouched rows are refreshed (#3232).
