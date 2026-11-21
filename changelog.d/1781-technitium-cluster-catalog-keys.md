### Fixed

- Technitium: the agent's TSIG key sync now preserves the `cluster-catalog.*` keys of a daemon with clustering initialised, so applies are no longer refused; clustering agent-managed nodes remains unsupported because cluster parameters replicate between peers. The blocklist sinkhole mapping reported in the same issue was already fixed in #2124.
