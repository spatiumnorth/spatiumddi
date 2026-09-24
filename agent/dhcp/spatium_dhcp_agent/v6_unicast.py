"""The host's global IPv6 addresses, for Kea's DHCPv6 unicast sockets (#1140).

``interfaces-config.interfaces: ["*"]`` makes kea-dhcp6 bind each
interface's link-local address and the ``ff02::1:2`` All_DHCP_Relay_Agents_
and_Servers group — and nothing else. A relay does not send there: it sends
its Relay-Forward to the server address it was configured with, which is a
GLOBAL unicast address, so with ``"*"`` alone every relayed Solicit reaches
the NIC and finds no socket. Kea opens a unicast socket only for an explicit
``"<iface>/<address>"`` entry.

Measured against kea-dhcp6 3.0.3 (2026-09-24) rather than taken from the
docs, because two properties decide the design:

* ``["*", "eth0/<global>"]`` keeps every wildcard socket AND adds the
  unicast one (``DHCPSRV_CFGMGR_USE_UNICAST``), and several unicast
  entries on one interface are all bound. So the entries are additive:
  nothing the wildcard already covered is lost.
* An entry naming an address the interface does not currently hold makes
  kea-dhcp6 refuse the WHOLE configuration (``DHCP6_INIT_FAIL`` — "interface
  'eth0' doesn't have address … assigned"). A configured address that
  drifted would therefore take DHCPv6 down entirely, which is why this is
  derived from the live host at render time and never from a stored setting,
  and why the agent re-renders when the set changes (``sync``).

The control plane cannot supply these: it is never told the host's IPv6
addresses (the supervisor reports NIC names only), and only the agent — on
the appliance, in the host network namespace — can see them.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import structlog

log = structlog.get_logger(__name__)

PROC_IF_INET6 = Path("/proc/net/if_inet6")

# ``/proc/net/if_inet6`` scope column. Only global scope is useful: a relay
# is off-link by definition, and link-local is what ``"*"`` already binds.
_SCOPE_GLOBAL = 0x00

# ``IFA_F_*`` bits in the flags column that make an address unfit to bind.
# Temporary (RFC 8981 privacy) addresses rotate on the order of hours;
# deprecated ones are on their way out; tentative / dad-failed ones cannot be
# bound at all. Any of them would put an address in the config that is about
# to vanish — and a vanished address fails the whole config (see above).
_IFA_F_TEMPORARY = 0x01
_IFA_F_DADFAILED = 0x08
_IFA_F_DEPRECATED = 0x20
_IFA_F_TENTATIVE = 0x40
_UNFIT = _IFA_F_TEMPORARY | _IFA_F_DADFAILED | _IFA_F_DEPRECATED | _IFA_F_TENTATIVE


def parse_if_inet6(text: str) -> list[tuple[str, str]]:
    """``/proc/net/if_inet6`` body → sorted ``[(ifname, address)]`` of the
    global, stable addresses Kea can bind.

    Row layout, whitespace-separated::

        <32 hex digits> <ifindex> <prefix len> <scope> <flags> <ifname>

    Sorted so the rendered document — and the change detection in ``sync``
    — does not depend on kernel enumeration order.
    """
    out: set[tuple[str, str]] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        hexaddr, _ifindex, _plen, scope_hex, flags_hex, ifname = parts[:6]
        try:
            scope = int(scope_hex, 16)
            flags = int(flags_hex, 16)
            addr = ipaddress.IPv6Address(int(hexaddr, 16))
        except ValueError:
            continue
        if ifname == "lo" or scope != _SCOPE_GLOBAL or flags & _UNFIT:
            continue
        if addr.is_link_local or addr.is_loopback or addr.is_multicast:
            continue
        out.add((ifname, addr.compressed))
    return sorted(out)


def global_ipv6_addresses(path: Path = PROC_IF_INET6) -> list[tuple[str, str]]:
    """The live host's bindable global IPv6 addresses, or ``[]``.

    A missing file means the kernel has IPv6 disabled; an unreadable one is
    logged and treated the same. Either way the render falls back to the
    wildcard alone — exactly the pre-#1140 behaviour, never a broken config.
    """
    try:
        text = path.read_text()
    except FileNotFoundError:
        return []
    except OSError as exc:
        log.warning("dhcp6_unicast_detect_failed", path=str(path), error=str(exc))
        return []
    return parse_if_inet6(text)


__all__ = ["PROC_IF_INET6", "global_ipv6_addresses", "parse_if_inet6"]
