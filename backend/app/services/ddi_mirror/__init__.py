"""Commercial-DDI live mirror (issue #4729).

``base`` — the vendor-neutral provider contract (``DDIProvider``) and the
neutral ``SourceObject`` every provider maps its objects into.
``infoblox`` — the Infoblox WAPI provider (the first vendor).
``registry`` — vendor key -> provider class; BlueCat and EfficientIP register
here when their providers land.
``reconcile`` — pulls a target into the ``ddi_mirror_object`` store.
``rehearsal`` — compares the store with live IPAM / DNS to show what an import
would create and what differs.

The mirror is read-only toward the source and never writes live IPAM / DNS.
"""
