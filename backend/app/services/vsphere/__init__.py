"""VMware vSphere integration — read-only REST mirror into IPAM (#4740).

Service layer. The reconciler + vSphere Automation REST client live here;
per-target row CRUD lives under ``app.api.v1.vsphere``; the Celery beat
sweep lives under ``app.tasks.vsphere_sync``.
"""

from __future__ import annotations
