{{/*
Chart-wide helpers. Mostly trivial wrappers around the standard Helm
patterns — extracted so templates don't repeat the boilerplate.
*/}}

{{- define "spatiumddi.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "spatiumddi.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "spatiumddi.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels applied to every resource.
*/}}
{{- define "spatiumddi.labels" -}}
helm.sh/chart: {{ include "spatiumddi.chart" . }}
{{ include "spatiumddi.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "spatiumddi.selectorLabels" -}}
app.kubernetes.io/name: {{ include "spatiumddi.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Per-component labels — include via:
  {{- include "spatiumddi.componentLabels" (merge (dict "component" "api") .) | nindent 4 }}
so the helper sees all root context plus the component name.
*/}}
{{- define "spatiumddi.componentLabels" -}}
helm.sh/chart: {{ include "spatiumddi.chart" . }}
app.kubernetes.io/name: {{ include "spatiumddi.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "spatiumddi.componentSelectorLabels" -}}
app.kubernetes.io/name: {{ include "spatiumddi.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Control-plane image — pass `imageName` (e.g. "spatiumddi-api") via merge:
  {{ include "spatiumddi.image" (merge (dict "imageName" "spatiumddi-api") .) }}
*/}}
{{- define "spatiumddi.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s/%s/%s:%s" .Values.image.registry .Values.image.repository .imageName $tag -}}
{{- end -}}

{{/*
Control-plane nodeSelector block. Issue #272 Phase 1 — emits a
``nodeSelector:`` stanza when either ``.Values.global.controlPlane
NodeSelector`` or the component-level override is non-empty, so the
six umbrella control-plane workloads (api / frontend / worker / beat
/ postgres / redis) share one selector path.

Pass the per-component override via merge:
  {{- include "spatiumddi.controlPlaneNodeSelector" (merge (dict "componentNodeSelector" .Values.api.nodeSelector) .) | nindent 6 }}

The helper returns nothing on empty merged map, so plain K8s
installs that haven't opted into the per-role label still let the
scheduler pick.
*/}}
{{- define "spatiumddi.controlPlaneNodeSelector" -}}
{{- $globalSel := default (dict) (.Values.global).controlPlaneNodeSelector -}}
{{- $componentSel := default (dict) .componentNodeSelector -}}
{{- $merged := merge (dict) $componentSel $globalSel -}}
{{- if $merged }}
nodeSelector:
  {{- toYaml $merged | nindent 2 }}
{{- end }}
{{- end -}}

{{/*
Emit the ``affinity:`` block for a replicated control-plane workload
(#590). Spreads a component's replicas one-per-node so a single node
loss costs at most one replica.

  {{- include "spatiumddi.podAntiAffinity" (merge (dict
        "component" "api"
        "mode" .Values.api.podAntiAffinity
        "replicas" .Values.api.replicas
        "override" .Values.api.affinity) .) | nindent 6 }}

``mode`` is one of:
  hard  — requiredDuringScheduling. The replica stays Pending until a
          distinct node is available. Correct on the appliance, where
          replicas tracks the control-plane node count exactly.
  soft  — preferredDuringScheduling. Best effort; the chart default so
          a BYO-Kubernetes install with more replicas than nodes still
          schedules.
  none  — emit no podAntiAffinity.

The default spread is MERGED into an operator-supplied
``<component>.affinity`` rather than replacing it: an operator who sets
``nodeAffinity`` (say, to keep a workload off spot/tainted nodes) must
not silently lose the cross-node spread that keeps a single node loss
survivable. Only an override that declares its OWN ``podAntiAffinity``
key wins — that one is an explicit opt-out, and merging the two would
render a duplicate key.

Nothing is spread below 2 replicas (nothing to spread).

#590 — api/worker/frontend previously defaulted to no affinity at all,
so a 3-node cluster could (and did) land 3 of 4 api pods on the seed.
Losing that node meant no ready api pod anywhere, and rescheduling off
a NotReady node waits out ``node.kubernetes.io/not-ready`` first — see
the matching tolerations on the appliance paths. Redis goes through the
same helper: its replicas are the ones whose mis-placement (two on the
seed, pinned there by local-path PVs) caused the outage.
*/}}
{{/*
Emit the ``strategy:`` block for a Deployment that may carry REQUIRED pod
anti-affinity (#590).

  {{- include "spatiumddi.deploymentStrategy" (dict
        "mode" .Values.api.podAntiAffinity
        "replicas" .Values.api.replicas) | nindent 2 }}

Required anti-affinity + ``replicas == number of eligible nodes`` makes the
default surge pod UNSCHEDULABLE, and the default ``maxUnavailable: 0`` then
forbids freeing a node by retiring an old pod first. The rollout wedges
permanently: the anti-affinity labelSelector matches on ``component``, which
the OUTGOING ReplicaSet's pods carry too, so the incoming surge pod sees
every node already occupied by one of its own.

Observed live on a 1→3 promote: two new api pods landed on the freshly
promoted members, the third sat Pending forever with "3 node(s) didn't match
pod anti-affinity rules" while the old pod held the seed.

So under ``hard`` we invert the knobs — retire one old pod, then schedule its
replacement onto the node it just freed. Costs one replica of capacity during
a rollout instead of deadlocking. (frontend's hostNetwork path uses Recreate
for the same underlying reason: an exclusive per-node resource.)
*/}}
{{- define "spatiumddi.deploymentStrategy" -}}
{{- $mode := default "soft" .mode -}}
strategy:
  type: RollingUpdate
  rollingUpdate:
  {{- if and (gt (int .replicas) 1) (eq $mode "hard") }}
    maxSurge: 0
    maxUnavailable: 1
  {{- else }}
    maxSurge: 1
    maxUnavailable: 0
  {{- end }}
{{- end -}}

{{- define "spatiumddi.podAntiAffinity" -}}
{{- $mode := default "soft" .mode -}}
{{- $affinity := deepCopy (default (dict) .override) -}}
{{- if and (gt (int .replicas) 1) (ne $mode "none") (not (hasKey $affinity "podAntiAffinity")) -}}
  {{- $selector := dict "matchLabels" (include "spatiumddi.componentSelectorLabels" . | fromYaml) -}}
  {{- $term := dict "labelSelector" $selector "topologyKey" "kubernetes.io/hostname" -}}
  {{- if eq $mode "hard" -}}
    {{- $_ := set $affinity "podAntiAffinity" (dict "requiredDuringSchedulingIgnoredDuringExecution" (list $term)) -}}
  {{- else -}}
    {{- $weighted := dict "weight" 100 "podAffinityTerm" $term -}}
    {{- $_ := set $affinity "podAntiAffinity" (dict "preferredDuringSchedulingIgnoredDuringExecution" (list $weighted)) -}}
  {{- end -}}
{{- end -}}
{{- if $affinity }}
affinity:
  {{- toYaml $affinity | nindent 2 }}
{{- end }}
{{- end -}}

{{/*
Name of the chart-owned secret carrying SECRET_KEY.
*/}}
{{- define "spatiumddi.appSecretName" -}}
{{- if .Values.auth.existingSecret -}}
{{- .Values.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-app" (include "spatiumddi.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Postgres connection parameters. Hostname + port + user + database come from
either the in-chart Postgres StatefulSet (templates/postgres.yaml) or the
externalDatabase block; the password is always referenced via a Secret
keyRef — never inlined.
*/}}
{{- define "spatiumddi.postgresHost" -}}
{{- if .Values.postgresql.enabled -}}
{{- if eq (.Values.postgresql.kind | default "standalone") "cnpg" -}}
{{/* CNPG auto-creates ``<cluster>-rw`` for the primary read/write
     service. The cluster object's name is the chart's fullname
     (see templates/cnpg-cluster.yaml). */}}
{{- printf "%s-postgresql-rw" (include "spatiumddi.fullname" .) -}}
{{- else -}}
{{- printf "%s-postgresql" (include "spatiumddi.fullname" .) -}}
{{- end -}}
{{- else -}}
{{- required "externalDatabase.host is required when postgresql.enabled=false" .Values.externalDatabase.host -}}
{{- end -}}
{{- end -}}

{{- define "spatiumddi.postgresPort" -}}
{{- if .Values.postgresql.enabled -}}5432{{- else -}}{{ .Values.externalDatabase.port }}{{- end -}}
{{- end -}}

{{- define "spatiumddi.postgresUser" -}}
{{- if .Values.postgresql.enabled -}}{{ .Values.postgresql.auth.username }}{{- else -}}{{ .Values.externalDatabase.username }}{{- end -}}
{{- end -}}

{{- define "spatiumddi.postgresDatabase" -}}
{{- if .Values.postgresql.enabled -}}{{ .Values.postgresql.auth.database }}{{- else -}}{{ .Values.externalDatabase.database }}{{- end -}}
{{- end -}}

{{/*
Name of the secret carrying the Postgres user password. For the in-
chart Postgres this is the chart-owned ``<fullname>-postgresql`` Secret
(key ``password``) — generated on first install via lookup() and
preserved across upgrades. ``postgresql.auth.existingSecret`` overrides
to a BYO secret. For external DB it's whatever the user set in
externalDatabase.existingSecret.
*/}}
{{- define "spatiumddi.postgresSecretName" -}}
{{- if .Values.postgresql.enabled -}}
{{- if .Values.postgresql.auth.existingSecret -}}
{{- .Values.postgresql.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-postgresql" (include "spatiumddi.fullname" .) -}}
{{- end -}}
{{- else if .Values.externalDatabase.existingSecret -}}
{{- .Values.externalDatabase.existingSecret -}}
{{- else -}}
{{- printf "%s-external-db" (include "spatiumddi.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "spatiumddi.postgresSecretPasswordKey" -}}
{{- if .Values.postgresql.enabled -}}password{{- else -}}{{ .Values.externalDatabase.existingSecretPasswordKey | default "password" }}{{- end -}}
{{- end -}}

{{/*
Redis connection. Hostname + port from either the bundled subchart or
externalRedis.
*/}}
{{- define "spatiumddi.redisHost" -}}
{{- if .Values.redis.enabled -}}
{{- printf "%s-redis-master" (include "spatiumddi.fullname" .) -}}
{{- else -}}
{{- required "externalRedis.host is required when redis.enabled=false" .Values.externalRedis.host -}}
{{- end -}}
{{- end -}}

{{- define "spatiumddi.redisPort" -}}
{{- if .Values.redis.enabled -}}6379{{- else -}}{{ .Values.externalRedis.port }}{{- end -}}
{{- end -}}

{{/*
True when the chart-owned Redis runs in Sentinel mode (#272 Phase 3).
Drives the sentinel:// URL branch in commonEnv + the master-name env.
*/}}
{{- define "spatiumddi.redisIsSentinel" -}}
{{- if and .Values.redis.enabled (eq (.Values.redis.kind | default "standalone") "sentinel") -}}true{{- end -}}
{{- end -}}

{{/*
Comma-separated sentinel host:port list for the redis-py-style
sentinel:// URL. Points at the per-pod headless DNS so the client can
reach every sentinel even mid-failover; the sentinel Service fronts
the same set for kombu.
*/}}
{{- define "spatiumddi.redisSentinelHosts" -}}
{{- $fullname := include "spatiumddi.fullname" . -}}
{{- $sts := printf "%s-redis" $fullname -}}
{{- $headless := printf "%s-redis-headless" $fullname -}}
{{- $n := int .Values.redis.sentinel.replicas -}}
{{- $hosts := list -}}
{{- range $i := until $n -}}
{{- $hosts = append $hosts (printf "%s-%d.%s.%s.svc.cluster.local:26379" $sts $i $headless $.Release.Namespace) -}}
{{- end -}}
{{- join "," $hosts -}}
{{- end -}}

{{- define "spatiumddi.redisAuthEnabled" -}}
{{- if .Values.redis.enabled -}}
{{- if .Values.redis.auth.enabled -}}true{{- end -}}
{{- else -}}
{{- if or .Values.externalRedis.password .Values.externalRedis.existingSecret -}}true{{- end -}}
{{- end -}}
{{- end -}}

{{- define "spatiumddi.redisSecretName" -}}
{{- if .Values.redis.enabled -}}
{{- if .Values.redis.auth.existingSecret -}}
{{- .Values.redis.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-redis" (include "spatiumddi.fullname" .) -}}
{{- end -}}
{{- else if .Values.externalRedis.existingSecret -}}
{{- .Values.externalRedis.existingSecret -}}
{{- else -}}
{{- printf "%s-external-redis" (include "spatiumddi.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "spatiumddi.redisSecretPasswordKey" -}}
{{- if .Values.redis.enabled -}}redis-password{{- else -}}{{ .Values.externalRedis.existingSecretPasswordKey | default "password" }}{{- end -}}
{{- end -}}

{{/*
Common env block for api / worker / beat. Only $(POSTGRES_PASSWORD) and
$(REDIS_PASSWORD) reference secrets; everything else is inline.
*/}}
{{- define "spatiumddi.commonEnv" -}}
{{/* Issue #274 — running version, surfaced by the api as
     ``settings.version`` and rendered in the sidebar's lower-
     left "v…" chip. Mirrors the docker-compose ``VERSION:
     ${SPATIUMDDI_VERSION:-dev}`` wiring on the helm path.
     Precedence: operator-pinned ``image.tag`` wins (e.g. for a
     manual rollback) → chart-packaged ``.Chart.AppVersion`` (the
     CalVer tag the release workflow stamps via
     ``helm package --app-version``) → falls through to the
     api's own ``"dev"`` fallback in ``app/config.py``. Same
     resolution chain as the existing ``spatiumddi.image``
     helper so the env value tracks the running image tag. */}}
- name: VERSION
  value: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "spatiumddi.postgresSecretName" . }}
      key: {{ include "spatiumddi.postgresSecretPasswordKey" . }}
- name: SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "spatiumddi.appSecretName" . }}
      key: secret-key
# #1159 — the /metrics scrape token. Optional: a Secret supplied through
# auth.existingSecret may not carry it, and then only API tokens can scrape.
- name: PROMETHEUS_METRICS_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "spatiumddi.appSecretName" . }}
      key: metrics-token
      optional: true
- name: DATABASE_URL
  value: "postgresql+asyncpg://{{ include "spatiumddi.postgresUser" . }}:$(POSTGRES_PASSWORD)@{{ include "spatiumddi.postgresHost" . }}:{{ include "spatiumddi.postgresPort" . }}/{{ include "spatiumddi.postgresDatabase" . }}"
{{- if eq (include "spatiumddi.redisIsSentinel" .) "true" }}
{{- $sentinelHosts := include "spatiumddi.redisSentinelHosts" . }}
{{- $sentinelSvc := printf "%s-redis-sentinel" (include "spatiumddi.fullname" .) }}
{{- /* #272 Phase 3 — Redis Sentinel. The app's redis-py helper parses
       the comma-separated host list in REDIS_URL; Celery/kombu reaches
       the sentinels through the Service VIP + the master_name set in
       celery_app.py's broker_transport_options. */}}
- name: REDIS_SENTINEL_MASTER
  value: {{ .Values.redis.sentinel.masterName | quote }}
{{- if .Values.redis.auth.enabled }}
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "spatiumddi.redisSecretName" . }}
      key: {{ include "spatiumddi.redisSecretPasswordKey" . }}
- name: REDIS_SENTINEL_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "spatiumddi.redisSecretName" . }}
      key: {{ include "spatiumddi.redisSecretPasswordKey" . }}
- name: REDIS_URL
  value: "sentinel://:$(REDIS_PASSWORD)@{{ $sentinelHosts }}/0"
- name: CELERY_BROKER_URL
  value: "sentinel://:$(REDIS_PASSWORD)@{{ $sentinelSvc }}:26379/1"
- name: CELERY_RESULT_BACKEND
  value: "sentinel://:$(REDIS_PASSWORD)@{{ $sentinelSvc }}:26379/2"
{{- else }}
- name: REDIS_URL
  value: "sentinel://{{ $sentinelHosts }}/0"
- name: CELERY_BROKER_URL
  value: "sentinel://{{ $sentinelSvc }}:26379/1"
- name: CELERY_RESULT_BACKEND
  value: "sentinel://{{ $sentinelSvc }}:26379/2"
{{- end }}
{{- else if eq (include "spatiumddi.redisAuthEnabled" .) "true" }}
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "spatiumddi.redisSecretName" . }}
      key: {{ include "spatiumddi.redisSecretPasswordKey" . }}
- name: REDIS_URL
  value: "redis://:$(REDIS_PASSWORD)@{{ include "spatiumddi.redisHost" . }}:{{ include "spatiumddi.redisPort" . }}/0"
- name: CELERY_BROKER_URL
  value: "redis://:$(REDIS_PASSWORD)@{{ include "spatiumddi.redisHost" . }}:{{ include "spatiumddi.redisPort" . }}/1"
- name: CELERY_RESULT_BACKEND
  value: "redis://:$(REDIS_PASSWORD)@{{ include "spatiumddi.redisHost" . }}:{{ include "spatiumddi.redisPort" . }}/2"
{{- else }}
- name: REDIS_URL
  value: "redis://{{ include "spatiumddi.redisHost" . }}:{{ include "spatiumddi.redisPort" . }}/0"
- name: CELERY_BROKER_URL
  value: "redis://{{ include "spatiumddi.redisHost" . }}:{{ include "spatiumddi.redisPort" . }}/1"
- name: CELERY_RESULT_BACKEND
  value: "redis://{{ include "spatiumddi.redisHost" . }}:{{ include "spatiumddi.redisPort" . }}/2"
{{- end }}
{{- if .Values.dnsAgents.enabled }}
{{/* DNS agent PSK — agents bootstrap-register against the api with
     this key, so the api / worker pods need it to verify the
     incoming registration handshake. The Secret is rendered by
     templates/dns-agent.yaml under the same name + key. */}}
- name: DNS_AGENT_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.dnsAgents.agentKey.existingSecret | default (printf "%s-dns-agent-key" (include "spatiumddi.fullname" .)) }}
      key: DNS_AGENT_KEY
{{- end }}
{{- if .Values.dhcpAgents.enabled }}
{{/* DHCP agent PSK. Agent side env var is SPATIUM_AGENT_KEY, but the
     control plane reads DHCP_AGENT_KEY (see backend/app/api/v1/dhcp/
     agents.py). The dhcp-agent Secret stores under SPATIUM_AGENT_KEY
     so we name the env var differently while pointing at the same
     value. */}}
- name: DHCP_AGENT_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.dhcpAgents.agentKey.existingSecret | default (printf "%s-dhcp-agent-key" (include "spatiumddi.fullname" .)) }}
      key: SPATIUM_AGENT_KEY
{{- end -}}
{{- end -}}

{{/*
Init container that blocks until the bundled / external Postgres is
accepting connections. Used by the migrate Job. ``pg_isready`` ships in
the api image (postgresql-client-16, see backend/Dockerfile).
*/}}
{{- define "spatiumddi.waitForPostgresInit" -}}
- name: wait-for-postgres
  image: {{ include "spatiumddi.image" (merge (dict "imageName" "spatiumddi-api") .) }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  command:
    - sh
    - -c
    - |
      until pg_isready -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -t 3 >/dev/null 2>&1; do
        echo "waiting for postgres at $PGHOST:$PGPORT..."
        sleep 3
      done
      echo "postgres is accepting connections"
  env:
    - name: PGHOST
      value: {{ include "spatiumddi.postgresHost" . | quote }}
    - name: PGPORT
      value: {{ include "spatiumddi.postgresPort" . | quote }}
    - name: PGUSER
      value: {{ include "spatiumddi.postgresUser" . | quote }}
    - name: PGDATABASE
      value: {{ include "spatiumddi.postgresDatabase" . | quote }}
{{- end -}}

{{/*
Init container that blocks until the DB schema reaches the alembic
head(s) baked into THIS image. Used by api / worker / beat.

Why "reach head" and not just "any alembic row exists" (#272 Phase 4 /
Phase 8 — rolling-upgrade ordering): during a chart upgrade the new
api/worker/beat Pods carry a newer image whose alembic head has moved.
If we only waited for *some* alembic_version row, a new Pod could start
against the OLD schema and hit UndefinedColumnError on the first request
touching a new column. By comparing this image's ``alembic heads``
against the live DB's ``alembic current`` we guarantee the migrate Job
(same new image) has finished applying the new migration before any new
app Pod accepts traffic.

Uses ``alembic`` from the api image (same binary + DATABASE_URL the
migrate Job uses), so no psql / secret plumbing is needed here — the
URL comes from commonEnv.
*/}}
{{- define "spatiumddi.waitForMigrateInit" -}}
- name: wait-for-migrate
  image: {{ include "spatiumddi.image" (merge (dict "imageName" "spatiumddi-api") .) }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  command:
    - sh
    - -c
    - |
      # Head(s) compiled into this image's migration tree. ``$1`` drops
      # the trailing "(head)" annotation; sort makes the comparison
      # order-independent across branched heads.
      HEADS=$(alembic heads 2>/dev/null | awk '{print $1}' | sort | tr '\n' ',')
      echo "this image's alembic head(s): ${HEADS:-<none>}"
      while :; do
        CUR=$(alembic current 2>/dev/null | awk '{print $1}' | sort | tr '\n' ',')
        if [ -n "$CUR" ] && [ "$CUR" = "$HEADS" ]; then
          echo "alembic at head ($CUR)"
          break
        fi
        echo "waiting for alembic to reach head; current=${CUR:-<unreachable/empty>}"
        sleep 3
      done
  env:
    {{- include "spatiumddi.commonEnv" . | nindent 4 }}
{{- end -}}

{{/*
#983 — the pod-level seccomp profile applied to every workload this chart
renders.

Kubernetes runs a container ``Unconfined`` unless a profile is asked for,
while docker-compose applies the runtime's default profile to every
service. So without this the SAME container images run with FEWER syscall
restrictions under Kubernetes than under Compose — a regression, not a
gap. ``RuntimeDefault`` under containerd is the same profile family
Compose gets from Docker, which is also why it is low-risk: the raw
sockets Kea needs, the api's pcap capture (#59) and nmap (#58) all
already run under it on a Compose install.

Returns the bare type string (or nothing when disabled) so a caller can
place it inside an existing ``securityContext:`` block or open its own:

    {{- with (include "spatiumddi.seccompProfileType" .) }}
    securityContext:
      seccompProfile:
        type: {{ . }}
    {{- end }}

``Localhost`` is rejected rather than passed through: it needs a
``localhostProfile`` path relative to the kubelet's seccomp root, which
this chart has no way to place on the node. Set the value to ``""`` to
omit the block entirely (an exotic runtime whose default profile breaks a
workload) — that restores the pre-#983 behaviour, it does not harden
anything.
*/}}
{{- define "spatiumddi.seccompProfileType" -}}
{{- $t := default "" (.Values.global).seccompProfile -}}
{{- if and $t (not (has $t (list "RuntimeDefault" "Unconfined"))) -}}
{{- fail (printf "global.seccompProfile must be \"RuntimeDefault\", \"Unconfined\" or \"\" — got %q. Localhost profiles need a localhostProfile path this chart cannot place on the node." $t) -}}
{{- end -}}
{{- $t -}}
{{- end -}}

{{/*
#983 — resolve a workload's PriorityClass name.

Every pod this chart renders is Burstable at priority 0 by default, which
makes them indistinguishable to two schedulers' worth of ranking:
kubelet eviction under memory / ephemeral-storage pressure orders victims
by priority THEN usage-over-request, and scheduler preemption gives a
pending pod no claim on a full node. With every priority equal, the
likeliest eviction victim is whichever pod grew the most — on an
appliance, BIND with a warm cache.

Defaults to empty: a bring-your-own cluster has its own priority policy,
and naming a PriorityClass that does not exist makes the apiserver
REJECT the pod outright, so this must never be set speculatively. The
appliance overlay (spatiumddi-firstboot's spatium-control valuesContent)
sets ``global.priorityClassName`` to the class the appliance chart
renders.

Args: ``component`` (the per-workload override) and ``fallback`` (the
chart-wide default). Returns the resolved name, or nothing.

UNSET and EMPTY are different, deliberately: a per-workload key left unset
(the shipped default, YAML null) INHERITS the chart-wide value, while
setting it to ``""`` means "no class for this one" and overrides a
non-empty chart-wide value. Sprig's ``default`` cannot express that — it
treats null and "" alike — so the nil test is explicit. Without it
``priorityClassName: ""`` would silently inherit, which is the opposite of
what a key documented as an override should do, and there would be no way
to leave a single workload unranked on a cluster that has a global policy.
*/}}
{{- define "spatiumddi.priorityClassName" -}}
{{- if kindIs "invalid" .component -}}
{{- default "" .fallback -}}
{{- else -}}
{{- .component -}}
{{- end -}}
{{- end -}}

{{/*
#983 Phase 2 item 8 — topology spread for a replicated control-plane
workload, umbrella chart only.

Only meaningful in ``soft`` anti-affinity mode. ``preferred`` anti-affinity
is a *preference*: the scheduler weighs it against everything else and can
still land three api replicas on one node, which is the whole failure the
replica count exists to avoid. ``maxSkew: 1`` with
``whenUnsatisfiable: ScheduleAnyway`` is a second, differently-shaped push
toward one-per-node that still degrades to "schedule it somewhere" rather
than leaving a replica Pending.

Emitted for NEITHER of the other two modes, on purpose:

  * ``hard`` already pins one replica per node with required anti-affinity —
    the appliance's shape (#590), where replicas track the control-plane node
    count exactly. A spread constraint there is inert at best.
  * ``none`` means the operator has taken placement into their own hands.

Also skipped at ``replicas: 1``, where there is nothing to spread, and
whenever the operator supplied their own ``topologySpreadConstraints`` —
this augments a default, it never overrides an explicit choice.

``ScheduleAnyway`` rather than ``DoNotSchedule`` is the load-bearing part:
DoNotSchedule on a cluster with fewer ready nodes than replicas leaves the
surplus permanently Pending, which converts a placement preference into an
outage. Operators who want the strict form set ``hard``.
*/}}
{{- define "spatiumddi.topologySpreadConstraints" -}}
{{- $mode := default "soft" .mode -}}
{{- if .override -}}
topologySpreadConstraints:
  {{- toYaml .override | nindent 2 }}
{{- else if and (gt (int .replicas) 1) (eq $mode "soft") -}}
{{- $selector := dict "matchLabels" (include "spatiumddi.componentSelectorLabels" . | fromYaml) -}}
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      {{- toYaml $selector | nindent 6 }}
{{- end -}}
{{- end -}}

{{/*
#983 Phase 2 item 5 — user namespaces (``hostUsers: false``, GA in
Kubernetes 1.36). Container root maps to an unprivileged host uid, so an
escape from the pod is not root on the node.

Default UNSET everywhere and it must stay that way in this chart: a
bring-your-own cluster may run a runtime without idmapped-mount support, and
there the pod does not start. Failing to start with a clear event is the
right failure — but it is still a failure, so it has to be the operator's
choice, not a chart default.

THE ELIGIBILITY LIST IN #983 IS WRONG ABOUT THE APPLIANCE, and this helper
is where that gets enforced rather than commented. The issue reasoned that
``api`` and ``worker`` neither hostNetwork nor hostPath-mount, which is true
of a plain Kubernetes install and false of an appliance: with
``api.applianceHostMounts.enabled`` the api bind-mounts five host
directories (and WRITES the slot-upgrade triggers and the maintenance flag),
and the worker bind-mounts the shared pcap store. spatiumddi-firstboot
chowns those 1000:1000 to match the image's uid — a mapping that a user
namespace changes by definition. That is the same "a wrong uid map corrupts
data rather than failing to start" hazard the issue reserved for Postgres,
so the combination is refused outright instead of being left to discover.

A PVC carries a quieter version of the same hazard on the appliance, where
the StorageClass is local-path and a PVC is a host directory underneath.
That one is documented at each knob rather than refused: the runtime may
idmap it correctly, and refusing would leave redis with no way to opt in on
a cluster where it works.

Args: ``value`` (bool or nil), ``conflict`` (bool), ``workload``, ``why``.
*/}}
{{- define "spatiumddi.hostUsers" -}}
{{- if not (kindIs "invalid" .value) -}}
{{- if and (not .value) .conflict -}}
{{- fail (printf "%s.hostUsers=false is refused: %s. A user namespace remaps every uid in the pod, so host files chowned to the image's uid stop being readable — and for a directory the pod WRITES that corrupts state rather than failing to start. Either leave hostUsers unset here, or turn off the host mounts." .workload .why) -}}
{{- end -}}
hostUsers: {{ .value }}
{{- end -}}
{{- end -}}
