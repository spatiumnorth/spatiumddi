{{/*
  Shared helpers for the spatiumddi-appliance chart (issue #183 Phase 2).
*/}}

{{/* Chart-level name + fullname helpers. The Helm convention is to
     prefix all rendered resources with the release name + chart name
     so two installs can coexist; on a single-node appliance both are
     fixed by the supervisor, but we keep the helper for symmetry
     with the existing charts/spatiumddi/ chart. */}}
{{- define "spatiumddi-appliance.name" -}}
{{- default "spatiumddi-appliance" .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "spatiumddi-appliance.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "spatiumddi-appliance.labels" -}}
app.kubernetes.io/name: {{ include "spatiumddi-appliance.name" . }}
{{ include "spatiumddi-appliance.podLabels" . }}
{{- end -}}

{{/* Pod-template labels: everything in .labels EXCEPT app.kubernetes.io/name,
     which every pod template sets to its own workload name (dns-bind9,
     dhcp-kea, ...) so the selector matches. Including .labels there too
     emitted the key twice in one map — YAML that yaml.v2 resolves last-wins
     (which is why the live pods were always labelled correctly) but that a
     strict decoder rejects outright: kubeconform, and kubectl's
     --validate=strict. Found by the #966 render gate on the first run. */}}
{{- define "spatiumddi-appliance.podLabels" -}}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: spatiumddi
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{/* Image-resolution helper. Air-gap forces pullPolicy: Never; the
     bytes live in containerd's content store already (preloaded at
     firstboot from /usr/lib/spatiumddi/images/*.tar.zst). */}}
{{- define "spatiumddi-appliance.imageRef" -}}
{{- $repo := required "image.repository required" .repository -}}
{{- $tag := default $.global.imageTag .tag -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}

{{/*
#983 — pod-level seccomp profile, shared by every workload this chart
renders. Mirrors ``spatiumddi.seccompProfileType`` in the umbrella chart;
duplicated rather than shared because Helm named templates are per-chart
and the appliance chart is not a subchart of the umbrella.

Kubernetes runs a container ``Unconfined`` unless a profile is asked for,
while docker-compose applies the runtime's default profile to every
service — so without this the appliance runs the SAME images with fewer
syscall restrictions than a Compose install. ``RuntimeDefault`` under
containerd is the same profile family Compose gets from Docker.

Returns the bare type string, or nothing when disabled.
*/}}
{{- define "spatiumddi-appliance.seccompProfileType" -}}
{{- $t := default "" (.Values.global).seccompProfile -}}
{{- if and $t (not (has $t (list "RuntimeDefault" "Unconfined"))) -}}
{{- fail (printf "global.seccompProfile must be \"RuntimeDefault\", \"Unconfined\" or \"\" — got %q. Localhost profiles need a localhostProfile path this chart cannot place on the node." $t) -}}
{{- end -}}
{{- $t -}}
{{- end -}}


{{/*
#1281 — an agent given the EXTERNAL control-plane URL (an off-cluster
appliance) verifies it against the certificate its supervisor pinned, in
place of the SPATIUM_INSECURE_SKIP_TLS_VERIFY=1 these pods used to set. That
connection carries the platform-wide agent key out and the DNS / DHCP
configuration back, so an unverified one handed both to anyone on the path.

The supervisor pins the certificate on first contact and re-pins a rotated
one only when the appliance CA vouches for it (``cp_tls``, #1219). Its tls/
directory holds only public material: the pin, its own client certificate
and the CA chain; the private key lives in identity/, which is not mounted.
The DIRECTORY is mounted, not the file: the supervisor replaces the pin
atomically (a new inode), which a single-file bind mount would never see.
``type: Directory`` rather than DirectoryOrCreate, so kubelet never creates
it root-owned ahead of the supervisor; the pod waits until it exists. The
agent reads the file on every client build and fails closed while it is
absent. The one exception is ``controlPlaneTls.insecureSkipVerify``, which the
supervisor sets only when it was itself started with the skip (see
values.yaml): a supervisor that does not verify pins nothing. Paths match ``cp_tls.PIN_FILENAME`` + the supervisor's STATE_DIR
(pinned by agent/supervisor/tests/test_role_pod_pinned_tls.py).
*/}}
{{- define "spatiumddi-appliance.cpPin.env" -}}
{{- if (.Values.controlPlaneTls).insecureSkipVerify }}
- name: SPATIUM_INSECURE_SKIP_TLS_VERIFY
  value: "1"
{{- else }}
- name: TLS_PINNED_CERTS_PATH
  value: /var/lib/spatium-cp-tls/control-plane.pem
{{- end }}
{{- end -}}

{{- define "spatiumddi-appliance.cpPin.mount" -}}
{{- if not (.Values.controlPlaneTls).insecureSkipVerify }}
- name: cp-tls-pin
  mountPath: /var/lib/spatium-cp-tls
  readOnly: true
{{- end }}
{{- end -}}

{{- define "spatiumddi-appliance.cpPin.volume" -}}
{{- if not (.Values.controlPlaneTls).insecureSkipVerify }}
- name: cp-tls-pin
  hostPath:
    path: {{ printf "%s/tls" .Values.supervisor.hostMounts.stateDir }}
    type: Directory
{{- end }}
{{- end -}}
