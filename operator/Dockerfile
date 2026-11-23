# The SpatiumDDI Operator: Red Hat's helm-operator runtime plus the umbrella
# chart baked in. Build from the REPOSITORY ROOT so the chart is in context:
#
#   docker buildx build -f operator/Dockerfile --build-arg VERSION=1.0.0 .
#
# The base is the operator-sdk project's own helm-operator image (UBI 9
# derived, multi-arch: amd64 + arm64). Its tag is pinned in versions.json and
# must equal the operator-sdk version used to generate the bundle.
FROM quay.io/operator-framework/helm-operator:v1.42.3

# The release version, stamped into the vendored chart's Chart.yaml. The
# checked-in chart carries the placeholders ``version: 0.1.0`` and
# ``appVersion: "0.0.0-dev"`` that release.yml overrides at ``helm package``
# time; the operator has to do the same, because the chart defaults every
# image tag (api, frontend, agents) to appVersion. An image built without
# this would try to pull ghcr.io/spatiumnorth/spatiumddi-api:0.0.0-dev.
ARG VERSION=0.0.0-dev

ENV HOME=/opt/helm
# 1001:0 is the base image's own user; group 0 + g=u keeps it usable under
# OpenShift's random-uid restricted-v2 SCC, which runs with group 0.
COPY --chown=1001:0 operator/watches.yaml ${HOME}/watches.yaml
COPY --chown=1001:0 charts/spatiumddi ${HOME}/helm-charts/spatiumddi

USER root
# Take the UBI security errata published since the base image was built: its OS
# layer lags the repositories, and Trivy fails the image on what is already
# fixed there. (The Go dependencies inside the helm-operator binary cannot be
# fixed from here; they move only with a new upstream release, see versions.json.)
RUN microdnf -y update --setopt=install_weak_deps=0 --nodocs && microdnf clean all \
 && sed -i -e "s|^version: .*|version: ${VERSION}|" \
           -e "s|^appVersion: .*|appVersion: \"${VERSION}\"|" \
           ${HOME}/helm-charts/spatiumddi/Chart.yaml \
 && grep -q "^version: ${VERSION}\$" ${HOME}/helm-charts/spatiumddi/Chart.yaml \
 && grep -q "^appVersion: \"${VERSION}\"\$" ${HOME}/helm-charts/spatiumddi/Chart.yaml \
 && chmod -R g=u ${HOME}
USER 1001

WORKDIR ${HOME}
