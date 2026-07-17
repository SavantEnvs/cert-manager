# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile for cert-manager (cert-manager/cert-manager) — a large Kubernetes
# controller project. OSS-Fuzz ships 11 harnesses across it: 9 native `func FuzzX(f *testing.F)`
# targets (controller reconcilers + a webhook admission validator) built via go-118-fuzz-build_v2
# (compile_native_go_fuzzer_v2), plus 2 LEGACY `func Fuzz(data []byte) int` targets in
# pkg/util/pki built via go-fuzz (go114-fuzz-build). go-118-fuzz-build_v2/go-fuzz only compile
# the targeted fuzz function + its import closure (not the whole cert-manager binary/all
# controllers), so the build stays bounded despite the size of the module.
#
# Builds ON TOP of the org C/C++ base image (ghcr.io/mayhemheroes/base). The base provides
# debian + clang/llvm + libFuzzer + the identities + the build-contract ENV. For a Go project,
# the base (C/C++ only — NO Go toolchain) needs Go added here as a USER root step, then the
# OSS-Fuzz Go fuzzing tooling that turns native/legacy Go fuzz harnesses into libFuzzer-
# instrumented binaries linked with $LIB_FUZZING_ENGINE.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t cert-manager-commit:test .

FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); never bake it as ENV — an empty value
# breaks clang. build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH

# Sanitizer override: the base exports SANITIZER_FLAGS (ASan+UBSan, halting) as the default.
# NOTE: the OSS-Fuzz Go path is ASAN-only (project.yaml sanitizers: [address]); the Go fuzz
# binaries are built with ASan and link the libFuzzer engine. build.sh handles the Go specifics.
ARG SANITIZER_FLAGS
ARG MAYHEM_JOBS=

# Pin the Go toolchain version (cert-manager's go.mod requires `go 1.26.0`).
ARG GO_VERSION=1.26.4
ARG GO_SHA256=1153d3d50e0ac764b447adfe05c2bcf08e889d42a02e0fe0259bd47f6733ad7f

# ── Go toolchain @ a FIXED, lockable, $HOME-independent prefix ──────────────────────────────────
# SPEC §6.2 item 8 + §6.5: commit build and PATCH re-run run under different $HOMEs.
# Pinning GOROOT/GOPATH/GOMODCACHE/GOCACHE under /opt/toolchains ensures the module cache
# populated during the first (online) image build is found again when build.sh re-runs offline.
ENV GOROOT=/opt/toolchains/go \
    GOPATH=/opt/toolchains/go-path \
    GOMODCACHE=/opt/toolchains/go-path/pkg/mod \
    GOCACHE=/opt/toolchains/go-path/build-cache \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=mod \
    PATH=/opt/toolchains/go/bin:/opt/toolchains/go-path/bin:/usr/local/bin:/usr/bin:/bin

# ── Install Go + the OSS-Fuzz Go fuzzing build tools (root step) ──────────────────────────────
# Replicates OSS-Fuzz base-builder's install_go.sh, the two tools cert-manager's own OSS-Fuzz
# build.sh actually uses:
#   * go114-fuzz-build (symlinked as `go-fuzz`) — LEGACY `func Fuzz([]byte) int` harnesses
#     (pkg/util/pki: FuzzUnmarshalSubjectStringToRDNSequence, FuzzDecodePrivateKeyBytes;
#     compile_go_fuzzer in the upstream OSS-Fuzz recipe).
#   * go-118-fuzz-build @ the `v2` branch, installed as go-118-fuzz-build_v2 — the NATIVE
#     `func FuzzX(f *testing.F)` harnesses (compile_native_go_fuzzer_v2 in the upstream recipe;
#     the 9 controller/webhook targets).
USER root
RUN install -d /opt/toolchains/go-path \
    && wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tgz \
    && echo "${GO_SHA256}  /tmp/go.tgz" | sha256sum -c - \
    && tar -C /opt/toolchains -xzf /tmp/go.tgz && rm /tmp/go.tgz \
    && go version \
    && go install github.com/mdempsky/go114-fuzz-build@latest \
    && ln -sf "$(go env GOPATH)/bin/go114-fuzz-build" "$(go env GOPATH)/bin/go-fuzz" \
    && git clone -q --depth=1 https://github.com/AdamKorcz/go-118-fuzz-build /tmp/go-118-fuzz-build \
    && ( cd /tmp/go-118-fuzz-build \
         && git fetch -q --depth=1 origin v2 \
         && git checkout -q FETCH_HEAD \
         && go build . \
         && mv go-118-fuzz-build "$(go env GOPATH)/bin/go-118-fuzz-build_v2" ) \
    && rm -rf /tmp/go-118-fuzz-build \
    && ls -la "$(go env GOPATH)/bin" \
    && chmod -R a+rX /opt/toolchains/go \
    && chown -R 2000:2000 /opt/toolchains/go-path \
    && go clean -cache 2>/dev/null || true

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git history)
# is copied to /mayhem as `mayhem`; build.sh builds in place.
USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

# Run cert-manager's own Go test suite (scoped to the fuzzed packages) at build time — a
# failing suite fails the image build. See mayhem/test.sh for why it's scoped, not `./...`.
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
