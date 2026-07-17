#!/usr/bin/env bash
#
# cert-manager/mayhem/build.sh — build cert-manager's 11 OSS-Fuzz Go fuzz targets as sanitized
# libFuzzer binaries, REPLICATING OSS-Fuzz's projects/cert-manager/build.sh:
#
#   cp $SRC/pki_fuzzer.go $SRC/cert-manager/pkg/util/pki/
#   compile_native_go_fuzzer_v2 .../internal/webhook/admission/certificaterequest/approval FuzzValidate FuzzValidate_approval
#   compile_native_go_fuzzer_v2 .../pkg/controller/certificates/trigger FuzzProcessItem FuzzProcessItem_trigger
#   compile_native_go_fuzzer_v2 .../pkg/controller/certificates/revisionmanager FuzzProcessItem FuzzProcessItem_revisionmanager
#   compile_native_go_fuzzer_v2 .../pkg/controller/certificates/issuing FuzzProcessItem FuzzProcessItem_issuing
#   compile_native_go_fuzzer_v2 .../pkg/controller/certificates/readiness FuzzProcessItem FuzzProcessItem_readiness
#   compile_native_go_fuzzer_v2 .../pkg/controller/certificates/keymanager FuzzProcessItem FuzzProcessItem_keymanager
#   compile_native_go_fuzzer_v2 .../pkg/controller/certificates/requestmanager FuzzProcessItem FuzzProcessItem_requestmanager
#   compile_native_go_fuzzer_v2 .../pkg/controller/certificaterequests/vault FuzzVaultCRController FuzzVaultCRController
#   compile_native_go_fuzzer_v2 .../pkg/controller/certificaterequests/venafi FuzzVenafiCRController FuzzVenafiCRController
#   compile_go_fuzzer .../pkg/util/pki FuzzUnmarshalSubjectStringToRDNSequence FuzzUnmarshalSubjectStringToRDNSequence
#   compile_go_fuzzer .../pkg/util/pki FuzzDecodePrivateKeyBytes FuzzDecodePrivateKeyBytes
#
# We produce all 11 binaries under /mayhem/<name>, preserving the OSS-Fuzz target names for
# corpus/defect continuity.
#
# pki_fuzzer.go is NOT part of upstream cert-manager (it's the harness carried in the OSS-Fuzz
# projects/cert-manager/ recipe) — it's committed here under mayhem/harness/ (keeping the git
# layer confined to mayhem/ + .github/workflows/, SPEC §6.4) and copied into the source tree at
# BUILD time only (this container's writable layer), exactly like the upstream OSS-Fuzz
# Dockerfile's `COPY build.sh pki_fuzzer.go $SRC/` + this script's own `cp`. It never lands in
# the git commit.
#
# NOTE (verified locally, not needed): the upstream OSS-Fuzz build.sh also `rm`s
# pkg/controller/certificates/{trigger,revisionmanager}/*_controller_test.go, claiming they
# "break the build". Building with go-118-fuzz-build_v2 (the same tool/version this Dockerfile
# installs) those two targets compile cleanly WITHOUT removing anything — so we ship both without
# that workaround (which would have been a non-additive `D` anyway).
#
# DWARF gate (SPEC §6.2 item 10): Go's gc compiler always emits DWARF4 (no downgrade flag).
# The go-118-fuzz-build_v2 / go-fuzz build path links via clang++ ($CXX), whose own compilation
# unit (and any cgo shims) land FIRST in the final binary. We force those to DWARF3 via
# CGO_CFLAGS/CGO_CXXFLAGS and the final clang++ link's $GO_DEBUG_FLAGS. verify-repo's check reads
# the FIRST CU's DWARF version (readelf -m1), which is the clang-compiled unit at DWARF3.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
# OSS-Fuzz Go path is ASAN-only (project.yaml sanitizers: [address]); UBSan is not part of the
# Go libFuzzer link. An explicit empty --build-arg SANITIZER_FLAGS= disables the sanitizer.
: "${SANITIZER_FLAGS=-fsanitize=address}"
: "${MAYHEM_JOBS:=$(nproc)}"
export CC CXX LIB_FUZZING_ENGINE SANITIZER_FLAGS MAYHEM_JOBS

# Debug-info flags (SPEC §6.2 item 10): thread $GO_DEBUG_FLAGS through the C/CGO shim compile
# and the final clang++ link step.
: "${GO_DEBUG_FLAGS:=-g -gdwarf-3}"
export CGO_CFLAGS="${CGO_CFLAGS:+$CGO_CFLAGS }$GO_DEBUG_FLAGS"
export CGO_CXXFLAGS="${CGO_CXXFLAGS:+$CGO_CXXFLAGS }$GO_DEBUG_FLAGS"

# Air-gapped contract (SPEC §6.5): the PATCH tier re-runs build.sh OFFLINE.
# $(go env GOMODCACHE) reads the pinned ENV under /opt/toolchains (set in the Dockerfile),
# so the file proxy path is correct regardless of $HOME.
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOPROXY="${GOPROXY:-file://$(go env GOMODCACHE)/cache/download,https://proxy.golang.org,direct}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"

: "${SRC:=/mayhem}"
cd "$SRC"
go version

# ── Copy the OSS-Fuzz harness into pkg/util/pki (build-time only, not committed) ──────────────
cp "$SRC/mayhem/harness/pki_fuzzer.go" "$SRC/pkg/util/pki/pki_fuzzer.go"

# go-fuzz (go114-fuzz-build) needs go-fuzz-dep on the module graph; -mod=mod + the file-proxy
# GOPROXY resolves it from the cache offline (no-op if already present from the first build).
go get github.com/dvyukov/go-fuzz/go-fuzz-dep 2>&1 | tail -5 || true

mkdir -p "$SRC/mayhem-build"

# ── NATIVE targets (func FuzzX(f *testing.F)) via go-118-fuzz-build_v2 ─────────────────────────
build_native() {
  local pkg="$1" func="$2" outname="$3"
  local dir
  dir="$(go list -tags gofuzz -f '{{.Dir}}' "$pkg")"
  echo "=== building $outname (native, $pkg :: $func) ==="
  go-118-fuzz-build_v2 -tags gofuzz -o "$SRC/mayhem-build/${outname}.a" -func "$func" "$dir"
  $CXX $SANITIZER_FLAGS $LIB_FUZZING_ENGINE $GO_DEBUG_FLAGS "$SRC/mayhem-build/${outname}.a" -o "/mayhem/$outname"
  echo "built /mayhem/$outname"
}

build_native github.com/cert-manager/cert-manager/internal/webhook/admission/certificaterequest/approval \
  FuzzValidate FuzzValidate_approval
build_native github.com/cert-manager/cert-manager/pkg/controller/certificates/trigger \
  FuzzProcessItem FuzzProcessItem_trigger
build_native github.com/cert-manager/cert-manager/pkg/controller/certificates/revisionmanager \
  FuzzProcessItem FuzzProcessItem_revisionmanager
build_native github.com/cert-manager/cert-manager/pkg/controller/certificates/issuing \
  FuzzProcessItem FuzzProcessItem_issuing
build_native github.com/cert-manager/cert-manager/pkg/controller/certificates/readiness \
  FuzzProcessItem FuzzProcessItem_readiness
build_native github.com/cert-manager/cert-manager/pkg/controller/certificates/keymanager \
  FuzzProcessItem FuzzProcessItem_keymanager
build_native github.com/cert-manager/cert-manager/pkg/controller/certificates/requestmanager \
  FuzzProcessItem FuzzProcessItem_requestmanager
build_native github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/vault \
  FuzzVaultCRController FuzzVaultCRController
build_native github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/venafi \
  FuzzVenafiCRController FuzzVenafiCRController

# ── LEGACY targets (func Fuzz(data []byte) int) via go-fuzz (go114-fuzz-build) ─────────────────
build_legacy() {
  local pkg="$1" func="$2" outname="$3"
  echo "=== building $outname (legacy go-fuzz, $pkg :: $func) ==="
  go-fuzz -tags gofuzz -func "$func" -o "$SRC/mayhem-build/${outname}.a" "$pkg"
  $CXX $SANITIZER_FLAGS $LIB_FUZZING_ENGINE $GO_DEBUG_FLAGS "$SRC/mayhem-build/${outname}.a" -o "/mayhem/$outname"
  echo "built /mayhem/$outname"
}

build_legacy github.com/cert-manager/cert-manager/pkg/util/pki \
  FuzzUnmarshalSubjectStringToRDNSequence FuzzUnmarshalSubjectStringToRDNSequence
build_legacy github.com/cert-manager/cert-manager/pkg/util/pki \
  FuzzDecodePrivateKeyBytes FuzzDecodePrivateKeyBytes

echo "build.sh complete:"
ls -la /mayhem/FuzzValidate_approval /mayhem/FuzzProcessItem_trigger /mayhem/FuzzProcessItem_revisionmanager \
       /mayhem/FuzzProcessItem_issuing /mayhem/FuzzProcessItem_readiness /mayhem/FuzzProcessItem_keymanager \
       /mayhem/FuzzProcessItem_requestmanager /mayhem/FuzzVaultCRController /mayhem/FuzzVenafiCRController \
       /mayhem/FuzzUnmarshalSubjectStringToRDNSequence /mayhem/FuzzDecodePrivateKeyBytes
