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
#
# Init-ordering shim (QA #1118): every target also links mayhem/go_runtime_ready.o FIRST. In a Go
# c-archive the runtime starts on its own thread from a load-time constructor and registers the
# Go coverage counters with libFuzzer from there, while libFuzzer's main thread concurrently calls
# TracePC::ClearInlineCounters(). Neither fuzz-build generator defines LLVMFuzzerInitialize, so
# nothing orders the two: a small fraction of starts SEGV at 0x10 inside libFuzzer before any
# input is read (or start with no counters loaded). The shim's LLVMFuzzerInitialize blocks until
# the Go runtime init tasks (including that registration) are done — the same wait the cgo export
# wrapper of LLVMFuzzerTestOneInput already performs on first call, just moved earlier. It
# executes no input, runs no target code and intercepts no signal. Compiled uninstrumented with
# $GO_DEBUG_FLAGS, so as the first object it also keeps the first CU at DWARF3.
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

# ── Init-ordering shim (see header): compiled once, linked FIRST into every target ─────────────
SHIM_O="$SRC/mayhem-build/go_runtime_ready.o"
$CC $GO_DEBUG_FLAGS -c "$SRC/mayhem/go_runtime_ready.c" -o "$SHIM_O"

# Fail loudly if a link ever drops the shim. (No `grep -q`: under pipefail it would close the pipe
# early, nm would die of SIGPIPE and the check would fail spuriously.)
check_shim() {
  nm "$1" | grep ' T LLVMFuzzerInitialize$' >/dev/null \
    || { echo "build.sh: LLVMFuzzerInitialize init-ordering shim missing from $1" >&2; exit 1; }
}

# ── Per-target build recipes ───────────────────────────────────────────────────────────────────
# Each target is: fuzz-build tool -> c-archive (.a) -> clang++ link with ASan + libFuzzer + shim.
# The stale binary is removed first: /mayhem/<target> is untracked-but-not-gitignored, so rlenv's
# `git clean -ffdX` keeps it, and a failed relink must never leave the previous binary standing in
# for the patched one.
#
# NATIVE targets (func FuzzX(f *testing.F)) via go-118-fuzz-build_v2
build_native() {
  local pkg="$1" func="$2" outname="$3"
  local dir
  dir="$(go list -tags gofuzz -f '{{.Dir}}' "$pkg")"
  echo "=== building $outname (native, $pkg :: $func) ==="
  rm -f "/mayhem/$outname" "$SRC/mayhem-build/${outname}.a"
  go-118-fuzz-build_v2 -tags gofuzz -o "$SRC/mayhem-build/${outname}.a" -func "$func" "$dir"
  $CXX $SANITIZER_FLAGS $LIB_FUZZING_ENGINE $GO_DEBUG_FLAGS "$SHIM_O" "$SRC/mayhem-build/${outname}.a" -o "/mayhem/$outname"
  check_shim "/mayhem/$outname"
  echo "built /mayhem/$outname"
}

# LEGACY targets (func Fuzz(data []byte) int) via go-fuzz (go114-fuzz-build)
build_legacy() {
  local pkg="$1" func="$2" outname="$3"
  echo "=== building $outname (legacy go-fuzz, $pkg :: $func) ==="
  rm -f "/mayhem/$outname" "$SRC/mayhem-build/${outname}.a"
  go-fuzz -tags gofuzz -func "$func" -o "$SRC/mayhem-build/${outname}.a" "$pkg"
  $CXX $SANITIZER_FLAGS $LIB_FUZZING_ENGINE $GO_DEBUG_FLAGS "$SHIM_O" "$SRC/mayhem-build/${outname}.a" -o "/mayhem/$outname"
  check_shim "/mayhem/$outname"
  echo "built /mayhem/$outname"
}

# ── Build the 11 targets CONCURRENTLY, up to $MAYHEM_JOBS at a time, memory permitting (QA #1093) ─
# With a warm GOCACHE every Go package is a cache hit; what remains per target is serial work —
# go-118-fuzz-build's packages.Load (~10-15 s), the Go linker writing a ~390 MB c-archive (10-30 s,
# mostly single-threaded) and the clang++ ASan link (~4 s). Run back to back that is ~230-315 s for
# 11 targets, which the graded rebuild's 450 s window cannot absorb on a slower runner. The targets
# are independent (distinct outputs; both fuzz-build tools write only uniquely named temp files and
# an -overlay, never the source tree), so they run side by side. Nothing about WHAT is built
# changes: same tools, same flags, same sources, every target rebuilt from the patched tree.
# Each job's output is buffered to its own log and replayed in target order; any failing job fails
# the build.
# Memory bounds the concurrency too: one native target peaks at ~4 GB resident (go-118-fuzz-build
# ~1.6 GB held while the Go linker it spawns peaks at ~2.4 GB), so the job count is also capped at
# (available memory / 4.5 GB), reading the container's cgroup limit when there is one. Too many
# jobs would swap and run slower than fewer.
mem_kb="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null || true)"
for cg in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory/memory.limit_in_bytes; do
  lim="$(cat "$cg" 2>/dev/null || true)"
  case "$lim" in ''|max|*[!0-9]*) continue ;; esac
  if [ -z "$mem_kb" ] || [ $(( lim / 1024 )) -lt "$mem_kb" ]; then mem_kb=$(( lim / 1024 )); fi
done
BUILD_JOBS="$MAYHEM_JOBS"
if [ -n "$mem_kb" ] && [ $(( mem_kb / 4718592 )) -lt "$BUILD_JOBS" ]; then BUILD_JOBS=$(( mem_kb / 4718592 )); fi
[ "$BUILD_JOBS" -ge 1 ] || BUILD_JOBS=1
echo "building 11 targets with up to $BUILD_JOBS concurrent jobs (MAYHEM_JOBS=$MAYHEM_JOBS, ~$(( ${mem_kb:-0} / 1048576 )) GB available)"
JOBLOG="$SRC/mayhem-build/jobs"
rm -rf "$JOBLOG"; mkdir -p "$JOBLOG"
TARGETS=()
spawn() {  # spawn <native|legacy> <pkg> <func> <outname>
  local kind="$1" outname="$4"
  while [ "$(jobs -rp | wc -l)" -ge "$BUILD_JOBS" ]; do wait -n || true; done
  TARGETS+=("$outname")
  # errexit stays in force inside the job; the EXIT trap records its status however it ends.
  ( trap "echo \$? > '$JOBLOG/$outname.rc'" EXIT; "build_$kind" "$2" "$3" "$outname" ) \
    > "$JOBLOG/$outname.log" 2>&1 &
}

M=github.com/cert-manager/cert-manager
spawn native "$M/internal/webhook/admission/certificaterequest/approval" FuzzValidate FuzzValidate_approval
spawn native "$M/pkg/controller/certificates/trigger"          FuzzProcessItem FuzzProcessItem_trigger
spawn native "$M/pkg/controller/certificates/revisionmanager"  FuzzProcessItem FuzzProcessItem_revisionmanager
spawn native "$M/pkg/controller/certificates/issuing"          FuzzProcessItem FuzzProcessItem_issuing
spawn native "$M/pkg/controller/certificates/readiness"        FuzzProcessItem FuzzProcessItem_readiness
spawn native "$M/pkg/controller/certificates/keymanager"       FuzzProcessItem FuzzProcessItem_keymanager
spawn native "$M/pkg/controller/certificates/requestmanager"   FuzzProcessItem FuzzProcessItem_requestmanager
spawn native "$M/pkg/controller/certificaterequests/vault"     FuzzVaultCRController FuzzVaultCRController
spawn native "$M/pkg/controller/certificaterequests/venafi"    FuzzVenafiCRController FuzzVenafiCRController
spawn legacy "$M/pkg/util/pki" FuzzUnmarshalSubjectStringToRDNSequence FuzzUnmarshalSubjectStringToRDNSequence
spawn legacy "$M/pkg/util/pki" FuzzDecodePrivateKeyBytes FuzzDecodePrivateKeyBytes
wait

failed=0
for t in "${TARGETS[@]}"; do
  cat "$JOBLOG/$t.log"
  rc="$(cat "$JOBLOG/$t.rc" 2>/dev/null || echo missing)"
  if [ "$rc" != 0 ]; then echo "build.sh: building $t FAILED (status $rc)" >&2; failed=1; fi
done
[ "$failed" -eq 0 ] || exit 1

echo "build.sh complete:"
ls -la /mayhem/FuzzValidate_approval /mayhem/FuzzProcessItem_trigger /mayhem/FuzzProcessItem_revisionmanager \
       /mayhem/FuzzProcessItem_issuing /mayhem/FuzzProcessItem_readiness /mayhem/FuzzProcessItem_keymanager \
       /mayhem/FuzzProcessItem_requestmanager /mayhem/FuzzVaultCRController /mayhem/FuzzVenafiCRController \
       /mayhem/FuzzUnmarshalSubjectStringToRDNSequence /mayhem/FuzzDecodePrivateKeyBytes
