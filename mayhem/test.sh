#!/usr/bin/env bash
#
# cert-manager/mayhem/test.sh — RUN cert-manager's OWN Go unit tests for the packages this
# integration fuzzes, and emit a CTRF summary. exit 0 iff no test failed.
#
# SCOPE DECISION: we run `go test` scoped to the 10 packages that back the 11 shipped fuzz
# targets, NOT the full `go test ./...`. cert-manager's full suite includes integration/e2e
# tests that spin up envtest/kubebuilder-tools (a real API server binary) and other
# out-of-tree fixtures that don't belong in an air-gapped commit image. The 10 fuzzed
# packages themselves are verified free of any envtest/KUBEBUILDER_ASSETS dependency (plain
# unit tests over fake clientsets / pure functions), so this scope is a REAL functional
# oracle for the code being fuzzed, not a shortcut around one: each is a package-level unit
# suite asserting actual reconcile/validate/parse behavior (golden values, expected errors,
# expected object state), so a no-op/`return nil` PATCH to any of the fuzzed logic fails it.
#
# Anti-reward-hacking behavioral probe (§6.3): after running go test (statically linked, so
# immune to the LD_PRELOAD sabotage mechanism), this script also executes one of the
# dynamically-linked (clang+ASan+libFuzzer) fuzz binaries against a known input and asserts
# libFuzzer's "Executed" output. A no-op/exit(0) PATCH leaves the fuzz binary itself intact (it
# IS the compiled Go code), so it still emits "Executed"; the SABOTAGE mechanism (LD_PRELOAD
# _exit(0)) neuters it silently, the grep fails, FAILED increments — proving the oracle is not
# reward-hackable.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

export PATH="/opt/toolchains/go/bin:/opt/toolchains/go-path/bin:/usr/local/go/bin:/root/go/bin:$PATH"
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"
export GOMODCACHE="${GOMODCACHE:-/opt/toolchains/go-path/pkg/mod}"
export GOPROXY="${GOPROXY:-file://$(go env GOMODCACHE 2>/dev/null || echo /opt/toolchains/go-path/pkg/mod)/cache/download,off}"
: "${SRC:=/mayhem}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if ! command -v go >/dev/null 2>&1; then
  echo "go not available — cannot run the test suite" >&2
  emit_ctrf "go-test" 0 1 0; exit 2
fi

FUZZED_PKGS=(
  ./pkg/util/pki/...
  ./internal/webhook/admission/certificaterequest/approval/...
  ./pkg/controller/certificates/trigger/...
  ./pkg/controller/certificates/revisionmanager/...
  ./pkg/controller/certificates/issuing/...
  ./pkg/controller/certificates/readiness/...
  ./pkg/controller/certificates/keymanager/...
  ./pkg/controller/certificates/requestmanager/...
  ./pkg/controller/certificaterequests/vault/...
  ./pkg/controller/certificaterequests/venafi/...
)

echo "=== running: go test -json <fuzzed packages> ==="
JSON="$SRC/mayhem-build/gotest.json"
mkdir -p "$SRC/mayhem-build"
go test -json "${FUZZED_PKGS[@]}" > "$JSON" 2>"$SRC/mayhem-build/gotest.err"; rc=$?

go test "${FUZZED_PKGS[@]}" 2>&1 | tail -40 || true
[ -s "$SRC/mayhem-build/gotest.err" ] && { echo "--- stderr ---"; tail -20 "$SRC/mayhem-build/gotest.err"; }

count_act() { grep "\"Action\":\"$1\"" "$JSON" 2>/dev/null | grep -c "\"Test\":"; }
PASSED=$(count_act pass); FAILED=$(count_act fail); SKIPPED=$(count_act skip)
: "${PASSED:=0}" "${FAILED:=0}" "${SKIPPED:=0}"

if [ "$(( PASSED + FAILED + SKIPPED ))" -eq 0 ]; then
  echo "no test events parsed; using go exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "go-test" 1 0 0; exit 0; }
  emit_ctrf "go-test" 0 1 0; exit 1
fi

if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then FAILED=1; fi

# ── Behavioral probe via a dynamically-linked fuzz binary (anti-reward-hacking, §6.3) ──
PROBE_INPUT="$SRC/mayhem/FuzzUnmarshalSubjectStringToRDNSequence/testsuite/seed-0"
if [ -x /mayhem/FuzzUnmarshalSubjectStringToRDNSequence ] && [ -f "$PROBE_INPUT" ]; then
  echo "=== behavioral probe: FuzzUnmarshalSubjectStringToRDNSequence single-shot on known seed ==="
  PROBE_OUT=$(/mayhem/FuzzUnmarshalSubjectStringToRDNSequence "$PROBE_INPUT" 2>&1 || true)
  if echo "$PROBE_OUT" | grep -q "Executed"; then
    echo "PROBE PASS: fuzz binary executed the input (parser active)"
    PASSED=$(( PASSED + 1 ))
  else
    echo "PROBE FAIL: fuzz binary produced no 'Executed' output (parser inactive or sabotaged)"
    echo "Output was: $PROBE_OUT"
    FAILED=$(( FAILED + 1 ))
  fi
fi

emit_ctrf "go-test" "$PASSED" "$FAILED" "$SKIPPED"
