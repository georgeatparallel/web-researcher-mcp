#!/usr/bin/env bash
set -uo pipefail

# Permanent regression gate for "site_login / site_logout + cookie vault"
# (see issue #241). Runs all 6 gates in order, regardless of earlier failures,
# then exits non-zero if any gate failed. Re-run after any change to
# internal/cookievault, internal/tools/site_session.go, the cookie paths in
# internal/scraper (cookies.go, browser.go, pipeline.go, ssrf.go), the vault
# wiring in internal/tools/scrape.go, or the STDIO consent bootstrap.
#
# Every named test must run AND pass: a name that matches nothing fails the
# gate, so a missing test can never read as green.
#
# Usage: bash scripts/harness-241.sh

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="$REPO_ROOT/.harness-out"
mkdir -p "$OUT_DIR"

GATE=0
FAILED=0

run_gate() {
  local name="$1" logfile="$2"
  shift 2
  GATE=$((GATE + 1))
  echo "==> Gate ${GATE}: ${name}"
  if "$@" >"$logfile" 2>&1; then
    echo "    PASS (log: ${logfile#"$REPO_ROOT"/})"
  else
    echo "    FAIL (exit $?) — see ${logfile#"$REPO_ROOT"/}"
    tail -n 30 "$logfile" | sed 's/^/    | /'
    FAILED=1
  fi
}

# run_named_tests <go-test-flags...> -- <pkg> <TestA TestB ...>
# Runs exactly the named tests in one package and requires every name to show
# "--- PASS" (a skip or a missing test is a failure).
run_named_tests() {
  local flags=() pkg names
  while [ "$1" != "--" ]; do flags+=("$1"); shift; done
  shift
  pkg="$1"
  names="$2"
  local pattern="^($(echo "$names" | tr ' ' '|'))\$"
  local log
  log="$(mktemp)"
  go test "${flags[@]}" "$pkg" -run "$pattern" -v -count=1 >"$log" 2>&1
  local rc=$?
  cat "$log"
  local missing=0 t
  for t in $names; do
    if ! grep -q -- "--- PASS: ${t} " "$log"; then
      echo "MISSING OR NOT PASSING: ${t} (${pkg})"
      missing=1
    fi
  done
  rm -f "$log"
  [ "$rc" -eq 0 ] && [ "$missing" -eq 0 ]
}

NEW_FILES="internal/cookievault/cookievault.go internal/cookievault/capture.go internal/tools/site_session.go internal/scraper/cookies.go"

run_gate "Lint (golangci-lint)" \
  "$OUT_DIR/241-01-lint.log" \
  make lint

run_gate "SAST (gosec) + pattern checks (rules S5/S7/S14/C2)" \
  "$OUT_DIR/241-02-sast.log" \
  bash -c '
    set -e
    make sec
    for f in '"$NEW_FILES"'; do test -f "$f" || { echo "missing $f"; exit 1; }; done
    echo "--- no http.DefaultClient / os/exec / panic in new files (S14) ---"
    ! grep -nE "http\.DefaultClient|\"os/exec\"|panic\(" '"$NEW_FILES"'
    echo "--- no TODO/FIXME in new files (C2) ---"
    ! grep -nE "TODO|FIXME" '"$NEW_FILES"'
    echo "--- no logging call touches cookie values/names (S7) ---"
    ! grep -nE "(slog|logger|Logger|log)\.[A-Za-z]+\(.*(\.Value|\.Name|[Cc]ookies)" '"$NEW_FILES"'
    echo "--- STDIO bootstrap never grants PurposeSessionCapture (S5) ---"
    ! grep -n "PurposeSessionCapture" cmd/web-researcher-mcp/main.go
    echo "--- PurposeSessionCapture declared (S5) ---"
    grep -q "PurposeSessionCapture" internal/consent/consent.go
  '

run_gate "Multi-instance isolation (rules I1, I4)" \
  "$OUT_DIR/241-03-isolation.log" \
  bash -c '
    '"$(declare -f run_named_tests)"'
    set -e
    run_named_tests -race -- ./internal/cookievault/ "TestMultiInstanceCookieVault TestMultiInstanceCapturer"
    run_named_tests -race -- ./internal/scraper/ "TestMultiInstancePipelineCookieIsolation"
  '

run_gate "Dead-code scan (go vet)" \
  "$OUT_DIR/241-04-deadcode.log" \
  go vet ./...

run_gate "Unit/integration tests (rules I2-I4, S1-S15, R1-R2, P1-P2, C3)" \
  "$OUT_DIR/241-05-unit.log" \
  bash -c '
    '"$(declare -f run_named_tests)"'
    set -e
    run_named_tests -race -- ./internal/cookievault/ "TestVaultKeyCollisionFree TestVaultTenantUserIsolation TestRegistrableDomain TestVaultRefusesInvalidDomains TestCookieOutsideVaultDomainDropped TestBundleTTLCap TestVaultFilesAreEncrypted TestVaultDataSubjectRoundTrip TestBundleCaps TestCaptureProfileDirRemovedOnEveryPath TestCaptureSemaphoreBound TestCaptureTimeoutAndCancel TestConstructionLaunchesNoBrowser"
    run_named_tests -race -- ./internal/scraper/ "TestSecureCookieNotSentOverHTTP TestHostOnlyVsDomainCookie TestRedirectToOtherHostDoesNotLeakCookie TestSSRFBlocksBeforeCookieSend TestResolveAndValidateHost TestBrowserValidatesBeforeSetCookies TestBrowserVaultScrapeUsesFreshIncognito TestConcurrentScrapesDoNotShareCookies TestVaultBackedSkipsCloudProxyTiers TestSessionCookieStaysSession TestExpiredCookiesDropped"
    run_named_tests -race -- ./internal/tools/ "TestVaultBackedScrapeBypassesCache TestAnonymousAfterAuthenticatedNeverServedFromCache TestCanaryCookieNeverLeaks TestSiteLoginRequiresConsent TestScrapeSkipsVaultWithoutConsent TestSiteLoginNotRegisteredWithoutCapturer TestSiteLogoutDeletesAndIsIdempotent TestSiteLogoutLeavesNoCacheEntries TestSiteLoginRejectsBadURLs TestSiteLoginDescriptionDisclosesToS TestNoVaultReadWhenDisabled TestCorruptVaultEntryDegradesToAnonymous TestToolsDocMatchesRegistry TestAllToolsHaveAnnotations"
    run_named_tests -race -- ./internal/config/ "TestConfigCookieVaultKeyValidation"
    run_named_tests -race -- ./cmd/web-researcher-mcp/ "TestStdioBootstrapNeverGrantsSessionCapture"
    make check-python-drift
  '

run_gate "E2E (real binary, vault-backed scrape + logout, recorded proof)" \
  "$OUT_DIR/241-06-e2e.log" \
  bash -c '
    '"$(declare -f run_named_tests)"'
    set -e
    run_named_tests -tags=e2e -- ./tests/e2e/ "TestSiteLogin241_E2E"
  '

echo
if [ "$FAILED" -ne 0 ]; then
  echo "HARNESS FAILED — see logs under ${OUT_DIR#"$REPO_ROOT"/}/"
  exit 1
fi

echo "HARNESS PASSED — all 6 gates green. Logs under ${OUT_DIR#"$REPO_ROOT"/}/"
exit 0
