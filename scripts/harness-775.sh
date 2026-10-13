#!/usr/bin/env bash
set -uo pipefail

# Permanent regression gate for "tool-owned browser profile for site_login / scrape_page"
# (see issue #775). Runs all 6 gates in order, regardless of earlier failures,
# then exits non-zero if any gate failed. Re-run after any change to
# internal/cookievault (profile*.go), internal/cache/streamcrypto.go, the profile
# scrape path in internal/scraper, internal/tools/site_session.go or scrape.go.
# Sibling of scripts/harness-241.sh, which still has to pass.
#
# Every named test must run AND pass: a name that matches nothing fails the
# gate, so a missing test can never read as green.
#
# Usage: bash scripts/harness-775.sh

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
  local rc=0
  go test "${flags[@]}" "$pkg" -run "$pattern" -v -count=1 >"$log" 2>&1 || rc=$?
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

export -f run_named_tests

NEW_FILES="internal/cache/streamcrypto.go internal/cookievault/profile.go internal/cookievault/profile_archive.go internal/cookievault/profile_browser.go internal/cookievault/browser_pipe.go internal/cookievault/browser_pipe_unix.go internal/cookievault/browser_pipe_windows.go internal/cookievault/pid_unix.go internal/cookievault/pid_windows.go internal/scraper/profile_browser.go"

run_gate "Lint (golangci-lint)" \
  "$OUT_DIR/775-01-lint.log" \
  make lint

run_gate "SAST (gosec) + pattern checks (rules 3, 6, 7, 12)" \
  "$OUT_DIR/775-02-sast.log" \
  bash -c '
    set -e
    # `! cmd` never trips set -e, so use an explicit check.
    none() { if "$@"; then echo "FOUND (see lines above)"; return 1; fi; }
    make sec
    for f in '"$NEW_FILES"'; do test -f "$f" || { echo "missing $f"; exit 1; }; done
    echo "--- no http.DefaultClient / os/exec / panic in new files ---"
    none grep -nE "http\.DefaultClient|panic\(" '"$NEW_FILES"'
    echo "--- os/exec only in the DevTools-pipe launcher and its platform hooks (fixed browser binary and flags) ---"
    none sh -c "grep -ln os/exec '"$NEW_FILES"' | grep -Ev \"/browser_pipe(_unix|_windows)?\\.go\\$\""
    echo "--- no TODO/FIXME in new files ---"
    none grep -nE "TODO|FIXME" '"$NEW_FILES"'
    echo "--- no logging call touches cookie values/names or paths (rule 6) ---"
    none grep -nE "(slog|logger|Logger|log)\.[A-Za-z]+\(.*(\.Value|\.Name|[Cc]ookies|[Dd]ir|[Pp]ath)" '"$NEW_FILES"'
    echo "--- profile mode never sets fingerprint overrides (rule 7) ---"
    none grep -nE "SetUserAgent|EmulationSetUserAgentOverride|EvalOnNewDocument|stealth\.|Incognito" internal/scraper/profile_browser.go
    echo "--- never kill the browser straight after Close (rule 8) ---"
    none grep -nE "\.Kill\(\)" internal/scraper/profile_browser.go
    echo "--- STDIO grants PurposeSessionCapture only behind COOKIE_VAULT_STDIO_CONSENT ---"
    none sh -c "grep -n PurposeSessionCapture cmd/web-researcher-mcp/main.go | grep -v stdio_env_optin"
    grep -B1 stdio_env_optin cmd/web-researcher-mcp/main.go | grep -q CookieVaultStdioConsent
  '

run_gate "Multi-instance isolation (rules 1, 2)" \
  "$OUT_DIR/775-03-isolation.log" \
  bash -c '
    set -e
    run_named_tests -race -- ./internal/cookievault/ "TestMultiInstanceProfileStore TestProfileStoreSubjectIsolation"
  '

run_gate "Dead-code scan (go vet + unused via lint)" \
  "$OUT_DIR/775-04-deadcode.log" \
  go vet ./...

run_gate "Unit/integration tests (rules 1-16)" \
  "$OUT_DIR/775-05-unit.log" \
  bash -c '
    set -e
    run_named_tests -race -- ./internal/cache/ "TestStreamCryptoRoundTrip TestStreamCryptoTamperTruncation"
    run_named_tests -race -- ./internal/cookievault/ "TestProfileArchiveEncryptedAtRest TestProfileTempDirRemovedOnAllExits TestStaleProfileTempDirsSwept TestProfileExtractRejectsTraversalAndLinks TestProfileLoginVerifiesPersistedCookies TestProfileScrapeSerialized TestProfileScrapeMinSpacing TestProfileScrapeBusyAfterWait TestProfileArchiveExcludesCaches TestProfileArchiveSizeCap TestProfileArchiveTTL TestProfileScrapeRepacksState TestVaultDataSubjectRoundTrip TestCaptureProfileDirRemovedOnEveryPath TestBrowserProfileModeNoOverrides"
    run_named_tests -race -- ./internal/scraper/ "TestProfileBlocksOffDomainNavigation TestProfileScrapeWaitsForLateContent TestProfileScrapeHonorsBrowserTierLimit"
    run_named_tests -race -- ./internal/tools/ "TestSiteLoginProfileRequiresConsent TestScrapeProfileGating TestScrapeProfileRawModeRefused TestSiteLogoutRemovesProfile TestLoginReplacesOtherKind TestProfileAuditAndMetrics TestScrapeAnonymousSkipsCookieLogin TestLoginHintForProfileNeedsWindow TestVaultBackedScrapeBypassesCache TestAnonymousAfterAuthenticatedNeverServedFromCache TestCanaryCookieNeverLeaks TestSiteLoginDescriptionDisclosesToS TestToolsDocMatchesRegistry TestAllToolsHaveAnnotations"
    run_named_tests -race -- ./internal/config/ "TestConfigCookieCaptureInHTTP TestConfigProfileTTL"
    run_named_tests -tags=live -- ./internal/cookievault/ "TestProfileLoginFastCloseLive"
    make check-python-drift
  '

run_gate "E2E (real binary, profile scrape over STDIO and HTTP, recorded proof)" \
  "$OUT_DIR/775-06-e2e.log" \
  bash -c '
    set -e
    run_named_tests -tags=e2e -- ./tests/e2e/ "TestE2EProfileScrapeSTDIO TestE2EProfileScrapeHTTP TestE2EProfileScrapeAcrossIdentities TestE2ESiteLoginRegistrationByTransport"
  '

echo
if [ "$FAILED" -ne 0 ]; then
  echo "HARNESS FAILED — see logs under ${OUT_DIR#"$REPO_ROOT"/}/"
  exit 1
fi

echo "HARNESS PASSED — all 6 gates green. Logs under ${OUT_DIR#"$REPO_ROOT"/}/"
exit 0
