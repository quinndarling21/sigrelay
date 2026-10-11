---
name: ci-triage
description: Triages a failed GitHub Actions run of the sigrelay repository. Reads the failing jobs' check-run annotations and logs (cppcheck and clang-tidy findings, failing ctest tests), plus the SARIF and JUnit artifacts when reachable, reruns timing-sensitive failing tests 20 times in isolation, classifies every item as real, flaky or false positive, posts one triage comment on the branch's open PR, and opens dispositions and fix PRs. Use when a CI run of this repository fails or when asked to triage a run ID or commit.
---

# CI triage

Follow the steps in order. Do not take any action a step does not allow. Shell hooks in this repository deny curl, wget, force pushes and similar commands; use `gh` and your pull-request tools instead, and report any block rather than working around it.

## 1. Load the run

Input: a workflow run ID, or the run that triggered you. If you have no run ID (for example the trigger only carries the head SHA), find the run for that commit:

```bash
gh run list --commit <sha> --workflow ci --json databaseId,headBranch,conclusion,event,createdAt
```

Pick the most recent completed run (non-empty `conclusion`, latest `createdAt`) and state which run you picked and why, for example: "run 123 (push, failure): the latest completed ci run for <sha>; the pull_request run 122 is older". If no run for the SHA has completed yet, wait for the newest one with `gh run watch <id>`.

```bash
gh run view <id> --json databaseId,headBranch,headSha,conclusion,event,jobs,url
```

Record `databaseId` (the run ID), `url`, `headBranch`, `headSha`, `event`, and every job whose `conclusion` is `failure` or `timed_out` (the failing jobs; keep each job's `databaseId` and `name`). If `conclusion` is empty the run is still in progress: wait with `gh run watch <id>` and load it again.

## 2. Skip rules

If either rule applies, reply with exactly one line and stop. Do not comment, rerun or open anything.

- `conclusion` is `success`: `No triage needed: run succeeded (run <id>)`
- `headBranch` starts with `cursor/`: `No triage needed: branch <headBranch> is an agent branch (run <id>)`

## 3. Collect evidence

Work in a directory outside the repository, for example `/tmp/ci-triage-<id>`. Use the sources in this order.

### (a) Check-run annotations

CI prints one `::error` annotation per cppcheck finding, clang-tidy finding and failing test. For each failing job, read them through its check run; the job `databaseId` from step 1 is its check-run ID:

```bash
gh api 'repos/{owner}/{repo}/check-runs/<job databaseId>/annotations' --paginate \
  --jq '.[] | [.annotation_level, .path, .start_line, .title, .message] | @tsv'
```

To list the run's check runs instead, go through its check suite:

```bash
suite=$(gh api 'repos/{owner}/{repo}/actions/runs/<id>' --jq .check_suite_id)
gh api "repos/{owner}/{repo}/check-suites/$suite/check-runs" --jq '.check_runs[] | [.id, .name, .conclusion] | @tsv'
```

Each `failure`-level annotation from the tools gives `path` (repository-relative), `start_line`, `title` (the cppcheck id, the clang-tidy check, or the ctest test name) and `message`. An annotation at `tests/CMakeLists.txt` line 1 is a test that printed no location (crash, timeout, missing executable); its message says so. Annotations without a file get the path `.github`: runner messages (such as `Process completed with exit code 1.` or runner image notices) and the job's closing `cppcheck` / `clang-tidy` summary line only show which step failed, while a finding that has no location keeps its rule id as `title`.

GitHub keeps at most 10 error annotations per step and 50 per job. Each tool ends its output with a total-count line, `<cppcheck|clang-tidy|ctest>: N error annotation(s) in total.`; when N is larger than what you received, take the remaining items from (b).

### (b) Failed logs

```bash
gh run view <id> --job <job databaseId> --log-failed
```

Keep at least one verbatim log line per failing job (the first error line, such as a compiler error, `The following tests FAILED:`, a finding printed by `tools/*_to_sarif.py` or `tools/junit_to_annotations.py`, or the `::error` summary line). The log also holds every item beyond the annotation limit: the cppcheck and clang-tidy jobs print every finding as `file:line[:col]: <severity>: <message> [<ruleId>]`, and build-and-test prints each failing test as `<file>:<line>: <test name>: <message>` in its "Annotate test failures" step, with the assertion output under `Run tests`. Failures that produce no annotation (compile error, configure error, tool install failure, timeout) only appear here.

### (c) Artifacts (best effort)

The `cppcheck-sarif`, `clang-tidy-sarif` and `ctest-junit` artifacts hold the complete lists, but agent VMs may not reach GitHub's artifact storage. Try once and never block on them; (a) and (b) are sufficient. An artifact is also missing when its job stopped early (for example `ctest-junit` after a build failure).

```bash
gh run download <id> -n cppcheck-sarif -n clang-tidy-sarif -n ctest-junit -D /tmp/ci-triage-<id> \
  || for name in cppcheck-sarif clang-tidy-sarif ctest-junit; do
       gh run download <id> -n "$name" -D "/tmp/ci-triage-<id>/$name" || echo "artifact $name not available"
     done
```

If they downloaded, list every SARIF result (ruleId, file, line, message) and every failing test (location, name, message):

```bash
python3 - /tmp/ci-triage-<id> <<'EOF'
import glob, json, sys

root = sys.argv[1]
for path in sorted(glob.glob(root + "/**/*.sarif", recursive=True)):
    with open(path) as handle:
        log = json.load(handle)
    for run in log["runs"]:
        tool = run["tool"]["driver"]["name"]
        for result in run.get("results", []):
            location = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = location.get("artifactLocation", {}).get("uri", "?")
            line = location.get("region", {}).get("startLine", "?")
            print("SARIF\t%s\t%s\t%s:%s\t%s" % (tool, result.get("ruleId"), uri, line,
                                               result["message"]["text"]))
EOF
# From the repository checkout; it maps the runner's paths to repository paths.
python3 tools/junit_to_annotations.py /tmp/ci-triage-<id>/ctest-junit/ctest-junit.xml
```

State in the final reply which sources were unavailable (annotations, logs or artifacts).

## 4. Classify every item

Items are: each cppcheck or clang-tidy finding, each failing test, and each failing job that is not explained by those two (compile error, configure error, tool install failure, timeout).

### (a) Rerun timing-sensitive tests before classifying them

For every failing test that involves time, timeouts, TTLs, randomness or ordering, rerun that single test 20 times in isolation on the failing commit before you classify it. Decide from the test function (`test_<name>` in `tests/test_*.c`; `tests/hooks/test_policies.py` for `hook_policies`, `tests/tools/test_annotations.py` for `report_tools`) and the code it calls: wall-clock reads, sleeps, timeouts, TTL or expiry logic, random values, threads, iteration order, or state shared with other tests. A test that timed out in CI qualifies. When unsure, rerun.

Build the failing commit with gcc, as the build-and-test job does, in a worktree outside the repository, and rerun the test there with this script. Save it as `/tmp/ci-triage-<id>/rerun.sh`:

```bash
#!/usr/bin/env bash
# Usage: rerun.sh <commit> <test name> <work dir> [extra ctest arguments]
# Prints "<passes>/<attempts that ran> passed", plus the count and reason of any attempts
# that did not run; or "did not run: <reason>" and exits 1 when no attempt ran.
sha=$1 name=$2 work=$3
shift 3
tree=$work/checkout
logs=$work/reruns

not_run() {
  if [ -n "${2:-}" ]; then tail -n 20 "$2" >&2; fi
  echo "did not run: $1"
  exit 1
}

[[ $sha =~ ^[0-9a-f]{40}$ ]] || not_run "invalid commit '$sha'"
[[ $name =~ ^[a-z0-9_]+$ ]] || not_run "invalid test name '$name'"
mkdir -p "$logs" || not_run "cannot create $logs"

if [ ! -e "$tree" ]; then
  git cat-file -e "$sha^{commit}" 2>/dev/null || git fetch origin "$sha" || not_run "git fetch origin $sha failed"
  git worktree add --detach "$tree" "$sha" || not_run "git worktree add failed"
fi
cd "$tree" || not_run "cannot enter $tree"
[ "$(git rev-parse --show-toplevel 2>/dev/null)" = "$(pwd -P)" ] || not_run "$tree is not a git worktree"
[ "$(git rev-parse HEAD)" = "$sha" ] || not_run "$tree is not at $sha"

cmake -S . -B build -DCMAKE_C_COMPILER=gcc -DCMAKE_COMPILE_WARNING_AS_ERROR=ON > "$logs/configure.log" 2>&1 \
  || not_run "configure failed" "$logs/configure.log"
cmake --build build --parallel > "$logs/build.log" 2>&1 || not_run "build failed" "$logs/build.log"

ran=0 passed=0
declare -A skipped=()
for i in $(seq 20); do
  log=$logs/$name.$i.log
  ctest --test-dir build -R "^$name\$" --output-on-failure "$@" > "$log" 2>&1
  # ctest prints "No tests were found!!!" and exits 0 when the name matches nothing.
  if ! grep -Eq "^1/1 Test +#[0-9]+: $name " "$log" \
    || ! grep -Eq '^(0|100)% tests passed, [01] tests failed out of 1$' "$log"; then
    reason="no matching test"
  elif grep -q '\*\*\*Not Run' "$log"; then
    reason="test did not start"
  else
    ran=$((ran + 1))
    if grep -q '^100% tests passed, 0 tests failed out of 1$' "$log"; then passed=$((passed + 1)); fi
    continue
  fi
  skipped[$reason]=$(( ${skipped[$reason]:-0} + 1 ))
  last_log=$log
done

if [ "$ran" -eq 0 ]; then not_run "$(IFS=';'; echo "${!skipped[*]}")" "$last_log"; fi
result="$passed/$ran passed"
for reason in "${!skipped[@]}"; do result+=", ${skipped[$reason]} did not run: $reason"; done
echo "$result"
```

Run it from the repository checkout, once per test, with the full `<headSha>` and the ctest test name (the annotation title, for example `sip_parses_invite`, not the C function `test_sip_parses_invite`). Later tests of the same run reuse `/tmp/ci-triage-<id>/checkout`:

```bash
bash /tmp/ci-triage-<id>/rerun.sh <headSha> <name> /tmp/ci-triage-<id>
```

Each setup step runs only if the previous one succeeded: the fetch (skipped when the commit is already local), `git worktree add`, the checks that the worktree is at `<headSha>` and that the script is inside it, the configure and the build. If one of them fails, no attempt can run: the script prints the end of the step's log and reports `did not run: <reason>`, for example `did not run: build failed`.

Each of the 20 ctest attempts writes its output to `/tmp/ci-triage-<id>/reruns/<name>.<n>.log`. An attempt counts only if the build succeeded and that output shows exactly the named test executed. Otherwise the attempt did not run (`no matching test`, or `test did not start` when ctest reports `***Not Run`): that is not a failure, and it is left out of the pass count. The script prints passes over the attempts that ran, for example `4/20 passed`, or `4/18 passed, 2 did not run: test did not start`. When no attempt ran, it prints the end of the last attempt's log and `did not run: <reason>`, for example `did not run: no matching test`. If it reports `no matching test`, check `<name>` against the annotation title and run it once more before falling back to the CI evidence.

ctest has no default timeout here, so for a test that timed out or hung in CI append `--timeout 60` to the command (the script passes extra arguments to ctest); a hang then counts as a failure instead of stalling the loop. Put the result in the Reruns column exactly as printed, for example `4/20 passed` or `did not run: build failed`, and read it as follows, where `<n>` is the number of attempts that ran:

- Mixed (some attempts that ran passed and some failed): flaky.
- `0/<n> passed`: real, a deterministic failure.
- `<n>/<n> passed`: the CI failure did not reproduce locally. Say so in the Reasoning and classify the test from the CI evidence (annotations, log, CI rerun) as below.
- `did not run: <reason>`: no attempt ran, so the rerun shows nothing about the test. It is not a failure: never write it as `0/20 passed` and never classify the test as real on the basis of the rerun. Classify the test from the CI evidence as below and say so in the Reasoning, for example "Did not run (build failed); classified from the CI log."

### (b) Classification

Classify each item as exactly one of:

- **real**: the code or the test is wrong and must be fixed.
- **flaky**: the result does not depend on the code. Requires evidence: a mixed result in the isolated reruns of (a); or, for a test that (a) did not rerun, that passed every attempt that ran there, or that reported `did not run` there, and for a failing job, it passes when the failed jobs are rerun in CI (`gh run rerun <id> --failed`, then `gh run watch <id>` and `gh run view <id> --attempt <n> --json jobs`), or the result depends on timing, ordering or the environment and you can point at that dependence. Rerun in CI at most once. A test with `0/<n> passed` is never flaky.
- **false positive**: the tool is wrong. Requires a concrete reason the code is correct, citing the code that makes it so (`file:line` of the bounds check or invariant the analyzer did not follow).

If you cannot produce the required evidence for flaky or false positive, classify the item as real.

For every item record:

- **Item**: the ruleId, the test name, or the job name.
- **Type**: `cppcheck`, `clang-tidy`, `test` or `job`.
- **Reruns**: `<passes>/<attempts that ran> passed` or `did not run: <reason>` from (a), as printed, then `CI attempt <n> passed` or `CI attempt <n> failed` if you reran the failed jobs in CI; `none` if neither.
- **Cause**: `file:line` (from the annotation, the finding or test line in the log, or SARIF/JUnit) or a verbatim quoted log line.
- **Reasoning**: one line.

## 5. Triage comment

Find the open PR for the branch:

```bash
gh pr list --head <headBranch> --state open --json number,url,baseRefName
```

If there is no open PR, go to step 8.

Otherwise, check for an earlier triage of the same pull request first ("Repeat failures on the same pull request" below), then post ONE comment on that PR (in Cursor Cloud Agents, the pull-request tool's `post_comment` with the PR URL; elsewhere `gh pr comment <number> --body-file <file>`). Record the comment URL. Format:

```markdown
## CI triage: run <id>

Run: <run url> (branch `<headBranch>`, commit `<headSha>`)
Failing jobs: <job>, <job>

| Item | Type | Classification | Reruns | Cause | Reasoning |
| --- | --- | --- | --- | --- | --- |
| `<item>` | <type> | <real, flaky or false positive> | <e.g. 4/20 passed, did not run: build failed, or none> | `<file:line>` or "<log line>" | <one line> |

Pull requests: none yet
```

Later steps add PR links by editing this comment in place (GitHub MCP `update_issue_comment`, or `gh api --method PATCH repos/<owner>/<repo>/issues/comments/<comment id> -F body=@<file>`). Never post a second triage comment for the same run.

### Repeat failures on the same pull request

A pull request can fail again after it was triaged, on a later push or a rerun. Before posting, list the pull request's comments and the open pull requests that may already cover its items, with read-only `gh`. `<number>` is the pull request being triaged; the `--jq` filter removes it from the pull request lists, because it can mention or touch the failing test without covering the finding:

```bash
gh pr view <number> --comments
gh api 'repos/{owner}/{repo}/issues/<number>/comments' --paginate \
  --jq '.[] | select(.body | startswith("## CI triage: run ")) | [.id, .html_url, .created_at, (.body | split("\n")[0])] | @tsv'
gh pr list --state open --base <headBranch> --json number,title,url,headRefName,body \
  --jq 'map(select(.number != <number>))'
gh pr list --state open --search '"CI triage" in:title' --json number,title,url,headRefName,baseRefName,body \
  --jq 'map(select(.number != <number>))'
gh pr list --state open --search '<ruleId or test name>' --json number,title,url,headRefName,baseRefName \
  --jq 'map(select(.number != <number>))'
```

- **Earlier triage comment.** A comment whose first line is `## CI triage: run <earlier id>` comes from this procedure; if there are several, take the latest. If it is for this same run, do not post again: edit it if your tooling supports that, otherwise leave it and report its URL. For an earlier run, the default is to post one new comment that names the run it supersedes (run ID and the run URL from the earlier comment's `Run:` line) and leads with what changed since then, followed by the usual run line and full table:

  ```markdown
  ## CI triage: run <id>

  Supersedes run <earlier id> (<earlier run url>), triaged in <earlier comment url>.

  Changes since run <earlier id>:
  - New: `<item>` (<classification>)
  - Resolved: `<item>`
  - Reclassified: `<item>` from <old> to <new>: <why>

  Run: <run url> (branch `<headBranch>`, commit `<headSha>`)
  ```

  Write `none` for an empty group. Only if your tooling supports editing comments (GitHub MCP `update_issue_comment`, or the `gh api --method PATCH` call above), edit the earlier comment in place instead, with the same content. Either way, the resulting comment is the triage comment for the later steps.
- **Open pull request for the same finding.** Before opening a dispositions or fix PR (steps 6 and 7), check the open pull requests listed above for one that already covers the same finding: the same rule ID and `file:line`, or the same failing test (read its title, body and `gh pr diff <its number>`). The pull request being triaged never covers its own finding, even if a search returns it. If another one does, do not open a duplicate: link it in the triage table by ending the item's Reasoning with `Covered by <pr url>.` and list it under `Pull requests:`. Open PRs only for the items no open pull request covers.

## 6. Dispositions PR (only if there are false positives or flaky items that no open pull request covers)

1. Create one branch off the failing branch's current head: `git fetch origin <headBranch>` and `git checkout -b cursor/ci-triage-<id>-dispositions origin/<headBranch>`. The `cursor/` prefix makes rule 2 skip CI runs of this branch. If `origin/<headBranch>` is no longer `<headSha>`, check that each item still applies and say so in the PR body.
2. For each false positive, add an inline suppression on the line directly above the flagged line, preceded by a justification comment:
   ```c
   /* False positive (CI triage run <id>): <why the code is correct>. */
   // cppcheck-suppress <ruleId>
   ```
   ```c
   /* False positive (CI triage run <id>): <why the code is correct>. */
   // NOLINTNEXTLINE(<check>)
   ```
   Suppress only the reported id or check on that line. Never disable checks in `.clang-tidy`, add `--suppress` to CI, or use a bare `NOLINT`.
3. For each flaky test, fix the nondeterminism: a deterministic or injected clock instead of wall-clock timing, random generators started from a fixed value, or explicit ordering. Raising a timeout, adding a sleep or a retry, or widening a tolerance does not fix it. Keep every assertion and expected value of the test. Step 6.4 proves the fix with 20/20 passes in isolation.

   Quarantine only when no such fix is feasible, for example when the nondeterminism comes from the runner or a system service the test cannot control. Add the test to `SIGRELAY_QUARANTINED_TESTS` in `tests/quarantine.cmake` with the reason and the triage comment URL as a trailing comment, and state the same reason in the PR body:
   ```cmake
   set(SIGRELAY_QUARANTINED_TESTS
     <test name>  # <why the nondeterminism cannot be fixed>; <triage comment url>
   )
   ```
4. Verify locally before opening the PR. This applies to every PR in steps 6 and 7:
   - Run `cppcheck --version` and `clang-tidy --version`. If either is missing, run `sudo apt-get install -y cppcheck clang-tidy` once; if a scanner is still missing, say so explicitly in the PR body (for example "clang-tidy not rerun locally: not installable in the agent environment") and leave that check to CI. Never skip a scanner silently.
   - Configure and build with both compilers, warnings as errors, then run `ctest -LE quarantine`.
   - Rerun the scanner that reported each item and confirm the item is gone and no new finding appears. Run both scanners whenever the change touches `src/` or `include/`, the directories they scan.
   - For each flaky test fixed in step 6.3, commit the fix and rerun the test 20 times in isolation with the script from step 4 (a), giving it the fix commit and a work directory for that commit: `bash /tmp/ci-triage-<id>/rerun.sh "$(git rev-parse HEAD)" <name> "/tmp/ci-triage-<id>/verify-$(git rev-parse --short HEAD)"`. It must report `20/20 passed`: all 20 attempts ran and passed. If step 4 (a) also gave 20/20 on the failing commit, the reruns cannot show the fix: say so in the PR body and name the change that removes the nondeterminism.
   - Put the tool versions and the results (ctest summary line, each converter's finding count, each fixed flaky test's rerun count next to its count from step 4 (a), for example "20/20 passed (4/20 on `<headSha>`)") in the PR body.

   The commands, as in `.github/workflows/ci.yml` (if the two differ, follow ci.yml). clang-tidy gets its own build directory here so that `build/` keeps the tests:
   ```bash
   cppcheck --version; clang-tidy --version
   cmake -S . -B build-clang -DCMAKE_C_COMPILER=clang -DCMAKE_COMPILE_WARNING_AS_ERROR=ON && cmake --build build-clang --parallel
   cmake -S . -B build -DCMAKE_C_COMPILER=gcc -DCMAKE_COMPILE_WARNING_AS_ERROR=ON && cmake --build build --parallel
   ctest --test-dir build -LE quarantine --output-on-failure
   cppcheck --std=c11 --language=c -I include \
     --enable=warning,style,performance,portability --check-level=exhaustive \
     --inline-suppr --error-exitcode=1 --xml --output-file=cppcheck.xml src include
   python3 tools/cppcheck_xml_to_sarif.py cppcheck.xml cppcheck.sarif
   cmake -S . -B build-tidy -DCMAKE_C_COMPILER=clang -DSIGRELAY_BUILD_TESTS=OFF
   clang-tidy -p build-tidy --quiet src/*.c > clang-tidy.log 2>&1; cat clang-tidy.log
   python3 tools/clang_tidy_to_sarif.py clang-tidy.log clang-tidy.sarif
   ```
   For the dispositions PR, every suppressed finding must be gone, every fixed flaky test must pass 20/20 in isolation, and nothing else may change. CI on the PR then confirms the result is green.
5. Open ONE PR targeting `<headBranch>`, titled `CI triage <id>: dispositions`, whose body lists each disposition with its reasoning (for a fixed flaky test its rerun counts, for a quarantined test why no fix is feasible) and links the triage comment.

## 7. Fix PRs (one per real item)

For each real item that no open pull request covers (step 5, "Repeat failures on the same pull request"):

1. Branch off the dispositions branch if step 6 created one, else off `origin/<headBranch>`: `cursor/ci-triage-<id>-fix-<short item name>`.
2. Fix the cause. Add a regression test for it in `tests/` (registered in `tests/test_list.h`, in `tests/hooks/test_policies.py` for hook scripts, or in `tests/tools/test_annotations.py` for the report tools in `tools/`) that fails without the fix and passes with it; check both. For parser code, the test feeds the malformed or boundary input that exposed the problem. Regression tests must never depend on cppcheck or clang-tidy being installed: for a static-analysis item the test covers the behaviour the finding exposed, and CI is the gate for the analyzer result.
3. Never weaken, skip, quarantine or delete an existing test, and never loosen an expected value to make a test pass.
4. Verify exactly as CI does, as in step 6.4.
5. Open one PR per item, targeting the dispositions branch (or `<headBranch>` when there is none), titled `CI triage <id>: fix <item>`, linking the triage comment.

Then edit the triage comment to replace `Pull requests: none yet` with a link to every PR you opened or found already open and the item it covers.

## 8. Branch without an open PR

Do not comment and do not open PRs. Put the full triage table in your reply, followed by the PRs you would open: for each, its title, base branch and planned change.

## 9. Final reply

Always state:

- the run ID and run URL, and if you looked the run up by commit, which run you picked and why;
- the failing jobs;
- at least one verbatim log line per failing job;
- each cppcheck and clang-tidy finding as ruleId and `file:line`;
- each failing test name;
- which evidence sources were unavailable (annotations, logs or artifacts);
- the classification table (Item | Type | Classification | Reruns | Cause | Reasoning);
- the triage comment URL, the earlier run it supersedes, and PR URLs (opened or already open), if any.

## Jenkins builds

A request for a Jenkins build (see the `Jenkinsfile`) carries the build URL, branch, commit and the failing stages' output instead of a run ID. Treat the build URL as the run ID and run URL, apply step 2 to the branch, take evidence from the request and the archived reports it names instead of check-run annotations, `gh run view` and `gh run download`, and continue from step 4. The isolated reruns of step 4 (a) apply as usual; rerunning the Jenkins build is not available, so otherwise classify an item as flaky only with timing, ordering or environment evidence.
