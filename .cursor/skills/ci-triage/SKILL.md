---
name: ci-triage
description: Triages a failed GitHub Actions run of the sigrelay repository. Collects failing job logs, cppcheck and clang-tidy SARIF and ctest JUnit results, classifies every item as real, flaky or false positive, posts one triage comment on the branch's open PR, and opens dispositions and fix PRs. Use when a CI run of this repository fails or when asked to triage a run ID.
---

# CI triage

Follow the steps in order. Do not take any action a step does not allow. Shell hooks in this repository deny curl, wget, force pushes and similar commands; use `gh` and your pull-request tools instead, and report any block rather than working around it.

## 1. Load the run

Input: a workflow run ID, or the run that triggered you.

```bash
gh run view <id> --json databaseId,headBranch,headSha,conclusion,event,jobs,url
```

Record `databaseId` (the run ID), `url`, `headBranch`, `headSha`, `event`, and every job whose `conclusion` is `failure` or `timed_out` (the failing jobs; keep each job's `databaseId` and `name`). If `conclusion` is empty the run is still in progress: wait with `gh run watch <id>` and load it again.

## 2. Skip rules

If either rule applies, reply with exactly one line and stop. Do not comment, rerun or open anything.

- `conclusion` is `success`: `No triage needed: run succeeded (run <id>)`
- `headBranch` starts with `cursor/`: `No triage needed: branch <headBranch> is an agent branch (run <id>)`

## 3. Collect evidence

Work in a directory outside the repository, for example `/tmp/ci-triage-<id>`.

For each failing job, read the failed steps' log:

```bash
gh run view <id> --job <job databaseId> --log-failed
```

Keep at least one verbatim log line per failing job (the first error line, such as a compiler error, `The following tests FAILED:`, a finding printed by `tools/*_to_sarif.py`, or the `::error` summary line).

Download the reports. Each artifact is missing when its job stopped early (for example `ctest-junit` after a build failure); that is expected, so continue with what exists:

```bash
gh run download <id> -n cppcheck-sarif -n clang-tidy-sarif -n ctest-junit -D /tmp/ci-triage-<id> \
  || for name in cppcheck-sarif clang-tidy-sarif ctest-junit; do
       gh run download <id> -n "$name" -D "/tmp/ci-triage-<id>/$name" || echo "artifact $name not available"
     done
```

List every SARIF result (ruleId, file, line, message) and every failing JUnit test (name, failure message, assertion output):

```bash
python3 - /tmp/ci-triage-<id> <<'EOF'
import glob, json, sys
import xml.etree.ElementTree as ET

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
for path in sorted(glob.glob(root + "/**/*.xml", recursive=True)):
    for case in ET.parse(path).getroot().iter("testcase"):
        failure = case.find("failure")
        if failure is None and case.get("status") != "fail":
            continue
        message = failure.get("message", "") if failure is not None else ""
        output = [l for l in (case.findtext("system-out") or "").splitlines() if l.strip()]
        print("JUNIT\t%s\t%s\t%s" % (case.get("name"), message, " | ".join(output[-5:])))
EOF
```

## 4. Classify every item

Items are: each SARIF result, each failing JUnit test, and each failing job that is not explained by those two (compile error, configure error, tool install failure, timeout). Classify each item as exactly one of:

- **real**: the code or the test is wrong and must be fixed.
- **flaky**: the result does not depend on the code. Requires evidence: it passes when the failed jobs are rerun (`gh run rerun <id> --failed`, then `gh run watch <id>` and `gh run view <id> --attempt <n> --json jobs`), or the test depends on timing, ordering or the environment and you can point at that dependence. Rerun at most once.
- **false positive**: the tool is wrong. Requires a concrete reason the code is correct, citing the code that makes it so (`file:line` of the bounds check or invariant the analyzer did not follow).

If you cannot produce the required evidence for flaky or false positive, classify the item as real.

For every item record:

- **Item**: the ruleId, the test name, or the job name.
- **Type**: `cppcheck`, `clang-tidy`, `test` or `job`.
- **Cause**: `file:line` (from SARIF, or the assertion line in the JUnit output) or a verbatim quoted log line.
- **Reasoning**: one line.

## 5. Triage comment

Find the open PR for the branch:

```bash
gh pr list --head <headBranch> --state open --json number,url,baseRefName
```

If there is no open PR, go to step 8.

Otherwise post ONE comment on that PR (in Cursor Cloud Agents, the pull-request tool's `post_comment` with the PR URL; elsewhere `gh pr comment <number> --body-file <file>`). Record the comment URL. Format:

```markdown
## CI triage: run <id>

Run: <run url> (branch `<headBranch>`, commit `<headSha>`)
Failing jobs: <job>, <job>

| Item | Type | Classification | Cause | Reasoning |
| --- | --- | --- | --- | --- |
| `<item>` | <type> | <real, flaky or false positive> | `<file:line>` or "<log line>" | <one line> |

Pull requests: none yet
```

Later steps add PR links by editing this comment in place (GitHub MCP `update_issue_comment`, or `gh api --method PATCH repos/<owner>/<repo>/issues/comments/<comment id> -F body=@<file>`). Never post a second triage comment for the same run.

## 6. Dispositions PR (only if there are false positives or flaky items)

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
3. For each flaky test, add its name to `SIGRELAY_QUARANTINED_TESTS` in `tests/quarantine.cmake` with the triage comment URL as a trailing comment:
   ```cmake
   set(SIGRELAY_QUARANTINED_TESTS
     <test name>  # <triage comment url>
   )
   ```
4. Verify exactly as CI does (the commands in `.github/workflows/ci.yml`): both builds with warnings as errors, `ctest -LE quarantine`, cppcheck and clang-tidy. Every suppressed finding must be gone and nothing else may change.
5. Open ONE PR targeting `<headBranch>`, titled `CI triage <id>: dispositions`, whose body lists each disposition with its reasoning and links the triage comment.

## 7. Fix PRs (one per real item)

For each real item:

1. Branch off the dispositions branch if step 6 created one, else off `origin/<headBranch>`: `cursor/ci-triage-<id>-fix-<short item name>`.
2. Fix the cause. Add a regression test for it in `tests/` (registered in `tests/test_list.h`, or in `tests/hooks/test_policies.py` for hook scripts) that fails without the fix and passes with it; check both. For parser code, the test feeds the malformed or boundary input that exposed the problem.
3. Never weaken, skip, quarantine or delete an existing test, and never loosen an expected value to make a test pass.
4. Verify exactly as CI does, as in step 6.4.
5. Open one PR per item, targeting the dispositions branch (or `<headBranch>` when there is none), titled `CI triage <id>: fix <item>`, linking the triage comment.

Then edit the triage comment to replace `Pull requests: none yet` with a link to every PR you opened and the item it covers.

## 8. Branch without an open PR

Do not comment and do not open PRs. Put the full triage table in your reply, followed by the PRs you would open: for each, its title, base branch and planned change.

## 9. Final reply

Always state:

- the run ID and run URL;
- the failing jobs;
- at least one verbatim log line per failing job;
- each SARIF result as ruleId and `file:line`;
- each failing JUnit test name;
- the classification table (Item | Type | Classification | Cause | Reasoning);
- the triage comment URL and PR URLs, if any.

## Jenkins builds

A request for a Jenkins build (see the `Jenkinsfile`) carries the build URL, branch, commit and the failing stages' output instead of a run ID. Treat the build URL as the run ID and run URL, apply step 2 to the branch, take evidence from the request and the archived reports it names instead of `gh run view` and `gh run download`, and continue from step 4. Rerunning is not available, so classify an item as flaky only with timing, ordering or environment evidence.
