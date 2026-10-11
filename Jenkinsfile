// Equivalent pipeline for teams on Jenkins. This repository's CI runs on
// GitHub Actions (.github/workflows/ci.yml); this file mirrors the same stages
// (build and ctest with JUnit, cppcheck SARIF, clang-tidy SARIF) for a team
// whose own repository builds on Jenkins. When a build fails, it asks a Cursor
// Cloud Agent to triage it with the ci-triage skill
// (.cursor/skills/ci-triage/SKILL.md) in that team's repository.
//
// Requirements on the Jenkins agent: cmake, gcc, clang, clang-tidy, cppcheck,
// python3 and curl; the JUnit plugin; and a "Secret text" credential with the
// id cursor-api-key holding a Cursor API key.

pipeline {
    agent any

    options {
        timeout(time: 30, unit: 'MINUTES')
    }

    stages {
        stage('Build and test') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '''
                        mkdir -p reports
                        status=0
                        {
                            cmake -S . -B build-clang -DCMAKE_C_COMPILER=clang -DCMAKE_COMPILE_WARNING_AS_ERROR=ON &&
                            cmake --build build-clang --parallel &&
                            cmake -S . -B build -DCMAKE_C_COMPILER=gcc -DCMAKE_COMPILE_WARNING_AS_ERROR=ON &&
                            cmake --build build --parallel &&
                            ctest --test-dir build -LE quarantine --output-on-failure \
                                --output-junit "$WORKSPACE/reports/ctest-junit.xml"
                        } > reports/build-and-test.log 2>&1 || status=$?
                        cat reports/build-and-test.log
                        if [ "$status" -ne 0 ]; then touch reports/build-and-test.failed; fi
                        exit "$status"
                    '''
                }
            }
        }

        // cppcheck 2.16+ can write SARIF itself; XML plus the converter keeps
        // the output identical to GitHub Actions for older distribution builds.
        // As there, third_party/zlib stays off the include path and
        // --library=zlib describes the zlib API, so only src and include are
        // analysed.
        stage('cppcheck') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '''
                        mkdir -p reports
                        cppcheck --version
                        status=0
                        cppcheck --std=c11 --language=c -I include --library=zlib \
                            --enable=warning,style,performance,portability --check-level=exhaustive \
                            --inline-suppr --error-exitcode=1 \
                            --xml --output-file=reports/cppcheck.xml \
                            src include > reports/cppcheck.log 2>&1 || status=$?
                        python3 tools/cppcheck_xml_to_sarif.py reports/cppcheck.xml reports/cppcheck.sarif \
                            >> reports/cppcheck.log 2>&1 || status=1
                        cat reports/cppcheck.log
                        if [ "$status" -ne 0 ]; then touch reports/cppcheck.failed; fi
                        exit "$status"
                    '''
                }
            }
        }

        stage('clang-tidy') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '''
                        mkdir -p reports
                        status=0
                        cmake -S . -B build-tidy -DCMAKE_C_COMPILER=clang -DSIGRELAY_BUILD_TESTS=OFF > /dev/null
                        clang-tidy -p build-tidy --quiet src/*.c > reports/clang-tidy-output.log 2>&1 || status=$?
                        version="$(clang-tidy --version | sed -n 's/.*version \\([0-9][0-9.]*\\).*/\\1/p' | head -n 1)"
                        python3 tools/clang_tidy_to_sarif.py reports/clang-tidy-output.log reports/clang-tidy.sarif \
                            --tool-version "$version" > reports/clang-tidy-findings.log 2>&1 || status=1
                        cat reports/clang-tidy-output.log reports/clang-tidy-findings.log > reports/clang-tidy.log
                        cat reports/clang-tidy.log
                        if [ "$status" -ne 0 ]; then touch reports/clang-tidy.failed; fi
                        exit "$status"
                    '''
                }
            }
        }
    }

    post {
        always {
            junit allowEmptyResults: true, testResults: 'reports/ctest-junit.xml'
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
        failure {
            withCredentials([string(credentialsId: 'cursor-api-key', variable: 'CURSOR_API_KEY')]) {
                sh '''
                    set +x
                    mkdir -p reports
                    branch="${BRANCH_NAME:-${GIT_BRANCH#origin/}}"
                    case "$branch" in
                        cursor/*) echo "Branch $branch is an agent branch; not requesting triage."; exit 0 ;;
                    esac
                    BRANCH="$branch" python3 - > reports/triage-request.json <<'EOF'
import glob
import json
import os
import re

newline = chr(10)
build_url = os.environ.get("BUILD_URL", "")
repo_url = os.environ.get("GIT_URL", "")
ssh = re.match("^git@([^:]+):(.+)$", repo_url)
if ssh:
    repo_url = "https://" + ssh.group(1) + "/" + ssh.group(2)
if repo_url.endswith(".git"):
    repo_url = repo_url[:-4]

evidence = []
for marker in sorted(glob.glob("reports/*.failed")):
    stage = os.path.basename(marker)[:-len(".failed")]
    with open("reports/" + stage + ".log", encoding="utf-8", errors="replace") as handle:
        lines = handle.read().splitlines()
    evidence.append("Stage " + stage + " failed. Last lines of its log:" + newline
                    + newline.join(lines[-80:]))

prompt = newline.join([
    "Run the ci-triage skill (.cursor/skills/ci-triage/SKILL.md) for a failed Jenkins build of this repository.",
    "Build: " + build_url + " (" + os.environ.get("JOB_NAME", "") + " #" + os.environ.get("BUILD_NUMBER", "") + ")",
    "Branch: " + os.environ["BRANCH"],
    "Commit: " + os.environ.get("GIT_COMMIT", ""),
    "Archived reports (ctest-junit.xml, cppcheck.sarif, clang-tidy.sarif): " + build_url + "artifact/reports/",
    "This is a Jenkins build, not a GitHub Actions run; follow the skill's section on Jenkins builds.",
    "",
] + evidence)

print(json.dumps({
    "name": ("CI triage: " + os.environ.get("JOB_NAME", "") + " #" + os.environ.get("BUILD_NUMBER", ""))[:100],
    "prompt": {"text": prompt},
    "repos": [{"url": repo_url, "startingRef": os.environ["BRANCH"]}],
    "autoCreatePR": False,
}))
EOF
                    # The key goes to curl on stdin so it never appears in the process list.
                    printf 'user = "%s:"\\n' "$CURSOR_API_KEY" | curl --config - \
                        --fail-with-body --silent --show-error --max-time 30 \
                        --header 'Content-Type: application/json' \
                        --data @reports/triage-request.json \
                        --output reports/triage-response.json \
                        https://api.cursor.com/v1/agents
                    python3 -c 'import json; d = json.load(open("reports/triage-response.json")); print("Triage agent:", d.get("agent", {}).get("url") or d.get("agent", {}).get("id"))'
                '''
            }
        }
    }
}
