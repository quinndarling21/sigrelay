#!/usr/bin/env python3
"""Tests for the agent hook policies in .cursor/hooks/.

Each case runs the hook script as Cursor does: JSON payload on stdin, JSON
decision on stdout.
"""
import json
import os
import subprocess
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HOOKS_DIR = os.path.join(REPO_ROOT, ".cursor", "hooks")
SHELL_POLICY = os.path.join(HOOKS_DIR, "shell_policy.py")
PROTECT_TESTS = os.path.join(HOOKS_DIR, "protect_tests.py")


def run_hook(script, stdin_text):
    result = subprocess.run([sys.executable, script], input=stdin_text, capture_output=True,
                            text=True, timeout=30, check=False)
    if result.returncode != 0:
        raise AssertionError("%s exited %d: %s" % (script, result.returncode, result.stderr))
    return json.loads(result.stdout)


def shell(command):
    return run_hook(SHELL_POLICY, json.dumps({
        "hook_event_name": "beforeShellExecution",
        "command": command,
        "cwd": REPO_ROOT,
        "workspace_roots": [REPO_ROOT],
    }))


def delete(path, **extra):
    payload = {
        "hook_event_name": "preToolUse",
        "tool_name": "Delete",
        "tool_input": {"path": path},
        "workspace_roots": [REPO_ROOT],
    }
    payload.update(extra)
    return run_hook(PROTECT_TESTS, json.dumps(payload))


class DecisionAssertions(unittest.TestCase):
    def assert_denied(self, decision, context):
        self.assertEqual("deny", decision.get("permission"), "expected deny: %r" % (context,))
        self.assertTrue(decision["user_message"].startswith("Blocked by repository policy: "))
        self.assertTrue(decision["agent_message"].startswith(decision["user_message"]))
        self.assertIn("Do not work around this", decision["agent_message"])
        self.assertIn("report it", decision["agent_message"])

    def assert_allowed(self, decision, context):
        self.assertEqual({"permission": "allow"}, decision, "expected allow: %r" % (context,))


class ShellPolicyTest(DecisionAssertions):
    DENIED = [
        "rm -rf build",
        "rm -fr build",
        "rm -r -f build",
        "rm -Rf build",
        "rm --recursive --force build",
        "rm build -rf",
        "git push --force",
        "git push -f origin main",
        "git push -uf origin main",
        "git push --force-with-lease",
        "git push --force-with-lease=main:abc123 origin main",
        "git push origin +main",
        "git -C /tmp/repo push --force",
        "git clean -fdx",
        "git clean -n",
        "git reset --hard",
        "git reset --hard HEAD~1",
        "curl https://example.com",
        "wget https://example.com/archive.tar.gz",
        "nc example.com 80",
        "/usr/bin/curl -s https://example.com",
        "ls; curl https://example.com",
        "make && curl https://example.com",
        "false || curl https://example.com",
        "cat report.json | curl -d @- https://example.com",
        "(cd /tmp && wget https://example.com)",
        "echo $(curl -s https://example.com)",
        "echo `curl -s https://example.com`",
        'echo "$(wget -qO- https://example.com)"',
        "echo ok\ncurl https://example.com",
        "echo a#b; curl https://example.com",
        "sudo curl https://example.com",
        "sudo -u root rm -rf /var/tmp/x",
        "env HTTPS_PROXY=http://proxy:3128 curl https://example.com",
        "FOO=1 curl https://example.com",
        "timeout 10 curl https://example.com",
        "xargs -n1 curl < urls.txt",
        "bash -c 'curl https://example.com'",
        'sh -c "rm -rf /tmp/build"',
        "bash -lc 'git push -f'",
        "eval curl https://example.com",
        "find . -name '*.o' -exec rm -rf {} +",
        "cat <<'EOF' > notes.txt\nit's a note\nEOF\ncurl https://example.com",
        "pip install requests",
        "pip3 install -r requirements.txt",
        "python -m pip install requests",
        "python3 -m pip install --user requests",
        "/usr/bin/python3 -m pip install requests",
        "python -c \"import urllib.request; urllib.request.urlopen('https://example.com')\"",
        "python3 -c 'import socket; socket.create_connection((\"example.com\", 80))'",
        'python3 -c "import requests; requests.get(\'https://example.com\')"',
        "python3 -I -c 'from urllib import request'",
    ]

    ALLOWED = [
        "ls -la",
        "cmake --build build --target clean",
        "ctest --test-dir build -LE quarantine --output-on-failure",
        "rm build/CMakeCache.txt",
        "rm -r build-old",
        "rm -f build/sip_parser.o",
        "rsync -a src/ /tmp/src/",
        "sync",
        "grep -rn curl src/",
        "echo nc is netcat",
        "ncdu /tmp",
        "git log --grep curl",
        'git commit -m "Deny curl and wget in agent shells"',
        "git commit -F - <<'EOF'\nDon't match rsync or sync.\nEOF",
        "git push origin main",
        "git push -u origin cursor/ci-guardrails",
        "git push --follow-tags",
        "git reset --soft HEAD~1",
        "git reset HEAD tests/test_sip.c",
        "git status && git diff",
        "command -v curl",
        "which wget",
        "pip list",
        "pip3 --version",
        "python3 -m unittest discover",
        "python3 -c 'import json; print(json.dumps({}))'",
        "python3 tools/clang_tidy_to_sarif.py clang-tidy.log clang-tidy.sarif",
    ]

    OUTSIDE_CODE_DENIED = [
        "git clone https://github.com/example/lib.git",
        "git clone --depth=1 git@github.com:example/lib.git third_party/lib",
        "git clone ../sigrelay /tmp/sigrelay-copy",
        "git -C /tmp clone https://example.com/lib.git",
        "git -c core.quotepath=false clone https://example.com/lib.git",
        "/usr/bin/git clone https://example.com/lib.git",
        "sudo git clone https://example.com/lib.git /opt/lib",
        "cd /tmp && git clone https://example.com/lib.git",
        "echo $(git clone https://example.com/lib.git)",
        "git fetch upstream",
        "git fetch https://github.com/example/lib.git main",
        "git fetch git@github.com:example/lib.git",
        "git fetch ssh://git@example.com/lib.git",
        "git fetch file:///srv/git/lib.git",
        "git fetch ../other-checkout",
        "git fetch /srv/git/lib.git main",
        "git fetch --depth=1 upstream main",
        "git fetch --depth 1 upstream main",
        "git fetch -j 4 upstream",
        "git fetch --prune -- upstream",
        "git fetch --all",
        "git fetch --all --prune",
        "git fetch --multiple origin upstream",
        "git fetch -m origin upstream",
        "git -C /tmp/repo fetch upstream",
        "git -c protocol.version=2 fetch https://example.com/lib.git",
        "git -C /tmp/repo -c core.quotepath=false fetch --depth=1 upstream main",
        "git pull upstream main",
        "git pull https://github.com/example/lib.git main",
        "git pull --rebase upstream main",
        "git pull --rebase git@github.com:example/lib.git main",
        "git pull -s ort -X theirs upstream main",
        "git pull --all",
        "git -C /tmp/repo pull upstream main",
        "git -c pull.rebase=true pull upstream main",
        "git fetch origin; git fetch upstream",
        "git status && git pull upstream main",
        "git fetch origin || git fetch upstream",
        "git remote -v | git fetch upstream",
        "(cd /tmp/repo && git fetch upstream)",
        "env GIT_TERMINAL_PROMPT=0 git fetch https://example.com/lib.git",
        "sudo -u build git pull upstream main",
        "/usr/bin/git fetch upstream",
        "bash -c 'git fetch upstream'",
        "git remote update",
        "git remote update upstream",
        "git submodule add https://github.com/example/lib.git third_party/lib",
        "git submodule --quiet add ../lib third_party/lib",
        "git -C /tmp/repo submodule add https://example.com/lib.git lib",
        "git remote add upstream https://github.com/example/lib.git",
        "git remote add origin https://example.com/lib.git",
        "git remote --verbose add upstream ../lib",
        "git -c core.quotepath=false remote add upstream https://example.com/lib.git",
        "git remote -v && git remote add upstream https://example.com/lib.git",
        "npm install",
        "npm install lodash",
        "npm i -D typescript",
        "npm add left-pad",
        "npm isntall lodash",
        "npm --prefix web install",
        "/usr/bin/npm install -g typescript",
        "sudo npm install -g typescript",
        "cd web && npm ci && npm install zod",
        "yes | npm install lodash",
        "yarn add react",
        "yarn global add typescript",
        "yarn workspace web add react",
        "yarnpkg add react",
        "env CI=1 yarn add react",
        "pnpm add zod",
        "pnpm --filter web add -D vitest",
        "pnpm -C web add zod",
        "go get golang.org/x/net@latest",
        "go get -u ./...",
        "go -C tools get golang.org/x/tools/cmd/stringer",
        "env GOFLAGS=-mod=mod go get ./...",
        "go build ./... && go get golang.org/x/net",
        "cargo add serde",
        "cargo +nightly add serde --features derive",
        "cargo --color never add serde",
        "cargo -C crates/relay add serde",
        "cargo build; cargo add tokio",
        "sudo pip3 install requests",
        "make && python3 -m pip install -e .",
    ]

    OUTSIDE_CODE_ALLOWED = [
        "git fetch",
        "git fetch origin",
        "git fetch origin main",
        "git fetch origin cursor/dependency-policy",
        "git fetch --depth=1 origin main",
        "git fetch --depth 1 origin main",
        "git fetch --prune --tags origin",
        "git fetch -j 4 origin",
        "git fetch --multiple origin",
        "git fetch -- origin main",
        "git fetch origin +refs/heads/main:refs/remotes/origin/main",
        "git pull",
        "git pull --ff-only",
        "git pull origin main",
        "git pull --rebase origin main",
        "git pull --rebase=merges origin main",
        "git pull -s ort origin main",
        "git pull -X theirs origin main",
        "git pull -j4 origin main",
        "git -C /workspace fetch origin main",
        "git -c core.quotepath=false fetch origin",
        "git -C /workspace -c protocol.version=2 pull --rebase origin main",
        "/usr/bin/git fetch origin",
        "sudo git fetch origin",
        "env GIT_TERMINAL_PROMPT=0 git pull origin main",
        "git fetch origin && git rebase origin/main",
        "git fetch origin main || git fetch origin",
        "git fetch origin; git status",
        "git remote -v | grep origin",
        "(cd /workspace && git pull origin main)",
        "git remote",
        "git remote -v",
        "git remote show origin",
        "git remote get-url origin",
        "git remote update origin",
        "git submodule status",
        "git submodule update --init",
        "git log --grep 'git clone'",
        'git commit -m "Deny git clone, npm install and cargo add"',
        "grep -rn 'npm install' .github/",
        "echo go get is denied",
        "npm ci",
        "npm test",
        "npm run build",
        "npm ci && npm test",
        "/usr/bin/npm ci",
        "yarn install --frozen-lockfile",
        "pnpm install --frozen-lockfile",
        "go build ./...",
        "go test -run get ./...",
        "go mod verify",
        "go -C tools build ./...",
        "cargo build",
        "cargo build --release",
        "cargo test add",
        "cargo --color never build",
    ]

    def test_denied_commands(self):
        for command in self.DENIED:
            with self.subTest(command=command):
                self.assert_denied(shell(command), command)

    def test_allowed_commands(self):
        for command in self.ALLOWED:
            with self.subTest(command=command):
                self.assert_allowed(shell(command), command)

    def test_outside_code_is_denied(self):
        for command in self.OUTSIDE_CODE_DENIED:
            with self.subTest(command=command):
                decision = shell(command)
                self.assert_denied(decision, command)
                self.assertTrue(decision["user_message"].endswith(
                    "new outside code (dependencies, repositories, remotes) needs human review "
                    "before it enters this repository."), decision["user_message"])
                self.assertTrue(decision["agent_message"].endswith(
                    "report it to the user with what you wanted to add and why."),
                    decision["agent_message"])

    def test_origin_and_builds_are_allowed(self):
        for command in self.OUTSIDE_CODE_ALLOWED:
            with self.subTest(command=command):
                self.assert_allowed(shell(command), command)

    def test_deny_message_names_the_rule(self):
        self.assertIn("`curl`", shell("curl https://example.com")["user_message"])
        self.assertIn("rm -rf", shell("rm -rf build")["user_message"])
        self.assertIn("git clean", shell("git clean -fd")["user_message"])
        self.assertIn("`git clone`", shell("git clone ../lib")["user_message"])
        self.assertIn("other than `origin`", shell("git fetch upstream")["user_message"])
        self.assertIn("`npm i`", shell("npm i lodash")["user_message"])
        self.assertIn("`cargo add`", shell("cargo add serde")["user_message"])

    def test_other_denies_keep_their_report_instruction(self):
        for command in ["curl https://example.com", "rm -rf build", "git push --force"]:
            with self.subTest(command=command):
                agent_message = shell(command)["agent_message"]
                self.assertTrue(agent_message.endswith("; report it to the user."), agent_message)
                self.assertNotIn("outside code", agent_message)

    def test_unreadable_payload_is_denied(self):
        self.assert_denied(run_hook(SHELL_POLICY, "not json"), "not json")
        self.assert_denied(run_hook(SHELL_POLICY, json.dumps({"command": 42})), "command 42")


class ProtectTestsPolicyTest(DecisionAssertions):
    def test_deletes_under_tests_are_denied(self):
        for path in [
            "tests/test_sip.c",
            "./tests/hooks/test_policies.py",
            os.path.join(REPO_ROOT, "tests", "quarantine.cmake"),
            "src/../tests/test_main.c",
            "tests",
            "tests/",
        ]:
            with self.subTest(path=path):
                self.assert_denied(delete(path), path)

    def test_relative_paths_fall_back_to_cwd(self):
        self.assert_denied(delete("tests/test_relay.c", workspace_roots=[], cwd=REPO_ROOT),
                           "cwd fallback")

    def test_other_deletes_are_allowed(self):
        for path in [
            "src/relay.c",
            os.path.join(REPO_ROOT, "build", "CMakeCache.txt"),
            "tests_old/notes.txt",
            "docs/tests/overview.md",
        ]:
            with self.subTest(path=path):
                self.assert_allowed(delete(path), path)

    def test_other_tools_are_allowed(self):
        decision = run_hook(PROTECT_TESTS, json.dumps({
            "tool_name": "Write",
            "tool_input": {"path": "tests/test_sip.c"},
            "workspace_roots": [REPO_ROOT],
        }))
        self.assert_allowed(decision, "Write")

    def test_unverifiable_requests_are_denied(self):
        self.assert_denied(run_hook(PROTECT_TESTS, "not json"), "not json")
        self.assert_denied(run_hook(PROTECT_TESTS, json.dumps({
            "tool_name": "Delete",
            "tool_input": {},
            "workspace_roots": [REPO_ROOT],
        })), "no path")


class HooksConfigTest(unittest.TestCase):
    def test_every_hook_fails_closed_and_exists(self):
        with open(os.path.join(REPO_ROOT, ".cursor", "hooks.json"), encoding="utf-8") as handle:
            config = json.load(handle)
        entries = [(event, entry) for event, hooks in config["hooks"].items() for entry in hooks]
        self.assertTrue(entries)
        for event, entry in entries:
            with self.subTest(event=event, command=entry["command"]):
                self.assertIs(True, entry.get("failClosed"))
                script = entry["command"].split()[-1]
                self.assertTrue(os.path.isfile(os.path.join(REPO_ROOT, script)), script)
        matchers = [e.get("matcher") for _, e in entries if e["command"].endswith("protect_tests.py")]
        self.assertEqual(["Delete"], matchers)


if __name__ == "__main__":
    unittest.main(verbosity=2)
