#!/usr/bin/env python3
"""Tests for the GitHub annotations and step summaries of the CI report tools.

Covers tools/cppcheck_xml_to_sarif.py, tools/clang_tidy_to_sarif.py,
tools/junit_to_annotations.py and tools/github_annotations.py. The inputs are
reports recorded from cppcheck 2.13, clang-tidy 18 and ctest, so neither
analyzer has to be installed. Each case runs the tools in a scratch checkout
with the GitHub Actions environment set explicitly, so a CI run of these tests
never writes to the real step summary.
"""
import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")
sys.dont_write_bytecode = True
sys.path.insert(0, TOOLS_DIR)
import github_annotations  # noqa: E402
from github_annotations import Item  # noqa: E402

OTHER_CHECKOUT = "/srv/ci/other-checkout"
CHECKOUT_FILES = [
    "include/sigrelay/relay.h",
    "src/relay.c",
    "src/sigrelay.c",
    "src/sip_parser.c",
    "tests/CMakeLists.txt",
    "tests/hooks/test_policies.py",
    "tests/test_relay.c",
    "tests/test_sip.c",
    "tests/tools/test_annotations.py",
    "tools/github_annotations.py",
]

CPPCHECK_XML = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
    <cppcheck version="2.13.0"/>
    <errors>
        <error id="arrayIndexOutOfBounds" severity="error" msg="Array &apos;buf[10]&apos; accessed at index 10, which is out of bounds." verbose="Array &apos;buf[10]&apos; accessed at index 10, which is out of bounds." cwe="788" file0="src/relay.c">
            <location file="src/relay.c" line="167" column="8" info="Array index out of bounds"/>
        </error>
        <error id="knownConditionTrueFalse" severity="style" msg="Condition &apos;(flags|1)!=0&apos; is always true" verbose="Condition &apos;(flags|1)!=0&apos; is always true" cwe="571" file0="src/relay.c">
            <location file="{workspace}/include/sigrelay/relay.h" line="42" column="9" info="Condition &apos;(flags|1)!=0&apos; is always true"/>
            <location file="{workspace}/include/sigrelay/relay.h" line="40" column="5" info="Assignment &apos;flags=0&apos;, assigned value is 0"/>
        </error>
        <error id="preprocessorErrorDirective" severity="error" msg="#error 100%, unsupported: a&#13;&#10;b" verbose="#error 100%, unsupported: a&#13;&#10;b" file0="src/sigrelay.c">
            <location file="./src/sigrelay.c" line="3" column="2"/>
        </error>
        <error id="missingIncludeSystem" severity="information" msg="Cppcheck cannot find all the include files (use --check-config for details)" verbose="Cppcheck cannot find all the include files."/>
    </errors>
</results>
"""

CLANG_TIDY_LOG = """[3/5] Processing file {workspace}/src/relay.c.
3096 warnings generated.
{workspace}/src/relay.c:168:12: error: 'atoi' used to convert a string to an integer value, but function will not report conversion errors; consider using 'strtol' instead [cert-err34-c,-warnings-as-errors]
  168 |     return atoi(text) + buf[0];
      |            ^
{workspace}/src/relay.c:168:23: error: The right operand of '+' is a garbage value [clang-analyzer-core.UndefinedBinaryOperatorResult,-warnings-as-errors]
  168 |     return atoi(text) + buf[0];
      |                       ^ ~~~~~~
{workspace}/src/relay.c:168:23: note: The right operand of '+' is a garbage value
/srv/ci/other-checkout/include/sigrelay/relay.h:30:5: error: suspicious usage of 'sizeof(K)'; did you mean 'K'? [bugprone-sizeof-expression,-warnings-as-errors]
/usr/include/x86_64-linux-gnu/bits/types.h:10:1: warning: declaration uses identifier '__sig_t', which is reserved [bugprone-reserved-identifier]
[5/5] Processing file {workspace}/src/sip_parser.c.
Error while processing {workspace}/src/sip_parser.c.
"""

JUNIT_XML = """<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="(empty)" tests="10" failures="6" disabled="1" skipped="2" hostname="" time="2" timestamp="2026-10-11T20:03:16">
	<testcase name="sip_parses_invite" classname="sip_parses_invite" time="0.001" status="fail">
		<failure message="Failed"/>
		<properties/>
		<system-out>{workspace}/tests/test_sip.c:94: msg.method: expected "INVITE", got "100%, x"
FAIL sip_parses_invite
</system-out>
	</testcase>
	<testcase name="sip_parses_response" classname="sip_parses_response" time="0.001" status="run">
		<properties/>
		<system-out>PASS sip_parses_response
</system-out>
	</testcase>
	<testcase name="relay_routes_exact_match" classname="relay_routes_exact_match" time="0.001" status="fail">
		<failure message="Failed"/>
		<properties/>
		<system-out>/srv/ci/other-checkout/tests/test_relay.c:28: table.count: expected 3, got 2
FAIL relay_routes_exact_match
</system-out>
	</testcase>
	<testcase name="relay_routes_parent_domain" classname="relay_routes_parent_domain" time="0.006" status="fail">
		<failure message="Subprocess aborted"/>
		<properties/>
		<system-out></system-out>
	</testcase>
	<testcase name="diameter_iterates_avps" classname="diameter_iterates_avps" time="1.002" status="fail">
		<failure message="Timeout"/>
		<properties/>
		<system-out>walking AVPs
</system-out>
	</testcase>
	<testcase name="diameter_parses_header" classname="diameter_parses_header" time="0" status="notrun">
		<skipped message="Unable to find executable"/>
		<properties/>
		<system-out>Unable to find executable: /srv/ci/build/tests/sigrelay_tests</system-out>
	</testcase>
	<testcase name="relay_rejects_invalid_routes" classname="relay_rejects_invalid_routes" time="0.001" status="notrun">
		<skipped message="SKIP_RETURN_CODE=4"/>
		<properties/>
		<system-out></system-out>
	</testcase>
	<testcase name="sip_rejects_truncated_input" classname="sip_rejects_truncated_input" time="0" status="disabled">
		<properties/>
		<system-out>Disabled</system-out>
	</testcase>
	<testcase name="hook_policies" classname="hook_policies" time="1.8" status="fail">
		<failure message="Failed"/>
		<properties/>
		<system-out>test_denied_commands (__main__.ShellPolicyTest.test_denied_commands) ... FAIL

======================================================================
FAIL: test_denied_commands (__main__.ShellPolicyTest.test_denied_commands)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/srv/ci/other-checkout/tests/hooks/test_policies.py", line 147, in test_denied_commands
    self.assert_denied(shell(command), command)
  File "/srv/ci/other-checkout/tests/hooks/test_policies.py", line 49, in assert_denied
    self.assertEqual("deny", decision.get("permission"), "expected deny: %r" % (context,))
AssertionError: 'deny' != 'allow'

----------------------------------------------------------------------
Ran 1 test in 0.002s

FAILED (failures=1)
</system-out>
	</testcase>
	<testcase name="report_tools" classname="report_tools" time="0.4" status="fail">
		<failure message="Failed"/>
		<properties/>
		<system-out>======================================================================
ERROR: test_paths (__main__.PathTest.test_paths)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "{workspace}/tests/tools/test_annotations.py", line 120, in test_paths
    github_annotations.repo_relative(None, ".")
  File "{workspace}/tools/github_annotations.py", line 54, in repo_relative
    absolute = os.path.abspath(path)
               ^^^^^^^^^^^^^^^^^^^^^
  File "&lt;frozen posixpath&gt;", line 399, in abspath
TypeError: expected str, bytes or os.PathLike object, not NoneType
</system-out>
	</testcase>
</testsuite>
"""

PASSING_JUNIT_XML = """<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="(empty)" tests="3" failures="0" disabled="0" skipped="1" hostname="" time="0" timestamp="2026-10-11T20:03:16">
	<testcase name="sip_parses_invite" classname="sip_parses_invite" time="0.001" status="run">
		<system-out>PASS sip_parses_invite
</system-out>
	</testcase>
	<testcase name="sip_parses_response" classname="sip_parses_response" time="0.001" status="run">
		<system-out>PASS sip_parses_response
</system-out>
	</testcase>
	<testcase name="relay_rejects_invalid_routes" classname="relay_rejects_invalid_routes" time="0.001" status="notrun">
		<skipped message="SKIP_RETURN_CODE=4"/>
		<system-out></system-out>
	</testcase>
</testsuite>
"""


@contextlib.contextmanager
def environment(**values):
    """Sets (or with None, removes) environment variables for the block."""
    saved = dict(os.environ)
    for name, value in values.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


class ToolTestCase(unittest.TestCase):
    def setUp(self):
        self.workspace = os.path.realpath(tempfile.mkdtemp(prefix="sigrelay-tools-"))
        self.addCleanup(shutil.rmtree, self.workspace)
        for path in CHECKOUT_FILES:
            full = os.path.join(self.workspace, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            open(full, "w", encoding="utf-8").close()
        self.summary = os.path.join(self.workspace, "summary.md")

    def write(self, name, text):
        with open(os.path.join(self.workspace, name), "w", encoding="utf-8") as handle:
            handle.write(text.replace("{workspace}", self.workspace))
        return name

    def run_tool(self, script, *args, github=True, env=None):
        tool_env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
        tool_env["PYTHONDONTWRITEBYTECODE"] = "1"
        if github:
            tool_env.update(GITHUB_ACTIONS="true", GITHUB_WORKSPACE=self.workspace,
                            GITHUB_STEP_SUMMARY=self.summary)
        tool_env.update(env or {})
        return subprocess.run([sys.executable, os.path.join(TOOLS_DIR, script)] + list(args),
                              cwd=self.workspace, env=tool_env, capture_output=True, text=True,
                              timeout=60, check=False)

    def read(self, name):
        with open(os.path.join(self.workspace, name), encoding="utf-8") as handle:
            return handle.read()

    @staticmethod
    def annotations(stdout):
        return [line for line in stdout.splitlines() if line.startswith("::")]


class EscapingTest(unittest.TestCase):
    def test_message_escaping(self):
        self.assertEqual("100%25 done%0D%0Anext: a, b",
                         github_annotations.escape_data("100% done\r\nnext: a, b"))

    def test_property_escaping(self):
        self.assertEqual("suite%3Acase%2C1 100%25%0A",
                         github_annotations.escape_property("suite:case,1 100%\n"))

    def test_percent_is_escaped_first(self):
        self.assertEqual("%253A%252C", github_annotations.escape_property("%3A%2C"))

    def test_command_format(self):
        self.assertEqual(
            "::error file=src/relay.c,line=12,col=5,title=cert-err34-c::'atoi' used, 100%25",
            github_annotations.error_command(
                Item("cert-err34-c", "'atoi' used, 100%", "src/relay.c", 12, 5)))
        self.assertEqual(
            "::error file=tests/test_sip.c,line=3,title=sip%3Acase%2Cone::a: b",
            github_annotations.error_command(Item("sip:case,one", "a: b", "tests/test_sip.c", 3,
                                                  None)))
        self.assertEqual("::error title=missingIncludeSystem::text",
                         github_annotations.error_command(
                             Item("missingIncludeSystem", "text", None, None, None)))


class PathTest(ToolTestCase):
    def test_absolute_path_under_workspace(self):
        with environment(GITHUB_WORKSPACE=self.workspace):
            self.assertEqual("src/relay.c", github_annotations.repo_relative(
                os.path.join(self.workspace, "src", "relay.c"), "/nonexistent"))

    def test_absolute_path_under_root(self):
        with environment(GITHUB_WORKSPACE="/nonexistent"):
            self.assertEqual("include/sigrelay/relay.h", github_annotations.repo_relative(
                os.path.join(self.workspace, "include", "sigrelay", "relay.h"), self.workspace))

    def test_path_from_another_checkout(self):
        with environment(GITHUB_WORKSPACE=None):
            self.assertEqual("tests/test_sip.c", github_annotations.repo_relative(
                OTHER_CHECKOUT + "/tests/test_sip.c", self.workspace))

    def test_path_outside_the_repository(self):
        with environment(GITHUB_WORKSPACE=None):
            self.assertIsNone(github_annotations.repo_relative(
                "/usr/include/x86_64-linux-gnu/bits/types.h", self.workspace))


class CppcheckTest(ToolTestCase):
    def test_annotations(self):
        xml = self.write("cppcheck.xml", CPPCHECK_XML)
        result = self.run_tool("cppcheck_xml_to_sarif.py", xml, "cppcheck.sarif")
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual([
            "::error file=src/relay.c,line=167,col=8,title=arrayIndexOutOfBounds::"
            "Array 'buf[10]' accessed at index 10, which is out of bounds.",
            "::error file=include/sigrelay/relay.h,line=42,col=9,title=knownConditionTrueFalse::"
            "Condition '(flags|1)!=0' is always true",
            "::error file=src/sigrelay.c,line=3,col=2,title=preprocessorErrorDirective::"
            "#error 100%25, unsupported: a%0D%0Ab",
            "::error title=missingIncludeSystem::"
            "Cppcheck cannot find all the include files (use --check-config for details)",
        ], self.annotations(result.stdout))
        self.assertTrue(result.stdout.splitlines()[-1].startswith(
            "cppcheck: 4 error annotation(s) in total. GitHub displays at most 10 per step and 50 "
            "per job; cppcheck.sarif and the step summary"))

    def test_step_summary(self):
        xml = self.write("cppcheck.xml", CPPCHECK_XML)
        self.run_tool("cppcheck_xml_to_sarif.py", xml, "cppcheck.sarif")
        lines = self.read("summary.md").splitlines()
        self.assertEqual("### cppcheck: 4 finding(s)", lines[0])
        self.assertEqual("| Rule | Location | Message |", lines[2])
        self.assertIn("| `knownConditionTrueFalse` | `include/sigrelay/relay.h:42:9` | "
                      "Condition '(flags\\|1)!=0' is always true |", lines)
        self.assertIn("| `preprocessorErrorDirective` | `src/sigrelay.c:3:2` | "
                      "#error 100%, unsupported: a b |", lines)
        self.assertIn("| `missingIncludeSystem` | none | Cppcheck cannot find all the include "
                      "files (use --check-config for details) |", lines)

    def test_no_findings(self):
        xml = self.write("cppcheck.xml", CPPCHECK_XML.split("<errors>")[0] + "<errors/></results>")
        result = self.run_tool("cppcheck_xml_to_sarif.py", xml, "cppcheck.sarif")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([], self.annotations(result.stdout))
        self.assertEqual("### cppcheck: no findings\n\n", self.read("summary.md"))

    def test_every_finding_is_printed_beyond_the_display_limit(self):
        errors = "".join(
            '<error id="unreadVariable" severity="style" msg="Variable is assigned a value '
            'that is never used." verbose="x"><location file="src/relay.c" line="%d" '
            'column="5"/></error>' % line for line in range(1, 13))
        xml = self.write("cppcheck.xml", CPPCHECK_XML.split("<errors>")[0]
                         + "<errors>" + errors + "</errors></results>")
        result = self.run_tool("cppcheck_xml_to_sarif.py", xml, "cppcheck.sarif")
        self.assertEqual(12, len(self.annotations(result.stdout)))
        self.assertIn("cppcheck: 12 error annotation(s) in total.", result.stdout)

    def test_sarif_is_unchanged_by_annotations(self):
        xml = self.write("cppcheck.xml", CPPCHECK_XML)
        self.run_tool("cppcheck_xml_to_sarif.py", xml, "annotated.sarif")
        plain = self.run_tool("cppcheck_xml_to_sarif.py", xml, "plain.sarif", github=False)
        self.assertEqual(self.read("plain.sarif"), self.read("annotated.sarif"))
        self.assertEqual([], self.annotations(plain.stdout))
        self.assertIn('"uri": "include/sigrelay/relay.h"', self.read("plain.sarif"))

    def test_flag_enables_annotations_outside_github_actions(self):
        xml = self.write("cppcheck.xml", CPPCHECK_XML)
        result = self.run_tool("cppcheck_xml_to_sarif.py", xml, "cppcheck.sarif",
                               "--github-annotations", github=False)
        self.assertEqual(4, len(self.annotations(result.stdout)))

    def test_summary_needs_github_actions_or_the_flag(self):
        xml = self.write("cppcheck.xml", CPPCHECK_XML)
        result = self.run_tool("cppcheck_xml_to_sarif.py", xml, "cppcheck.sarif", github=False,
                               env={"GITHUB_STEP_SUMMARY": self.summary})
        self.assertEqual([], self.annotations(result.stdout))
        self.assertFalse(os.path.exists(self.summary))


class ClangTidyTest(ToolTestCase):
    def test_annotations(self):
        log = self.write("clang-tidy.log", CLANG_TIDY_LOG)
        result = self.run_tool("clang_tidy_to_sarif.py", log, "clang-tidy.sarif",
                               "--tool-version", "18.1.3")
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual([
            "::error file=src/relay.c,line=168,col=12,title=cert-err34-c::'atoi' used to convert "
            "a string to an integer value, but function will not report conversion errors; "
            "consider using 'strtol' instead",
            "::error file=src/relay.c,line=168,col=23,"
            "title=clang-analyzer-core.UndefinedBinaryOperatorResult::"
            "The right operand of '+' is a garbage value",
            "::error file=include/sigrelay/relay.h,line=30,col=5,title=bugprone-sizeof-expression::"
            "suspicious usage of 'sizeof(K)'; did you mean 'K'?",
            "::error title=bugprone-reserved-identifier::/usr/include/x86_64-linux-gnu/bits/"
            "types.h:10:1: declaration uses identifier '__sig_t', which is reserved",
            "::error file=src/sip_parser.c,title=clang-tidy-processing-error::"
            "Error while processing %s/src/sip_parser.c." % self.workspace,
        ], self.annotations(result.stdout))
        self.assertIn("clang-tidy: 5 error annotation(s) in total.", result.stdout)

    def test_step_summary(self):
        log = self.write("clang-tidy.log", CLANG_TIDY_LOG)
        self.run_tool("clang_tidy_to_sarif.py", log, "clang-tidy.sarif")
        lines = self.read("summary.md").splitlines()
        self.assertEqual("### clang-tidy: 5 finding(s)", lines[0])
        self.assertEqual("| Rule | Location | Message |", lines[2])
        self.assertIn("| `cert-err34-c` | `src/relay.c:168:12` | 'atoi' used to convert a string "
                      "to an integer value, but function will not report conversion errors; "
                      "consider using 'strtol' instead |", lines)
        processing = [line for line in lines if line.startswith(
            "| `clang-tidy-processing-error` | `src/sip_parser.c` | Error while processing ")]
        self.assertEqual(1, len(processing), lines)
        self.assertTrue(processing[0].endswith("/src/sip\\_parser.c. |"), processing[0])

    def test_no_findings(self):
        log = self.write("clang-tidy.log", "[1/5] Processing file src/relay.c.\n")
        result = self.run_tool("clang_tidy_to_sarif.py", log, "clang-tidy.sarif")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([], self.annotations(result.stdout))
        self.assertEqual("### clang-tidy: no findings\n\n", self.read("summary.md"))


class JUnitTest(ToolTestCase):
    def test_annotations(self):
        xml = self.write("ctest-junit.xml", JUNIT_XML)
        result = self.run_tool("junit_to_annotations.py", xml)
        self.assertEqual(1, result.returncode, result.stderr)
        annotations = self.annotations(result.stdout)
        self.assertEqual(7, len(annotations), result.stdout)
        self.assertEqual(
            '::error file=tests/test_sip.c,line=94,title=sip_parses_invite::'
            'msg.method: expected "INVITE", got "100%25, x"', annotations[0])
        self.assertEqual(
            "::error file=tests/test_relay.c,line=28,title=relay_routes_exact_match::"
            "table.count: expected 3, got 2", annotations[1])
        self.assertEqual(
            "::error file=tests/hooks/test_policies.py,line=49,title=hook_policies::"
            "AssertionError: 'deny' != 'allow'", annotations[5])
        self.assertEqual(
            "::error file=tools/github_annotations.py,line=54,title=report_tools::"
            "TypeError: expected str, bytes or os.PathLike object, not NoneType", annotations[6])
        self.assertIn("ctest: 7 of 8 tests failed (2 skipped)", result.stdout)
        self.assertIn("ctest: 7 error annotation(s) in total.", result.stdout)

    def test_location_fallback(self):
        xml = self.write("ctest-junit.xml", JUNIT_XML)
        annotations = self.annotations(self.run_tool("junit_to_annotations.py", xml).stdout)
        prefix = "::error file=tests/CMakeLists.txt,line=1,title="
        note = ("the test output names no file:line location, so this points at "
                "tests/CMakeLists.txt, where the tests are registered")
        self.assertEqual(prefix + "relay_routes_parent_domain::Subprocess aborted: " + note,
                         annotations[2])
        self.assertEqual(prefix + "diameter_iterates_avps::Timeout: " + note
                         + "; last output line: walking AVPs", annotations[3])
        self.assertEqual(prefix + "diameter_parses_header::Unable to find executable: " + note
                         + "; last output line: Unable to find executable: "
                         "/srv/ci/build/tests/sigrelay_tests", annotations[4])

    def test_step_summary(self):
        xml = self.write("ctest-junit.xml", JUNIT_XML)
        self.run_tool("junit_to_annotations.py", xml)
        lines = self.read("summary.md").splitlines()
        self.assertEqual("### ctest: 7 of 8 tests failed (2 skipped)", lines[0])
        self.assertEqual("| Test | Location | Message |", lines[2])
        self.assertIn('| `sip_parses_invite` | `tests/test_sip.c:94` | '
                      'msg.method: expected "INVITE", got "100%, x" |', lines)

    def test_all_passed(self):
        xml = self.write("ctest-junit.xml", PASSING_JUNIT_XML)
        result = self.run_tool("junit_to_annotations.py", xml)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([], self.annotations(result.stdout))
        self.assertEqual("ctest: all 2 tests passed (1 skipped)", result.stdout.strip())
        self.assertEqual("### ctest: all 2 tests passed (1 skipped)\n\n", self.read("summary.md"))

    def test_missing_report(self):
        result = self.run_tool("junit_to_annotations.py", "ctest-junit.xml")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([], self.annotations(result.stdout))
        self.assertIn("ctest did not run", self.read("summary.md"))

    def test_unreadable_report(self):
        xml = self.write("ctest-junit.xml", "<testsuite")
        self.assertEqual(2, self.run_tool("junit_to_annotations.py", xml).returncode)


if __name__ == "__main__":
    unittest.main(verbosity=2)
