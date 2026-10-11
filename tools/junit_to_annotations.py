#!/usr/bin/env python3
"""Report failing tests from a ctest JUnit file as GitHub error annotations.

Usage: junit_to_annotations.py CTEST_JUNIT_XML [--root DIR] [--github-annotations]

Each failing test case is located from its output: the C test harness prints
"<path>/tests/test_x.c:<line>: <message>", and for Python unittest the last
traceback frame inside the repository is used. A test whose output names no
such location (a crash, timeout or missing executable) is reported at
tests/CMakeLists.txt line 1, where the tests are registered, and the message
says so.

Prints every failing test and exits 1 if there is at least one, 0 if all
passed or there is no report (ctest did not run), and 2 if the XML cannot be
read. In GitHub Actions (or with --github-annotations) each failing test is
also printed as an error annotation and listed in the step summary; see
github_annotations.py.
"""
import argparse
import os
import re
import sys
import xml.etree.ElementTree as ET

import github_annotations
from github_annotations import Item

FALLBACK_PATH = "tests/CMakeLists.txt"
HARNESS = re.compile(r"^(?P<file>[^\s:][^:]*):(?P<line>\d+): (?P<message>.*\S)")
FRAME = re.compile(r'^\s+File "(?P<file>[^"<][^"]*)", line (?P<line>\d+)')


def outcome(case):
    """("failed" | "skipped" | "passed", ctest's status message)."""
    for tag in ("failure", "error"):
        node = case.find(tag)
        if node is not None:
            return "failed", node.get("message") or tag
    status = case.get("status", "")
    if status == "fail":
        return "failed", "Failed"
    if status == "disabled":
        return "skipped", "Disabled"
    skipped = case.find("skipped")
    if skipped is not None:
        message = skipped.get("message", "")
        # ctest also marks tests it could not start (missing executable,
        # failed setup test) as notrun/skipped, but counts them as failures.
        if status == "notrun" and not message.startswith("SKIP_"):
            return "failed", message or "Not Run"
        return "skipped", message
    return "passed", ""


def locate(output, root):
    """(path, line, message) for the first location in the test output, or None."""
    lines = output.splitlines()
    for text in lines:
        match = HARNESS.match(text)
        if match:
            path = github_annotations.repo_relative(match["file"], root)
            if path:
                return path, int(match["line"]), match["message"]
    frame = None
    for text in lines:
        match = FRAME.match(text)
        if match:
            path = github_annotations.repo_relative(match["file"], root)
            if path:
                frame = (path, int(match["line"]))
        elif frame and text.strip() and not text[0].isspace():
            return frame + (text.strip(),)
    return None


def failure_item(case, status, root):
    parts = [case.findtext(tag) or "" for tag in ("failure", "error", "system-out", "system-err")]
    output = "\n".join(p for p in parts if p.strip())
    name = case.get("name", "unknown")
    found = locate(output, root)
    if found:
        path, line, message = found
        return Item(name, message, path, line, None)
    message = ("%s: the test output names no file:line location, so this points at %s, "
               "where the tests are registered" % (status, FALLBACK_PATH))
    last = [text.strip() for text in output.splitlines() if text.strip()]
    if last:
        message += "; last output line: %s" % last[-1]
    return Item(name, message, FALLBACK_PATH, 1, None)


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("xml")
    parser.add_argument("--root", default=os.getcwd())
    parser.add_argument("--github-annotations", action="store_true",
                        help="print GitHub error annotations (default when GITHUB_ACTIONS=true)")
    args = parser.parse_args(argv)
    annotate = github_annotations.enabled(args.github_annotations)

    root = os.path.abspath(args.root)
    if not os.path.exists(args.xml):
        print("no JUnit report at %s: ctest did not run" % args.xml)
        if annotate:
            github_annotations.append_summary(
                "ctest: no JUnit report (ctest did not run; see the build steps)", "Test", [])
        return 0
    try:
        tree = ET.parse(args.xml).getroot()
    except (OSError, ET.ParseError) as exc:
        print("cannot read JUnit report %s: %s" % (args.xml, exc), file=sys.stderr)
        return 2

    items = []
    passed = skipped = 0
    for case in tree.iter("testcase"):
        result, status = outcome(case)
        if result == "failed":
            items.append(failure_item(case, status, root))
        elif result == "skipped":
            skipped += 1
        else:
            passed += 1

    for item in items:
        print("%s: %s: %s" % (github_annotations.location(item.path, item.line), item.title,
                              item.message))
    total = passed + len(items)
    if items:
        headline = "ctest: %d of %d tests failed" % (len(items), total)
    else:
        headline = "ctest: all %d tests passed" % passed
    if skipped:
        headline += " (%d skipped)" % skipped
    print(headline)
    if annotate:
        github_annotations.print_annotations("ctest", items, args.xml)
        github_annotations.append_summary(headline, "Test", items)
    return 1 if items else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
