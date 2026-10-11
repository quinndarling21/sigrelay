"""GitHub Actions error annotations and step summaries for the CI report tools.

cppcheck_xml_to_sarif.py, clang_tidy_to_sarif.py and junit_to_annotations.py
use this module when they run in GitHub Actions (GITHUB_ACTIONS=true) or get
--github-annotations: they print one ::error workflow command per item and
append a markdown table of every item to $GITHUB_STEP_SUMMARY.

GitHub displays at most 10 error annotations per step and 50 per job, so the
tools end with a line giving the total count; the SARIF and JUnit reports
(uploaded as CI artifacts) and the step summary hold the complete list.
"""
import collections
import os
import re

Item = collections.namedtuple("Item", "title message path line col")

MARKDOWN_SPECIAL = re.compile(r"([\\`*_\[\]<>|~])")


def enabled(flag):
    return flag or os.environ.get("GITHUB_ACTIONS") == "true"


def escape_data(text):
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text):
    return escape_data(text).replace(":", "%3A").replace(",", "%2C")


def error_command(item):
    properties = [(name, value) for name, value in (
        ("file", item.path), ("line", item.line), ("col", item.col), ("title", item.title))
        if value not in (None, "")]
    command = "::error"
    if properties:
        command += " " + ",".join(
            "%s=%s" % (name, escape_property(str(value))) for name, value in properties)
    return command + "::" + escape_data(item.message)


def repo_relative(path, root):
    """path relative to the repository root, or None if it lies outside the repository.

    Relative paths are taken from the current directory. Absolute paths are
    tried against $GITHUB_WORKSPACE and root; a path from another checkout
    (for example a report downloaded from CI) keeps its longest suffix that
    exists in the repository.
    """
    roots = [os.path.abspath(r) for r in (os.environ.get("GITHUB_WORKSPACE"), root) if r]
    absolute = os.path.abspath(path)
    for base in roots:
        rel = os.path.relpath(absolute, base)
        if rel != os.curdir and rel != os.pardir and not rel.startswith(os.pardir + os.sep):
            return rel.replace(os.sep, "/")
    parts = absolute.strip(os.sep).split(os.sep)
    for start in range(1, len(parts)):
        candidate = os.path.join(*parts[start:])
        if any(os.path.isfile(os.path.join(base, candidate)) for base in roots):
            return candidate.replace(os.sep, "/")
    return None


def location(path, line=None, col=None):
    text = path
    if line:
        text += ":%d" % line
        if col:
            text += ":%d" % col
    return text


def sarif_items(results, root):
    """One Item per SARIF result written by the converters in this directory."""
    items = []
    for result in results:
        message = result["message"]["text"]
        path = line = col = None
        if result.get("locations"):
            physical = result["locations"][0]["physicalLocation"]
            uri = physical["artifactLocation"]["uri"]
            region = physical.get("region", {})
            line, col = region.get("startLine"), region.get("startColumn")
            path = repo_relative(os.path.join(root, uri), root)
            if path is None:
                message = "%s: %s" % (location(uri, line, col), message)
                line = col = None
        items.append(Item(result["ruleId"], message, path, line, col))
    return items


def print_annotations(label, items, report):
    if not items:
        return
    for item in items:
        print(error_command(item))
    print("%s: %d error annotation(s) in total. GitHub displays at most 10 per step and 50 per "
          "job; %s and the step summary list all of them." % (label, len(items), report))


def markdown_text(text):
    return MARKDOWN_SPECIAL.sub(r"\\\1", " ".join(str(text).split()).replace("&", "&amp;"))


def markdown_code(text):
    return "`%s`" % text if "`" not in text and "|" not in text else markdown_text(text)


def append_summary(heading, first_column, items):
    """Appends a table of items, or just the heading when there are none."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    lines = ["### " + heading]
    if items:
        lines += ["", "| %s | Location | Message |" % first_column, "| --- | --- | --- |"]
        for item in items:
            where = markdown_code(location(item.path, item.line, item.col)) if item.path else "none"
            lines.append("| %s | %s | %s |" % (
                markdown_code(item.title), where, markdown_text(item.message)))
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n\n")
