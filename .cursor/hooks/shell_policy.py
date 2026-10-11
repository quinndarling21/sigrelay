#!/usr/bin/env python3
"""beforeShellExecution policy for agent shells in this repository.

Reads the hook payload on stdin and prints {"permission": "allow"} or a deny
response. Commands are split into words with shlex, and a rule only applies to
the word in command position: after ;, &&, ||, |, &, a newline, a subshell or
a command substitution, after variable assignments and wrappers (sudo, env,
xargs, timeout, ...), and inside bash -c / sh -c / eval / find -exec. The
program is matched by basename, so /usr/bin/curl is curl, while arguments that
merely contain a blocked word (grep curl, rsync) are not matched.

Heredoc bodies are checked as commands as well, so a heredoc line that starts
with a blocked command is denied.
"""
import json
import os
import re
import shlex
import sys

PUNCTUATION = "();<>|&`\n"
OPERATOR = re.compile(r"(\|\||&&|;;|[;&|()`\n])")
REDIRECTION = re.compile(r"^&?(<<<|<<|<>|>>|<|>)[&|]?$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
PYTHON = re.compile(r"^python(\d+(\.\d+)*)?$")
PIP = re.compile(r"^pip(\d+(\.\d+)*)?$")
NETWORK_MODULES = re.compile(r"\b(urllib\w*|requests|socket\w*)\b")
SHORT_OPTIONS = re.compile(r"^-[A-Za-z]+$")
MAX_DEPTH = 8

NETWORK_TOOLS = {"curl", "wget", "nc", "ncat", "netcat", "nc.openbsd", "nc.traditional"}
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "ash"}
KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}"}

# Wrapper programs that run another command, mapped to their options that take
# a separate value. timeout also takes a positional duration before the command.
WRAPPERS = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T",
             "--user", "--group", "--host", "--prompt", "--chdir"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "--unset", "--chdir"},
    "command": set(),
    "builtin": set(),
    "exec": {"-a"},
    "nohup": set(),
    "time": {"-f", "-o", "--format", "--output"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "-p", "--class", "--classdata"},
    "stdbuf": {"-i", "-o", "-e"},
    "setsid": set(),
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "xargs": {"-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "--arg-file", "--delimiter",
              "--max-args", "--max-lines", "--max-procs", "--max-chars"},
}
GIT_OPTIONS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env",
                          "--super-prefix"}


class ParseError(Exception):
    pass


def deny(reason):
    user_message = "Blocked by repository policy: " + reason
    return {
        "permission": "deny",
        "user_message": user_message,
        "agent_message": user_message + " Do not work around this (no other tool, wrapper or "
                         "rewritten command); report it to the user.",
    }


def tokenize(text):
    lexer = shlex.shlex(text, posix=True, punctuation_chars=PUNCTUATION)
    lexer.whitespace_split = True
    lexer.whitespace = " \t\r"
    # '#' only starts a comment at the beginning of a word in sh; shlex would
    # also cut "a#b" short and hide what follows, so comments are not stripped.
    lexer.commenters = ""
    return list(lexer)


def naive_tokenize(text):
    """Fallback for unbalanced quotes: split on operators and blanks, drop quotes."""
    tokens = []
    for part in OPERATOR.split(text):
        if OPERATOR.fullmatch(part):
            tokens.append(part)
        else:
            tokens.extend(word.strip("'\"") for word in part.split())
    return [t for t in tokens if t]


def is_separator(token):
    return (bool(token) and all(c in PUNCTUATION for c in token)
            and not REDIRECTION.match(token))


def segments(tokens):
    current = []
    for token in tokens:
        if is_separator(token):
            if current:
                yield current
            current = []
        else:
            current.append(token)
    if current:
        yield current


def substitutions(word):
    """Command substitutions inside a word, e.g. the body of "$(curl x)" or `curl x`."""
    found = []
    start = word.find("$(")
    while start != -1:
        depth, end = 0, start + 1
        while end < len(word):
            if word[end] == "(":
                depth += 1
            elif word[end] == ")":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        found.append(word[start + 2:end])
        start = word.find("$(", start + 2)
    parts = word.split("`")
    found.extend(parts[1::2])
    return found


def skip_wrapper(name, words, i):
    takes_value = WRAPPERS[name]
    positional = 1 if name == "timeout" else 0
    while i < len(words):
        word = words[i]
        if word == "--":
            return i + 1
        if word.startswith("-") and len(word) > 1:
            i += 2 if word in takes_value else 1
        elif name == "env" and ASSIGNMENT.match(word):
            i += 1
        elif positional:
            positional -= 1
            i += 1
        else:
            break
    return i


def shell_command_string(args):
    """The script passed to sh -c / bash -c, if any."""
    seen_c = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-o", "+o", "-O", "+O"):
            i += 2
            continue
        if SHORT_OPTIONS.match(arg):
            seen_c = seen_c or "c" in arg[1:]
        elif arg.startswith("--") or arg.startswith("+"):
            pass
        elif seen_c:
            return arg
        else:
            return None
        i += 1
    return None


def rm_reason(args):
    recursive = force = False
    for arg in args:
        if arg == "--":
            break
        if arg.startswith("--"):
            name = arg[2:]
            recursive = recursive or (bool(name) and "recursive".startswith(name))
            force = force or (bool(name) and "force".startswith(name))
        elif arg.startswith("-") and len(arg) > 1:
            recursive = recursive or "r" in arg or "R" in arg
            force = force or "f" in arg
    if recursive and force:
        return ("`rm -rf` (recursive forced delete) is not allowed because it can irreversibly "
                "remove the workspace.")
    return None


def git_reason(args):
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in GIT_OPTIONS_WITH_VALUE else 1
    if i >= len(args):
        return None
    subcommand, rest = args[i], args[i + 1:]
    if subcommand == "push":
        for arg in rest:
            name = arg[2:].split("=", 1)[0] if arg.startswith("--") else None
            forced = (
                (name is not None and (name.startswith("force")
                                       or (len(name) >= 3 and "force".startswith(name))))
                or (SHORT_OPTIONS.match(arg) is not None and "f" in arg)
                or (arg.startswith("+") and len(arg) > 1)
            )
            if forced:
                return ("force pushes (`git push --force`, `-f`, `--force-with-lease` or a "
                        "`+refspec`) are not allowed because they rewrite shared history.")
    elif subcommand == "clean":
        return "`git clean` is not allowed because it permanently deletes untracked files."
    elif subcommand == "reset":
        for arg in rest:
            if arg.startswith("--") and len(arg) > 3 and "--hard".startswith(arg):
                return "`git reset --hard` is not allowed because it discards uncommitted work."
    return None


def pip_reason(args):
    if "install" in [a for a in args if not a.startswith("-")]:
        return "`pip install` is not allowed because new dependencies need review."
    return None


def python_reason(args):
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-" or not arg.startswith("-"):
            return None  # a script or stdin; only -c and -m are inspected
        if arg.startswith("--"):
            i += 2 if arg == "--check-hash-based-pycs" else 1
            continue
        flags = arg[1:]
        for j, flag in enumerate(flags):
            if flag not in "cmWX":
                continue
            value, rest = flags[j + 1:], args[i + 1:]
            if not value:
                value = args[i + 1] if i + 1 < len(args) else ""
                rest = args[i + 2:]
                i += 1
            if flag == "c":
                if NETWORK_MODULES.search(value):
                    return ("`python -c` code that uses urllib, requests or socket is not "
                            "allowed because new network calls need review.")
                return None
            if flag == "m":
                return pip_reason(rest) if value == "pip" else None
            break
        i += 1
    return None


def program_reason(name, args):
    if name in NETWORK_TOOLS:
        return "`%s` is not allowed in agent shells because new network calls need review." % name
    if name == "rm":
        return rm_reason(args)
    if name == "git":
        return git_reason(args)
    if PIP.match(name):
        return pip_reason(args)
    if PYTHON.match(name):
        return python_reason(args)
    return None


def segment_reason(words, depth):
    for word in words:
        for inner in substitutions(word):
            reason = command_reason(inner, depth + 1)
            if reason:
                return reason

    i = 0
    while i < len(words):
        word = words[i]
        name = os.path.basename(word)
        if ASSIGNMENT.match(word) or word in KEYWORDS:
            i += 1
        elif name == "command" and i + 1 < len(words) and words[i + 1] in ("-v", "-V"):
            return None  # looks a command up without running it
        elif name in WRAPPERS:
            i = skip_wrapper(name, words, i + 1)
        else:
            break
    if i >= len(words):
        return None

    name = os.path.basename(words[i])
    args = words[i + 1:]
    if name in SHELLS:
        script = shell_command_string(args)
        return command_reason(script, depth + 1) if script else None
    if name == "eval":
        return command_reason(" ".join(args), depth + 1)
    if name == "find":
        for j, arg in enumerate(args):
            if arg in ("-exec", "-execdir", "-ok", "-okdir"):
                reason = segment_reason(args[j + 1:], depth + 1)
                if reason:
                    return reason
        return None
    return program_reason(name, args)


def command_reason(command, depth=0):
    if depth > MAX_DEPTH:
        raise ParseError("command nesting is too deep to check")
    try:
        tokens = tokenize(command)
    except ValueError:
        # Typically a heredoc whose text has an apostrophe; check line by line.
        for line in command.split("\n"):
            try:
                line_tokens = tokenize(line)
            except ValueError:
                line_tokens = naive_tokenize(line)
            for words in segments(line_tokens):
                reason = segment_reason(words, depth)
                if reason:
                    return reason
        return None
    for words in segments(tokens):
        reason = segment_reason(words, depth)
        if reason:
            return reason
    return None


def evaluate(payload):
    command = payload.get("command") if isinstance(payload, dict) else None
    if not isinstance(command, str):
        return deny("the hook payload has no command to check, so it cannot be verified.")
    try:
        reason = command_reason(command)
    except ParseError as exc:
        return deny("%s." % exc)
    return deny(reason) if reason else {"permission": "allow"}


def main():
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        payload = None
    print(json.dumps(evaluate(payload)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
