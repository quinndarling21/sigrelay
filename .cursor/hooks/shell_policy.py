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

Variable assignments in front of a command (VAR=x cmd, env VAR=x cmd) are passed
into bash -c / eval / find -exec, so they are checked where they reach git.
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
NETWORK_TOOL_WORDS = re.compile(r"\b(curl|wget|nc|ncat|netcat)\b")
JS_NETWORK = re.compile(r"\b(fetch|https?|http2|net|tls|dgram|dns|undici|WebSocket)\b")
PERL_NETWORK = re.compile(r"\b(LWP|HTTP::Tiny|IO::Socket|Net::HTTPS?|Net::FTP|Socket|URI)\b")
RUBY_NETWORK = re.compile(
    r"open-uri|\b(OpenURI|Net::HTTPS?|Net::FTP|net/https?|net/ftp|\w*Socket|socket|URI)\b")
INTERPRETER = re.compile(r"^(node|nodejs|bun|perl|ruby)(\d+(\.\d+)*)?$")
# Options that run inline code, and the network APIs that code may not use.
INLINE_CODE = {
    "node": ("ep", ("--eval", "--print"), JS_NETWORK,
             "fetch, http, https, net, tls, dgram, undici"),
    "bun": ("ep", ("--eval", "--print"), JS_NETWORK,
            "fetch, http, https, net, tls, dgram, undici"),
    "perl": ("eE", (), PERL_NETWORK,
             "LWP, HTTP::Tiny, IO::Socket, Net::HTTP, Net::FTP, Socket, URI"),
    "ruby": ("e", (), RUBY_NETWORK, "open-uri, Net::HTTP, Net::FTP, Socket, URI"),
}
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

# git fetch / git pull options that may take their value as the next word
# ("--depth 1", "-j 4"), as long options and short option letters. Options
# with an optional value (pull's -j, -r, -S, --log) only take it attached.
FETCH_OPTIONS_WITH_VALUE = {
    "fetch": ({"--upload-pack", "--jobs", "--depth", "--shallow-since", "--shallow-exclude",
               "--deepen", "--refmap", "--server-option", "--negotiation-tip", "--filter",
               "--submodule-prefix", "--recurse-submodules-default"}, "jo"),
    "pull": ({"--cleanup", "--strategy", "--strategy-option", "--upload-pack", "--depth",
              "--shallow-since", "--shallow-exclude", "--deepen", "--refmap", "--server-option",
              "--negotiation-tip"}, "sXo"),
}
LS_REMOTE_OPTIONS_WITH_VALUE = {"--upload-pack", "--sort", "--server-option"}
CONFIG_OPTIONS_WITH_VALUE = {"--file", "--blob", "--type", "--default", "--comment", "--value"}
CONFIG_SUBCOMMANDS = {"get", "list", "set", "unset", "rename-section", "remove-section", "edit"}
CONFIG_READS = ("get", "list", "unset", "remove-section")
CARGO_OPTIONS_WITH_VALUE = {"--color", "--config", "--explain"}
NPM_INSTALL = {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal",
               "isntall", "add", "install-test", "it"}
# npm, yarn and pnpm accept options with values and nested commands anywhere
# (npm --prefix web install, yarn global add, pnpm --filter web add), so every
# word that is not an option is checked.
NODE_PACKAGE_ADD = {"npm": NPM_INSTALL, "yarn": {"add"}, "pnpm": {"add"}}
# pnpm install / pnpm i add the packages they are given; yarn rejects them today.
# These are the install options whose value may be the next word.
NODE_INSTALL_OPTIONS_WITH_VALUE = {
    "pnpm": ({"--filter", "--filter-prod", "--test-pattern", "--changed-files-ignore-pattern",
              "--workspace-concurrency", "--child-concurrency", "--network-concurrency", "--dir",
              "--global-dir", "--hoist-pattern", "--public-hoist-pattern", "--lockfile-dir",
              "--loglevel", "--modules-dir", "--store-dir", "--virtual-store-dir", "--reporter",
              "--package-import-method", "--trust-policy", "--trust-policy-exclude",
              "--trust-policy-ignore-after"}, "FC"),
    "yarn": ({"--use-yarnrc", "--prod", "--production", "--link-folder", "--global-folder",
              "--modules-folder", "--preferred-cache-folder", "--cache-folder", "--mutex",
              "--emoji", "--cwd", "--proxy", "--https-proxy", "--registry",
              "--network-concurrency", "--network-timeout", "--scripts-prepend-node-path",
              "--otp"}, ""),
}

# Config that decides where git fetches from: -c, --config-env and GIT_CONFIG_*
# overrides of any key in these sections are denied.
REDIRECTING_CONFIG = re.compile(r"^(remote|url|include|includeif)\.", re.IGNORECASE)
REDIRECTING_SECTION = re.compile(r"^(remote|url|include|includeif)(\.|$)", re.IGNORECASE)
# Keys that git config may not write.
RETARGETING_CONFIG = re.compile(
    r"^(remote\..+\.(url|pushurl)|url\..+\.(insteadof|pushinsteadof)|include\.path|includeif\..+)$",
    re.IGNORECASE)
GIT_CONFIG_FILE_ENV = {"GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"}
GIT_CONFIG_KEY_ENV = re.compile(r"^GIT_CONFIG_KEY_\d+$")
# These decide where git finds ~/.gitconfig and $XDG_CONFIG_HOME/git/config.
CONFIG_HOME_ENV = {"HOME", "XDG_CONFIG_HOME"}
EXPORTS = {"export", "declare", "typeset", "readonly", "local"}

OUR_REPO = "quinndarling21/sigrelay"
OUR_OWNER, OUR_NAME = OUR_REPO.split("/")
# OWNER/REPO, HOST/OWNER/REPO or a URL, as gh -R and GH_REPO accept them.
GITHUB_REPO = re.compile(
    r"^(?:(?:(?:https?|ssh|git)://(?:[^@/]+@)?|[^@/:]+@)?(?:www\.)?github\.com[/:])?"
    r"([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", re.IGNORECASE)
GITHUB_URL = re.compile(r"(?:^|[^\w.-])(?:www\.)?github\.com[/:]([\w.-]+)/([\w.-]+)",
                        re.IGNORECASE)
GH_API_HOST = re.compile(r"^https?://api\.github\.com(?=/|$)", re.IGNORECASE)
GH_API_OPTIONS_WITH_VALUE = {"--cache", "--field", "--header", "--hostname", "--input", "--jq",
                             "--method", "--preview", "--raw-field", "--template"}
# GraphQL lookups whose target repository cannot be read from the query.
GRAPHQL_LOOKUP = re.compile(r"\b(node|nodes|search)\s*\(")
GRAPHQL_REPOSITORY = re.compile(r"\brepository\s*\(([^)]*)\)")
GRAPHQL_LOGIN = re.compile(r'\blogin\s*:\s*(?:"([^"]*)"|\$(\w+))')

OUTSIDE_CODE = ("new outside code (dependencies, repositories, remotes) needs human review "
                "before it enters this repository.")
CONFIG_OVERRIDE = ("A git config override of `remote.*`, `url.*`, `include.*`, `includeIf.*` or "
                   "the config file location")
CONFIG_WRITE = ("A `git config` write to `remote.*.url`, `remote.*.pushurl`, `url.*.insteadOf`, "
                "`url.*.pushInsteadOf`, `include.path` or `includeIf.*`")
GH_OTHER_REPO = "`gh` aimed at a repository other than `%s`" % OUR_REPO
GH_OTHER_HOST = "`gh` aimed at a host other than `github.com`"


class ParseError(Exception):
    pass


def deny(reason):
    user_message = "Blocked by repository policy: " + reason
    report = "report it to the user"
    if reason.endswith(OUTSIDE_CODE):
        report += " with what you wanted to add and why"
    return {
        "permission": "deny",
        "user_message": user_message,
        "agent_message": user_message + " Do not work around this (no other tool, wrapper or "
                         "rewritten command); " + report + ".",
    }


def outside_code(command):
    return "%s is not allowed in agent shells because %s" % (command, OUTSIDE_CODE)


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


def positional_words(args, long_with_value, short_with_value):
    """Words that are neither options nor option values; everything after -- counts."""
    words = []
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            words.extend(args[i:])
            break
        if arg.startswith("--"):
            if arg in long_with_value:
                i += 1
        elif arg.startswith("-") and len(arg) > 1:
            # A short option with a value ends its cluster: -j4, or -qj 4.
            for j, flag in enumerate(arg[1:], 1):
                if flag in short_with_value:
                    if j == len(arg) - 1:
                        i += 1
                    break
        else:
            words.append(arg)
    return words


def fetch_reason(subcommand, args):
    """git fetch / git pull may only name origin as the remote, or no remote at all."""
    long_with_value, short_with_value = FETCH_OPTIONS_WITH_VALUE[subcommand]
    multiple = False
    for arg in args:
        if arg == "--":
            break
        name = arg[2:].split("=", 1)[0] if arg.startswith("--") else None
        # git accepts unambiguous prefixes of long options (--al is --all).
        if name is not None and len(name) >= 2 and "all".startswith(name):
            return outside_code("`git %s --all` (every configured remote, not only `origin`)"
                                % subcommand)
        if subcommand == "fetch":
            multiple = multiple or (bool(name) and "multiple".startswith(name)) or (
                SHORT_OPTIONS.match(arg) is not None and "m" in arg)
    words = positional_words(args, long_with_value, short_with_value)
    remotes = words if multiple else words[:1]
    if any(remote != "origin" for remote in remotes):
        return outside_code("`git %s` from a remote other than `origin`" % subcommand)
    return None


def redirecting_key(key):
    """Whether a config key can point git elsewhere; a key that is unknown here can."""
    return not key or "$" in key or "`" in key or REDIRECTING_CONFIG.match(key) is not None


def env_override(assignment, git):
    """Whether VAR=value, or a bare VAR being exported, changes the config git reads.

    HOME and XDG_CONFIG_HOME only count when git is the program (git is True).
    """
    name, _, value = assignment.partition("=")
    if name in GIT_CONFIG_FILE_ENV:
        return True
    if name in CONFIG_HOME_ENV:
        return git
    if GIT_CONFIG_KEY_ENV.match(name):
        return redirecting_key(value)
    if name == "GIT_CONFIG_PARAMETERS":
        try:
            entries = shlex.split(value)
        except ValueError:
            return True
        return not entries or any(redirecting_key(e.split("=", 1)[0]) for e in entries)
    return False


def env_reason(assignments, git):
    """Why VAR=value assignments (or bare exported names) are not allowed, if they are not."""
    for assignment in assignments:
        name, _, value = assignment.partition("=")
        if name == "GH_REPO" and not is_our_repo(value):
            return outside_code(GH_OTHER_REPO)
        if name == "GH_HOST" and value.lower() != "github.com":
            return outside_code(GH_OTHER_HOST)
        if env_override(assignment, git):
            return outside_code(CONFIG_OVERRIDE)
    return None


def short_flags(args, short_with_value):
    """Letters of short option clusters, up to the first letter that takes a value."""
    flags = ""
    for arg in args:
        if arg == "--":
            break
        if arg.startswith("-") and not arg.startswith("--"):
            for flag in arg[1:]:
                flags += flag
                if flag in short_with_value:
                    break
    return flags


def config_reason(args):
    """git config may read anything, but may not write where remotes and includes point."""
    end = args.index("--") if "--" in args else len(args)
    names = [a[2:].split("=", 1)[0] for a in args[:end] if a.startswith("--")]
    flags = short_flags(args, "ft")
    words = positional_words(args, CONFIG_OPTIONS_WITH_VALUE, "ft")
    action = None
    if words and words[0] in CONFIG_SUBCOMMANDS:
        action, words = words[0], words[1:]
    # git accepts unambiguous prefixes of long options (--ed is --edit).
    if action == "edit" or "e" in flags or any(len(n) >= 2 and "edit".startswith(n)
                                                for n in names):
        return outside_code("`git config --edit` (it can rewrite where remotes point)")
    if action == "rename-section" or any(len(n) >= 3 and "rename-section".startswith(n)
                                         for n in names):
        if any(REDIRECTING_SECTION.match(w) for w in words):
            return outside_code(CONFIG_WRITE)
        return None
    if action in CONFIG_READS or "l" in flags or any(n.startswith(CONFIG_READS) for n in names):
        return None
    # A single name is a read; a name and a value (set, --add, --replace-all) is a write.
    if len(words) >= 2 and any(RETARGETING_CONFIG.match(w) for w in words):
        return outside_code(CONFIG_WRITE)
    return None


def git_reason(args, env=()):
    if any(env_override(assignment, True) for assignment in env):
        return outside_code(CONFIG_OVERRIDE)
    i = 0
    while i < len(args) and args[i].startswith("-"):
        option, value = args[i], None
        if option.startswith("--config-env="):
            option, value = "--config-env", option.split("=", 1)[1]
            i += 1
        elif option in GIT_OPTIONS_WITH_VALUE:
            value = args[i + 1] if i + 1 < len(args) else ""
            i += 2
        else:
            i += 1
        # Checked for every subcommand, since an alias can hide which one runs.
        if option in ("-c", "--config-env") and redirecting_key(value.split("=", 1)[0]):
            return outside_code(CONFIG_OVERRIDE)
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
    elif subcommand == "clone":
        return outside_code("`git clone`")
    elif subcommand in ("fetch", "pull"):
        return fetch_reason(subcommand, rest)
    elif subcommand in ("remote", "submodule"):
        words = [a for a in rest if not a.startswith("-")]
        if words[:1] == ["add"]:
            return outside_code("`git %s add`" % subcommand)
        # git remote update fetches every remote unless it is given names.
        if subcommand == "remote" and words[:1] == ["update"]:
            if not words[1:] or any(remote != "origin" for remote in words[1:]):
                return outside_code("`git remote update` from a remote other than `origin`")
        if subcommand == "remote" and words[:1] == ["set-url"]:
            return outside_code("`git remote set-url`")
        if subcommand == "remote" and words[:1] == ["rename"] and "origin" in words[2:]:
            return outside_code("`git remote rename` onto `origin`")
    elif subcommand == "config":
        return config_reason(rest)
    elif subcommand == "archive":
        for arg in rest:
            if arg == "--":
                break
            name = arg[2:].split("=", 1)[0] if arg.startswith("--") else ""
            if name and "remote".startswith(name):
                return outside_code("`git archive --remote`")
    elif subcommand == "ls-remote":
        words = positional_words(rest, LS_REMOTE_OPTIONS_WITH_VALUE, "o")
        if words[:1] not in ([], ["origin"]):
            return outside_code("`git ls-remote` against a remote other than `origin`")
    return None


def pip_reason(args):
    if "install" in [a for a in args if not a.startswith("-")]:
        return outside_code("`pip install`")
    return None


def package_reason(name, args):
    if name == "yarnpkg":
        name = "yarn"
    if name in NODE_PACKAGE_ADD:
        for word in args:
            if not word.startswith("-") and word in NODE_PACKAGE_ADD[name]:
                return outside_code("`%s %s`" % (name, word))
        if name in NODE_INSTALL_OPTIONS_WITH_VALUE:
            words = positional_words(args, *NODE_INSTALL_OPTIONS_WITH_VALUE[name])
            for j, word in enumerate(words):
                if word in ("install", "i") and words[j + 1:]:
                    return outside_code("`%s %s` with a package name" % (name, word))
    elif name == "go":
        if positional_words(args, {"--C"}, "C")[:1] == ["get"]:
            return outside_code("`go get`")
    elif name == "cargo":
        if args and args[0].startswith("+"):
            args = args[1:]
        if positional_words(args, CARGO_OPTIONS_WITH_VALUE, "CZ")[:1] == ["add"]:
            return outside_code("`cargo add`")
    return None


def same_repo(owner, name):
    if name.lower().endswith(".git"):
        name = name[:-4]
    return "%s/%s" % (owner.lower(), name.lower()) == OUR_REPO


def is_our_repo(spec):
    match = GITHUB_REPO.match(spec.strip())
    return match is not None and same_repo(match.group(1), match.group(2))


def option_values(args, long_name, short_name=""):
    """Values of one option: --name v, --name=v, -X v, -Xv, -X=v, or -wX v in a cluster."""
    values = []
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            break
        if arg == long_name:
            values.append(args[i] if i < len(args) else "")
            i += 1
        elif arg.startswith(long_name + "="):
            values.append(arg[len(long_name) + 1:])
        elif short_name and arg.startswith("-") and not arg.startswith("--") and short_name in arg:
            value = arg[arg.index(short_name) + 1:]
            if value.startswith("="):
                value = value[1:]
            if not value:
                value = args[i] if i < len(args) else ""
                i += 1
            values.append(value)
    return values


def gh_command(args):
    """(index, word) of each gh command word, found as cobra finds subcommands: a flag
    without = is taken to have a value."""
    words = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            break
        if not arg.startswith("-"):
            words.append((i, arg))
            i += 1
        elif "=" in arg or arg in ("-h", "--help", "--version") or (
                not arg.startswith("--") and len(arg) != 2):
            i += 1
        else:
            i += 2
    return words


def graphql_value(arguments, key, fields):
    match = re.search(r'\b%s\s*:\s*(?:"([^"]*)"|\$(\w+))' % key, arguments)
    if match is None:
        return None
    value = match.group(1) if match.group(1) is not None else fields.get(match.group(2))
    return value.lower() if value is not None else None


def gh_graphql_reason(args):
    """gh api graphql may only name this repository, in a query given on the command line."""
    fields = {}
    for value in option_values(args, "--field", "F") + option_values(args, "--raw-field", "f"):
        key, _, field = value.partition("=")
        fields[key] = field
    query = fields.get("query", "")
    if (option_values(args, "--input") or not query or query.startswith("@")
            or GRAPHQL_LOOKUP.search(query)):
        return outside_code(GH_OTHER_REPO)
    for arguments in GRAPHQL_REPOSITORY.findall(query):
        if (graphql_value(arguments, "owner", fields) not in (OUR_OWNER, "{owner}")
                or graphql_value(arguments, "name", fields) not in (OUR_NAME, "{repo}")):
            return outside_code(GH_OTHER_REPO)
    for literal, variable in GRAPHQL_LOGIN.findall(query):
        login = literal if not variable else fields.get(variable, "")
        if login.lower() not in (OUR_OWNER, "{owner}"):
            return outside_code(GH_OTHER_REPO)
    if any(not same_repo(owner, name) for owner, name in GITHUB_URL.findall(query)):
        return outside_code(GH_OTHER_REPO)
    return None


def gh_api_reason(args):
    if any(host.lower() != "github.com" for host in option_values(args, "--hostname")):
        return outside_code(GH_OTHER_HOST)
    words = positional_words(args, GH_API_OPTIONS_WITH_VALUE, "FHXfpqt")
    if not words:
        return None
    endpoint = GH_API_HOST.sub("", words[0], count=1)
    if "://" in endpoint:
        return outside_code(GH_OTHER_HOST)
    path = endpoint.split("?", 1)[0].split("#", 1)[0].strip("/")
    parts = path.split("/")
    # {owner} and {repo} are filled in from this checkout.
    ours = (len(parts) >= 3 and parts[1].lower() in (OUR_OWNER, "{owner}")
            and parts[2].lower() in (OUR_NAME, "{repo}"))
    if "%" in path or "." in parts or ".." in parts:
        return outside_code(GH_OTHER_REPO)
    if parts[0].lower() == "graphql":
        return gh_graphql_reason(args)
    if parts[0].lower() == "repositories" or (parts[0].lower() == "repos" and not ours):
        return outside_code(GH_OTHER_REPO)
    return None


def gh_reason(args):
    end = args.index("--") if "--" in args else len(args)
    if any(not is_our_repo(repo) for repo in option_values(args[:end], "--repo", "R")):
        return outside_code(GH_OTHER_REPO)
    command = gh_command(args)
    path = [word for _, word in command[:2]]
    if path in (["repo", "clone"], ["gist", "clone"]):
        return outside_code("`gh %s clone`" % path[0])
    if path == ["release", "download"]:
        return outside_code("`gh release download`")
    if path[:1] in (["extension"], ["extensions"], ["ext"]) and path[1:] == ["install"]:
        return outside_code("`gh extension install`")
    if path == ["repo", "fork"] and any(arg.split("=", 1)[0] in ("--clone", "--remote")
                                        and not arg.endswith("=false") for arg in args[:end]):
        return outside_code("`gh repo fork --clone` or `--remote`")
    if path in (["pr", "checkout"], ["pr", "diff"]):
        for arg in args:
            if any(not same_repo(owner, name) for owner, name in GITHUB_URL.findall(arg)):
                return outside_code(GH_OTHER_REPO)
    if path[:1] == ["api"]:
        return gh_api_reason(args[command[0][0] + 1:])
    return None


def inline_code_reason(interpreter, args):
    """node/bun -e, perl -e and ruby -e code may not use network APIs or run network tools."""
    short, long_names, network, apis = INLINE_CODE[interpreter]
    runs_code = any(
        arg.split("=", 1)[0] in long_names
        or (len(arg) > 1 and arg[0] == "-" and arg[1] != "-"
            and (arg[1] in short or (SHORT_OPTIONS.match(arg) is not None
                                     and any(flag in short for flag in arg[1:]))))
        for arg in args)
    # Also read module names attached to their option: perl -MLWP::Simple, ruby -ropen-uri.
    text = " ".join(args + [arg[2:] for arg in args if arg[:1] == "-" and arg[1:2] != "-"])
    if runs_code and (network.search(text) or NETWORK_TOOL_WORDS.search(text)):
        return ("`%s -%s` code that uses %s or a network tool is not allowed because new "
                "network calls need review." % (interpreter, short[0], apis))
    return None


def deno_reason(args):
    words = [arg for arg in args if not arg.startswith("-")]
    if "eval" in words:
        code = " ".join(args[args.index("eval") + 1:])
        if JS_NETWORK.search(code) or NETWORK_TOOL_WORDS.search(code):
            return ("`deno eval` code that uses fetch, http, https, net, tls, dgram, undici or a "
                    "network tool is not allowed because new network calls need review.")
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
                if NETWORK_MODULES.search(value) or NETWORK_TOOL_WORDS.search(value):
                    return ("`python -c` code that uses urllib, requests, socket or a network "
                            "tool is not allowed because new network calls need review.")
                return None
            if flag == "m":
                return pip_reason(rest) if value == "pip" else None
            break
        i += 1
    return None


def program_reason(name, args, env):
    if name in NETWORK_TOOLS:
        return "`%s` is not allowed in agent shells because new network calls need review." % name
    if name == "rm":
        return rm_reason(args)
    if name == "git":
        return git_reason(args, env)
    if name == "gh":
        return gh_reason(args)
    if name == "deno":
        return deno_reason(args)
    interpreter = INTERPRETER.match(name)
    if interpreter:
        return inline_code_reason(interpreter.group(1).replace("nodejs", "node"), args)
    if name in EXPORTS:
        # Exported variables reach every later command in this shell.
        return env_reason([arg for arg in args if not arg.startswith("-")], True)
    if PIP.match(name):
        return pip_reason(args)
    if PYTHON.match(name):
        return python_reason(args)
    return package_reason(name, args)


def segment_reason(words, depth, env=()):
    """env holds the VAR=value assignments that an enclosing command passes down."""
    for word in words:
        for inner in substitutions(word):
            reason = command_reason(inner, depth + 1, env)
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
    assignments = [word for word in words[:i] if ASSIGNMENT.match(word)]
    if i >= len(words):
        # Assignments without a command stay set for the rest of the shell.
        return env_reason(assignments, True)
    # GIT_CONFIG_* and GH_* only configure git and gh, which any program can run.
    reason = env_reason(assignments, False)
    if reason:
        return reason
    env = tuple(env) + tuple(assignments)

    name = os.path.basename(words[i])
    args = words[i + 1:]
    if name in SHELLS:
        script = shell_command_string(args)
        return command_reason(script, depth + 1, env) if script else None
    if name == "eval":
        return command_reason(" ".join(args), depth + 1, env)
    if name == "find":
        for j, arg in enumerate(args):
            if arg in ("-exec", "-execdir", "-ok", "-okdir"):
                reason = segment_reason(args[j + 1:], depth + 1, env)
                if reason:
                    return reason
        return None
    return program_reason(name, args, env)


def command_reason(command, depth=0, env=()):
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
                reason = segment_reason(words, depth, env)
                if reason:
                    return reason
        return None
    for words in segments(tokens):
        reason = segment_reason(words, depth, env)
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
