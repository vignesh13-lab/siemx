"""Split an SPL query into pipe stages and score its complexity."""
import re

HARD = {"transaction", "streamstats", "eventstats", "map", "foreach", "appendpipe"}
MEDIUM = {"rex", "lookup", "join", "append", "inputlookup", "eval", "dedup", "timechart"}


def split_stages(spl: str) -> list[str]:
    """Split on | but ignore pipes inside quotes or [subsearch] brackets.
    Inside a quoted string a backslash escapes the next character (SPL: \\" is a quote
    inside a string), so "a\\"b|c" stays one string."""
    stages, buf, depth, quote = [], [], 0, None
    chars = iter(spl)
    for ch in chars:
        if quote:
            buf.append(ch)
            if ch == "\\":
                buf.append(next(chars, ""))
            elif ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch == "[":
            depth += 1
            buf.append(ch)
        elif ch == "]":
            depth -= 1
            buf.append(ch)
        elif ch == "|" and depth == 0:
            stages.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        stages.append("".join(buf).strip())
    return [s for s in stages if s]


def strip_comments(spl: str) -> str:
    """Remove Splunk inline comments (```...```), never inside a quoted string. An
    unterminated ``` is left as it is (the search would fail in Splunk too)."""
    out, i, quote = [], 0, None
    while i < len(spl):
        ch = spl[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < len(spl):
                out.append(spl[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch == '"':
            quote = ch
            out.append(ch)
        elif spl.startswith("```", i):
            end = spl.find("```", i + 3)
            if end == -1:
                out.append(spl[i:])
                break
            out.append(" ")
            i = end + 3
            continue
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def normalize_spl(spl: str) -> str:
    """The same search in the form the rules read: comments removed, and an explicit
    `search` command at the start dropped (`search a=1` and `| search a=1` mean `a=1`).
    A generating command at the start (`| tstats ...`) is kept as written."""
    spl = strip_comments(spl).strip()
    body = spl[1:].lstrip() if spl.startswith("|") else spl
    m = re.match(r"(?i)search\s+", body)
    if m:
        return body[m.end():]
    return spl


def command_of(stage: str) -> str:
    m = re.match(r"\s*(\w+)", stage)
    return m.group(1).lower() if m else ""


def complexity(spl: str) -> str:
    cmds = {command_of(s) for s in split_stages(spl)[1:]}
    if "[" in spl or cmds & HARD:
        return "hard"
    if cmds & MEDIUM:
        return "medium"
    return "simple"
