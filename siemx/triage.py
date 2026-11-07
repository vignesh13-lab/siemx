"""Split an SPL query into pipe stages and score its complexity."""
import re

HARD = {"transaction", "streamstats", "eventstats", "map", "foreach", "appendpipe"}
MEDIUM = {"rex", "lookup", "join", "append", "inputlookup", "eval", "dedup", "timechart"}


def split_stages(spl: str) -> list[str]:
    """Split on | but ignore pipes inside quotes or [subsearch] brackets."""
    stages, buf, depth, quote = [], [], 0, None
    for ch in spl:
        if quote:
            buf.append(ch)
            if ch == quote:
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
