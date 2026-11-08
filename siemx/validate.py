"""Roadmap 5: validate generated KQL / XQL before anyone reviews it.

KQL - Microsoft's official parser (Kusto.Language, npm @kusto/language-service-next)
      in a long-running Node process (tools/kql-validate/validate.js; starting Node and
      loading the parser per query would take ~1 s each).
      * syntax always (e.g. "summarise" -> "Query operator expected")
      * semantic analysis when the table is in mappings/fields.json: unknown functions
        (hallucinations like strlength()), unknown columns, type errors
      * Sentinel functions the generic parser does not know (_GetWatchlist) are allowed
      * unknown tables: syntax only, so the validator does not cry wolf
      Install: npm ci --prefix tools/kql-validate. Without Node it falls back to basic checks.
XQL - Palo Alto publishes no parser. Checked here: balanced brackets/quotes and every
      stage and function name against the official XQL reference (rag/sources.json).
      This is a NAME check, not a parse; a Cortex dry-run would need a tenant.

check(query, target, scope):
  scope "all"   for LLM output: every problem (unknown columns may be hallucinations)
  scope "rules" for rule output and gold pairs: syntax errors and unknown functions only.
                Columns are checked by schema.py, and gold uses illustrative field names;
                an unknown column cascades into type errors with many wordings.
  Measured: all 56 rule outputs of the 40-query test set parse with no problems.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
from pathlib import Path

from . import config

TOOL_DIR = Path(__file__).resolve().parent.parent / "tools" / "kql-validate"
SENTINEL_FUNCTIONS = ("_GetWatchlist", "_GetWatchlistAlias")   # Sentinel watchlist docs
_PLAIN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


# ---- basic checks (always; quote-aware) ---------------------------------------------------

def _outside_quotes(query: str) -> tuple[str, bool]:
    """Text with string literals removed, and whether all quotes were closed."""
    out, quote, i = [], None, 0
    while i < len(query):
        ch = query[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        else:
            out.append(ch)
        i += 1
    return "".join(out), quote is None


def basic_problems(query: str) -> list[str]:
    if not query.strip():
        return ["empty output"]
    code, closed = _outside_quotes(query)
    problems = [] if closed else ["unbalanced quotes"]
    if code.count("(") != code.count(")"):
        problems.append("unbalanced parentheses")
    return problems


# ---- KQL: official parser in a Node process ----------------------------------------------

class KqlValidator:
    """One Node process for many queries; thread-safe (pipeline workers share it)."""

    def __init__(self):
        self.proc = None
        self.lock = threading.Lock()
        self.n = 0

    @staticmethod
    def available() -> bool:
        return bool(shutil.which("node")) and (TOOL_DIR / "node_modules").exists()

    def _start(self):
        self.proc = subprocess.Popen(
            ["node", str(TOOL_DIR / "validate.js")], cwd=TOOL_DIR, text=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            encoding="utf-8", bufsize=1)
        hello = json.loads(self.proc.stdout.readline())
        if not hello.get("ready"):
            raise RuntimeError("KQL validator did not start")

    def run(self, query: str, table: str | None, columns: str | None) -> dict:
        with self.lock:
            if self.proc is None or self.proc.poll() is not None:
                self._start()
            self.n += 1
            req = {"id": str(self.n), "query": query, "table": table, "columns": columns}
            self.proc.stdin.write(json.dumps(req) + "\n")
            self.proc.stdin.flush()
            return json.loads(self.proc.stdout.readline())

    def close(self):
        if self.proc is not None:
            self.proc.stdin.close()
            self.proc.wait(timeout=10)
            self.proc = None


_KQL = KqlValidator()


def kql_table_schema(query: str) -> tuple[str | None, str | None]:
    """Table at the start of the query and its declared columns from mappings/fields.json.
    Columns without a known type are declared `dynamic` (see typed_table)."""
    from . import schema
    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", query)
    if not m:
        return None, None
    table = m.group(1)
    cols = schema.known_fields(table, "kql")
    if not cols:
        return table, None
    parts = []
    for c in cols:
        t = schema.field_type(table, "kql", c) or "dynamic"
        name = c if _PLAIN.fullmatch(c) else "['" + c + "']"
        parts.append(f"{name}:{t}")
    return table, "(" + ", ".join(parts) + ")"


def typed_table(table: str | None) -> bool:
    """Type errors are only trustworthy when fields.json gives column types."""
    from . import schema
    cols = schema.known_fields(table, "kql") if table else None
    return bool(cols) and all(schema.field_type(table, "kql", c) for c in cols)


_NAME_ERROR = "does not refer to any known"     # unknown function / column / table


def _where(query: str, start: int) -> str:
    line = query.count("\n", 0, start) + 1
    col = start - (query.rfind("\n", 0, start) + 1) + 1
    snippet = query[start:start + 30].split("\n")[0]
    return f"line {line} col {col}: `{snippet}`"


def kql_problems(query: str, scope: str = "all") -> list[str]:
    table, columns = kql_table_schema(query)
    res = _KQL.run(query, table, columns)
    if "error" in res:
        return [f"KQL validator error: {res['error']}"]
    syntax = [d for d in res["syntax"] if d["severity"] == "Error"]
    semantic = [d for d in res["semantic"] if d["severity"] == "Error"]
    other_table = any("known table" in d["message"] for d in semantic)
    typed = typed_table(table)
    out = [f"KQL syntax: {d['message']} ({_where(query, d['start'])})" for d in syntax]
    for d in semantic:
        m = d["message"]
        if any(f"'{f}'" in m for f in SENTINEL_FUNCTIONS):
            continue                                   # Sentinel-only functions
        if "known table" in m:
            continue                                   # a table without a schema here
        if scope == "rules" and "known function" not in m:
            continue   # rule output: columns are checked by schema.py, and an unknown column
                       # cascades into type errors ("No common type", "Column name expected")
        if "known column" in m and other_table:
            continue                                   # cascade of a table without a schema
        if not typed and _NAME_ERROR not in m:
            continue                                   # column types unknown: only name errors
        out.append(f"KQL semantic: {m} ({_where(query, d['start'])})")
    return list(dict.fromkeys(out))[:MAX_PROBLEMS]


# ---- XQL: names against the official reference ----------------------------------------------

_XQL_OPERATORS = {"not", "and", "or", "in", "contains", "incidr", "incidr6", "as", "by",
                  "left", "right", "inner"}      # join type = left (subquery) is not a call
MAX_PROBLEMS = 3     # one mistake often cascades into several parser errors; the first matters
_NAMES: dict | None = None


def xql_reference() -> dict | None:
    """{'stages': {...}, 'functions': {...}} from rag/sources.json, or None if missing."""
    global _NAMES
    if _NAMES is None:
        f = config.ROOT / "rag" / "sources.json"
        if not f.exists():
            f = Path(__file__).resolve().parent.parent / "rag" / "sources.json"
        if not f.exists():
            return None
        data = json.loads(f.read_text(encoding="utf-8"))
        stages, funcs = set(), set()
        for s in data["sources"]:
            if s["lang"] != "xql":
                continue
            name = re.sub(r"_with_(window)?comp_stage$", "", s["slug"])
            (stages if s["kind"] == "stage" else funcs).add(name)
        _NAMES = {"stages": stages, "functions": funcs}
    return _NAMES


def xql_problems(query: str) -> list[str]:
    ref = xql_reference()
    if ref is None:
        return []
    code, _ = _outside_quotes(query)
    out = []
    starts = re.findall(r"(?:^|\|)\s*([A-Za-z_]+)", code) + re.findall(r"\(\s*(dataset)\b", code)
    for st in starts:
        if st.lower() not in ref["stages"]:
            out.append(f"XQL: unknown stage '{st}' (not in the official XQL reference)")
    for fn in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", code):
        name = fn.lower()
        if name in _XQL_OPERATORS or name in ref["stages"]:
            continue
        if name not in ref["functions"]:
            out.append(f"XQL: unknown function '{fn}' (not in the official XQL reference)")
    return list(dict.fromkeys(out))


_SPL_COMMANDS: set[str] | None = None


def spl_commands() -> set[str] | None:
    """Command names from the official SPL Search Reference pages in rag/sources.json.
    Functions are documented in grouped pages (text-functions, ...), so only commands
    are checked."""
    global _SPL_COMMANDS
    if _SPL_COMMANDS is None:
        f = config.ROOT / "rag" / "sources.json"
        if not f.exists():
            f = Path(__file__).resolve().parent.parent / "rag" / "sources.json"
        if not f.exists():
            return None
        data = json.loads(f.read_text(encoding="utf-8"))
        _SPL_COMMANDS = {s["slug"] for s in data["sources"]
                         if s["lang"] == "spl" and s["kind"] == "command"}
    return _SPL_COMMANDS or None


def spl_problems(query: str) -> list[str]:
    """Every command after a pipe must be an official SPL command. The first stage is
    the base search (index=... terms), not a command, unless the query starts with '|'
    (| tstats ..., | inputlookup ...)."""
    cmds = spl_commands()
    if cmds is None:
        return []
    code, _ = _outside_quotes(query)
    out = []
    for name in re.findall(r"\|\s*([A-Za-z_][A-Za-z0-9_]*)", code):
        if name.lower() not in cmds:
            out.append(f"SPL: unknown command '{name}' (not in the official Search Reference)")
    return list(dict.fromkeys(out))


# ---- entry points --------------------------------------------------------------------------------

def status() -> dict:
    return {"kql": "official parser (Kusto.Language)" if KqlValidator.available()
            else "basic checks only (run: npm ci --prefix tools/kql-validate)",
            "xql": "name check against the official reference" if xql_reference()
            else "basic checks only (rag/sources.json missing)",
            "spl": "command-name check against the official reference" if spl_commands()
            else "basic checks only (rag/sources.json missing)",
            "elk": "Kibana's KQL grammar (port in siemx/elk.py)"}


def check(query: str, target: str, scope: str = "all") -> list[str]:
    if target == "elk":               # escapes like \( make the generic paren count wrong
        from . import elk
        return elk.problems(query)[:MAX_PROBLEMS]
    problems = basic_problems(query)
    if problems and "empty output" in problems:
        return problems
    if target == "kql" and KqlValidator.available():
        problems += kql_problems(query, scope)
    elif target == "xql":
        problems += xql_problems(query)
    elif target == "spl":
        problems += spl_problems(query)
    return list(dict.fromkeys(problems))[:MAX_PROBLEMS]
