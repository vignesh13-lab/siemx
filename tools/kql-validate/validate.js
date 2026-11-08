// KQL validation server for siemx (roadmap 5).
//
// Uses Microsoft's official parser, Kusto.Language (npm @kusto/language-service-next,
// the JavaScript build used by the Kusto editors). One process serves many queries:
// read one JSON request per line on stdin, write one JSON response per line on stdout.
//
// request:  {"id": "...", "query": "...", "table": "SecurityEvent" | null,
//            "columns": "(TimeGenerated:datetime, Computer:string, ...)" | null}
// response: {"id": "...", "mode": "semantic" | "syntax",
//            "syntax": [diagnostic], "semantic": [diagnostic]}   (semantic = only the extra ones)
//            diagnostic = {"severity", "message", "start", "length"}
//
// mode "semantic": the table's columns are declared, so unknown functions, columns and
//                  type errors are reported (ParseAndAnalyze)
// mode "syntax":   unknown table schema -> grammar only (Parse), to avoid false errors
require("@kusto/language-service-next/bridge.js");   // Bridge.NET runtime must load first
require("@kusto/language-service-next");
const readline = require("readline");

const K = Kusto.Language;
const globalsCache = new Map();

function globalsFor(table, columns) {
  const key = `${table}${columns}`;
  if (!globalsCache.has(key)) {
    const t = new K.Symbols.TableSymbol.$ctor7(table, columns, "");
    const db = new K.Symbols.DatabaseSymbol.ctor("siemx", [t]);
    globalsCache.set(key, K.GlobalState.Default.WithDatabase(db));
  }
  return globalsCache.get(key);
}

function diagnostics(code) {
  const list = code.GetDiagnostics();
  const out = [];
  for (let i = 0; i < list.Count; i++) {
    const d = list.getItem(i);
    out.push({ severity: String(d.Severity), message: d.Message, start: d.Start, length: d.Length });
  }
  return out;
}

function validate(req) {
  const syntax = diagnostics(K.KustoCode.Parse(req.query));
  if (req.table && req.columns) {
    // semantic diagnostics include the syntax ones; return only the extra ones
    const seen = new Set(syntax.map((d) => `${d.start}:${d.message}`));
    const all = diagnostics(K.KustoCode.ParseAndAnalyze(req.query, globalsFor(req.table, req.columns)));
    const semantic = all.filter((d) => !seen.has(`${d.start}:${d.message}`));
    return { id: req.id, mode: "semantic", syntax, semantic };
  }
  return { id: req.id, mode: "syntax", syntax, semantic: [] };
}

const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  if (!line.trim()) return;
  let res;
  try {
    res = validate(JSON.parse(line));
  } catch (e) {
    res = { id: null, error: String(e) };
  }
  process.stdout.write(JSON.stringify(res) + "\n");
});
process.stdout.write(JSON.stringify({ ready: true, parser: "Kusto.Language 12.4.1" }) + "\n");
