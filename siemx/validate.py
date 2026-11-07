"""Syntax check hook. Start cheap, replace with real parsers/validators."""


def check(query: str, target: str) -> list[str]:
    problems = []
    if not query.strip():
        problems.append("empty output")
    if query.count("(") != query.count(")"):
        problems.append("unbalanced parentheses")
    if query.count('"') % 2:
        problems.append("unbalanced quotes")
    # TODO: KQL -> run through a KQL parser or dry run;
    #       XQL -> dry-run via Cortex API; keep errors for the LLM retry loop.
    return problems
