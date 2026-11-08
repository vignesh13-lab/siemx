import argparse
import json
from . import pipeline


def main():
    p = argparse.ArgumentParser(prog="siemx")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("convert", help="convert detections/spl/** (skips unchanged files)")
    c.add_argument("--to", default="kql,xql")
    c.add_argument("--workers", type=int, default=4)
    c.add_argument("--force", action="store_true")

    sub.add_parser("status", help="counts per status")
    sub.add_parser("review", help="list needs-review / unsupported")

    a = p.parse_args()
    if a.cmd == "convert":
        counts = pipeline.run(a.to.split(","), a.workers, a.force)
        print(json.dumps({"summary": counts}))
    elif a.cmd == "status":
        print(json.dumps(pipeline.status(), indent=2))
    elif a.cmd == "review":
        for m in sorted(pipeline.review_list(), key=lambda m: (m["src"], m["target"])):
            print(f"{m['status']:13} {m['target']}  {m['src']}  conf={m.get('confidence')}"
                  f"  method={m.get('method')}")
            for w in m.get("warnings") or []:
                print(f"    - {w}")


if __name__ == "__main__":
    main()
