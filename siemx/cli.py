import argparse
import json
import os

from . import config, pipeline


def main():
    p = argparse.ArgumentParser(prog="siemx")
    sub = p.add_subparsers(dest="cmd", required=True)

    client = argparse.ArgumentParser(add_help=False)
    client.add_argument("--client", default=os.environ.get("SIEMX_CLIENT"),
                        help="use mappings/clients/<client>/ and write to converted/<client>/ "
                             "(default: $SIEMX_CLIENT, else shared mappings only)")

    c = sub.add_parser("convert", parents=[client],
                       help="convert detections/spl/** (skips unchanged files)")
    c.add_argument("--to", default="kql,xql")
    c.add_argument("--workers", type=int, default=4)
    c.add_argument("--force", action="store_true")
    c.add_argument("--path", help="only convert detections/spl/<path>/** (e.g. a client folder)")

    sub.add_parser("status", parents=[client], help="counts per status")
    sub.add_parser("review", parents=[client], help="list needs-review / unsupported")

    a = p.parse_args()
    config.set_client(a.client)
    if a.cmd == "convert":
        counts = pipeline.run(a.to.split(","), a.workers, a.force, a.path)
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
