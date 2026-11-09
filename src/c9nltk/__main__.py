"""CLI: python -m c9nltk <config> <hex-pickle>  (static analysis only)."""
import sys

from . import cases, opstream, policy


def main(argv) -> int:
    if len(argv) != 2 or argv[0] not in {c for c, _ in policy.CONFIGS}:
        sys.stderr.write("usage: python -m c9nltk punkt|model|misconfig_os|"
                         "misconfig_eval <hex>\n")
        return 2
    try:
        data = bytes.fromhex(argv[1])
        found = opstream.extract_globals(data)
    except ValueError as exc:
        print(f"MALFORMED\t{exc}")
        return 1
    syms = cases.symbols()
    for mod, name in found:
        if not isinstance(mod, str):
            print("UNKNOWN\tSTACK_GLOBAL operands not statically known")
            continue
        for ver in ("pre", "post"):
            label, rule = policy.decide(ver, argv[0], mod, name, syms)
            print(f"{ver}\t{mod}\t{name}\t{label}\t{rule}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
