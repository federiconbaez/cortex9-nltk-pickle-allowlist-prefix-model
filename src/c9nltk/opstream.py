"""Static extraction of the globals a pickle names, without unpickling.

Uses ``pickletools.genops`` and a symbolic stack; ``pickle.loads`` and
``pickle.Unpickler`` are never used. Anything the symbolic stack cannot
follow is reported as UNKNOWN (fail closed), never guessed.
"""
from __future__ import annotations

import pickle
import pickletools

_STR_OPS = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "STRING", "BINSTRING", "SHORT_BINSTRING",
}
_MARK = object()
MAX_BYTES = 1 << 20


class Unknown:
    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return "Unknown"


def build_stack_global(module: str, name: str, arg: str = "x") -> bytes:
    """Same byte layout as the upstream test helper (DIFF L296-309):
    PROTO 4, module, name, STACK_GLOBAL, arg, TUPLE1, REDUCE, STOP."""
    def su(s: str) -> bytes:
        b = s.encode("utf-8")
        if len(b) > 255:
            raise ValueError("string too long for SHORT_BINUNICODE")
        return pickle.SHORT_BINUNICODE + bytes([len(b)]) + b
    return (pickle.PROTO + bytes([4]) + su(module) + su(name)
            + pickle.STACK_GLOBAL + su(arg) + pickle.TUPLE1 + pickle.REDUCE
            + pickle.STOP)


def build_global(module: str, name: str) -> bytes:
    """Protocol 0 GLOBAL opcode: ``c<module>\\n<name>\\n`` then STOP."""
    if "\n" in module or "\n" in name:
        raise ValueError("newline in module or name")
    return (pickle.GLOBAL + module.encode("utf-8") + b"\n"
            + name.encode("utf-8") + b"\n" + pickle.STOP)


def build_memo(module: str, name: str) -> bytes:
    """Module and name memoized, then fetched back with BINGET."""
    def su(s: str) -> bytes:
        b = s.encode("utf-8")
        return pickle.SHORT_BINUNICODE + bytes([len(b)]) + b
    return (pickle.PROTO + bytes([4]) + su(module) + pickle.MEMOIZE + pickle.POP
            + su(name) + pickle.MEMOIZE + pickle.POP
            + pickle.BINGET + b"\x00" + pickle.BINGET + b"\x01"
            + pickle.STACK_GLOBAL + pickle.STOP)


def extract_globals(data) -> list:
    """Return [(module, name)] in stream order, or raise ValueError.

    A STACK_GLOBAL whose operands are not both known strings yields
    (Unknown, Unknown).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("input must be bytes")
    if len(data) > MAX_BYTES:
        raise ValueError("input too large")
    stack: list = []
    memo: dict = {}
    found: list = []
    try:
        for op, arg, _pos in pickletools.genops(bytes(data)):
            n = op.name
            if n == "GLOBAL" or n == "INST":
                mod, _, nm = arg.partition(" ")
                found.append((mod, nm))
                stack.append(Unknown())
                continue
            if n == "STACK_GLOBAL":
                if len(stack) < 2:
                    raise ValueError("STACK_GLOBAL on short stack")
                nm, mod = stack.pop(), stack.pop()
                if isinstance(mod, str) and isinstance(nm, str):
                    found.append((mod, nm))
                else:
                    found.append((Unknown(), Unknown()))
                stack.append(Unknown())
                continue
            if n in _STR_OPS:
                val = arg.decode("latin-1") if isinstance(arg, bytes) else arg
                stack.append(val)
                continue
            if n == "MEMOIZE":
                if not stack:
                    raise ValueError("MEMOIZE on empty stack")
                memo[len(memo)] = stack[-1]
                continue
            if n in ("PUT", "BINPUT", "LONG_BINPUT"):
                if not stack:
                    raise ValueError("PUT on empty stack")
                memo[arg] = stack[-1]
                continue
            if n in ("GET", "BINGET", "LONG_BINGET"):
                if arg not in memo:
                    raise ValueError("GET of unknown memo key")
                stack.append(memo[arg])
                continue
            if n == "MARK":
                stack.append(_MARK)
                continue
            if n in ("PROTO", "FRAME", "STOP"):
                continue
            _generic(op, stack)
    except ValueError:
        raise
    except Exception as exc:  # genops raises several types on bad input
        raise ValueError(f"malformed pickle: {type(exc).__name__}") from None
    return found


def _generic(op, stack: list) -> None:
    before = op.stack_before
    if pickletools.markobject in before:
        while stack and stack[-1] is not _MARK:
            stack.pop()
        if not stack:
            raise ValueError("no MARK on stack")
        stack.pop()
        rest = [s for s in before if s not in (pickletools.markobject,
                                                pickletools.stackslice)]
    else:
        rest = list(before)
    for _ in rest:
        if not stack:
            raise ValueError(f"{op.name} on short stack")
        stack.pop()
    for _ in op.stack_after:
        stack.append(Unknown())
