import ast
import pickle
import unittest
from pathlib import Path
from unittest import mock

from c9nltk import cases, opstream, policy

SRC = Path(__file__).resolve().parent.parent / "src" / "c9nltk"


class NeverUnpickle(unittest.TestCase):
    def test_source_never_unpickles(self):
        """AST check: no call or reference to an unpickling or eval API."""
        banned = {"loads", "load", "Unpickler", "eval", "exec", "__import__",
                  "import_module", "find_class"}
        for f in SRC.glob("*.py"):
            tree = ast.parse(f.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                name = (node.attr if isinstance(node, ast.Attribute) else
                        node.id if isinstance(node, ast.Name) else None)
                self.assertNotIn(name, banned, f"{f.name}:{getattr(node, 'lineno', 0)}")
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    mods = [a.name for a in node.names] + [
                        getattr(node, "module", None) or ""]
                    self.assertNotIn("importlib", mods, f.name)

    def test_analysis_does_not_touch_the_unpickler(self):
        boom = mock.Mock(side_effect=AssertionError("unpickler used"))
        data = opstream.build_stack_global("os", "system", "x")
        with mock.patch.object(pickle, "loads", boom), \
                mock.patch.object(pickle, "load", boom), \
                mock.patch.object(pickle, "Unpickler", boom):
            self.assertEqual(opstream.extract_globals(data), [("os", "system")])
        boom.assert_not_called()


class ExtractorEdges(unittest.TestCase):
    def test_truncated_stream_is_malformed(self):
        data = opstream.build_stack_global("numpy", "load")[:-3]
        with self.assertRaises(ValueError):
            opstream.extract_globals(data)

    def test_non_bytes_rejected(self):
        with self.assertRaises(ValueError):
            opstream.extract_globals("cos\nsystem\n.")

    def test_oversize_rejected(self):
        with self.assertRaises(ValueError):
            opstream.extract_globals(b"N" * (opstream.MAX_BYTES + 1))

    def test_stack_global_with_non_string_operands_is_unknown(self):
        data = (pickle.PROTO + b"\x04" + pickle.NONE + pickle.NONE
                + pickle.STACK_GLOBAL + pickle.STOP)
        (mod, name), = opstream.extract_globals(data)
        self.assertIsInstance(mod, opstream.Unknown)
        self.assertIsInstance(name, opstream.Unknown)

    def test_get_of_unknown_memo_is_malformed(self):
        data = pickle.PROTO + b"\x04" + pickle.BINGET + b"\x07" + pickle.STOP
        with self.assertRaises(ValueError):
            opstream.extract_globals(data)

    def test_protocol_0_dump_of_a_real_class_is_seen(self):
        data = pickle.dumps(policy.Config, protocol=0)
        self.assertIn(("c9nltk.policy", "Config"),
                      opstream.extract_globals(data))

    def test_protocol_4_dump_with_framing_and_memo(self):
        data = pickle.dumps([policy.Config, policy.Symbol], protocol=4)
        got = opstream.extract_globals(data)
        self.assertIn(("c9nltk.policy", "Config"), got)
        self.assertIn(("c9nltk.policy", "Symbol"), got)

    def test_gadget_hidden_inside_a_list_is_still_found(self):
        inner = opstream.build_stack_global("numpy", "load")[2:-1]  # no PROTO/STOP
        data = (pickle.PROTO + b"\x04" + pickle.EMPTY_LIST + pickle.MARK
                + inner + pickle.APPENDS + pickle.STOP)
        self.assertEqual(opstream.extract_globals(data), [("numpy", "load")])


class PolicyEdges(unittest.TestCase):
    def test_prefix_needs_a_dot_boundary(self):
        # "osx" is not "os" nor "os.*"; "nltk.tokenizer" is not under "nltk.tokenize".
        self.assertFalse(policy.module_denied("osx"))
        self.assertTrue(policy.module_denied("os.path"))
        self.assertEqual(policy.decide("pre", "punkt", "nltk.tokenizer", "X")[0],
                         "REJECT_NOT_ALLOWLISTED")

    def test_dunder_requires_both_ends(self):
        self.assertEqual(policy.decide("post", "model", "numpy", "__x")[0],
                         "ALLOW_UNRESOLVED")
        self.assertEqual(policy.decide("post", "model", "numpy", "__x__")[0],
                         "REJECT_DUNDER")

    def test_reexport_from_denied_module_rejected_after_resolution(self):
        syms = {("numpy", "alias"): policy.Symbol(
            "function", "subprocess", "Popen", "command")}
        self.assertEqual(policy.decide("pre", "model", "numpy", "alias", syms)[0],
                         "ALLOW")
        self.assertEqual(policy.decide("post", "model", "numpy", "alias", syms),
                         ("REJECT_REEXPORT_DENIED", "L186-191"))

    def test_resolved_denied_global_under_alias(self):
        syms = {("numpy", "ld"): policy.Symbol("function", "numpy", "load", "io")}
        self.assertEqual(policy.decide("post", "model", "numpy", "ld", syms)[0],
                         "REJECT_DENIED_RESOLVED")

    def test_safe_builtin_survives_denied_module(self):
        syms = cases.symbols()
        self.assertEqual(policy.decide("post", "model", "builtins", "int", syms)[0],
                         "ALLOW")
        self.assertEqual(policy.decide("post", "model", "builtins", "eval")[0],
                         "REJECT_DENIED_MODULE")

    def test_denylist_matches_saved_diff_text(self):
        diff = cases.ROOT / "fixtures" / "diff_excerpt.txt"
        text = diff.read_text(encoding="utf-8")
        for mod in policy.DENIED_MODULE_PREFIXES:
            self.assertIn(f'"{mod}",', text)
        for mod, name in policy.DENIED_GLOBALS:
            self.assertIn(f'("{mod}", "{name}"),', text)


if __name__ == "__main__":
    unittest.main()
