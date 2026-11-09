"""Answers to PRACTICE.md, one test per level."""
import unittest

from c9nltk import cases, opstream, policy

S = cases.symbols()


def both(cfg, mod, name):
    return (policy.decide("pre", cfg, mod, name, S)[0],
            policy.decide("post", cfg, mod, name, S)[0])


class Practice(unittest.TestCase):
    def test_level_1_read_the_opcodes(self):
        data = opstream.build_stack_global("nltk.tokenize.punkt",
                                           "PunktParameters")
        self.assertEqual(opstream.extract_globals(data),
                         [("nltk.tokenize.punkt", "PunktParameters")])

    def test_level_2_prefix_vs_exact(self):
        self.assertEqual(both("punkt", "nltk.tokenize.punkt", "PunktParameters"),
                         ("ALLOW", "ALLOW"))

    def test_level_3_in_namespace_gadget(self):
        self.assertEqual(both("model", "numpy.f2py.crackfortran", "myeval"),
                         ("ALLOW", "REJECT_DENIED_MODULE"))

    def test_level_4_qualname_gadget_blocked_by_module(self):
        # Blocked by the denied-module backstop (GHSA-x99w), not by the
        # dotted-name guard, which belongs to GHSA-4489 and is out of scope.
        self.assertEqual(both("punkt", "nltk.tokenize.repp",
                              "ReppTokenizer._execute"),
                         ("ALLOW", "REJECT_DENIED_MODULE"))

    def test_level_5_same_module_sink(self):
        self.assertEqual(both("model", "numpy", "load"),
                         ("ALLOW", "REJECT_DENIED_GLOBAL"))

    def test_level_6_defense_in_depth_misconfig(self):
        self.assertEqual(both("misconfig_eval", "builtins", "eval"),
                         ("ALLOW", "REJECT_ALLOWED_BUT_DENIED_MODULE"))

    def test_level_7_compat_cost(self):
        self.assertEqual(both("punkt", "collections", "defaultdict"),
                         ("REJECT_NOT_ALLOWLISTED", "ALLOW"))

    def test_level_8_reexport_after_resolution(self):
        syms = {("numpy", "alias"): policy.Symbol("function", "os", "system",
                                                  "command")}
        self.assertEqual(policy.decide("post", "model", "numpy", "alias", syms)[0],
                         "REJECT_REEXPORT_DENIED")


if __name__ == "__main__":
    unittest.main()
