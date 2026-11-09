import unittest

from c9nltk import cases


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.syms = cases.symbols()
        cls.cases = cases.load_cases()
        cls.rows = {c["id"]: cases.evaluate(c, cls.syms) for c in cls.cases}
        cls.expected = {}
        for r in cases.read_tsv(cases.ROOT / "fixtures/expected.tsv")[1:]:
            cls.expected[(r[0], r[1])] = (r[2], r[3])

    def test_expected_covers_every_case(self):
        self.assertEqual(len(self.expected), 2 * len(self.cases))

    def test_model_matches_independent_derivation(self):
        for cid, row in self.rows.items():
            for ver in ("pre", "post"):
                with self.subTest(case=cid, version=ver):
                    self.assertEqual((row[ver], row[ver + "_sink"]),
                                     self.expected[(cid, ver)])

    def test_model_matches_hand_labels(self):
        for c in self.cases:
            with self.subTest(case=c["id"]):
                row = self.rows[c["id"]]
                self.assertEqual(row["pre"], c["hand_pre"])
                self.assertEqual(row["post"], c["hand_post"])

    def test_static_extraction_recovers_the_name(self):
        for cid, row in self.rows.items():
            with self.subTest(case=cid):
                self.assertEqual(row["extracted"], "ok")

    def test_acceptance_pre_reaches_at_least_two_sinks(self):
        sinks = [r for r in self.rows.values()
                 if r["cls"] == "pos" and r["pre_sink"] != "-"]
        self.assertGreaterEqual(len(sinks), 2)

    def test_acceptance_post_blocks_every_positive(self):
        for r in self.rows.values():
            if r["cls"] == "pos":
                with self.subTest(case=r["id"]):
                    self.assertTrue(r["post"].startswith("REJECT"))
                    self.assertEqual(r["post_sink"], "-")

    def test_acceptance_negatives_load_under_both(self):
        for r in self.rows.values():
            if r["cls"] in ("neg", "compat"):
                with self.subTest(case=r["id"]):
                    self.assertTrue(r["post"].startswith("ALLOW"))
            if r["cls"] == "neg":
                self.assertTrue(r["pre"].startswith("ALLOW"))

    def test_every_rule_cites_a_diff_line(self):
        for r in self.rows.values():
            for ver in ("pre", "post"):
                self.assertRegex(r[ver + "_rule"], r"^L\d+(-\d+)?$")


if __name__ == "__main__":
    unittest.main()
