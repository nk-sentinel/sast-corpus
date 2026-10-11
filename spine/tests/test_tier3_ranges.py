import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from validate.tier3_ranges import changed_lines


class InsertionsOccupyNoLinesOnTheOtherSide(unittest.TestCase):
    """The defect this module was first written with.

    A security fix is usually a pure insertion — a guard added before a sink. An
    inserted block occupies no lines in the *buggy* file, so collecting changed
    lines in the buggy file's coordinates and then comparing them against a
    range in the *fixed* file reports every such case as a miss. The first run
    of this check said 8 of 21 tier-3 traps did not touch their patch; all 21
    do.
    """

    BEFORE = ["def f(x):", "    return open(x)"]
    AFTER = ["def f(x):", "    if '..' in x:", "        raise ValueError", "    return open(x)"]

    def test_the_inserted_lines_are_named_in_the_fixed_file(self):
        self.assertEqual(changed_lines(self.BEFORE, self.AFTER, "after"), {2, 3})

    def test_the_seam_is_named_in_the_buggy_file(self):
        """Nothing was changed there, so the only honest answer is the join."""
        self.assertEqual(changed_lines(self.BEFORE, self.AFTER, "before"), {2})

    def test_a_trap_range_on_the_inserted_guard_is_covered(self):
        touched = changed_lines(self.BEFORE, self.AFTER, "after")

        self.assertTrue(touched & set(range(2, 4)))


class DeletionsAreTheMirrorImage(unittest.TestCase):
    BEFORE = ["a", "bad()", "c"]
    AFTER = ["a", "c"]

    def test_the_removed_line_is_named_in_the_buggy_file(self):
        self.assertEqual(changed_lines(self.BEFORE, self.AFTER, "before"), {2})

    def test_the_seam_is_named_in_the_fixed_file(self):
        self.assertEqual(changed_lines(self.BEFORE, self.AFTER, "after"), {2})


class ReplacementsNameBothSides(unittest.TestCase):
    BEFORE = ["a", "query(s)", "c"]
    AFTER = ["a", "query(?, s)", "c"]

    def test_before(self):
        self.assertEqual(changed_lines(self.BEFORE, self.AFTER, "before"), {2})

    def test_after(self):
        self.assertEqual(changed_lines(self.BEFORE, self.AFTER, "after"), {2})


class AnUnchangedFileHasNoTouchedLines(unittest.TestCase):
    def test_identical_sides(self):
        same = ["a", "b", "c"]

        self.assertEqual(changed_lines(same, same, "before"), set())
        self.assertEqual(changed_lines(same, same, "after"), set())


if __name__ == "__main__":
    unittest.main()
