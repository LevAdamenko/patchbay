import pytest

from patchbay.diffutil import PatchError, added_lines, apply, normalize, revert_hunk, touched_paths


DIFF = """--- a/guard.py
+++ b/guard.py
@@ -1,2 +1,3 @@
 one
-two
+TWO
+three
@@ -5 +6 @@
-five
+FIVE
"""


def test_apply_and_revert_each_hunk_round_trip():
    original = "one\ntwo\nthree\nfour\nfive\n"
    patched = "one\nTWO\nthree\nthree\nfour\nFIVE\n"
    assert apply(original, DIFF) == patched
    assert revert_hunk(patched, DIFF, 0) == "one\ntwo\nthree\nfour\nFIVE\n"
    assert revert_hunk(patched, DIFF, 1) == "one\nTWO\nthree\nthree\nfour\nfive\n"


def test_apply_rejects_context_mismatch():
    with pytest.raises(PatchError):
        apply("one\nnot-two\nthree\nfour\nfive\n", DIFF)


def test_added_lines_and_touched_paths():
    assert added_lines(DIFF) == [2, 3, 6]
    assert touched_paths(DIFF) == ["guard.py"]


SOURCE = "".join(f"line {number}\n" for number in range(1, 21))
# Content is right, but both hunks claim wrong positions and the first a wrong count.
OFF_DIFF = """--- a/m.py
+++ b/m.py
@@ -3,4 +3,5 @@
 line 5
-line 6
+line six
+line 6.5
 line 7
@@ -10,3 +11,3 @@
 line 14
-line 15
+line fifteen
 line 16
"""


def test_normalize_relocates_hunks_by_content():
    with pytest.raises(PatchError):
        apply(SOURCE, OFF_DIFF)
    fixed = normalize(SOURCE, OFF_DIFF)
    assert "@@ -5,3 +5,4 @@" in fixed
    assert "@@ -14,3 +15,3 @@" in fixed
    patched = apply(SOURCE, fixed)
    assert "line six\nline 6.5\nline 7\n" in patched
    assert "line 14\nline fifteen\nline 16\n" in patched
    assert added_lines(fixed) == [6, 7, 16]
    assert revert_hunk(patched, fixed, 1) == apply(SOURCE, fixed.split("@@ -14")[0])


def test_normalize_never_fuzzes_content():
    with pytest.raises(PatchError):
        normalize(SOURCE, OFF_DIFF.replace(" line 7\n", " line 70\n"))


def test_normalize_keeps_hunks_in_order_on_repeated_context():
    source = "a\nb\na\nb\n"
    diff = "--- a/m.py\n+++ b/m.py\n@@ -1,2 +1,2 @@\n a\n-b\n+B\n@@ -1,2 +1,2 @@\n a\n-b\n+B\n"
    assert apply(source, normalize(source, diff)) == "a\nB\na\nB\n"
