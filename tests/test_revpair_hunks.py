# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Unit tests for the revpair ``git diff -U0 -M`` parser and line mapping."""

from __future__ import annotations

from benchmarks.builders.revpair.hunks import parse_unified_diff, unquote_git_path

_DIFF = """\
diff --git a/src/app.c b/src/app.c
index 1111111..2222222 100644
--- a/src/app.c
+++ b/src/app.c
@@ -0,0 +1,2 @@
+#include <a.h>
+#include <b.h>
@@ -10 +12 @@ int f(void)
-    strcpy(buf, src);
+    strncpy(buf, src, n);
@@ -20,2 +21,0 @@ int g(void)
--- a removed line that looks like a header
--- another one
@@ -30,0 +30,1 @@
+    check();
diff --git a/old/name.py b/new/name.py
similarity index 90%
rename from old/name.py
rename to new/name.py
index 3333333..4444444 100644
--- a/old/name.py
+++ b/new/name.py
@@ -5 +5 @@
-x = 1
+x = 2
diff --git a/same.txt b/moved.txt
similarity index 100%
rename from same.txt
rename to moved.txt
diff --git a/gone.py b/gone.py
deleted file mode 100644
index 5555555..0000000
--- a/gone.py
+++ /dev/null
@@ -1,3 +0,0 @@
-a
-b
-c
diff --git a/fresh.py b/fresh.py
new file mode 100644
index 0000000..6666666
--- /dev/null
+++ b/fresh.py
@@ -0,0 +1 @@
+print('hi')
diff --git a/logo.png b/logo.png
index 7777777..8888888 100644
Binary files a/logo.png and b/logo.png differ
"""


def test_parses_files_and_statuses() -> None:
    idx = parse_unified_diff(_DIFF)
    by_status = {(f.old_path, f.new_path): f.status for f in idx.files}
    assert by_status == {
        ("src/app.c", "src/app.c"): "modified",
        ("old/name.py", "new/name.py"): "renamed",
        ("same.txt", "moved.txt"): "renamed",
        ("gone.py", None): "deleted",
        (None, "fresh.py"): "added",
        ("logo.png", "logo.png"): "modified",
    }
    logo = idx.for_old_path("logo.png")
    assert logo is not None and logo.is_binary


def test_header_lookalike_body_lines_do_not_split_file() -> None:
    fd = parse_unified_diff(_DIFF).for_old_path("src/app.c")
    assert fd is not None
    assert [(h.old_start, h.old_count, h.new_start, h.new_count) for h in fd.hunks] == [
        (0, 0, 1, 2),
        (10, 1, 12, 1),
        (20, 2, 21, 0),
        (30, 0, 30, 1),
    ]
    assert fd.deleted_ranges == [(10, 10), (20, 21)]
    assert fd.added_ranges == [(1, 2), (12, 12), (30, 30)]
    assert fd.insertion_points == [0, 30]


def test_map_old_to_new() -> None:
    fd = parse_unified_diff(_DIFF).for_old_path("src/app.c")
    assert fd is not None
    assert fd.map_old_to_new(1) == 3  # shifted by the 2-line insertion at top
    assert fd.map_old_to_new(9) == 11
    assert fd.map_old_to_new(10) is None  # modified
    assert fd.map_old_to_new(15) == 17
    assert fd.map_old_to_new(20) is None  # deleted
    assert fd.map_old_to_new(25) == 25  # +2 then -2
    assert fd.map_old_to_new(30) == 30  # insertion is *after* old line 30
    assert fd.map_old_to_new(31) == 32


def test_overlaps_old_includes_adjacent_insertion() -> None:
    fd = parse_unified_diff(_DIFF).for_old_path("src/app.c")
    assert fd is not None
    assert fd.overlaps_old(10, 10)
    assert fd.overlaps_old(19, 20)
    assert not fd.overlaps_old(15, 15)
    assert fd.overlaps_old(31, 31)  # check() inserted right before old line 31
    assert not fd.overlaps_old(31, 31, include_insertions=False)


def test_rename_and_delete_mapping() -> None:
    idx = parse_unified_diff(_DIFF)
    assert idx.rename_old_to_new("old/name.py") == "new/name.py"
    assert idx.rename_old_to_new("same.txt") == "moved.txt"
    assert idx.rename_old_to_new("untouched.py") == "untouched.py"
    assert idx.rename_old_to_new("gone.py") is None
    assert idx.map_old_line("same.txt", 7) == ("moved.txt", 7)
    assert idx.map_old_line("gone.py", 2) == (None, None)
    assert idx.map_old_line("old/name.py", 5) == ("new/name.py", None)


def test_hunk_header_without_counts_means_one() -> None:
    fd = parse_unified_diff(_DIFF).for_old_path("old/name.py")
    assert fd is not None
    assert fd.hunks[0].old_count == 1 and fd.hunks[0].new_count == 1


def test_unquote_git_path() -> None:
    assert unquote_git_path("plain/path.c") == "plain/path.c"
    assert unquote_git_path('"a/tab\\there.c"') == "a/tab\there.c"
    assert unquote_git_path('"a/\\303\\251.c"') == "a/é.c"
