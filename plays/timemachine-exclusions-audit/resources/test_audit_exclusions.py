"""Subprocess-mocked unit tests for audit_exclusions.py.

Run with:  python3 -m unittest resources.test_audit_exclusions -v
       or:  cd resources && python3 -m unittest test_audit_exclusions -v

No real tmutil/xattr/defaults call is ever made here -- every subprocess.run
call is mocked. The one real filesystem I/O this suite does is inside a
tempfile.TemporaryDirectory it creates and tears down itself (for the
discover-job walk tests); it never touches a real Time Machine exclusion,
never sets or removes an xattr on a real path, and never shells out to a
real macOS tool. Written to close the gap the review flagged: parser and
failure-branch coverage existed only as runtime-pass claims in the lint
artifact, not as tests.
"""

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock as mock
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent / "audit_exclusions.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("audit_exclusions_under_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ae = _load_module()


def completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=["x"], returncode=returncode, stdout=stdout, stderr=stderr)


# =============================================================================
# Small pure helpers
# =============================================================================


class ClampTests(unittest.TestCase):
    def test_within_range(self):
        self.assertEqual(ae.clamp(2, 1, 4), 2)

    def test_below_range(self):
        self.assertEqual(ae.clamp(0, 1, 4), 1)

    def test_above_range(self):
        self.assertEqual(ae.clamp(99, 1, 4), 4)


class StripSepsTests(unittest.TestCase):
    def test_strips_field_and_record_separators(self):
        poisoned = "a" + ae.FS + "b" + ae.RS + "c"
        self.assertNotIn(ae.FS, ae.strip_seps(poisoned))
        self.assertNotIn(ae.RS, ae.strip_seps(poisoned))

    def test_non_string_passthrough(self):
        self.assertEqual(ae.strip_seps(None), None)


class RedactHomeTests(unittest.TestCase):
    """Finding 3: redaction must cover $HOME AND other accounts' home
    prefixes, while leaving a caller-supplied non-home path intact."""

    def test_home_path_redacted(self):
        with mock.patch.object(ae, "HOME", "/Users/demo"):
            self.assertEqual(ae.redact_home("/Users/demo/Documents/proj"), "~/Documents/proj")

    def test_other_account_username_redacted(self):
        with mock.patch.object(ae, "HOME", "/Users/demo"):
            out = ae.redact_home("/Users/otherperson/Shared/proj")
            self.assertNotIn("otherperson", out)
            self.assertEqual(out, "/Users/other-user/Shared/proj")

    def test_linux_other_home_redacted(self):
        with mock.patch.object(ae, "HOME", "/home/demo"):
            out = ae.redact_home("/home/bob/data")
            self.assertNotIn("bob", out)
            self.assertEqual(out, "/home/other-user/data")

    def test_non_home_path_passes_through(self):
        with mock.patch.object(ae, "HOME", "/Users/demo"):
            self.assertEqual(ae.redact_home("/Volumes/Backup/Projects"), "/Volumes/Backup/Projects")

    def test_empty_and_none(self):
        self.assertEqual(ae.redact_home(""), "")
        self.assertIsNone(ae.redact_home(None))


class UnpackPathsTests(unittest.TestCase):
    def test_well_formed_records(self):
        packed = ae.FS.join(["/a", "project"]) + ae.RS + ae.FS.join(["/b", "root-fixed"])
        parsed, dropped = ae.unpack_paths(packed, 2)
        self.assertEqual(parsed, [("/a", "project"), ("/b", "root-fixed")])
        self.assertEqual(dropped, 0)

    def test_malformed_record_dropped(self):
        packed = "/a" + ae.FS + "project" + ae.RS + "malformed-no-separator"
        parsed, dropped = ae.unpack_paths(packed, 2)
        self.assertEqual(parsed, [("/a", "project")])
        self.assertEqual(dropped, 1)

    def test_empty_path_field_dropped(self):
        packed = "" + ae.FS + "project"
        parsed, dropped = ae.unpack_paths(packed, 1)
        self.assertEqual(parsed, [])
        self.assertEqual(dropped, 1)

    def test_empty_packed(self):
        self.assertEqual(ae.unpack_paths("", 0), ([], 0))


class MatchesSkipPathTests(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(ae.matches_skip_path("/a/b", ["/a/b"]))

    def test_nested_match(self):
        self.assertTrue(ae.matches_skip_path("/a/b/c", ["/a/b"]))

    def test_trailing_slash_in_skip_entry(self):
        self.assertTrue(ae.matches_skip_path("/a/b/c", ["/a/b/"]))

    def test_sibling_prefix_is_not_a_match(self):
        # /a/bcd must not match skip prefix /a/b (no path separator boundary).
        self.assertFalse(ae.matches_skip_path("/a/bcd", ["/a/b"]))

    def test_no_match(self):
        self.assertFalse(ae.matches_skip_path("/x/y", ["/a/b"]))


class PlatformNoteTests(unittest.TestCase):
    def test_darwin_gets_no_note(self):
        with mock.patch.object(ae.platform, "system", return_value="Darwin"):
            system_name, note = ae.platform_note()
        self.assertEqual(system_name, "darwin")
        self.assertIsNone(note)

    def test_linux_gets_the_exact_stated_note(self):
        with mock.patch.object(ae.platform, "system", return_value="Linux"):
            system_name, note = ae.platform_note()
        self.assertEqual(system_name, "linux")
        self.assertEqual(note, "Time Machine is a macOS system")

    def test_other_platform_also_degrades(self):
        with mock.patch.object(ae.platform, "system", return_value="Windows"):
            system_name, note = ae.platform_note()
        self.assertEqual(system_name, "windows")
        self.assertEqual(note, "Time Machine is a macOS system")


# =============================================================================
# Deadline / timeout floor (Finding 7)
# =============================================================================


class RunTimeoutTests(unittest.TestCase):
    def test_timeout_floors_at_min_call_timeout(self):
        deadline_at = time.monotonic() + 0.5  # less than MIN_CALL_TIMEOUT_S remains
        with mock.patch.object(ae.subprocess, "run", return_value=completed()) as run_mock:
            ae.run(["true"], deadline_at, ae.TMUTIL_CEILING_S)
        self.assertEqual(run_mock.call_args.kwargs["timeout"], ae.MIN_CALL_TIMEOUT_S)

    def test_timeout_bounded_by_ceiling(self):
        deadline_at = time.monotonic() + 999  # plenty remains
        with mock.patch.object(ae.subprocess, "run", return_value=completed()) as run_mock:
            ae.run(["true"], deadline_at, ae.XATTR_CEILING_S)
        self.assertEqual(run_mock.call_args.kwargs["timeout"], ae.XATTR_CEILING_S)

    def test_no_time_left_raises_before_spawning(self):
        deadline_at = time.monotonic() - 1  # already past
        with mock.patch.object(ae.subprocess, "run") as run_mock:
            with self.assertRaises(TimeoutError):
                ae.run(["true"], deadline_at, ae.XATTR_CEILING_S)
        run_mock.assert_not_called()


# =============================================================================
# System SkipPaths (defaults export / plist parsing) -- Finding 6
# =============================================================================


class ReadSystemSkipPathsTests(unittest.TestCase):
    def _deadline(self):
        return time.monotonic() + 30

    def test_ok_with_skip_paths(self):
        plist_xml = (
            "<?xml version='1.0'?><!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' "
            "'http://www.apple.com/DTDs/PropertyList-1.0.dtd'><plist version='1.0'><dict>"
            "<key>SkipPaths</key><array><string>/Users/demo/node_modules</string></array>"
            "</dict></plist>"
        )
        with mock.patch.object(ae, "run", return_value=completed(stdout=plist_xml)):
            result = ae.read_system_skip_paths(self._deadline())
        self.assertEqual(result["state"], "ok")
        self.assertEqual(result["paths"], ["/Users/demo/node_modules"])

    def test_missing_skip_paths_key_is_healthy_empty(self):
        plist_xml = (
            "<?xml version='1.0'?><plist version='1.0'><dict></dict></plist>"
        )
        with mock.patch.object(ae, "run", return_value=completed(stdout=plist_xml)):
            result = ae.read_system_skip_paths(self._deadline())
        self.assertEqual(result, {"state": "ok", "paths": [], "detail": None})

    def test_nonzero_exit_degrades_only_this_source(self):
        with mock.patch.object(ae, "run", return_value=completed(returncode=1, stderr="boom")):
            result = ae.read_system_skip_paths(self._deadline())
        self.assertEqual(result["state"], "error")
        self.assertEqual(result["paths"], [])

    def test_timeout_degrades_only_this_source(self):
        with mock.patch.object(ae, "run", side_effect=subprocess.TimeoutExpired(cmd="defaults", timeout=10)):
            result = ae.read_system_skip_paths(self._deadline())
        self.assertEqual(result["state"], "error")
        self.assertIn("timed out", result["detail"])

    def test_truncated_xml_expat_error_is_caught_not_raised(self):
        """Regression test for finding 6: truncated XML previously escaped
        as xml.parsers.expat.ExpatError, uncaught by (ValueError, TypeError),
        and crashed run_check instead of degrading this source only."""
        truncated = '<?xml version="1.0"?><plist><dict>'
        with mock.patch.object(ae, "run", return_value=completed(stdout=truncated)):
            result = ae.read_system_skip_paths(self._deadline())  # must not raise
        self.assertEqual(result["state"], "error")
        self.assertEqual(result["paths"], [])

    def test_skip_paths_present_but_wrong_type(self):
        plist_xml = (
            "<?xml version='1.0'?><plist version='1.0'><dict>"
            "<key>SkipPaths</key><string>not-a-list</string></dict></plist>"
        )
        with mock.patch.object(ae, "run", return_value=completed(stdout=plist_xml)):
            result = ae.read_system_skip_paths(self._deadline())
        self.assertEqual(result["state"], "error")

    def test_deadline_already_passed_skips_without_spawning(self):
        with mock.patch.object(ae, "run") as run_mock:
            result = ae.read_system_skip_paths(time.monotonic() - 1)
        run_mock.assert_not_called()
        self.assertEqual(result["state"], "error")


# =============================================================================
# xattr checks
# =============================================================================


class CheckXattrTests(unittest.TestCase):
    def _deadline(self):
        return time.monotonic() + 30

    def test_present(self):
        with mock.patch.object(ae, "run", return_value=completed(returncode=0)):
            state, present, detail = ae.check_xattr("/a", self._deadline())
        self.assertEqual((state, present), ("ok", True))

    def test_absent_is_data_not_error(self):
        with mock.patch.object(ae, "run", return_value=completed(returncode=1, stderr="No such xattr: com.apple...")):
            state, present, detail = ae.check_xattr("/a", self._deadline())
        self.assertEqual((state, present, detail), ("ok", False, None))

    def test_path_vanished(self):
        with mock.patch.object(ae, "run", return_value=completed(returncode=1, stderr="No such file or directory")):
            state, present, detail = ae.check_xattr("/a", self._deadline())
        self.assertEqual((state, present), ("error", None))
        self.assertIn("no longer exists", detail)

    def test_other_error(self):
        with mock.patch.object(ae, "run", return_value=completed(returncode=13, stderr="Permission denied")):
            state, present, detail = ae.check_xattr("/a", self._deadline())
        self.assertEqual((state, present), ("error", None))

    def test_timeout(self):
        with mock.patch.object(ae, "run", side_effect=subprocess.TimeoutExpired(cmd="xattr", timeout=5)):
            state, present, detail = ae.check_xattr("/a", self._deadline())
        self.assertEqual((state, present), ("error", None))
        self.assertIn("timed out", detail)

    def test_deadline_already_passed_skips_without_spawning(self):
        with mock.patch.object(ae, "run") as run_mock:
            state, present, detail = ae.check_xattr("/a", time.monotonic() - 1)
        run_mock.assert_not_called()
        self.assertEqual(state, "error")


# =============================================================================
# tmutil batch parsing / correlation -- Finding 4
# =============================================================================


class RunTmutilBatchTests(unittest.TestCase):
    def _deadline(self):
        return time.monotonic() + 30

    def test_positional_correlation_survives_path_canonicalization(self):
        """Regression test for finding 4: tmutil echoes back /private/tmp for
        an input of /tmp (symlink canonicalization). Exact-string matching
        would report /tmp unknown despite a valid answer; positional
        matching must not."""
        paths = ["/tmp", "/definitely/not/a/real/path"]
        stdout = "[Included] /private/tmp\n[UNKNOWN] /definitely/not/a/real/path\n"
        with mock.patch.object(ae, "run", return_value=completed(stdout=stdout)):
            states, err = ae.run_tmutil_batch(paths, self._deadline())
        self.assertIsNone(err)
        self.assertEqual(states, {"/tmp": "Included", "/definitely/not/a/real/path": "UNKNOWN"})

    def test_ordinary_batch(self):
        paths = ["/a", "/b", "/c"]
        stdout = "[Included] /a\n[Excluded] /b\n[UNKNOWN] /c\n"
        with mock.patch.object(ae, "run", return_value=completed(stdout=stdout)):
            states, err = ae.run_tmutil_batch(paths, self._deadline())
        self.assertIsNone(err)
        self.assertEqual(states, {"/a": "Included", "/b": "Excluded", "/c": "UNKNOWN"})

    def test_nonzero_exit_code_is_not_trusted_stdout_still_parsed(self):
        paths = ["/a"]
        with mock.patch.object(ae, "run", return_value=completed(stdout="[Included] /a\n", returncode=1)):
            states, err = ae.run_tmutil_batch(paths, self._deadline())
        self.assertIsNone(err)
        self.assertEqual(states, {"/a": "Included"})

    def test_line_count_mismatch_degrades_whole_batch_never_guesses(self):
        paths = ["/a", "/b", "/c"]
        stdout = "[Included] /a\n[Excluded] /b\n"  # only 2 lines for 3 paths
        with mock.patch.object(ae, "run", return_value=completed(stdout=stdout)):
            states, err = ae.run_tmutil_batch(paths, self._deadline())
        self.assertIsNone(states)
        self.assertIn("positional correlation is not safe", err)

    def test_unexpected_output_format_yields_zero_parsed_lines(self):
        paths = ["/a"]
        with mock.patch.object(ae, "run", return_value=completed(stdout="garbage, no brackets here\n")):
            states, err = ae.run_tmutil_batch(paths, self._deadline())
        self.assertIsNone(states)
        self.assertIn("0 status line(s)", err)

    def test_timeout(self):
        with mock.patch.object(ae, "run", side_effect=subprocess.TimeoutExpired(cmd="tmutil", timeout=20)):
            states, err = ae.run_tmutil_batch(["/a"], self._deadline())
        self.assertIsNone(states)
        self.assertIn("timed out", err)

    def test_deadline_already_passed_skips_without_spawning(self):
        with mock.patch.object(ae, "run") as run_mock:
            states, err = ae.run_tmutil_batch(["/a"], time.monotonic() - 1)
        run_mock.assert_not_called()
        self.assertIsNone(states)


# =============================================================================
# Inherited ancestor lookup -- Finding 5
# =============================================================================


class FindInheritedAncestorTests(unittest.TestCase):
    def _deadline(self):
        return time.monotonic() + 30

    def test_finds_ancestor_that_carries_the_xattr(self):
        with mock.patch.object(ae, "HOME", "/Users/demo"):
            path = "/Users/demo/Documents/proj/sub/deep"

            def fake_check_xattr(candidate, deadline_at):
                if candidate == "/Users/demo/Documents/proj":
                    return "ok", True, None
                return "ok", False, None

            with mock.patch.object(ae, "check_xattr", side_effect=fake_check_xattr):
                result = ae.find_inherited_ancestor(path, self._deadline())
        self.assertEqual(result, "~/Documents/proj")

    def test_stops_at_first_ancestor_found_never_climbs_further(self):
        calls = []

        with mock.patch.object(ae, "HOME", "/Users/demo"):
            path = "/Users/demo/Documents/proj/sub/deep"

            def fake_check_xattr(candidate, deadline_at):
                calls.append(candidate)
                return "ok", candidate == "/Users/demo/Documents/proj/sub", None

            with mock.patch.object(ae, "check_xattr", side_effect=fake_check_xattr):
                result = ae.find_inherited_ancestor(path, self._deadline())
        self.assertEqual(result, "~/Documents/proj/sub")
        self.assertEqual(calls, ["/Users/demo/Documents/proj/sub"])  # never climbed to proj or Documents

    def test_no_ancestor_found_returns_none_and_stops_at_home(self):
        with mock.patch.object(ae, "HOME", "/Users/demo"):
            path = "/Users/demo/Documents/proj/sub"
            with mock.patch.object(ae, "check_xattr", return_value=("ok", False, None)) as xattr_mock:
                result = ae.find_inherited_ancestor(path, self._deadline())
        self.assertIsNone(result)
        # HOME itself is never probed -- reporting "your whole home
        # directory is excluded" is out of scope for this label.
        probed = {call.args[0] for call in xattr_mock.call_args_list}
        self.assertNotIn("/Users/demo", probed)

    def test_deadline_exhausted_mid_walk_returns_none(self):
        with mock.patch.object(ae, "HOME", "/Users/demo"):
            path = "/Users/demo/Documents/proj/sub"
            result = ae.find_inherited_ancestor(path, time.monotonic() - 1)
        self.assertIsNone(result)

    def test_respects_max_levels_bound(self):
        with mock.patch.object(ae, "HOME", "/"):
            deep = "/" + "/".join(f"lvl{i}" for i in range(ae.ANCESTOR_LOOKUP_MAX_LEVELS + 5))
            with mock.patch.object(ae, "check_xattr", return_value=("ok", False, None)) as xattr_mock:
                result = ae.find_inherited_ancestor(deep, self._deadline())
        self.assertIsNone(result)
        self.assertLessEqual(xattr_mock.call_count, ae.ANCESTOR_LOOKUP_MAX_LEVELS)


# =============================================================================
# run_check end-to-end (mocked subprocess + platform) -- Finding 8 scenarios
# =============================================================================


class RunCheckIntegrationTests(unittest.TestCase):
    def _run_check_with(self, argv_tail, subprocess_side_effect, platform_system="Darwin"):
        argv = ["audit_exclusions.py", "check"] + argv_tail
        stdout_buf = io.StringIO()
        with mock.patch.object(ae.sys, "argv", argv), \
             mock.patch.object(ae.platform, "system", return_value=platform_system), \
             mock.patch.object(ae.subprocess, "run", side_effect=subprocess_side_effect), \
             contextlib.redirect_stdout(stdout_buf):
            ae.run_check()
        return json.loads(stdout_buf.getvalue())

    def test_linux_short_circuits_with_no_subprocess_calls(self):
        argv = ["audit_exclusions.py", "check", "", ""]
        stdout_buf = io.StringIO()
        with mock.patch.object(ae.sys, "argv", argv), \
             mock.patch.object(ae.platform, "system", return_value="Linux"), \
             mock.patch.object(ae.subprocess, "run") as run_mock, \
             contextlib.redirect_stdout(stdout_buf):
            ae.run_check()
        run_mock.assert_not_called()
        report = json.loads(stdout_buf.getvalue())
        self.assertTrue(report["ok"])
        self.assertEqual(report["platform"], "linux")
        self.assertEqual(report["note"], "Time Machine is a macOS system")
        self.assertEqual(report["excluded_rows"], [])

    def test_total_tmutil_unavailable(self):
        packed = "/a" + ae.FS + "project" + ae.RS + "/b" + ae.FS + "project"

        def side_effect(argv, capture_output, text, timeout):
            if argv[0] == "tmutil":
                return completed(stdout="[UNKNOWN] /a\n[UNKNOWN] /b\n")
            if argv[0] == "xattr":
                return completed(returncode=1, stderr="No such xattr")
            if argv[0] == "defaults":
                return completed(stdout="<?xml version='1.0'?><plist><dict></dict></plist>")
            raise AssertionError("unexpected command: " + repr(argv))

        report = self._run_check_with([packed, "2"], side_effect)
        self.assertTrue(report["tmutil_unavailable"])
        self.assertEqual(report["excluded_count"], 0)
        self.assertEqual(report["unknown_count"], 2)

    def test_partial_unknown_with_zero_exclusions(self):
        """Presentation-equivalent scenario the review asked be covered:
        zero excluded but not a clean run -- some paths unresolved."""
        packed = "/a" + ae.FS + "project" + ae.RS + "/b" + ae.FS + "project"

        def side_effect(argv, capture_output, text, timeout):
            if argv[0] == "tmutil":
                return completed(stdout="[Included] /a\n[UNKNOWN] /b\n")
            if argv[0] == "xattr":
                return completed(returncode=1, stderr="No such xattr")
            if argv[0] == "defaults":
                return completed(stdout="<?xml version='1.0'?><plist><dict></dict></plist>")
            raise AssertionError("unexpected command: " + repr(argv))

        report = self._run_check_with([packed, "2"], side_effect)
        self.assertFalse(report["tmutil_unavailable"])
        self.assertEqual(report["excluded_count"], 0)
        self.assertEqual(report["unknown_count"], 1)

    def test_inherited_sticky_xattr_labeling_end_to_end(self):
        packed = "/Users/demo/Documents/proj/child" + ae.FS + "project"

        def side_effect(argv, capture_output, text, timeout):
            if argv[0] == "tmutil":
                return completed(stdout="[Excluded] /Users/demo/Documents/proj/child\n")
            if argv[0] == "xattr":
                path = argv[-1]
                if path == "/Users/demo/Documents/proj":
                    return completed(returncode=0)  # ancestor carries the xattr
                return completed(returncode=1, stderr="No such xattr")
            if argv[0] == "defaults":
                return completed(stdout="<?xml version='1.0'?><plist><dict></dict></plist>")
            raise AssertionError("unexpected command: " + repr(argv))

        with mock.patch.object(ae, "HOME", "/Users/demo"):
            report = self._run_check_with([packed, "1"], side_effect)
        self.assertEqual(report["excluded_count"], 1)
        row = report["excluded_rows"][0]
        self.assertEqual(row["exclusion_source"], "inherited-sticky-xattr")
        self.assertEqual(row["inherited_from"], "~/Documents/proj")

    def test_own_item_sticky_xattr_wins_over_ancestor_lookup(self):
        packed = "/Users/demo/Documents/proj" + ae.FS + "project"

        def side_effect(argv, capture_output, text, timeout):
            if argv[0] == "tmutil":
                return completed(stdout="[Excluded] /Users/demo/Documents/proj\n")
            if argv[0] == "xattr":
                return completed(returncode=0)  # present on the item itself
            if argv[0] == "defaults":
                return completed(stdout="<?xml version='1.0'?><plist><dict></dict></plist>")
            raise AssertionError("unexpected command: " + repr(argv))

        with mock.patch.object(ae, "HOME", "/Users/demo"):
            report = self._run_check_with([packed, "1"], side_effect)
        row = report["excluded_rows"][0]
        self.assertEqual(row["exclusion_source"], "sticky-xattr")
        self.assertIsNone(row["inherited_from"])

    def test_batch_split_across_multiple_tmutil_calls(self):
        n = ae.BATCH_SIZE + 5
        records = [(f"/p{i}" + ae.FS + "project") for i in range(n)]
        packed = ae.RS.join(records)
        seen_batches = []

        def side_effect(argv, capture_output, text, timeout):
            if argv[0] == "tmutil":
                batch_paths = argv[2:]
                seen_batches.append(len(batch_paths))
                lines = "".join(f"[Included] {p}\n" for p in batch_paths)
                return completed(stdout=lines)
            if argv[0] == "xattr":
                return completed(returncode=1, stderr="No such xattr")
            if argv[0] == "defaults":
                return completed(stdout="<?xml version='1.0'?><plist><dict></dict></plist>")
            raise AssertionError("unexpected command: " + repr(argv))

        report = self._run_check_with([packed, str(n)], side_effect)
        self.assertEqual(report["paths_checked"], n)
        self.assertEqual(sum(seen_batches), n)
        self.assertEqual(len(seen_batches), 2)  # BATCH_SIZE+5 -> two batches
        for size in seen_batches:
            self.assertLessEqual(size, ae.BATCH_SIZE)

    def test_malformed_record_count_mismatch_warns(self):
        packed = "/a" + ae.FS + "project"  # one record, expected_total says 3

        def side_effect(argv, capture_output, text, timeout):
            if argv[0] == "tmutil":
                return completed(stdout="[Included] /a\n")
            if argv[0] == "xattr":
                return completed(returncode=1, stderr="No such xattr")
            if argv[0] == "defaults":
                return completed(stdout="<?xml version='1.0'?><plist><dict></dict></plist>")
            raise AssertionError("unexpected command: " + repr(argv))

        report = self._run_check_with([packed, "3"], side_effect)
        self.assertIsNotNone(report["warning"])
        self.assertIn("discover reported 3", report["warning"])


# =============================================================================
# run_discover -- Finding 3/8 (walk boundaries, caps, redaction)
# =============================================================================


class RunDiscoverIntegrationTests(unittest.TestCase):
    def _run_discover_with(self, base_dir, max_depth, platform_system="Darwin", home=None):
        argv = ["audit_exclusions.py", "discover", base_dir, str(max_depth)]
        stdout_buf = io.StringIO()
        patches = [
            mock.patch.object(ae.sys, "argv", argv),
            mock.patch.object(ae.platform, "system", return_value=platform_system),
        ]
        if home is not None:
            patches.append(mock.patch.object(ae, "HOME", home))
        # Neutralize the fixed-roots/dev-dir probes so a real developer
        # machine's actual ~/Documents etc. never leaks into a test's
        # assertions -- discover job never shells out, so nothing here
        # mocks subprocess; only os.path.isdir is guided.
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            with contextlib.redirect_stdout(stdout_buf):
                ae.run_discover()
        return json.loads(stdout_buf.getvalue())

    def test_linux_short_circuits(self):
        report = self._run_discover_with("~/Documents", 2, platform_system="Linux")
        self.assertTrue(report["ok"])
        self.assertEqual(report["note"], "Time Machine is a macOS system")
        self.assertEqual(report["paths_packed"], "")

    def test_missing_base_dir_warns_but_still_probes_fixed_roots(self):
        with tempfile.TemporaryDirectory() as home_dir:
            missing_base = os.path.join(home_dir, "does-not-exist")
            report = self._run_discover_with(missing_base, 2, home=home_dir)
        self.assertIn("does not exist", report["warning"])
        self.assertEqual(report["projects_found"], 0)

    def test_project_marker_stops_descent(self):
        with tempfile.TemporaryDirectory() as base:
            repo = os.path.join(base, "repo")
            os.makedirs(os.path.join(repo, ".git"))
            # A marker one level DEEPER than the found project dir must never
            # be discovered as a second, separate project -- the walk must
            # not descend into `repo` once `.git` is found there.
            nested_marker_dir = os.path.join(repo, "nested")
            os.makedirs(os.path.join(nested_marker_dir, "package.json"))  # dir named package.json is fine as a marker-name probe
            report = self._run_discover_with(base, 4, home=base)
        self.assertEqual(report["projects_found"], 1)

    def test_max_projects_cap_reported_as_truncated(self):
        with tempfile.TemporaryDirectory() as base:
            for i in range(5):
                os.makedirs(os.path.join(base, f"repo{i}", ".git"))
            with mock.patch.object(ae, "MAX_PROJECTS", 2):
                report = self._run_discover_with(base, 2, home=base)
        self.assertTrue(report["truncated"])
        self.assertEqual(report["projects_found"], 2)
        self.assertIn("cap", report["warning"])

    def test_base_display_is_redacted(self):
        with tempfile.TemporaryDirectory() as base:
            report = self._run_discover_with(base, 2, home=base)
        self.assertTrue(report["base_display"].startswith("~"))
        self.assertNotIn(base, report["base_display"])


if __name__ == "__main__":
    unittest.main()
