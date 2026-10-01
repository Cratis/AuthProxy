# Copyright (c) Cratis. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.

"""Regression specs for the actual Bash probe displayed in the Azure guide.

Run: python3 -B -m unittest discover -s Documentation/azure/specs -v
"""

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


class BackendIsolationSpecs(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        guide = (Path(__file__).parents[1] / "index.md").read_text()
        script = re.search(r"```bash\n(#!/usr/bin/env bash\n.*?)\n```", guide, re.S)
        self.assertIsNotNone(script)
        self.probe = self.root / "probe.sh"
        self.probe.write_text(script.group(1) + "\n")
        curl = self.root / "curl"
        curl.write_text(
            f"#!{sys.executable}\n"
            "import os, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "pathlib.Path(args[args.index('-o') + 1]).write_text(os.environ['PROBE_BODY'])\n"
            "sys.stdout.write(os.environ['PROBE_STATUS'])\n"
            "sys.exit(int(os.environ['PROBE_EXIT']))\n"
        )
        curl.chmod(0o700)

    def run_probe(self, targets=None, status="000", exit_code=0, body=""):
        if targets is None:
            targets = ["https://backend.example/probe"]
        env = dict(os.environ, PATH=f"{self.root}:{os.environ['PATH']}",
                   PROBE_STATUS=status, PROBE_EXIT=str(exit_code), PROBE_BODY=body)
        return subprocess.run(["bash", str(self.probe), *targets], env=env,
                              text=True, capture_output=True, timeout=5)

    def test_no_targets_fails(self):
        self.assertNotEqual(self.run_probe(targets=[]).returncode, 0)

    def test_dns_and_connection_failures_pass_without_http_response(self):
        for exit_code in (6, 7):
            with self.subTest(exit_code=exit_code):
                self.assertEqual(self.run_probe(exit_code=exit_code).returncode, 0)

    def test_indeterminate_transport_failures_fail(self):
        for exit_code in (0, 5, 18, 28, 35, 60):
            with self.subTest(exit_code=exit_code):
                self.assertNotEqual(self.run_probe(exit_code=exit_code).returncode, 0)

    def test_every_http_response_fails_by_default(self):
        for status in ("200", "204", "302", "401", "403", "404", "500"):
            with self.subTest(status=status):
                self.assertNotEqual(self.run_probe(status=status).returncode, 0)

    def test_status_is_preserved_when_body_times_out(self):
        result = self.run_probe(status="200", exit_code=28)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTP 200, curl 28", result.stderr)

    def test_http_response_cannot_pass_as_connection_failure(self):
        self.assertNotEqual(self.run_probe(status="200", exit_code=7).returncode, 0)

    def test_expected_status_and_literal_platform_marker_pass(self):
        for status in ("401", "403", "404"):
            with self.subTest(status=status):
                target = f"https://backend.example/probe|{status}|platform [denial]"
                result = self.run_probe([target], status=status, body="<p>platform [denial]</p>")
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_application_denial_does_not_match_platform_marker(self):
        target = "https://backend.example/probe|403|platform denial"
        result = self.run_probe([target], status="403", body="Application: Forbidden")
        self.assertNotEqual(result.returncode, 0)

    def test_platform_marker_with_wrong_status_fails(self):
        target = "https://backend.example/probe|403|platform denial"
        self.assertNotEqual(self.run_probe([target], status="404", body="platform denial").returncode, 0)

    def test_matching_denial_with_incomplete_transfer_fails(self):
        target = "https://backend.example/probe|403|platform denial"
        result = self.run_probe([target], status="403", exit_code=28, body="platform denial")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTP 403, curl 28", result.stderr)

    def test_malformed_or_unsafe_expectations_fail(self):
        for suffix in ("403", "403|", "000|marker", "200|marker", "500|marker", "403|a|b"):
            with self.subTest(suffix=suffix):
                result = self.run_probe([f"https://backend.example/probe|{suffix}"], exit_code=7)
                self.assertNotEqual(result.returncode, 0)

    def test_one_failing_target_fails_the_whole_probe(self):
        targets = ["https://first.example/probe|403|platform denial", "https://second.example/probe"]
        self.assertNotEqual(self.run_probe(targets, status="403", body="platform denial").returncode, 0)

    def test_one_invalid_target_is_not_hidden_by_a_later_pass(self):
        targets = ["https://first.example/probe|403", "https://second.example/probe"]
        self.assertNotEqual(self.run_probe(targets, exit_code=7).returncode, 0)


if __name__ == "__main__":
    unittest.main()
