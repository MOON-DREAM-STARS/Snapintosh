#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline refusal/decoder tests; synthetic inputs are not hardware results."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
TOOL = Path(__file__).with_name("check-ego-capabilities.py")
SPEC = importlib.util.spec_from_file_location("ego_capabilities", TOOL)
CAPS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPS)


def evidence(registers=None, provenance="synthetic", **extra):
    result = {"schema_version": 1, "provenance": provenance,
              "registers": {} if registers is None else registers}
    result.update(extra)
    return result


def feature(data, name):
    return CAPS.assess_capabilities(data)["features"][name]


class GranuleTests(unittest.TestCase):
    def view(self, s1, s2, **extra):
        return evidence({"ID_AA64MMFR0_EL1": (s1 << 20) | (s2 << 32)}, **extra)

    def test_stage2_zero_inherits_stage1(self):
        self.assertEqual(feature(self.view(1, 0), "granule16_s2")["status"], "present")
        self.assertEqual(feature(self.view(0, 0), "granule16_s2")["status"], "absent")

    def test_stage2_one_is_absent_not_supported(self):
        data = self.view(1, 1)
        self.assertEqual(feature(data, "granule16_s1")["status"], "present")
        self.assertEqual(feature(data, "granule16_s2")["status"], "absent")

    def test_stage2_independent_support_and_52_bit(self):
        for encoding in (2, 3):
            with self.subTest(encoding=encoding):
                data = self.view(0, encoding)
                self.assertEqual(feature(data, "granule16_s2")["status"], "present")
                self.assertEqual(feature(data, "granule16_s1")["status"], "absent")

    def test_reserved_stage2_is_unknown(self):
        for encoding in range(4, 16):
            self.assertEqual(feature(self.view(1, encoding), "granule16_s2")["status"], "unknown")

    def test_reserved_stage1_is_unknown(self):
        for encoding in range(3, 16):
            self.assertEqual(feature(self.view(encoding, 0), "granule16_s2")["status"], "unknown")

    def test_stage2_inheritance_needs_unmasked_stage1(self):
        mask = ["ID_AA64MMFR0_EL1.TGran16"]
        self.assertEqual(feature(self.view(1, 0, masked_fields=mask), "granule16_s2")["status"], "unknown")
        self.assertEqual(feature(self.view(1, 2, masked_fields=mask), "granule16_s2")["status"], "present")

    def test_native_granule_is_not_a_shadow_backend_gate(self):
        report = CAPS.assess_capabilities(self.view(0, 1))
        self.assertNotIn("granule16_s1", report["backend"]["reported_blockers"])
        self.assertNotIn("granule16_s2", report["backend"]["reported_blockers"])


class FeatureTests(unittest.TestCase):
    def test_nv2_legacy_encoding(self):
        data = evidence({"ID_AA64MMFR2_EL1": 2 << 24})
        self.assertEqual(feature(data, "nv2")["status"], "present")

    def test_nv2_only_uses_bit20_with_nv_zero(self):
        for fraction in (1, 2, 3):
            data = evidence({"ID_AA64MMFR2_EL1": 0,
                             "ID_AA64MMFR4_EL1": fraction << 20})
            self.assertEqual(feature(data, "nv2")["status"], "present")

    def test_e2h0_does_not_invent_nv2(self):
        data = evidence({"ID_AA64MMFR2_EL1": 1 << 24,
                         "ID_AA64MMFR4_EL1": 15 << 24})
        self.assertEqual(feature(data, "nv")["status"], "present")
        self.assertEqual(feature(data, "nv2")["status"], "absent")

    def test_nv_zero_requires_fraction_evidence(self):
        data = evidence({"ID_AA64MMFR2_EL1": 0})
        self.assertEqual(feature(data, "nv2")["status"], "unknown")
        data["registers"]["ID_AA64MMFR4_EL1"] = 0
        self.assertEqual(feature(data, "nv2")["status"], "absent")

    def test_inconsistent_or_reserved_nested_encoding_is_unknown(self):
        for nv, fraction in ((1, 1), (2, 1), (3, 0), (0, 15)):
            data = evidence({"ID_AA64MMFR2_EL1": nv << 24,
                             "ID_AA64MMFR4_EL1": fraction << 20})
            self.assertEqual(feature(data, "nv2")["status"], "unknown")

    def test_pauth_isar2_algorithms(self):
        data = evidence({"ID_AA64ISAR1_EL1": 0,
                         "ID_AA64ISAR2_EL1": (5 << 12) | (1 << 8)})
        self.assertEqual(feature(data, "address_pauth")["status"], "present")
        self.assertEqual(feature(data, "generic_pauth")["status"], "present")

    def test_pauth_missing_alternative_is_not_zero(self):
        data = evidence({"ID_AA64ISAR1_EL1": 0})
        self.assertEqual(feature(data, "address_pauth")["status"], "unknown")
        self.assertEqual(feature(data, "generic_pauth")["status"], "unknown")
        data["registers"]["ID_AA64ISAR2_EL1"] = 0
        self.assertEqual(feature(data, "address_pauth")["status"], "absent")

    def test_reserved_pauth_is_not_assumed_supported(self):
        data = evidence({"ID_AA64ISAR1_EL1": 15 << 4, "ID_AA64ISAR2_EL1": 0})
        self.assertEqual(feature(data, "address_pauth")["status"], "unknown")

    def test_ssbs_level_one_is_not_ssbs2(self):
        data = evidence({"ID_AA64PFR1_EL1": 1 << 4})
        self.assertEqual(feature(data, "ssbs")["status"], "present")
        self.assertEqual(feature(data, "ssbs2")["status"], "absent")

    def test_tlbi_outer_shareable_is_not_range(self):
        self.assertEqual(feature(evidence({"ID_AA64ISAR0_EL1": 1 << 56}), "tlbi_range")["status"], "absent")
        self.assertEqual(feature(evidence({"ID_AA64ISAR0_EL1": 2 << 56}), "tlbi_range")["status"], "present")

    def test_rng_ecv_and_dit_bit_locations(self):
        data = evidence({"ID_AA64ISAR0_EL1": (1 << 60) | (1 << 32),
                         "ID_AA64MMFR0_EL1": 2 << 60,
                         "ID_AA64PFR0_EL1": 1 << 48})
        for name in ("rndr", "ecv", "sha3", "dit"):
            self.assertEqual(feature(data, name)["status"], "present")

    def test_dczid_requires_the_pinned_exact_geometry(self):
        self.assertEqual(feature(evidence({"DCZID_EL0": 4}), "dc_zva_64")["status"], "present")
        for value in (0, 5, 20):
            self.assertEqual(feature(evidence({"DCZID_EL0": value}), "dc_zva_64")["status"], "absent")


class ProvenanceTests(unittest.TestCase):
    def test_filtered_absence_never_claims_host_absence(self):
        registers = {name: 0 for name in CAPS.REGISTERS}
        for provenance in CAPS.FILTERED_VIEWS:
            report = CAPS.assess_capabilities(evidence(registers, provenance))
            self.assertEqual(report["backend"]["reported_blockers"], [])
            self.assertEqual(report["features"]["rndr"]["status"], "unknown")
            self.assertEqual(report["features"]["rndr"]["reported"], "absent")

    def test_explicit_mask_overrides_positive_values(self):
        data = evidence({"ID_AA64MMFR0_EL1": 1 << 60}, "linux_sanitized",
                        masked_fields=["ID_AA64MMFR0_EL1.ECV"])
        result = feature(data, "ecv")
        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["fields"]["ID_AA64MMFR0_EL1.ECV"])

    def test_linux_hidden_fields_are_unknown_even_when_positive(self):
        data = evidence({"ID_AA64PFR0_EL1": (1 << 48) | (1 << 8),
                         "ID_AA64PFR1_EL1": 2 << 4,
                         "ID_AA64ISAR0_EL1": (1 << 60) | (2 << 56) | (1 << 32),
                         "ID_AA64ISAR1_EL1": (1 << 24) | (3 << 4),
                         "ID_AA64MMFR0_EL1": (1 << 60) | (2 << 32) | (1 << 20),
                         "ID_AA64MMFR1_EL1": 1 << 20,
                         "ID_AA64MMFR2_EL1": 2 << 24,
                         "ID_AA64MMFR4_EL1": 0}, "linux_sanitized")
        report = CAPS.assess_capabilities(data)
        for name in ("nv", "nv2", "granule16_s1", "granule16_s2", "pan", "el2_advertised", "tlbi_range"):
            self.assertEqual(report["features"][name]["status"], "unknown")
        for name in ("ecv", "rndr", "address_pauth", "generic_pauth", "dit", "sha3", "ssbs", "ssbs2"):
            self.assertEqual(report["features"][name]["status"], "present")
        self.assertEqual(set(report["automatically_masked_fields"]), CAPS.LINUX_HIDDEN_FIELDS)

    def test_public_windows_sample_is_only_a_visible_view(self):
        # Public numeric measurements, not copied GPL source or a new capture:
        # https://github.com/VirtualBox/virtualbox/commit/2f36df7749e6228e72bbcc675883a4b77b69f66a
        data = evidence({"ID_AA64ISAR0_EL1": "0x0010100010211120",
                         "ID_AA64ISAR1_EL1": "0x0000000001200031",
                         "ID_AA64MMFR0_EL1": "0x0000011100101022",
                         "ID_AA64MMFR2_EL1": "0x0000000100001011",
                         "ID_AA64PFR0_EL1": "0x1100000011111112",
                         "ID_AA64PFR1_EL1": "0x10"}, "windows_visible")
        report = CAPS.assess_capabilities(data)
        for name in ("rndr", "ecv", "nv2", "granule16_s2", "ssbs2", "dit", "sha3", "tlbi_range"):
            self.assertEqual(report["features"][name]["status"], "unknown")
        for name in ("address_pauth", "generic_pauth", "granule16_s1", "ssbs"):
            self.assertEqual(report["features"][name]["status"], "present")
        self.assertEqual(report["evidence_scope"], "filtered_view_only")

    def test_no_positive_register_set_can_qualify_a_machine(self):
        registers = {"ID_AA64PFR0_EL1": (1 << 48) | (1 << 8),
                     "ID_AA64PFR1_EL1": 2 << 4,
                     "ID_AA64ISAR0_EL1": (1 << 60) | (2 << 56) | (1 << 32),
                     "ID_AA64ISAR1_EL1": (1 << 24) | (3 << 4),
                     "ID_AA64ISAR2_EL1": 0,
                     "ID_AA64MMFR0_EL1": (1 << 60) | (2 << 32) | (1 << 20),
                     "ID_AA64MMFR1_EL1": 1 << 20,
                     "ID_AA64MMFR2_EL1": 2 << 24,
                     "ID_AA64MMFR4_EL1": 0, "DCZID_EL0": 4, "CNTFRQ_EL0": 19200000}
        for provenance in CAPS.PROVENANCES - {"uefi_el1"}:
            report = CAPS.assess_capabilities(evidence(registers, provenance, execution_el=2))
            self.assertEqual(report["backend"]["reported_blockers"], [])
            self.assertEqual(report["backend"]["assessment"], "not_qualified")
            self.assertEqual(report["hardware_status"], "NOT RUN")
            self.assertNotIn("boot_allowed", json.dumps(report))

    def test_documentation_and_synthetic_scopes_are_explicit(self):
        for provenance, scope in (("documentation", "reference_only"), ("synthetic", "synthetic_only")):
            report = CAPS.assess_capabilities(evidence({"ID_AA64ISAR0_EL1": 0}, provenance))
            self.assertEqual(report["evidence_scope"], scope)
            self.assertEqual(report["hardware_status"], "NOT RUN")

    def test_missing_null_and_zero_remain_distinct(self):
        for registers in ({}, {"ID_AA64ISAR0_EL1": None}):
            self.assertEqual(feature(evidence(registers), "rndr")["status"], "unknown")
        self.assertEqual(feature(evidence({"ID_AA64ISAR0_EL1": 0}), "rndr")["status"], "absent")


class InputTests(unittest.TestCase):
    def test_valid_normalization_does_not_mutate_input(self):
        original = evidence({"ID_AA64ISAR0_EL1": "0x1000000000000000"})
        before = copy.deepcopy(original)
        parsed = CAPS.parse_evidence(json.dumps(original))
        self.assertEqual(parsed["registers"]["ID_AA64ISAR0_EL1"], 1 << 60)
        CAPS.assess_capabilities(original)
        self.assertEqual(original, before)

    def test_invalid_values_do_not_leak(self):
        secret = "PRIVATE_EXAMPLE_DO_NOT_ECHO"
        bad = [True, False, -1, 1 << 64, 1.5, "1234", "0x", "0x" + "f" * 17, secret, []]
        for value in bad:
            with self.assertRaises(CAPS.EvidenceError) as caught:
                CAPS.assess_capabilities(evidence({"ID_AA64ISAR0_EL1": value}))
            self.assertNotIn(secret, str(caught.exception))

    def test_schema_rejects_unknown_content(self):
        bad = [[], {}, evidence(provenance="private-secret"),
               evidence({"private-secret": "private-secret"}),
               evidence(masked_fields=["private-secret"]), evidence(execution_el=True),
               evidence(provenance="raw_el2", execution_el=1),
               evidence(provenance="uefi_el1", execution_el=2)]
        extra = evidence()
        extra["private-secret"] = "private-secret"
        bad.append(extra)
        for data in bad:
            with self.assertRaises(CAPS.EvidenceError) as caught:
                CAPS.assess_capabilities(data)
            self.assertNotIn("private-secret", str(caught.exception))

    def test_duplicate_members_and_nonfinite_values_are_refused(self):
        for text in ('{"schema_version":1,"schema_version":1}',
                     '{"schema_version":NaN}', '{"schema_version":Infinity}'):
            with self.assertRaises(CAPS.EvidenceError):
                CAPS.parse_evidence(text)

    def test_malformed_and_oversized_input_are_refused(self):
        for text in ("PRIVATE_EXAMPLE_DO_NOT_ECHO", "[" * 2000,
                     " " * (CAPS.MAX_INPUT_BYTES + 1)):
            with self.assertRaises(CAPS.EvidenceError) as caught:
                CAPS.parse_evidence(text)
            self.assertNotIn("PRIVATE_EXAMPLE_DO_NOT_ECHO", str(caught.exception))

    def test_isolated_surrogates_raise_a_fixed_evidence_error(self):
        for text in ("\ud800", "\udfff", "PRIVATE_EXAMPLE_DO_NOT_ECHO\ud800"):
            with self.assertRaises(CAPS.EvidenceError) as caught:
                CAPS.parse_evidence(text)
            self.assertEqual(str(caught.exception), "input is not valid UTF-8 JSON")

    def test_mask_list_is_strict(self):
        field = "ID_AA64MMFR0_EL1.ECV"
        for masks in (field, [field, field], [None], [{}]):
            with self.assertRaises(CAPS.EvidenceError):
                CAPS.assess_capabilities(evidence(masked_fields=masks))


class CliTests(unittest.TestCase):
    def run_tool(self, raw, *args):
        return subprocess.run([sys.executable, "-B", str(TOOL), *args], input=raw,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    def test_stdin_json_review_is_not_a_qualification(self):
        result = self.run_tool(json.dumps(evidence()).encode(), "--input", "-")
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertEqual(report["backend"]["assessment"], "not_qualified")
        self.assertEqual(report["hardware_status"], "NOT RUN")

    def test_text_output_and_exit_mean_review_only(self):
        result = self.run_tool(json.dumps(evidence()).encode(), "--input", "-", "--format", "text")
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"NOT QUALIFIED", result.stdout)
        self.assertIn(b"Hardware status: NOT RUN", result.stdout)

    def test_cli_does_not_echo_secrets_or_paths(self):
        secret = b"PRIVATE_EXAMPLE_DO_NOT_ECHO"
        cases = [self.run_tool(secret, "--input", "-"),
                 self.run_tool(b"\xff", "--input", "-"),
                 self.run_tool(b"", "--input", "/PRIVATE_EXAMPLE_DO_NOT_ECHO/absent.json"),
                 self.run_tool(b"", "--private-secret", secret.decode())]
        for result in cases:
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(secret, result.stdout + result.stderr)
            self.assertNotIn(b"Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
