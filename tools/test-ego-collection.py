#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host tests for inventory privacy and the KVM query boundary.

Run: python3 tools/test-ego-collection.py

All arm64/KVM cases are injected fixtures. These tests do not operate on /dev/kvm
or test MateBook hardware. The PowerShell collector requires separate Windows
validation and is not represented as tested by this suite.
"""

import errno
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest


MODULE_PATH = Path(__file__).with_name("collect-ego-linux.py")
SPEC = importlib.util.spec_from_file_location("ego_linux_collector", MODULE_PATH)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class FakeFiles(collector.ReadOnlyFiles):
    def __init__(self, entries=None):
        self.entries = entries or {}
        self.reads = []

    def read_bytes(self, path, limit=65536, source=None):
        self.reads.append(path)
        source = source or path
        value = self.entries.get(path, FileNotFoundError(errno.ENOENT, "fixture missing"))
        if isinstance(value, OSError):
            return collector.read_error(source, value)
        if isinstance(value, str):
            value = value.encode("utf-8")
        if len(value) > limit:
            return collector.observation("invalid", source, reason="size_limit_exceeded")
        return collector.observation("ok", source, value)


def fixture_files():
    return FakeFiles({
        "/proc/sys/kernel/osrelease": "6.18.3-example-private-host",
        "/proc/cmdline": "root=UUID=00000000-0000-0000-0000-000000000001 arm64.nopauth efi=noruntime",
        "/proc/cpuinfo": """processor : 0
Features : fp asimd cpuid paca pacg ilrcpc
CPU implementer : 0x41
CPU architecture : 8
CPU variant : 0x0
CPU part : 0xd4b
CPU revision : 0
Serial : EXAMPLE_PRIVATE_SERIAL

processor : 1
Features : fp asimd cpuid paca pacg ilrcpc
CPU implementer : 0x41
CPU architecture : 8
CPU variant : 0x0
CPU part : 0xd4c
CPU revision : 0
""",
        "/proc/meminfo": "MemTotal:       16000000 kB\nMemFree: 1000000 kB\n",
        "/sys/class/dmi/id/sys_vendor": "HUAWEI",
        "/sys/class/dmi/id/product_name": "GK-W7X",
        "/sys/class/dmi/id/bios_version": "2.16",
        "/sys/firmware/devicetree/base/model": "Huawei MateBook E Go\0",
        "/sys/firmware/devicetree/base/compatible": "huawei,gaokun3\0qcom,sc8280xp\0",
        "/sys/devices/system/cpu/cpu0/regs/identification/midr_el1": "0x00000000410fd4b0\n",
        "/sys/devices/system/cpu/cpu0/regs/identification/revidr_el1": "0x1\n",
        "/sys/devices/system/cpu/cpu1/regs/identification/midr_el1": "0x00000000410fd4c0\n",
        "/proc/config.gz": gzip.compress(b"CONFIG_KVM=y\nCONFIG_ARM64_PTR_AUTH=y\nCONFIG_ARM64_4K_PAGES=y\n# CONFIG_ARM64_16K_PAGES is not set\nCONFIG_CMDLINE=EXAMPLE_PRIVATE_SECRET\n"),
    })


class FakeKvm:
    def __init__(self, api=12, capabilities=None, open_error=None, stat_error=None, character=True):
        self.api = api
        self.capabilities = capabilities or {}
        self.open_error = open_error
        self.stat_error = stat_error
        self.character = character
        self.calls = []
        self.closed = []
        self.flags = None

    def stat(self, path):
        self.calls.append(("stat", path))
        if self.stat_error:
            raise self.stat_error
        mode = stat.S_IFCHR if self.character else stat.S_IFREG
        return types.SimpleNamespace(st_mode=mode | 0o660)

    def open(self, path, flags):
        self.calls.append(("open", path))
        self.flags = flags
        if self.open_error:
            raise self.open_error
        return 7

    def ioctl(self, descriptor, request, argument):
        self.calls.append(("ioctl", descriptor, request, argument))
        # This external boundary must reject every request capable of VM setup,
        # register modification, memory mapping, or guest execution.
        if request == 0xAE00 and argument == 0:
            value = self.api
        elif request == 0xAE03 and argument in (165, 171, 172, 177, 240):
            value = self.capabilities.get(argument, 0)
        else:
            raise AssertionError("ioctl outside read-only query contract")
        if isinstance(value, OSError):
            raise value
        return value

    def close(self, descriptor):
        self.closed.append(descriptor)

    def probe(self, arm64=True):
        return collector.probe_kvm(arm64, self.stat, self.open, self.close, self.ioctl)


class PrivacyAndInventoryTests(unittest.TestCase):
    def test_inventory_excludes_unselected_private_data(self):
        files = fixture_files()
        kvm = FakeKvm(capabilities={165: 40, 171: 1, 172: 1})
        report = collector.collect(files, "aarch64", kvm.probe)
        encoded = json.dumps(report)
        for excluded in ("EXAMPLE_PRIVATE_SERIAL", "EXAMPLE_PRIVATE_SECRET", "example-private-host",
                         "00000000-0000-0000-0000-000000000001", "MemFree"):
            self.assertNotIn(excluded, encoded)
        self.assertEqual(report["kernel"]["numeric_release"]["value"], "6.18.3")
        self.assertTrue(report["kernel"]["numeric_release"]["suffix_omitted"])
        self.assertEqual(report["memory"]["total"]["value"], 16000000 * 1024)
        cpus = report["cpu"]["processors"]["value"]
        self.assertEqual([row["cpu_part"]["value"] for row in cpus], [0xd4b, 0xd4c])
        self.assertEqual(cpus[1]["revidr_el1"]["status"], "missing")
        self.assertEqual(report["kvm"]["guest_execution"]["status"], "not_tested")
        self.assertEqual(report["kvm"]["host_el2_ownership"]["status"], "not_tested")
        for path in files.reads:
            self.assertNotIn("serial", path)
            self.assertNotIn("uuid", path)
            self.assertNotIn("aidr", path)
            self.assertNotIn("/var/log", path)
            self.assertNotIn("/dev/kmsg", path)
        self.assertNotIn("registers", report)

    def test_cmdline_allowlist_rejects_private_and_malformed_values(self):
        raw = ("root=/private/EXAMPLE_SECRET user=EXAMPLE_SECRET "
               "arm64.nopauth id_aa64mmfr0.ecv=1 maxcpus=8 "
               "id_aa64isar1.apa=EXAMPLE_SECRET kvm-arm.mode=EXAMPLE_SECRET "
               "id_aa64mmfr2.nv=EXAMPLE_SECRET efi=noruntime ip=192.0.2.1")
        item = collector.parse_cmdline(collector.observation("ok", "/proc/cmdline", raw))
        self.assertNotIn("EXAMPLE_SECRET", json.dumps(item))
        self.assertNotIn("192.0.2.1", json.dumps(item))
        args = item["value"]["arguments"]
        self.assertTrue(args["arm64.nopauth"]["present"])
        self.assertEqual(args["maxcpus"]["occurrences"][0]["value"], 8)
        self.assertEqual(args["id_aa64mmfr0.ecv"]["occurrences"][0]["value"], 1)
        self.assertEqual(args["id_aa64isar1.apa"]["occurrences"][0]["status"], "redacted")
        self.assertTrue(item["value"]["other_cpu_id_override_present"])

    def test_duplicate_overrides_are_preserved_without_claiming_effective_value(self):
        item = collector.parse_cmdline(collector.observation(
            "ok", "/proc/cmdline", "id_aa64isar1.apa=0 id_aa64isar1.apa=3"))
        entries = item["value"]["arguments"]["id_aa64isar1.apa"]["occurrences"]
        self.assertEqual([entry["value"] for entry in entries], [0, 3])

    def test_nopauth_report_is_context_not_physical_feature_diagnosis(self):
        files = fixture_files()
        files.entries["/proc/cpuinfo"] = files.entries["/proc/cpuinfo"].replace(" paca pacg", "")
        report = collector.collect(files, "aarch64", FakeKvm().probe)
        self.assertTrue(report["boot"]["selected_arguments"]["value"]["arguments"]["arm64.nopauth"]["present"])
        self.assertNotIn("paca", report["cpu"]["processors"]["value"][0]["features_of_interest"]["value"])
        self.assertNotIn("hardware_pauth", report)
        self.assertEqual(report["kvm"]["guest_execution"]["status"], "not_tested")

    def test_text_redacts_paths_addresses_ids_and_control_characters(self):
        for value in ("example@example.invalid", "\\private\\example", "192.0.2.42",
                      "00:11:22:33:44:55", "00000000-0000-0000-0000-000000000001",
                      "model\nEXAMPLE_PRIVATE", "model\x00EXAMPLE_PRIVATE"):
            with self.subTest(value=value):
                result = collector.safe_text(value, "fixture:model")
                self.assertEqual(result["status"], "redacted")
                self.assertNotIn("value", result)
        self.assertEqual(collector.safe_text("GK-W7X", "fixture")["value"], "GK-W7X")
        self.assertEqual(collector.safe_text("Intel CPU @ 2.60GHz", "fixture")["status"], "ok")

    def test_error_messages_cannot_escape_into_report(self):
        failure = PermissionError(errno.EACCES, "EXAMPLE_PRIVATE_USER /private/path")
        result = collector.read_error("fixture", failure)
        self.assertEqual(result["status"], "permission_denied")
        self.assertEqual(result["error_code"], "EACCES")
        self.assertNotIn("EXAMPLE_PRIVATE", json.dumps(result))
        files = fixture_files()
        files.entries["/proc/cpuinfo"] = failure
        report = collector.collect(files, "aarch64", FakeKvm().probe)
        self.assertEqual(report["cpu"]["processors"]["status"], "permission_denied")

    def test_missing_sources_remain_explicit(self):
        report = collector.collect(FakeFiles(), "aarch64", FakeKvm().probe)
        self.assertEqual(report["device"]["dt_model"]["status"], "missing")
        self.assertEqual(report["cpu"]["processors"]["status"], "missing")
        self.assertEqual(report["memory"]["total"]["status"], "missing")
        self.assertEqual(report["boot"]["selected_arguments"]["status"], "missing")
        self.assertEqual(report["kernel"]["configuration"]["status"], "missing")

    def test_non_arm_does_not_query_kvm_or_decode_arm_fields(self):
        files = fixture_files()
        files.entries["/proc/cpuinfo"] = "processor : 0\nmodel name : Example x86 CPU\nflags : paca cpuid\n"
        kvm = FakeKvm()
        report = collector.collect(files, "x86_64", kvm.probe)
        self.assertEqual(kvm.calls, [])
        self.assertEqual(report["kvm"]["status"], "not_applicable_non_arm64")
        self.assertFalse(report["platform"]["arm64_queries_enabled"])
        self.assertNotIn("features_of_interest", report["cpu"]["processors"]["value"][0])
        self.assertFalse(any("/regs/" in path for path in files.reads))

    def test_cpu_fields_are_parsed_without_copying_extra_fields(self):
        raw = "processor : 0\nFeatures : fp cpuid paca EXAMPLE_PRIVATE_FEATURE\nCPU part : invalid\nSerial : EXAMPLE_PRIVATE_SERIAL\n"
        result = collector.parse_cpuinfo(collector.observation("ok", "/proc/cpuinfo", raw), True)
        self.assertNotIn("EXAMPLE_PRIVATE", json.dumps(result))
        self.assertEqual(result["value"][0]["cpu_part"]["status"], "invalid")
        self.assertEqual(result["value"][0]["cpu_revision"]["status"], "missing")
        self.assertEqual(result["value"][0]["features_of_interest"]["value"], ["cpuid", "fp", "paca"])

    def test_kernel_config_only_selected_values_are_serialized(self):
        files = fixture_files()
        config = collector.collect_config(files, collector.observation("ok", "fixture", "6.18.3"))
        self.assertEqual(config["value"]["CONFIG_KVM"]["value"], "y")
        self.assertEqual(config["value"]["CONFIG_ARM64_16K_PAGES"]["value"], "n")
        self.assertNotIn("EXAMPLE_PRIVATE", json.dumps(config))
        self.assertEqual(config["value"]["CONFIG_ARM64_PA_BITS"]["status"], "missing")

    def test_config_fallback_does_not_publish_custom_filename(self):
        files = FakeFiles({"/boot/config-6.18.3-EXAMPLE_PRIVATE": "CONFIG_KVM=y\n"})
        config = collector.collect_config(files, collector.observation("ok", "fixture", "6.18.3-EXAMPLE_PRIVATE"))
        self.assertEqual(config["status"], "ok")
        self.assertNotIn("EXAMPLE_PRIVATE", json.dumps(config))

    def test_config_fallback_rejects_path_components(self):
        files = FakeFiles()
        collector.collect_config(files, collector.observation("ok", "fixture", "6.18.3/../../private"))
        self.assertEqual(files.reads, ["/proc/config.gz"])

    def test_bounded_reads_and_bad_compression_fail_explicitly(self):
        files = FakeFiles({"/proc/config.gz": b"invalid gzip", "/proc/cmdline": "x" * 70000})
        self.assertEqual(collector.collect_config(files, collector.observation("missing", "fixture"))["status"], "invalid")
        self.assertEqual(collector.parse_cmdline(files.read_text("/proc/cmdline"))["status"], "invalid")

    def test_corrupt_deflate_body_is_reported_without_aborting_inventory(self):
        # Valid gzip header followed by the reserved DEFLATE block type (3).
        payload = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x07"
        files = fixture_files()
        files.entries["/proc/config.gz"] = payload
        report = collector.collect(files, "aarch64", FakeKvm().probe)
        self.assertEqual(report["kernel"]["configuration"]["status"], "invalid")
        self.assertEqual(report["kernel"]["configuration"]["reason"], "invalid_compressed_config")
        self.assertEqual(report["cpu"]["processors"]["status"], "ok")

    def test_dt_compatible_rejects_identifiers_and_addresses(self):
        path = "/sys/firmware/devicetree/base/compatible"
        for token in ("vendor,00000000-0000-0000-0000-000000000001",
                      "vendor,0123456789abcdef0123456789abcdef",
                      "vendor,192.0.2.1"):
            with self.subTest(token=token):
                item = collector.collect_compatible(FakeFiles({path: token + "\0"}))
                self.assertEqual(item["status"], "redacted")
                self.assertNotIn(token, json.dumps(item))

    def test_wsl_marker_is_recorded_without_full_release(self):
        files = fixture_files()
        files.entries["/proc/sys/kernel/osrelease"] = "6.6.87.2-microsoft-standard-WSL2-EXAMPLE_PRIVATE"
        report = collector.collect(files, "aarch64", FakeKvm().probe)
        self.assertTrue(report["platform"]["wsl_marker"]["value"])
        self.assertNotIn("EXAMPLE_PRIVATE", json.dumps(report))


class KvmBoundaryTests(unittest.TestCase):
    def test_success_queries_do_not_mean_guest_success(self):
        kvm = FakeKvm(capabilities={165: 40, 171: 1, 172: 1, 177: 1, 240: 0})
        report = kvm.probe()
        self.assertEqual(report["status"], "capabilities_queried")
        self.assertEqual(report["api_version"]["value"], 12)
        self.assertEqual(report["capabilities"]["arm_vm_ipa_size"]["value"], 40)
        self.assertEqual(report["capabilities"]["arm_guest_el2"]["value"], 0)
        self.assertEqual(report["guest_execution"]["status"], "not_tested")
        self.assertEqual(report["host_el2_ownership"]["status"], "not_tested")
        self.assertEqual(kvm.flags & os.O_ACCMODE, os.O_RDONLY)
        self.assertEqual(kvm.closed, [7])
        self.assertEqual(len([call for call in kvm.calls if call[0] == "ioctl"]), 6)

    def test_missing_and_access_denied_are_distinct(self):
        missing = FakeKvm(stat_error=FileNotFoundError(errno.ENOENT, "fixture"))
        denied = FakeKvm(open_error=PermissionError(errno.EACCES, "private fixture"))
        self.assertEqual(missing.probe()["status"], "missing")
        report = denied.probe()
        self.assertEqual(report["status"], "permission_denied")
        self.assertEqual(report["api_version"]["status"], "not_attempted")
        self.assertEqual(denied.closed, [])

    def test_regular_file_is_not_accepted_as_kvm_device(self):
        kvm = FakeKvm(character=False)
        self.assertEqual(kvm.probe()["status"], "invalid_device")
        self.assertEqual([entry[0] for entry in kvm.calls], ["stat"])

    def test_api_error_closes_descriptor(self):
        kvm = FakeKvm(api=OSError(errno.ENOTTY, "EXAMPLE_PRIVATE"))
        report = kvm.probe()
        self.assertEqual(report["status"], "api_query_failed")
        self.assertEqual(kvm.closed, [7])
        self.assertNotIn("EXAMPLE_PRIVATE", json.dumps(report))

    def test_unknown_api_prevents_capability_queries(self):
        kvm = FakeKvm(api=11)
        self.assertEqual(kvm.probe()["status"], "unexpected_api_version")
        self.assertEqual(len([call for call in kvm.calls if call[0] == "ioctl"]), 1)
        self.assertEqual(kvm.closed, [7])

    def test_failed_capability_does_not_become_absent(self):
        kvm = FakeKvm(capabilities={171: OSError(errno.EIO, "EXAMPLE_PRIVATE")})
        report = kvm.probe()
        self.assertEqual(report["status"], "capability_query_incomplete")
        self.assertEqual(report["capabilities"]["arm_ptrauth_address"]["status"], "error")
        self.assertNotIn("value", report["capabilities"]["arm_ptrauth_address"])
        self.assertEqual(report["capabilities"]["arm_ptrauth_generic"]["value"], 0)
        self.assertEqual(kvm.closed, [7])


class OutputTests(unittest.TestCase):
    def test_default_output_is_json(self):
        output = io.StringIO()
        collector.write_report({"schema_version": 1, "example": True}, stdout=output)
        self.assertEqual(json.loads(output.getvalue()), {"schema_version": 1, "example": True})

    def test_new_file_is_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            collector.write_report({"example": 1}, path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                collector.write_report({"example": 2}, path)
            self.assertEqual(json.loads(path.read_text()), {"example": 1})

    def test_existing_symlink_is_not_followed_for_output(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "existing.json"
            link = Path(directory) / "link.json"
            target.write_text("preserve")
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                collector.write_report({"example": 1}, link)
            self.assertEqual(target.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main(verbosity=2)
