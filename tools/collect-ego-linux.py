#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Collect a small, local Linux inventory for MateBook E Go research.

Usage: python3 tools/collect-ego-linux.py [--output NEW_FILE.json]

Only Python's standard library is used. This tool does not run commands, read
logs, change boot settings, create a VM, or upload anything. On native arm64 it
opens /dev/kvm read-only and uses two query ioctls. Its observations are NOT raw
CPU feature registers or evidence that a guest has run. See `limitations` in the
report. Output files are created exclusively with mode 0600.
"""

import argparse
import errno
import gzip
import io
import json
import os
import re
import stat
import sys
import zlib


# Interface facts, independently implemented from the Linux UAPI:
# https://github.com/torvalds/linux/blob/master/include/uapi/linux/kvm.h
# https://docs.kernel.org/virt/kvm/api.html
# _IO on arm64: no size/direction bits, type 0xAE, command 0x00 or 0x03.
KVM_GET_API_VERSION = 0xAE00
KVM_CHECK_EXTENSION = 0xAE03
KVM_API_VERSION = 12
KVM_CAPABILITIES = {
    "arm_vm_ipa_size": 165,
    "arm_ptrauth_address": 171,
    "arm_ptrauth_generic": 172,
    "arm_nisv_to_user": 177,
    "arm_guest_el2": 240,
}

ARM_FEATURES = frozenset("""
    fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid
    asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 sve asimdfhm
    dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp sve2 flagm2 frint i8mm
    bf16 rng bti mte ecv
""".split())
CONFIG_KEYS = (
    "CONFIG_KVM", "CONFIG_ARM64_PTR_AUTH", "CONFIG_ARM64_PTR_AUTH_KERNEL",
    "CONFIG_ARM64_4K_PAGES", "CONFIG_ARM64_16K_PAGES", "CONFIG_ARM64_64K_PAGES",
    "CONFIG_ARM64_VA_BITS", "CONFIG_ARM64_PA_BITS",
)
FLAG_KEYS = frozenset((
    "arm64.nopauth", "arm64.nobti", "arm64.nosve", "nosmp",
    "clk_ignore_unused", "pd_ignore_unused",
))
ENUM_KEYS = {
    "kvm-arm.mode": frozenset(("none", "nvhe", "protected", "nested")),
    "efi": frozenset(("noruntime",)),
}
INTEGER_KEYS = frozenset(("maxcpus", "nr_cpus"))
OVERRIDE_KEYS = frozenset((
    "id_aa64isar1.apa", "id_aa64isar1.api", "id_aa64isar1.gpa",
    "id_aa64isar1.gpi", "id_aa64isar2.apa3", "id_aa64isar2.gpa3",
    "id_aa64mmfr0.ecv",
))
CMDLINE_KEYS = FLAG_KEYS | ENUM_KEYS.keys() | INTEGER_KEYS | OVERRIDE_KEYS
IDENTIFIER_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|\b[0-9a-f]{24,}\b",
    re.IGNORECASE,
)


def observation(status, source, value=None, **details):
    """A value is present only for a successful, deliberately selected field."""
    item = {"status": status, "source": source}
    if status == "ok":
        item["value"] = value
    item.update(details)
    return item


def read_error(source, exc):
    code = getattr(exc, "errno", None)
    status_name = {
        errno.ENOENT: "missing", errno.ENOTDIR: "missing",
        errno.EACCES: "permission_denied", errno.EPERM: "permission_denied",
    }.get(code, "error")
    # Exception messages can contain paths, usernames, or provider output.
    return observation(status_name, source, error_code=errno.errorcode.get(code, "UNKNOWN"))


class ReadOnlyFiles:
    """Bounded reads; injected test implementations use the same interface."""

    def read_bytes(self, path, limit=65536, source=None):
        source = source or path
        try:
            with open(path, "rb") as stream:
                value = stream.read(limit + 1)
        except OSError as exc:
            return read_error(source, exc)
        if len(value) > limit:
            return observation("invalid", source, reason="size_limit_exceeded")
        return observation("ok", source, value)

    def read_text(self, path, limit=65536, source=None):
        item = self.read_bytes(path, limit, source)
        if item["status"] != "ok":
            return item
        try:
            item["value"] = item["value"].decode("utf-8").strip()
        except UnicodeError:
            return observation("invalid", item["source"], reason="invalid_utf8")
        return item


def safe_text(value, source):
    """Accept OEM model/version text, rejecting common identifying strings."""
    value = str(value).strip()
    if not value:
        return observation("missing", source)
    # CPU brand strings sometimes contain a frequency after a literal @.
    checked = re.sub(r" @ [0-9]+(?:\.[0-9]+)?\s*[GM]Hz\b", "", value)
    if (len(value) > 160 or IDENTIFIER_PATTERN.search(value)
            or re.search(r"[/\\@:\r\n\x00-\x1f]", checked)
            or not re.fullmatch(r"[\w .,+()\[\]-]+", checked, re.UNICODE)):
        return observation("redacted", source, reason="unexpected_model_or_version_text")
    for candidate in re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", value):
        if all(int(part) <= 255 for part in candidate.split(".")):
            return observation("redacted", source, reason="address_like_text")
    return observation("ok", source, value)


def model_file(files, path):
    item = files.read_text(path, 2048)
    if item["status"] != "ok":
        return item
    return safe_text(item["value"].rstrip("\0"), path)


def parse_kernel_release(item):
    if item["status"] != "ok":
        return item
    match = re.match(r"^([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-rc[0-9]+)?)", item["value"])
    if not match:
        return observation("invalid", item["source"], reason="unrecognized_version")
    return observation("ok", item["source"], match.group(1),
                       suffix_omitted=match.end() != len(item["value"]))


def parse_cmdline(item):
    if item["status"] != "ok":
        return item
    found = {key: [] for key in sorted(CMDLINE_KEYS)}
    other_override = False
    for token in item["value"].split():
        key, separator, value = token.partition("=")
        if key not in CMDLINE_KEYS:
            other_override |= key.startswith("id_aa64")
            continue
        source = "kernel command line:" + key
        if key in FLAG_KEYS and not separator:
            entry = observation("ok", source, True)
        elif key in ENUM_KEYS and value in ENUM_KEYS[key]:
            entry = observation("ok", source, value)
        elif (key in INTEGER_KEYS and re.fullmatch(r"[0-9]{1,4}", value)
              and 0 <= int(value) <= 4096):
            entry = observation("ok", source, int(value))
        elif key in OVERRIDE_KEYS and re.fullmatch(r"(?:0x)?[0-9a-fA-F]", value):
            entry = observation("ok", source, int(value, 16))
        else:
            entry = observation("redacted", source, reason="value_not_in_allowlist")
        found[key].append(entry)
    return observation("ok", item["source"], {
        "arguments": {key: {"present": bool(entries), "occurrences": entries}
                      for key, entries in found.items()},
        "other_cpu_id_override_present": other_override,
    })


def integer_field(value, source, maximum=0xffffffff):
    if value is None:
        return observation("missing", source)
    try:
        if not re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", value.strip()):
            raise ValueError
        number = int(value, 16 if value.strip().startswith("0x") else 10)
        if number < 0 or number > maximum:
            raise ValueError
    except (ValueError, TypeError):
        return observation("invalid", source, reason="invalid_integer")
    return observation("ok", source, number)


def parse_cpuinfo(item, arm64):
    if item["status"] != "ok":
        return item
    rows = []
    for block in re.split(r"\n\s*\n", item["value"]):
        fields = {}
        for line in block.splitlines():
            key, separator, value = line.partition(":")
            if separator:
                fields[key.strip()] = value.strip()
        if "processor" not in fields:
            continue
        index = integer_field(fields["processor"], "/proc/cpuinfo:processor", 4095)
        if index["status"] != "ok":
            continue
        source = "/proc/cpuinfo:cpu" + str(index["value"])
        row = {"processor": index}
        if arm64:
            for name in ("CPU implementer", "CPU architecture", "CPU variant",
                         "CPU part", "CPU revision"):
                row[name.lower().replace(" ", "_")] = integer_field(fields.get(name), source + ":" + name)
            if "Features" in fields:
                row["features_of_interest"] = observation(
                    "ok", source + ":Features", sorted(set(fields["Features"].split()) & ARM_FEATURES))
            else:
                row["features_of_interest"] = observation("missing", source + ":Features")
        else:
            row["model"] = safe_text(fields.get("model name", ""), source + ":model name")
            row["arm_features"] = observation("not_applicable", source, reason="not_arm64")
        rows.append(row)
    if not rows:
        return observation("missing", item["source"], reason="no_processor_records")
    return observation("ok", item["source"], rows)


def collect_cpu(files, arm64):
    cpus = parse_cpuinfo(files.read_text("/proc/cpuinfo", 2 * 1024 * 1024), arm64)
    if arm64 and cpus["status"] == "ok":
        for row in cpus["value"]:
            index = row["processor"]["value"]
            for register in ("midr_el1", "revidr_el1"):
                path = f"/sys/devices/system/cpu/cpu{index}/regs/identification/{register}"
                item = files.read_text(path, 128)
                if item["status"] == "ok":
                    item = integer_field(item["value"], path, (1 << 64) - 1)
                    if item["status"] == "ok":
                        item["value"] = f"0x{item['value']:016x}"
                row[register] = item
    return cpus


def collect_memory(files):
    item = files.read_text("/proc/meminfo", 65536)
    if item["status"] != "ok":
        return item
    match = re.search(r"^MemTotal:\s+([0-9]+)\s+kB\s*$", item["value"], re.MULTILINE)
    if not match:
        return observation("missing", "/proc/meminfo:MemTotal")
    return observation("ok", "/proc/meminfo:MemTotal", int(match.group(1)) * 1024,
                       units="bytes", meaning="memory_visible_to_running_kernel")


def collect_config(files, release):
    source = "running kernel configuration"
    compressed = files.read_bytes("/proc/config.gz", 1024 * 1024, source)
    if compressed["status"] == "ok":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(compressed["value"])) as stream:
                data = stream.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                return observation("invalid", source, reason="size_limit_exceeded")
            text = data.decode("utf-8")
        except (OSError, EOFError, UnicodeError, zlib.error):
            return observation("invalid", source, reason="invalid_compressed_config")
    else:
        # The suffix is used only to find the local file, never included in the
        # report, a source label, or an error message. Do not follow path input.
        raw_release = release.get("value", "") if release["status"] == "ok" else ""
        if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,200}", raw_release):
            return observation(compressed["status"], source, reason="config_unavailable")
        fallback = files.read_text("/boot/config-" + raw_release, 2 * 1024 * 1024, source)
        if fallback["status"] != "ok":
            return observation(fallback["status"], source, reason="config_unavailable",
                               attempts={"proc_config": compressed["status"],
                                         "boot_config": fallback["status"]})
        text = fallback["value"]
    values = {}
    for key in CONFIG_KEYS:
        enabled = re.search(r"^" + key + r"=(y|m|n|[0-9]{1,2})$", text, re.MULTILINE)
        disabled = re.search(r"^# " + key + r" is not set$", text, re.MULTILINE)
        if enabled or disabled:
            values[key] = observation("ok", source + ":" + key,
                                      enabled.group(1) if enabled else "n")
        else:
            values[key] = observation("missing", source + ":" + key)
    return observation("ok", source, values)


def collect_compatible(files):
    path = "/sys/firmware/devicetree/base/compatible"
    item = files.read_text(path, 2048)
    if item["status"] != "ok":
        return item
    tokens = item["value"].rstrip("\0").split("\0")
    if not tokens or any(not re.fullmatch(r"[A-Za-z0-9_.+-]+,[A-Za-z0-9_.+-]+", token)
                         or len(token) > 100
                         or safe_text(token, path)["status"] != "ok" for token in tokens):
        return observation("redacted", path, reason="unexpected_compatible_format")
    return observation("ok", path, tokens)


def probe_kvm(arm64, stat_fn=os.stat, open_fn=os.open, close_fn=os.close, ioctl_fn=None):
    """Query the existing KVM interface; never create a VM or execute a guest."""
    result = {
        "status": "not_attempted",
        "device": observation("not_attempted", "/dev/kvm"),
        "api_version": observation("not_attempted", "KVM_GET_API_VERSION"),
        "capabilities": {name: observation("not_attempted", "KVM_CHECK_EXTENSION", capability_id=number)
                         for name, number in KVM_CAPABILITIES.items()},
        "host_el2_ownership": observation("not_tested", "collector_scope"),
        "guest_execution": observation("not_tested", "collector_scope"),
    }
    if not arm64:
        result["status"] = "not_applicable_non_arm64"
        result["device"] = observation("not_applicable", "/dev/kvm", reason="not_arm64")
        return result
    try:
        device_stat = stat_fn("/dev/kvm")
    except OSError as exc:
        result["device"] = read_error("/dev/kvm", exc)
        result["status"] = result["device"]["status"]
        return result
    if not stat.S_ISCHR(device_stat.st_mode):
        result["status"] = "invalid_device"
        result["device"] = observation("invalid", "/dev/kvm", reason="not_character_device")
        return result
    result["device"] = observation("ok", "/dev/kvm", {"character_device": True})
    try:
        descriptor = open_fn("/dev/kvm", os.O_RDONLY | os.O_CLOEXEC)
    except OSError as exc:
        result["device"] = read_error("/dev/kvm:open_read_only", exc)
        result["status"] = result["device"]["status"]
        return result
    try:
        if ioctl_fn is None:
            import fcntl
            ioctl_fn = fcntl.ioctl
        try:
            api = ioctl_fn(descriptor, KVM_GET_API_VERSION, 0)
            result["api_version"] = observation("ok", "KVM_GET_API_VERSION", api)
        except OSError as exc:
            result["api_version"] = read_error("KVM_GET_API_VERSION", exc)
            result["status"] = "api_query_failed"
            return result
        if api != KVM_API_VERSION:
            result["status"] = "unexpected_api_version"
            return result
        for name, number in KVM_CAPABILITIES.items():
            try:
                value = ioctl_fn(descriptor, KVM_CHECK_EXTENSION, number)
                if not isinstance(value, int) or value < 0:
                    result["capabilities"][name] = observation(
                        "invalid", "KVM_CHECK_EXTENSION", capability_id=number)
                else:
                    result["capabilities"][name] = observation(
                        "ok", "KVM_CHECK_EXTENSION", value, capability_id=number)
            except OSError as exc:
                result["capabilities"][name] = read_error("KVM_CHECK_EXTENSION", exc)
                result["capabilities"][name]["capability_id"] = number
        result["status"] = ("capabilities_queried" if all(
            entry["status"] == "ok" for entry in result["capabilities"].values())
            else "capability_query_incomplete")
    finally:
        close_fn(descriptor)
    return result


def collect(files=None, machine=None, kvm_probe=probe_kvm):
    files = files or ReadOnlyFiles()
    machine = machine if machine is not None else os.uname().machine
    architecture = machine.lower() if machine.lower() in (
        "aarch64", "arm64", "x86_64", "i386", "i686", "armv7l", "riscv64") else "other"
    arm64 = architecture in ("aarch64", "arm64")
    release = files.read_text("/proc/sys/kernel/osrelease", 512)
    cmdline = parse_cmdline(files.read_text("/proc/cmdline", 65536))
    try:
        page_size = observation("ok", "sysconf:SC_PAGE_SIZE", os.sysconf("SC_PAGE_SIZE"), units="bytes")
    except (ValueError, OSError) as exc:
        page_size = read_error("sysconf:SC_PAGE_SIZE", exc)
    wsl = observation("ok", "kernel release:WSL marker", bool(re.search(
        r"microsoft|wsl", release["value"], re.IGNORECASE))) if release["status"] == "ok" else observation(
            "unknown", "kernel release:WSL marker")
    return {
        "schema_version": 1,
        "report_kind": "ego_linux_inventory",
        "collector": {"name": "collect-ego-linux", "version": 1},
        "platform": {"os": "Linux", "architecture": observation("ok", "uname:machine", architecture),
                     "arm64_queries_enabled": arm64, "wsl_marker": wsl},
        "device": {
            "manufacturer": model_file(files, "/sys/class/dmi/id/sys_vendor"),
            "product_model": model_file(files, "/sys/class/dmi/id/product_name"),
            "bios_version": model_file(files, "/sys/class/dmi/id/bios_version"),
            "dt_model": model_file(files, "/sys/firmware/devicetree/base/model"),
            "dt_compatible": collect_compatible(files),
        },
        "cpu": {"processors": collect_cpu(files, arm64),
                "feature_scope": "Linux userspace-visible feature subset, not raw hardware registers"},
        "memory": {"total": collect_memory(files)},
        "kernel": {"numeric_release": parse_kernel_release(release), "page_size": page_size,
                   "configuration": collect_config(files, release)},
        "boot": {"selected_arguments": cmdline},
        "kvm": kvm_probe(arm64),
        "limitations": [
            "This inventory is not the register-report schema used by check-ego-capabilities.",
            "No logs, full command line, unique device IDs, firmware blobs or network configuration were collected.",
            "Review OEM-provided model/version text before sharing; no report is uploaded automatically.",
            "CPU Features are Linux's exposed safe set; absence does not prove the silicon lacks a feature.",
            "arm64.nopauth, CPU ID overrides, kernel configuration and firmware can mask PAuth.",
            "No privileged feature registers, current EL, 16K guest translation or NV2 were measured.",
            "Host page size does not establish guest stage-1 or stage-2 granule support.",
            "KVM API/capability results do not prove host EL2 ownership or successful VM/vCPU creation or execution.",
            "arm_guest_el2 is nested guest EL2 support, not a measurement of host execution level.",
            "A zero KVM capability means unavailable through this kernel interface, not necessarily absent in hardware.",
        ],
    }


def write_report(report, output=None, stdout=None):
    """Write JSON to stdout, or create one new local file without overwriting."""
    encoded = json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
    if output is None:
        (stdout or sys.stdout).write(encoded)
        return
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(encoded)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", metavar="NEW_FILE.json", help="create a new local report; refuse existing paths")
    args = parser.parse_args(argv)
    if sys.platform != "linux":
        parser.exit(2, "This collector requires Linux. Use collect-ego-windows.ps1 on Windows.\n")
    try:
        write_report(collect(), args.output)
    except FileExistsError:
        parser.exit(2, "Output already exists; nothing was overwritten.\n")
    except OSError as exc:
        parser.exit(2, "Report output failed (" + errno.errorcode.get(exc.errno, "UNKNOWN") + ").\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
