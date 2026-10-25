#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Review one supplied CPU register view; never access or qualify hardware.

Input schema 1 accepts only schema_version, provenance, registers, and the
optional masked_fields and execution_el members. Register values are null,
unsigned 64-bit integers, or 0x-prefixed hex strings. Missing is not zero.
The provenance describes the register *view*, not an independently verified
attestation. A Windows, Linux, or guest view can hide host hardware features.

Field encodings are architectural facts, independently expressed here. Sources:
https://github.com/torvalds/linux/blob/master/arch/arm64/tools/sysreg
https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers
Linux EL0 visibility is defined by sections 3-4 of:
https://github.com/torvalds/linux/blob/master/Documentation/arch/arm64/cpu-feature-registers.rst
MMFR4.NV_frac is [23:20]; [27:24] is E2H0, not NV_frac. The latter is
mislabelled in the pinned upstream probes/run.py and prepare.c comment.

This utility is deliberately independent of run.py/q1n1 and of all boot gates.
Even a complete positive register view remains NOT QUALIFIED: instructions,
state restoration, Apple ABI, the board port, and all CPU classes need tests.
"""

import argparse
import json
from pathlib import Path
import re
import sys


BACKEND_REVISION = "940eeb95ba637528dc45ba098e6b8091163dd489"
MAX_INPUT_BYTES = 65536
PROVENANCES = frozenset((
    "raw_el2", "uefi_el1", "linux_sanitized", "windows_visible",
    "kvm_guest", "documentation", "synthetic",
))
FILTERED_VIEWS = frozenset((
    "uefi_el1", "linux_sanitized", "windows_visible", "kvm_guest",
))
REGISTERS = frozenset((
    "MIDR_EL1", "ID_AA64PFR0_EL1", "ID_AA64PFR1_EL1",
    "ID_AA64ISAR0_EL1", "ID_AA64ISAR1_EL1", "ID_AA64ISAR2_EL1",
    "ID_AA64MMFR0_EL1", "ID_AA64MMFR1_EL1", "ID_AA64MMFR2_EL1",
    "ID_AA64MMFR4_EL1", "CNTFRQ_EL0", "DCZID_EL0",
))
# A masked field is unusable even when its numeric value appears positive.
FIELDS = {
    "ID_AA64PFR0_EL1.EL2": 8,
    "ID_AA64PFR0_EL1.DIT": 48,
    "ID_AA64PFR1_EL1.SSBS": 4,
    "ID_AA64ISAR0_EL1.RNDR": 60,
    "ID_AA64ISAR0_EL1.SHA3": 32,
    "ID_AA64ISAR0_EL1.TLB": 56,
    "ID_AA64ISAR1_EL1.APA": 4,
    "ID_AA64ISAR1_EL1.API": 8,
    "ID_AA64ISAR1_EL1.GPA": 24,
    "ID_AA64ISAR1_EL1.GPI": 28,
    "ID_AA64ISAR2_EL1.APA3": 12,
    "ID_AA64ISAR2_EL1.GPA3": 8,
    "ID_AA64MMFR0_EL1.ECV": 60,
    "ID_AA64MMFR0_EL1.TGran16": 20,
    "ID_AA64MMFR0_EL1.TGran16_2": 32,
    "ID_AA64MMFR1_EL1.PAN": 20,
    "ID_AA64MMFR2_EL1.NV": 24,
    "ID_AA64MMFR4_EL1.NV_frac": 20,
}
MASKABLE = frozenset(FIELDS) | frozenset(("CNTFRQ_EL0", "DCZID_EL0"))
# The Linux MRS-emulation ABI does not expose these fields. A supplied nonzero
# value is no more usable as hardware evidence than the ABI's missing-feature
# encoding. ECV, RNDR, PAC, DIT, SHA3 and SSBS are explicitly visible.
LINUX_HIDDEN_FIELDS = frozenset((
    "ID_AA64PFR0_EL1.EL2", "ID_AA64ISAR0_EL1.TLB",
    "ID_AA64MMFR0_EL1.TGran16", "ID_AA64MMFR0_EL1.TGran16_2",
    "ID_AA64MMFR1_EL1.PAN", "ID_AA64MMFR2_EL1.NV",
    "ID_AA64MMFR4_EL1.NV_frac",
))
BACKEND_REQUIREMENTS = (
    "el2_execution", "nv2", "ecv", "rndr", "address_pauth",
    "generic_pauth", "pan", "dc_zva_64",
)
SOURCE_BASE = "https://github.com/Snapintosh/Snapintosh/blob/" + BACKEND_REVISION


class EvidenceError(ValueError):
    """A fixed, non-sensitive explanation of invalid input."""


def _u64(value):
    if value is None:
        return None
    if type(value) is int and 0 <= value < (1 << 64):
        return value
    if isinstance(value, str) and re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}", value):
        return int(value, 16)
    raise EvidenceError("register values must be null or unsigned 64-bit numbers")


def validate_evidence(data):
    """Return a normalized copy, rejecting unrecognized or ambiguous content."""
    allowed = {"schema_version", "provenance", "registers", "masked_fields", "execution_el"}
    required = {"schema_version", "provenance", "registers"}
    if type(data) is not dict or not required <= data.keys() or data.keys() - allowed:
        raise EvidenceError("input must match the schema 1 object")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise EvidenceError("unsupported schema version")
    provenance = data["provenance"]
    if not isinstance(provenance, str) or provenance not in PROVENANCES:
        raise EvidenceError("unrecognized evidence provenance")
    registers = data["registers"]
    if type(registers) is not dict or registers.keys() - REGISTERS:
        raise EvidenceError("register object contains an unsupported member")
    masks = data.get("masked_fields", [])
    if (type(masks) is not list or len(masks) > len(MASKABLE)
            or any(not isinstance(field, str) or field not in MASKABLE for field in masks)
            or len(set(masks)) != len(masks)):
        raise EvidenceError("masked_fields must contain unique recognized field names")
    execution_el = data.get("execution_el")
    if execution_el is not None and (type(execution_el) is not int or execution_el not in range(4)):
        raise EvidenceError("execution_el must be null or an exception level from 0 to 3")
    if provenance == "raw_el2" and execution_el not in (None, 2):
        raise EvidenceError("execution level contradicts raw_el2 provenance")
    if provenance == "uefi_el1" and execution_el not in (None, 1):
        raise EvidenceError("execution level contradicts uefi_el1 provenance")
    return {
        "schema_version": 1, "provenance": provenance,
        "registers": {name: _u64(value) for name, value in registers.items()},
        "masked_fields": list(masks), "execution_el": execution_el,
    }


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON object member")
        result[key] = value
    return result


def parse_evidence(text):
    """Parse bounded JSON without including any supplied text in errors."""
    if not isinstance(text, str):
        raise EvidenceError("input must be JSON text")
    try:
        encoded_size = len(text.encode("utf-8"))
    except UnicodeError:
        raise EvidenceError("input is not valid UTF-8 JSON") from None
    if encoded_size > MAX_INPUT_BYTES:
        raise EvidenceError("input exceeds the supported size")
    try:
        data = json.loads(text, object_pairs_hook=_unique_object,
                          parse_constant=lambda unused: _bad_constant())
    except EvidenceError:
        raise
    except (ValueError, RecursionError):
        raise EvidenceError("input is not valid bounded JSON") from None
    return validate_evidence(data)


def _bad_constant():
    raise EvidenceError("non-finite JSON numbers are not accepted")


def _field(data, name):
    if (name in data["masked_fields"] or
            (data["provenance"] == "linux_sanitized" and name in LINUX_HIDDEN_FIELDS)):
        return None
    register, unused = name.split(".", 1)
    value = data["registers"].get(register)
    return None if value is None else (value >> FIELDS[name]) & 15


def _register(data, name):
    return None if name in data["masked_fields"] else data["registers"].get(name)


def _encoding(value, present, absent=(0,)):
    if value is None:
        return "unknown"
    if value in present:
        return "present"
    if value in absent:
        return "absent"
    return "unknown"


def _feature(data, fields, reported, detail):
    # An absent feature in a filtered view is not evidence of absent silicon.
    # Positive values describe only this view; they never qualify the board.
    status = reported
    if reported == "absent" and data["provenance"] in FILTERED_VIEWS:
        status = "unknown"
        detail += " The view may filter this feature; host absence is unproven."
    if data["provenance"] == "linux_sanitized" and LINUX_HIDDEN_FIELDS.intersection(fields):
        detail += " The Linux EL0 MRS ABI hides a required field; its supplied value is not used."
    return {
        "status": status, "reported": reported,
        "fields": {name: _field(data, name) for name in fields},
        "detail": detail,
    }


def _simple(data, field, present, detail, absent=(0,)):
    return _feature(data, (field,), _encoding(_field(data, field), present, absent), detail)


def _pauth(data, fields, levels):
    values = [_encoding(_field(data, field), levels) for field in fields]
    reported = ("present" if "present" in values else
                "absent" if all(value == "absent" for value in values) else "unknown")
    return _feature(data, fields, reported,
                    "Any recognized algorithm can advertise PAC; Apple key/ABI semantics and execution remain untested.")


def _nested(data, want_nv2):
    fields = ("ID_AA64MMFR2_EL1.NV", "ID_AA64MMFR4_EL1.NV_frac")
    nv, fraction = (_field(data, field) for field in fields)
    reported = "unknown"
    if nv in (1, 2) and fraction in (None, 0):
        reported = "present" if nv == 2 or not want_nv2 else "absent"
    elif nv == 0 and fraction in (0, 1, 2, 3):
        reported = "absent" if fraction == 0 else "present"
    # Missing NV_frac with NV=0 cannot exclude the NV2-only encoding.
    # Nonzero NV with nonzero NV_frac is not a recognized combination.
    return _feature(data, fields, reported,
                    "NV_frac at [23:20] can advertise NV2-only with NV=0; reserved or inconsistent encodings remain unknown.")


def decode_features(data):
    """Decode a validated view; callers should normally use assess_capabilities."""
    features = {
        "rndr": _simple(data, "ID_AA64ISAR0_EL1.RNDR", (1,),
                        "The pinned backend uses RNDR for a fresh PAC-domain seed; this is an implementation choice."),
        "ecv": _simple(data, "ID_AA64MMFR0_EL1.ECV", (1, 2),
                       "The pinned scaled-counter backend requires ECV; its traps and timebase are not tested here."),
        "nv": _nested(data, False),
        "nv2": _nested(data, True),
        "address_pauth": _pauth(data, ("ID_AA64ISAR1_EL1.APA", "ID_AA64ISAR1_EL1.API",
                                       "ID_AA64ISAR2_EL1.APA3"), (1, 2, 3, 4, 5, 6)),
        "generic_pauth": _pauth(data, ("ID_AA64ISAR1_EL1.GPA", "ID_AA64ISAR1_EL1.GPI",
                                       "ID_AA64ISAR2_EL1.GPA3"), (1,)),
        "granule16_s1": _simple(data, "ID_AA64MMFR0_EL1.TGran16", (1, 2),
                               "0 means unavailable, 1 means 16K, 2 adds 52-bit support; no table walk was performed."),
        "ssbs": _simple(data, "ID_AA64PFR1_EL1.SSBS", (1, 2),
                        "SSBS level 1 does not include the level-2 MSR/MRS instructions."),
        "ssbs2": _simple(data, "ID_AA64PFR1_EL1.SSBS", (2,),
                         "VMAPPLE's SSBS2 assumption is stronger than SSBS level 1.", (0, 1)),
        "dit": _simple(data, "ID_AA64PFR0_EL1.DIT", (1,),
                       "A CPU advertisement only; it is not a complete armv8.5a compatibility check."),
        "sha3": _simple(data, "ID_AA64ISAR0_EL1.SHA3", (1,),
                        "A CPU advertisement only; no guest instruction stream was audited."),
        "tlbi_range": _simple(data, "ID_AA64ISAR0_EL1.TLB", (2,),
                              "TLB=1 adds outer-shareable operations, not range invalidation.", (0, 1)),
        "pan": _simple(data, "ID_AA64MMFR1_EL1.PAN", (1, 2, 3),
                       "The pinned backend checks PAN and SCTLR state; only the feature field is decoded."),
        "el2_advertised": _simple(data, "ID_AA64PFR0_EL1.EL2", (1, 2),
                                  "Advertised EL2 does not establish that firmware will give the loader EL2."),
    }
    granule = _field(data, "ID_AA64MMFR0_EL1.TGran16_2")
    s2_reported = (features["granule16_s1"]["reported"] if granule == 0 else
                   _encoding(granule, (2, 3), (1,)))
    features["granule16_s2"] = _feature(
        data, ("ID_AA64MMFR0_EL1.TGran16_2", "ID_AA64MMFR0_EL1.TGran16"), s2_reported,
        "Stage 2: 0 inherits stage 1, 1 means unavailable, 2 means supported, 3 adds 52-bit support. Stage 1 and 2 need separate tests.")
    dczid = _register(data, "DCZID_EL0")
    dcz_reported = ("unknown" if dczid is None or dczid > 31 else
                    "present" if dczid == 4 else "absent")
    features["dc_zva_64"] = _feature(
        data, (), dcz_reported, "The pinned prepare.c requires DCZID_EL0 exactly 4: 64-byte DC ZVA enabled.")
    features["dc_zva_64"]["reported_value"] = dczid
    execution_el = data["execution_el"]
    execution = ("unknown" if execution_el is None else
                 "present" if execution_el == 2 else "absent")
    features["el2_execution"] = _feature(
        data, (), execution, "This is the supplied capture level, not proof of a usable q1n1/EL2 entry or restoration path.")
    features["el2_execution"]["reported_value"] = execution_el
    return features


def assess_capabilities(data):
    """Produce a research report, never a boot-admission decision."""
    data = validate_evidence(data)
    features = decode_features(data)
    blockers = [name for name in BACKEND_REQUIREMENTS if features[name]["status"] == "absent"]
    unknown = [name for name in BACKEND_REQUIREMENTS if features[name]["status"] == "unknown"]
    provenance = data["provenance"]
    scope = ("reference_only" if provenance == "documentation" else
             "synthetic_only" if provenance == "synthetic" else
             "filtered_view_only" if provenance in FILTERED_VIEWS else "supplied_el2_view_only")
    return {
        "schema_version": 1, "provenance": provenance, "evidence_scope": scope,
        "automatically_masked_fields": sorted(LINUX_HIDDEN_FIELDS) if provenance == "linux_sanitized" else [],
        "coverage": "One supplied register set; coverage of every CPU class is not established.",
        "features": features,
        "counter_frequency_hz": _register(data, "CNTFRQ_EL0"),
        "backend": {
            "name": "Snapintosh A16 stock-kernel monitor",
            "revision": BACKEND_REVISION, "assessment": "not_qualified",
            "reported_blockers": blockers, "unresolved_register_requirements": unknown,
            "meaning": "These are requirements of the pinned backend in this evidence scope, not a verdict on all macOS routes.",
            "still_required": [
                "Confirm EL2 ownership and register views on each intended CPU class.",
                "Validate NV2/VNCR behavior, timer traps, PAC key switching and state restoration with controls.",
                "Validate Apple PAC, arm64e ABI and the exact guest instruction stream.",
                "Port and qualify the SC8280XP memory map, interrupts, q1n1 transport and board devices.",
                "Perform an authorized recorded hardware experiment; no hardware was accessed by this tool.",
            ],
            "sources": [SOURCE_BASE + "/probes/xnuboot/prepare.c",
                        SOURCE_BASE + "/probes/xnuboot/pauth.c"],
        },
        "route_notes": [
            "Native 16K is not required by the current shadow-paging backend. Its advertisement does not validate a table walk.",
            "VMAPPLE/KVM and a source-built EL1 kernel are separate research routes. NV2 is not a universal macOS requirement.",
            "VMAPPLE still needs a compatible guest ISA, PAC contract, granules and virtual devices; no alternate route is qualified here.",
            "Filtered, documented and synthetic values do not establish missing host silicon features. A raw ID read is not a behavior test.",
        ],
        "hardware_status": "NOT RUN",
    }


def render_text(report):
    lines = ["Snapintosh CPU evidence review: NOT QUALIFIED",
             "Backend revision: " + report["backend"]["revision"],
             "Evidence scope: " + report["evidence_scope"], report["coverage"], ""]
    for name, result in report["features"].items():
        lines.append("{}: {} (reported {})".format(name, result["status"], result["reported"]))
    lines.extend(("", "Reported backend blockers: " + (", ".join(report["backend"]["reported_blockers"]) or "none identified"),
                  "Unresolved register requirements: " + (", ".join(report["backend"]["unresolved_register_requirements"]) or "none in this view"),
                  report["backend"]["meaning"], "Hardware status: NOT RUN", ""))
    lines.extend(report["backend"]["still_required"])
    lines.extend(report["route_notes"])
    return "\n".join(lines) + "\n"


class _Parser(argparse.ArgumentParser):
    def error(self, unused_message):
        # argparse normally repeats unrecognized arguments and their values.
        self.exit(2, "error: invalid command-line arguments; use --help\n")


def main(argv=None):
    parser = _Parser(description=__doc__)
    parser.add_argument("--input", required=True, help="schema 1 JSON file; use - for stdin")
    parser.add_argument("--format", choices=("json", "text"), default="json")
    args = parser.parse_args(argv)
    try:
        if args.input == "-":
            raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        else:
            with Path(args.input).open("rb") as stream:
                raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise EvidenceError("input exceeds the supported size")
        report = assess_capabilities(parse_evidence(raw.decode("utf-8")))
    except EvidenceError as error:
        print("error: " + str(error), file=sys.stderr)
        return 2
    except (OSError, UnicodeError):
        print("error: input could not be read as UTF-8 JSON", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report), end="")
    # A successful review is not a successful hardware qualification.
    return 0


if __name__ == "__main__":
    sys.exit(main())
