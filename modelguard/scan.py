#!/usr/bin/env python3
"""
Static scanner for serialized ML model artifacts (pickle / PyTorch .pt / .pkl).

ML models are commonly distributed as pickles, and unpickling executes arbitrary
code via __reduce__ — a poisoned model file runs code the moment you load it.
ModelGuard inspects the pickle's OPCODES WITHOUT EVER UNPICKLING IT (pickletools
.genops), flagging references to dangerous callables (os.system, subprocess,
eval/exec, ...) combined with REDUCE — the signature of a code-execution payload.

Handles both GLOBAL (arg = "module\\nname") and protocol-2+ STACK_GLOBAL, which
takes the module and name from the two preceding string pushes on the stack.

Maps to MITRE ATLAS AML.T0010 (ML Supply Chain Compromise).
SAFETY: never calls pickle.load / torch.load — only reads opcodes.
"""
from __future__ import annotations

import hashlib
import pickletools
import zipfile
from dataclasses import dataclass
from pathlib import Path

DANGEROUS_MODULES = {
    "os", "nt", "posix", "subprocess", "sys", "socket", "shutil", "pty",
    "builtins", "__builtin__", "operator", "importlib", "runpy", "webbrowser",
}
DANGEROUS_NAMES = {"system", "popen", "exec", "eval", "compile", "__import__",
                   "check_output", "check_call", "call", "run", "Popen", "spawn",
                   "spawnl", "getattr", "open"}

STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
              "SHORT_BINSTRING", "BINSTRING", "STRING"}


@dataclass
class Finding:
    severity: str          # "critical" | "warn"
    opcode: str
    detail: str


def _iter_streams(path: Path):
    data = path.read_bytes()
    if zipfile.is_zipfile(path):                 # PyTorch .pt = zip of pickles
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if "pkl" in name or name.endswith("data"):
                    yield z.read(name)
    else:
        yield data


def _is_dangerous(module: str, name: str) -> bool:
    return module.split(".")[0] in DANGEROUS_MODULES or name in DANGEROUS_NAMES


def scan_file(path: Path) -> tuple[list[Finding], str]:
    findings: list[Finding] = []
    sha = hashlib.sha256(path.read_bytes()).hexdigest()

    for stream in _iter_streams(path):
        recent: list[str] = []      # recent string literals, for STACK_GLOBAL
        dangerous_global = False
        try:
            for op, arg, _ in pickletools.genops(stream):
                nm = op.name
                if nm in STRING_OPS and isinstance(arg, str):
                    recent.append(arg)
                    recent = recent[-4:]
                elif nm == "GLOBAL":                 # arg = "module\nname"
                    mod, _, name = str(arg).partition("\n")
                    if _is_dangerous(mod, name):
                        dangerous_global = True
                        findings.append(Finding("critical", nm, f"imports {mod}.{name}"))
                elif nm == "STACK_GLOBAL":            # module,name from stack
                    mod = recent[-2] if len(recent) >= 2 else ""
                    name = recent[-1] if recent else ""
                    if _is_dangerous(mod, name):
                        dangerous_global = True
                        findings.append(Finding("critical", nm, f"imports {mod}.{name}"))
                elif nm == "REDUCE" and dangerous_global:
                    findings.append(Finding("critical", nm,
                                    "REDUCE on a dangerous callable = code execution on load"))
        except Exception as e:
            findings.append(Finding("warn", "PARSE", f"unparseable (suspicious): {e}"))
    return findings, sha
