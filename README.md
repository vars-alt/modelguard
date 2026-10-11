# ModelGuard 🔐

A **static scanner for malicious ML model artifacts**. Downloaded models ship as serialized files (`.pkl`, PyTorch `.pt`), and **loading one executes arbitrary code** through pickle's `__reduce__`. ModelGuard inspects an artifact's opcodes *without ever loading it* and flags the signature of a code-execution payload — then checks file integrity against a trusted manifest.

> Project **[6]** in a portfolio on adversarial ML & AI security — the **AI supply-chain / cloud-security** piece. Maps to **MITRE ATLAS AML.T0010 (ML Supply Chain Compromise)**.

---

## The problem

```python
torch.load("model_from_the_internet.pt")   # can run os.system(...) before you ever use the model
```

A poisoned model is a code-execution vector, not just bad weights. The risk lives in CI/CD and model registries — exactly where a static, load-free check belongs.

## What it catches

Example run on the bundled samples:

```
🟢 samples/benign.pkl      sha256=8e25cae7af52…  — no code-execution payload
🔴 samples/malicious.pkl   sha256=9052f4f854f7…
     [STACK_GLOBAL] imports posix.system
     [REDUCE] REDUCE on a dangerous callable = code execution on load

1 artifact(s) flagged.
```

It detects references to dangerous callables (`os.system`, `subprocess`, `eval`/`exec`, …) combined with `REDUCE`, across both legacy `GLOBAL` and protocol-2+ `STACK_GLOBAL` encodings, and inside PyTorch `.pt` zip archives.

## Quickstart

```bash
python make_samples.py              # creates a benign and a (inert) malicious sample
python scan.py samples/             # scan a directory or a single file
python scan.py models/ --manifest manifest.json   # also verify SHA-256 integrity
```

Standard library only. `scan.py` **exits non-zero when anything is flagged**, so it drops straight into CI as a gate on model artifacts before they're trusted.

## Cloud / CI

`.github/workflows/run.yml` scans artifacts on every push — the natural home for supply-chain checks, where models enter a registry or bucket. The same command gates a cloud model pipeline.

## 🔒 Safety

The malicious sample's payload is a harmless `echo` and is **inert until unpickled** — and ModelGuard never unpickles anything. Creating detectable fixtures this way is standard practice for security scanners. Do not manually load `samples/malicious.pkl`.

## Roadmap

- Safetensors recommendation + conversion guidance
- Model signing / provenance verification (Sigstore-style)
- Scan Hugging Face repos and cloud buckets directly
- Severity scoring aligned to NIST AI RMF

## License

MIT — see [LICENSE](LICENSE).
