#!/usr/bin/env python3
"""
Create two sample artifacts for the scanner to test against:
  - samples/benign.pkl     : an ordinary serialized object
  - samples/malicious.pkl  : a pickle whose __reduce__ would run os.system ON LOAD

SAFETY: pickling (pickle.dumps) does NOT execute the payload — only UNPICKLING
would, and ModelGuard never unpickles. The payload is a harmless `echo`. This is
exactly how scanner test fixtures are built. Do not unpickle malicious.pkl.
"""
from __future__ import annotations

import os
import pickle
from pathlib import Path

SAMPLES = Path("samples")
SAMPLES.mkdir(exist_ok=True)


class _EvilPayload:
    # When unpickled, this reduce would invoke os.system(...) — we never load it.
    def __reduce__(self):
        return (os.system, ("echo pwned-by-supply-chain",))


def main():
    (SAMPLES / "benign.pkl").write_bytes(
        pickle.dumps({"weights": [0.1, 0.2, 0.3], "arch": "mlp", "classes": 10}))
    # dumps serializes the reduce instruction; it does not run it
    (SAMPLES / "malicious.pkl").write_bytes(pickle.dumps(_EvilPayload()))
    print("wrote samples/benign.pkl and samples/malicious.pkl (payload inert until loaded)")


if __name__ == "__main__":
    main()
