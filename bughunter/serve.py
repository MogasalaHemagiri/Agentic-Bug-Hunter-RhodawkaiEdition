#!/usr/bin/env python3
"""Launch the local shuvonsec.me lookalike target.

For recordings:  `python3 serve.py`  is the command; nothing in the visible
output mentions "demo". The actual implementation lives in `demo/app.py`.

⚠️  Intentionally vulnerable. Run locally only.
"""

import os
import runpy
import sys
from pathlib import Path

if __name__ == "__main__":
    # Recording-friendly default: suppress the toolkit banner so the terminal
    # looks like a plain web server start-up. Set SHUVONSEC_QUIET=0 to opt back in.
    os.environ.setdefault("SHUVONSEC_QUIET", "1")
    # Live-run fix: make `python3 bughunter/serve.py` work from any CWD without
    # PYTHONPATH=. — demo.app imports repo-relative modules, so the repository
    # root must be importable before runpy executes it.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    runpy.run_module("demo.app", run_name="__main__")
