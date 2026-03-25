from __future__ import annotations

import os
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for path in [os.path.join(ROOT, "krimo_ai", "src"), os.path.join(ROOT, "src"), ROOT]:
    if path not in sys.path:
        sys.path.insert(0, path)

from krimo_ai.main import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
