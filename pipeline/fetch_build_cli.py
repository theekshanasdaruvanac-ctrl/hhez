"""Warm the artifact cache for one build id: python fetch_build_cli.py 36727"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.fetch_artifact import fetch_build  # noqa: E402

if __name__ == "__main__":
    build = sys.argv[1] if len(sys.argv) > 1 else "latest"
    print(fetch_build(build))