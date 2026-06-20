#!/usr/bin/env python3
"""後方互換ラッパー。build_streamlit_secrets.py を使ってください。"""

import subprocess
import sys
from pathlib import Path

if __name__ == "__main__":
    script = Path(__file__).with_name("build_streamlit_secrets.py")
    argv = [sys.executable, str(script)]
    if len(sys.argv) == 2 and not sys.argv[1].startswith("-"):
        argv.extend(["--json", sys.argv[1]])
    else:
        argv.extend(sys.argv[1:])
    if "--print" not in argv and "--write" not in argv:
        argv.append("--print")
    raise SystemExit(subprocess.call(argv))
