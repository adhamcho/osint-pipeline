from pathlib import Path
import sys


# Allow `python main.py ...` from the project root without installing the package globally.
PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from osint_pipeline.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
