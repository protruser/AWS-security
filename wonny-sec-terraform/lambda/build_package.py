"""Build the Monitoring Lambda deployment zip with its PyMySQL dependency."""

import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parent
BUILD_DIR = SOURCE_DIR / "build" / "monitoring_lambda"
ZIP_PATH = SOURCE_DIR / "build" / "monitoring_lambda.zip"


def main():
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    BUILD_DIR.mkdir(parents=True)

    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-compile",
            "-r",
            str(SOURCE_DIR / "requirements.txt"),
            "--target",
            str(BUILD_DIR),
        ],
        check=True,
    )
    shutil.copy2(SOURCE_DIR / "monitoring_lambda.py", BUILD_DIR / "monitoring_lambda.py")

    ZIP_PATH.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in BUILD_DIR.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(BUILD_DIR))

    print(ZIP_PATH)


if __name__ == "__main__":
    main()
