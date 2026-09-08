"""Build the shipped corpus without local helper imports.

python tests/quality/build.py --out /tmp/crashlink-quality
python tests/quality/build.py --out /tmp/crashlink-quality --native \
    --hl-source /path/to/hashlink --hl-library-dir /path/to/hashlink/build/bin

Native fixtures intentionally target unstripped x86-64 ELF on Linux, at O0/O2.
This does not certify stripped images, PE, ARM64, or executable reconstruction.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
from pathlib import Path


def build(output: Path, native: bool = False, hl_source: str = "", hl_library_dir: str = "") -> None:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source_dir = Path(__file__).resolve().parent
    for source in sorted(source_dir.glob("*.hx")):
        shutil.copyfile(source, output / source.name)
        subprocess.run(
            ["haxe", "-cp", str(output), "-main", source.stem, "-hl", str(output / f"{source.stem}.hl")],
            check=True,
            timeout=60,
        )
    if not native:
        return
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
        raise RuntimeError("Native regression fixtures require Linux x86-64")
    include = Path(hl_source).resolve() / "src"
    library = Path(hl_library_dir).resolve()
    if not (include / "hlc.h").is_file() or not (library / "libhl.so").is_file():
        raise RuntimeError("--native requires HashLink source and a built libhl.so")
    generated = output / "native-c"
    generated.mkdir(exist_ok=True)
    entry = generated / "QualityNative.c"
    subprocess.run(
        ["haxe", "-cp", str(output), "-main", "QualityNative", "-hl", str(entry)],
        check=True,
        timeout=60,
    )
    for tier in ("O0", "O2"):
        subprocess.run(
            [
                os.environ.get("CC", "cc"),
                f"-{tier}",
                "-g",
                "-Wno-incompatible-pointer-types",
                f"-I{generated}",
                f"-I{include}",
                str(entry),
                f"-L{library}",
                f"-Wl,-rpath,{library}",
                "-lhl",
                "-lm",
                "-ldl",
                "-lpthread",
                "-o",
                str(output / f"QualityNative-{tier}.elf"),
            ],
            check=True,
            timeout=120,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--native", action="store_true")
    parser.add_argument("--hl-source", default=os.environ.get("HL_SOURCE", ""))
    parser.add_argument("--hl-library-dir", default=os.environ.get("HL_LIBRARY_DIR", ""))
    args = parser.parse_args()
    build(args.out, args.native, args.hl_source, args.hl_library_dir)
