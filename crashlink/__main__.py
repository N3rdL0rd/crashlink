"""
Entrypoint for the crashlink CLI.
"""

from __future__ import annotations

import argparse
import atexit
import importlib
import inspect
import os
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import traceback
import webbrowser
from typing import Callable, Dict, List, Optional, Tuple, Set, cast

from crashlink.hlc import code_to_c, code_to_c_files

from . import decomp, disasm, globals
from .core import (
    XRef,
    TargetKind,
    SourceKind,
    RefKind,
    USE_TQDM,
    ProgressCallback,
)
from .asm import AsmFile
from .core import (
    Bytecode,
    Function,
    Native,
    Virtual,
    tIndex,
    strRef,
    gIndex,
    Enum,
    Type,
    Fun,
    Obj,
    Ref,
    Null,
    Packed,
    GUID,
    Abstract,
)
from .globals import VERSION
from .interp.vm import VM  # type: ignore
from .opcodes import opcode_docs, opcodes
from .pseudo import pseudo
from hlrun.patch import Patch

_SUBCOMMAND_HELP: Dict[str, str] = {
    "gui": "Launch the graphical bytecode inspector",
    "hlc": "Transpile HashLink bytecode to C and emit a matching build script",
    "mcp": "Run crashlink as an MCP server for AI-assisted analysis",
    "info": "Print summary information about a bytecode file",
    "disasm": "Disassemble a function from a bytecode file",
    "search": "Search strings in a bytecode file",
    "funcs": "List functions in a bytecode file",
    "decompile": "Decompile a function or class to pseudo-Haxe (INCOMPLETE, usually functional)",
    "db": "Work with .cldb analysis databases",
}


def _make_progress_cb() -> "Optional[ProgressCallback]":
    if USE_TQDM:
        try:
            from tqdm import tqdm as _tqdm

            bar = _tqdm(
                total=100,
                desc="loading",
                unit="%",
                bar_format="{desc} {bar}| {n_fmt}/{total_fmt}% [{elapsed}<{remaining}]",
            )
            _last: List[int] = [0]

            def _cb(frac: float, status: str) -> None:
                pct = int(frac * 100)
                bar.set_description_str(status, refresh=False)
                delta = pct - _last[0]
                if delta > 0:
                    bar.update(delta)
                    _last[0] = pct
                if frac >= 1.0:
                    bar.close()

            return _cb
        except Exception:
            pass

    # No tqdm available (it's an optional extra) — fall back to plain status lines
    # so long-running operations (e.g. `hlc` on a large bytecode file) still show
    # visible progress instead of appearing to hang.
    _last_pct: List[int] = [-1]

    def _plain_cb(frac: float, status: str) -> None:
        pct = int(frac * 100)
        if pct != _last_pct[0]:
            _last_pct[0] = pct
            end = "\n" if frac >= 1.0 else ""
            print(
                f"\r[{pct:3d}%] {status}" + " " * 20 + end,
                end="",
                file=sys.stderr,
                flush=True,
            )

    return _plain_cb


def _load_code_from_cli_path(path: str, no_constants: bool) -> Bytecode:
    is_haxe = True
    with open(path, "rb") as f:
        if f.read(3) == b"HLB":
            is_haxe = False
        else:
            f.seek(0)
            try:
                f.read(128).decode("utf-8")
            except UnicodeDecodeError:
                is_haxe = False

    if is_haxe:
        stripped = path.split(".")[0]
        os.system(f"haxe -hl {stripped}.hl -main {path}")
        with open(f"{stripped}.hl", "rb") as f:
            return Bytecode().deserialise(f, init_globals=not no_constants, progress_cb=_make_progress_cb())

    if not path.endswith(".pkl"):
        with open(path, "rb") as f:
            return Bytecode().deserialise(f, init_globals=not no_constants, progress_cb=_make_progress_cb())

    try:
        import dill  # type: ignore[import-untyped]

        with open(path, "rb") as f:
            return cast(Bytecode, dill.load(f))
    except ImportError:
        print("Dill not found. Install dill to unpickle bytecode, or install crashlink with the [extras] option.")
        sys.exit(1)


def _default_hlc_output(path: str) -> str:
    p = Path(path)
    return str(p.with_suffix(".c"))


def _hlc_native_libs(code: Bytecode) -> List[str]:
    return sorted({n.lib.resolve(code).lstrip("?") for n in code.natives if n.lib.resolve(code).lstrip("?") != "std"})


def _find_hdll(lib: str, search_dirs: List[Path]) -> Path | None:
    filename = f"{lib}.hdll"
    seen: Set[Path] = set()
    for raw_dir in search_dirs:
        directory = raw_dir.expanduser().resolve()
        if directory in seen or not directory.exists():
            continue
        seen.add(directory)
        direct = directory / filename
        if direct.is_file():
            return direct
        for match in directory.rglob(filename):
            if match.is_file():
                return match.resolve()
    return None


def _build_search_dirs(hashlink_dir: Path, extra_hdll_dirs: List[str]) -> List[Path]:
    dirs = [hashlink_dir / "build" / "bin", hashlink_dir]
    dirs.extend(Path(d) for d in extra_hdll_dirs)
    return dirs


def _find_shared_lib(filename: str, search_dirs: List[Path]) -> Path | None:
    seen: Set[Path] = set()
    for raw_dir in search_dirs:
        directory = raw_dir.expanduser().resolve()
        if directory in seen or not directory.exists():
            continue
        seen.add(directory)
        direct = directory / filename
        if direct.is_file():
            return direct
        for match in directory.rglob(filename):
            if match.is_file():
                return match.resolve()
    return None


def _find_any_shared_lib(filenames: List[str], search_dirs: List[Path]) -> Path | None:
    for filename in filenames:
        match = _find_shared_lib(filename, search_dirs)
        if match is not None:
            return match
    return None


def _resolve_native_hdlls(
    native_libs: List[str], hashlink_dir: Path, extra_hdll_dirs: List[str]
) -> tuple[Dict[str, Path], List[str]]:
    resolved: Dict[str, Path] = {}
    missing: List[str] = []
    search_dirs = _build_search_dirs(hashlink_dir, extra_hdll_dirs)
    for lib in native_libs:
        path = _find_hdll(lib, search_dirs)
        if path is None:
            missing.append(lib)
        else:
            resolved[lib] = path
    return resolved, missing


def _compile_objects_parallel(
    c_paths: List[str],
    hashlink_dir: Path,
    use_clang: bool,
    use_ccache: bool,
    opt_level: str,
    obj_dir: Path,
) -> List[str]:
    """Compiles each C file to an object file, in parallel across cores.
    Returns the object paths. Raises on the first compile failure."""
    import concurrent.futures

    obj_dir.mkdir(parents=True, exist_ok=True)
    cc: List[str] = (["ccache"] if use_ccache else []) + ["clang" if use_clang else "cc"]
    base_flags = [
        opt_level,
        "-Wno-incompatible-pointer-types",
        f"-I{hashlink_dir / 'src'}",
    ]

    def compile_one(c_path: str) -> str:
        obj = str(obj_dir / (Path(c_path).stem + ".o"))
        cmd = cc + base_flags + ["-c", c_path, "-o", obj]
        print("Compiling:", " ".join(cmd))
        subprocess.run(cmd, check=True)
        return obj

    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
        return list(pool.map(compile_one, c_paths))


def _build_compile_command(
    c_paths: List[str],
    bin_path: str,
    hashlink_dir: Path,
    hdll_paths: List[Path],
    native_libs: List[str],
    extra_hdll_dirs: List[str],
    use_clang: bool,
    use_ccache: bool,
    opt_level: str = "-O2",
    include_hlc_main: bool = True,
) -> List[str]:
    search_dirs = _build_search_dirs(hashlink_dir, extra_hdll_dirs)
    cmd: List[str] = []
    if use_ccache:
        cmd.append("ccache")
    cmd.append("clang" if use_clang else "cc")
    cmd.extend(
        [
            opt_level,
            "-Wno-incompatible-pointer-types",
            f"-I{hashlink_dir / 'src'}",
            *c_paths,
        ]
    )
    if include_hlc_main:
        cmd.append(str(hashlink_dir / "src" / "hlc_main.c"))
    cmd.extend(str(p) for p in hdll_paths)
    if "uv" in native_libs:
        explicit_uv = _find_any_shared_lib(["libuv.so", "libuv.so.1"], search_dirs)
        if explicit_uv is not None:
            cmd.append(str(explicit_uv))
            cmd.append(f"-Wl,-rpath-link,{explicit_uv.parent}")
        else:
            try:
                uv_flags = subprocess.check_output(["pkg-config", "--libs", "libuv"], text=True).strip().split()
                cmd.extend(uv_flags)
            except Exception:
                cmd.append("-luv")
    if "steam" in native_libs:
        steam_api = _find_shared_lib("libsteam_api.so", search_dirs)
        if steam_api is not None:
            cmd.append(f"-L{steam_api.parent}")
            cmd.append("-lsteam_api")
            cmd.append(f"-Wl,-rpath-link,{steam_api.parent}")
            cmd.append(f"-Wl,-rpath,{steam_api.parent}")
    cmd.extend(
        [
            f"-L{hashlink_dir / 'build' / 'bin'}",
            "-lhl",
            "-lm",
            "-ldl",
            "-lpthread",
            "-lstdc++" if "steam" in native_libs else "",
            f"-Wl,-rpath,{hashlink_dir / 'build' / 'bin'}",
            "-o",
            bin_path,
        ]
    )
    return [part for part in cmd if part]


def _build_hlc_script(
    c_paths: List[str],
    bin_path: str,
    native_libs: List[str],
    hashlink_dir: Path,
    extra_hdll_dirs: List[str],
    use_clang: bool,
    use_ccache: bool,
    opt_level: str = "-O2",
) -> str:
    extra_dirs_literal = " ".join(f'"{d}"' for d in extra_hdll_dirs)
    c_files_literal = " ".join(f'"{p}"' for p in c_paths)
    script = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        f'HASHLINK_DIR="${{HASHLINK_DIR:-{hashlink_dir}}}"',
        f"C_FILES=({c_files_literal})",
        f'OUT_FILE="{bin_path}"',
        f"EXTRA_HDLL_DIRS=({extra_dirs_literal})",
        f"USE_CLANG={'1' if use_clang else '0'}",
        f"USE_CCACHE={'1' if use_ccache else '0'}",
        f'OPT_LEVEL="{opt_level}"',
        "",
        'if [ ! -f "$HASHLINK_DIR/build/bin/libhl.so" ]; then',
        '  echo "error: libhl.so not found under $HASHLINK_DIR/build/bin" >&2',
        "  exit 1",
        "fi",
        "",
        "find_hdll() {",
        '  local name="$1"',
        "  shift",
        '  local filename="${name}.hdll"',
        "  local dir match",
        '  for dir in "$@"; do',
        '    [ -d "$dir" ] || continue',
        '    if [ -f "$dir/$filename" ]; then',
        '      printf "%s\\n" "$dir/$filename"',
        "      return 0",
        "    fi",
        '    match=$(find "$dir" -type f -name "$filename" -print -quit 2>/dev/null || true)',
        '    if [ -n "$match" ]; then',
        '      printf "%s\\n" "$match"',
        "      return 0",
        "    fi",
        "  done",
        "  return 1",
        "}",
        "",
        'SEARCH_DIRS=("$HASHLINK_DIR/build/bin" "$HASHLINK_DIR" "${EXTRA_HDLL_DIRS[@]}")',
        "HDLL_ARGS=()",
        'HDLL_DIRS=("$HASHLINK_DIR/build/bin")',
        "EXTRA_LINK_ARGS=()",
        "CC_BIN=cc",
        "CC_PREFIX=()",
        'if [ "$USE_CLANG" = "1" ]; then CC_BIN=clang; fi',
        'if [ "$USE_CCACHE" = "1" ]; then CC_PREFIX=(ccache); fi',
        "find_shared_lib() {",
        '  local filename="$1"',
        "  shift",
        "  local dir match",
        '  for dir in "$@"; do',
        '    [ -d "$dir" ] || continue',
        '    if [ -f "$dir/$filename" ]; then',
        '      printf "%s\n" "$dir/$filename"',
        "      return 0",
        "    fi",
        '    match=$(find "$dir" -type f -name "$filename" -print -quit 2>/dev/null || true)',
        '    if [ -n "$match" ]; then',
        '      printf "%s\n" "$match"',
        "      return 0",
        "    fi",
        "  done",
        "  return 1",
        "}",
    ]
    for lib in native_libs:
        script += [
            f'path=$(find_hdll "{lib}" "${{SEARCH_DIRS[@]}}" || true)',
            'if [ -z "$path" ]; then',
            f'  echo "error: could not find {lib}.hdll in search directories" >&2',
            "  exit 1",
            "fi",
            'HDLL_ARGS+=("$path")',
            'HDLL_DIRS+=("$(dirname "$path")")',
        ]
    if "uv" in native_libs:
        script += [
            'explicit_uv=$(find_shared_lib "libuv.so" "${SEARCH_DIRS[@]}" || true)',
            'if [ -z "$explicit_uv" ]; then explicit_uv=$(find_shared_lib "libuv.so.1" "${SEARCH_DIRS[@]}" || true); fi',
            'if [ -n "$explicit_uv" ]; then',
            '  EXTRA_LINK_ARGS+=("$explicit_uv" "-Wl,-rpath-link,$(dirname "$explicit_uv")")',
            '  HDLL_DIRS+=("$(dirname "$explicit_uv")")',
            "elif command -v pkg-config >/dev/null 2>&1; then",
            "  UV_LIBS=$(pkg-config --libs libuv 2>/dev/null || true)",
            '  if [ -n "$UV_LIBS" ]; then EXTRA_LINK_ARGS+=( $UV_LIBS ); else EXTRA_LINK_ARGS+=("-luv"); fi',
            "else",
            '  EXTRA_LINK_ARGS+=("-luv")',
            "fi",
        ]
    if "steam" in native_libs:
        script += [
            'steam_api=$(find_shared_lib "libsteam_api.so" "${SEARCH_DIRS[@]}" || true)',
            'if [ -n "$steam_api" ]; then',
            '  EXTRA_LINK_ARGS+=("-L$(dirname "$steam_api")" "-lsteam_api" "-Wl,-rpath-link,$(dirname "$steam_api")" "-Wl,-rpath,$(dirname "$steam_api")" "-lstdc++")',
            '  HDLL_DIRS+=("$(dirname "$steam_api")")',
            "else",
            '  echo "warning: libsteam_api.so not found in search directories" >&2',
            "fi",
        ]
    script += [
        "",
        "# Compile each translation unit to an object file, in parallel across cores,",
        "# then link. (With a single generated C file this is one compile job; with",
        "# --split N it's N+2, which is the whole point of splitting.)",
        "NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)",
        "OBJ_DIR=$(mktemp -d)",
        "trap 'rm -rf \"$OBJ_DIR\"' EXIT",
        "OBJS=()",
        'for c in "${C_FILES[@]}" "$HASHLINK_DIR/src/hlc_main.c"; do',
        '  obj="$OBJ_DIR/$(basename "$c").o"',
        '  OBJS+=("$obj")',
        '  "${CC_PREFIX[@]}" "$CC_BIN" "$OPT_LEVEL" -Wno-incompatible-pointer-types \\',
        '    -I"$HASHLINK_DIR/src" -c "$c" -o "$obj" &',
        '  while [ "$(jobs -rp | wc -l)" -ge "$NPROC" ]; do wait -n; done',
        "done",
        "wait",
        "",
        '"${CC_PREFIX[@]}" "$CC_BIN" "$OPT_LEVEL" \\',
        '  "${OBJS[@]}" \\',
        '  "${HDLL_ARGS[@]}" \\',
        "  ${EXTRA_LINK_ARGS[@]} \\",
        '  -L"$HASHLINK_DIR/build/bin" -lhl -lm -ldl -lpthread \\',
        '  -Wl,-rpath,"$HASHLINK_DIR/build/bin" \\',
        '  -o "$OUT_FILE"',
        "",
        'echo "Built $OUT_FILE"',
        'LD_PATH=$(IFS=:; echo "${HDLL_DIRS[*]}")',
        'echo "Run with: LD_LIBRARY_PATH=$LD_PATH $OUT_FILE"',
    ]
    return "\n".join(script) + "\n"


def info_main(argv: List[str]) -> None:
    parser = argparse.ArgumentParser(
        description="Print summary information about a bytecode file.",
        prog="crashlink info",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(
            [
                "examples:",
                "  crashlink info game.hl",
                "      Print version, function/type/string counts, etc.",
                "",
                "  crashlink info game.hl -N",
                "      Same, but skip constant resolution (useful for malformed files).",
            ]
        ),
    )
    parser.add_argument("file", help="Input .hl / .dat file")
    parser.add_argument("-N", "--no-constants", action="store_true", help="Skip constant resolution")
    args = parser.parse_args(argv)
    code = _load_code_from_cli_path(args.file, args.no_constants)
    print(f"Version: {code.version}")
    print(f"Has debug info: {code.has_debug_info}")
    print(f"Functions: {len(code.functions)}")
    print(f"Natives: {len(code.natives)}")
    print(f"Types: {len(code.types)}")
    print(f"Strings: {len(code.strings.value)}")
    print(f"Ints: {len(code.ints)}")
    print(f"Floats: {len(code.floats)}")
    print(f"Globals: {len(code.global_types)}")


def disasm_main(argv: List[str]) -> None:
    parser = argparse.ArgumentParser(
        description="Disassemble a function from a bytecode file.",
        prog="crashlink disasm",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(
            [
                "examples:",
                "  crashlink disasm game.hl 42",
                "      Disassemble the function with findex 42 (use 'crashlink funcs' to find indexes).",
                "",
                "  crashlink disasm game.hl 42 -N",
                "      Disassemble without resolving constants first.",
            ]
        ),
    )
    parser.add_argument("file", help="Input .hl / .dat file")
    parser.add_argument("findex", type=int, help="Function index to disassemble")
    parser.add_argument("-N", "--no-constants", action="store_true", help="Skip constant resolution")
    args = parser.parse_args(argv)
    code = _load_code_from_cli_path(args.file, args.no_constants)
    for func in code.functions:
        if func.findex.value == args.findex:
            print(disasm.func(code, func))
            return
    for native in code.natives:
        if native.findex.value == args.findex:
            print(disasm.native_header(code, native))
            return
    print(f"Function f@{args.findex} not found.", file=sys.stderr)
    sys.exit(1)


def search_main(argv: List[str]) -> None:
    parser = argparse.ArgumentParser(
        description="Search strings in a bytecode file.",
        prog="crashlink search",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(
            [
                "examples:",
                "  crashlink search game.hl password",
                "      Print every string containing 'password' (case-insensitive), with its s@ index.",
                "",
                '  crashlink search game.hl "http://"',
                "      Find embedded URLs.",
            ]
        ),
    )
    parser.add_argument("file", help="Input .hl / .dat file")
    parser.add_argument("query", help="Substring to search for (case-insensitive)")
    parser.add_argument("-N", "--no-constants", action="store_true", help="Skip constant resolution")
    args = parser.parse_args(argv)
    code = _load_code_from_cli_path(args.file, args.no_constants)
    matches = [(i, s) for i, s in enumerate(code.strings.value) if args.query.lower() in s.lower()]
    if not matches:
        print(f'No strings matching "{args.query}".')
    for i, s in matches:
        print(f"s@{i}: {s}")


def db_main(argv: List[str]) -> None:
    from . import database as db

    parser = argparse.ArgumentParser(
        description="Work with .cldb analysis databases.",
        prog="crashlink db",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(
            [
                "examples:",
                "  crashlink db info game.cldb",
                "      Show format version, source hash, and counts of renames/comments/cached functions.",
                "",
                "  crashlink db check game.cldb game.hl",
                "      Verify game.cldb still matches game.hl before trusting its cached data.",
                "",
                "  crashlink db renames game.cldb",
                "  crashlink db comments game.cldb",
                "      List the individual renames or comments stored in the database.",
            ]
        ),
    )
    sub = parser.add_subparsers(dest="action", required=True)

    p_info = sub.add_parser(
        "info",
        help="Show summary info for a .cldb",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  crashlink db info game.cldb",
    )
    p_info.add_argument("cldb", help="Path to the .cldb file")

    p_check = sub.add_parser(
        "check",
        help="Validate a .cldb against a bytecode file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  crashlink db check game.cldb game.hl",
    )
    p_check.add_argument("cldb", help="Path to the .cldb file")
    p_check.add_argument("file", help="Bytecode (.hl/.dat) file to check against")
    p_check.add_argument("-N", "--no-constants", action="store_true", help="Skip constant resolution")

    p_renames = sub.add_parser(
        "renames",
        help="List renames stored in a .cldb",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  crashlink db renames game.cldb",
    )
    p_renames.add_argument("cldb", help="Path to the .cldb file")

    p_comments = sub.add_parser(
        "comments",
        help="List comments stored in a .cldb",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  crashlink db comments game.cldb",
    )
    p_comments.add_argument("cldb", help="Path to the .cldb file")

    args = parser.parse_args(argv)

    if args.action == "info":
        try:
            info = db.inspect_database(args.cldb)
        except (db.DatabaseError, OSError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"Format version: {info.format_version}")
        print(
            f"Source: {info.source_basename}  ({info.source_size} bytes, HL v{info.hl_version}, {info.nfunctions} functions)"
        )
        print(f"Source hash: {info.source_hash_hex}")
        print(f"Renames: {len(info.renames)}")
        print(f"Comments: {len(info.comments)}")
        print(f"Cached functions: {len(info.cache_findices)}")
        if info.session is not None:
            s = info.session
            print(f"Session: view_mode={s.view_mode}  theme={s.theme_name!r}  open_tabs={len(s.open_findices)}")
        else:
            print("Session: none")

    elif args.action == "check":
        code = _load_code_from_cli_path(args.file, args.no_constants)
        try:
            result = db.load_database(args.cldb, code=code, source_path=args.file)
        except (db.DatabaseError, OSError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        if not result.matched:
            for w in result.warnings:
                print(f"MISMATCH: {w}")
            sys.exit(1)
        print(f"OK — {args.cldb} matches {args.file}")
        print(
            f"  {result.renames_applied} renames, {result.comments_applied} comments, "
            f"{len(result.cache)} cached functions would apply"
        )

    elif args.action == "renames":
        try:
            info = db.inspect_database(args.cldb)
        except (db.DatabaseError, OSError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        if not info.renames:
            print("No renames.")
        for findex, reg_idx, def_op, name in info.renames:
            where = f"op {def_op}" if def_op is not None else "initial"
            print(f"f@{findex}  reg{reg_idx} ({where})  ->  {name}")

    elif args.action == "comments":
        try:
            info = db.inspect_database(args.cldb)
        except (db.DatabaseError, OSError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        if not info.comments:
            print("No comments.")
        for findex, src_op_idx, text in info.comments:
            print(f"f@{findex}  op {src_op_idx}:  {text}")


def funcs_main(argv: List[str]) -> None:
    parser = argparse.ArgumentParser(
        description="List functions in a bytecode file.",
        prog="crashlink funcs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(
            [
                "examples:",
                "  crashlink funcs game.hl",
                "      List user-code functions (stdlib and natives hidden by default).",
                "",
                "  crashlink funcs game.hl --std --natives",
                "      Include stdlib functions and native stubs too.",
                "",
                "  crashlink funcs game.hl | grep -i update",
                "      Find a function by name to get its findex for 'crashlink disasm'/'decompile'.",
            ]
        ),
    )
    parser.add_argument("file", help="Input .hl / .dat file")
    parser.add_argument("--std", action="store_true", help="Include stdlib functions")
    parser.add_argument("--natives", action="store_true", help="Include native stubs")
    parser.add_argument("-N", "--no-constants", action="store_true", help="Skip constant resolution")
    args = parser.parse_args(argv)
    code = _load_code_from_cli_path(args.file, args.no_constants)
    for func in code.functions:
        if disasm.is_std(code, func) and not args.std:
            continue
        print(disasm.func_header(code, func))
    if args.natives:
        for native in code.natives:
            if disasm.is_std(code, native) and not args.std:
                continue
            print(disasm.native_header(code, native))


def decompile_main(argv: List[str]) -> None:
    parser = argparse.ArgumentParser(
        description="Decompile a function or class to pseudo-Haxe. INCOMPLETE — usually functional, but a work in progress.",
        prog="crashlink decompile",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(
            [
                "examples:",
                "  crashlink decompile game.hl 42",
                "      Decompile the function with findex 42 to pseudo-Haxe.",
                "",
                "  crashlink decompile game.hl 17 --class",
                "      Decompile the whole class at tIndex 17 (all of its methods).",
                "",
                "  crashlink funcs game.hl | grep -i MyClass",
                "      Find the findex/tIndex to pass in, by name.",
            ]
        ),
    )
    parser.add_argument("file", help="Input .hl / .dat file")
    parser.add_argument("index", type=int, help="findex for a function, or tIndex with --class")
    parser.add_argument(
        "--class",
        dest="is_class",
        action="store_true",
        help="Treat index as a tIndex and decompile the whole class",
    )
    parser.add_argument("-N", "--no-constants", action="store_true", help="Skip constant resolution")
    args = parser.parse_args(argv)
    print(
        "[warning] Decompiler is a work in progress — usually functional, but output may be incorrect or incomplete for some functions.",
        file=sys.stderr,
    )
    code = _load_code_from_cli_path(args.file, args.no_constants)

    if args.is_class:
        from .decomp import IRClass

        try:
            typ = code.types[args.index]
        except IndexError:
            print(f"Type t@{args.index} not found.", file=sys.stderr)
            sys.exit(1)
        if not isinstance(typ.definition, Obj):
            print(f"Type t@{args.index} is not a class.", file=sys.stderr)
            sys.exit(1)
        ir_class = IRClass(code, typ.definition)
        print(ir_class.pseudo())
    else:
        from .decomp import IRFunction
        from .pseudo import pseudo as _pseudo

        for func in code.functions:
            if func.findex.value == args.index:
                ir = IRFunction(code, func)
                print(_pseudo(ir))
                return
        print(f"Function f@{args.index} not found.", file=sys.stderr)
        sys.exit(1)


def hlc_main(argv: List[str]) -> None:
    parser = argparse.ArgumentParser(
        description="Transpile HashLink bytecode to C and emit a matching build script.",
        prog="crashlink hlc",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(
            [
                "examples:",
                "  crashlink hlc game.hl",
                "      Emit game.c and a build script next to it, but don't compile.",
                "",
                "  crashlink hlc game.hl --build",
                "      Emit and immediately compile/link against libhl (uses $HASHLINK_DIR or --hashlink-dir).",
                "",
                "  crashlink hlc game.hl --build -O0",
                "      Faster dev builds: skip most C compiler optimization (a single generated",
                "      file can't be parallelized across cores, so this is the main speed lever).",
                "",
                "  crashlink hlc game.hl --build --split 8 --hdll-dir ./hdll",
                "      Split the generated C into 8 translation units for parallel compilation,",
                "      and look in ./hdll for any HDLLs the bytecode depends on.",
            ]
        ),
    )
    parser.add_argument("file", help="Input .hl / .dat / Haxe source file")
    parser.add_argument("-o", "--output", help="Output C filename")
    parser.add_argument("--build", help="Compile the generated C immediately", action="store_true")
    parser.add_argument("--clang", help="Use clang/clang++ instead of cc/c++", action="store_true")
    parser.add_argument("--ccache", help="Prefix compiler invocation with ccache", action="store_true")
    parser.add_argument(
        "-O",
        "--opt-level",
        choices=["0", "1", "2", "3", "s", "z"],
        default="2",
        help="Compiler optimization level (default: 2). Use 0 for much faster dev builds; a single generated "
        "C file can't be parallelized across cores, so lowering this is the main way to speed up --build "
        "without splitting the output.",
    )
    parser.add_argument(
        "--hashlink-dir",
        help="HashLink source/build root to use for includes, libhl, and HDLL search",
        default=os.environ.get("HASHLINK_DIR", "/home/nerd/code/hashlink"),
    )
    parser.add_argument(
        "--hdll-dir",
        help="Extra directory to search for HDLLs. Can be passed multiple times.",
        action="append",
        default=[],
    )
    parser.add_argument(
        "-N",
        "--no-constants",
        help="Don't resolve constants during deserialisation",
        action="store_true",
    )
    parser.add_argument(
        "-j",
        "--split",
        type=int,
        default=1,
        metavar="N",
        help="Split the generated C into N function translation units (plus a shared "
        "header and a data/entry TU) so compilation can run in parallel across cores. "
        "Default 1 = classic single-file output.",
    )
    args = parser.parse_args(argv)
    if args.split < 1:
        parser.error("--split must be >= 1")

    code = _load_code_from_cli_path(args.file, args.no_constants)
    out_c = args.output or _default_hlc_output(args.file)
    out_bin = str(Path(out_c).with_suffix(""))
    build_script = str(Path(out_c).with_suffix(".build.sh"))
    hashlink_dir = Path(args.hashlink_dir).expanduser().resolve()

    out_dir = Path(out_c).resolve().parent
    out_dir.mkdir(parents=True, exist_ok=True)
    basename = Path(out_c).stem
    files = code_to_c_files(code, parts=args.split, basename=basename, progress_cb=_make_progress_cb())
    c_files: List[str] = []
    for rel_name, content in files.items():
        path = out_dir / rel_name
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        if rel_name.endswith(".c"):
            c_files.append(str(path))
    c_files.sort()  # data TU first, then parts (basename.c < basename.pNN.c)

    opt_level = f"-O{args.opt_level}"
    native_libs = _hlc_native_libs(code)
    script = _build_hlc_script(
        c_files,
        out_bin,
        native_libs,
        hashlink_dir,
        args.hdll_dir,
        args.clang,
        args.ccache,
        opt_level,
    )
    with open(build_script, "w") as f:
        f.write(script)
    os.chmod(build_script, 0o755)

    resolved_hdlls, missing_hdlls = _resolve_native_hdlls(native_libs, hashlink_dir, args.hdll_dir)

    if len(c_files) == 1:
        print(f"Wrote C output: {out_c}")
    else:
        print(f"Wrote C output: {len(c_files)} translation units + {basename}.h in {out_dir}")
    print(f"Wrote build script: {build_script}")
    if native_libs:
        print("Native libraries:", ", ".join(native_libs))
    else:
        print("Native libraries: none")
    if missing_hdlls:
        print("Missing HDLLs:", ", ".join(missing_hdlls))
    print(f"Build with: {build_script}")

    if args.build:
        if missing_hdlls:
            print("Cannot build: missing required HDLLs")
            sys.exit(1)
        if len(c_files) > 1:
            # parallel per-TU compile, then a link-only invocation over the objects
            objs = _compile_objects_parallel(
                c_files + [str(hashlink_dir / "src" / "hlc_main.c")],
                hashlink_dir,
                args.clang,
                args.ccache,
                opt_level,
                out_dir / f"{basename}.objs",
            )
            cmd = _build_compile_command(
                objs,
                out_bin,
                hashlink_dir,
                [resolved_hdlls[lib] for lib in native_libs],
                native_libs,
                args.hdll_dir,
                args.clang,
                args.ccache,
                opt_level,
                include_hlc_main=False,
            )
        else:
            cmd = _build_compile_command(
                c_files,
                out_bin,
                hashlink_dir,
                [resolved_hdlls[lib] for lib in native_libs],
                native_libs,
                args.hdll_dir,
                args.clang,
                args.ccache,
                opt_level,
            )
        print("Compiling:", " ".join(cmd))
        subprocess.run(cmd, check=True)
        print(f"Built binary: {out_bin}")


def primary(
    name: str,
) -> Callable[[Callable[[Commands, List[str]], None]], Callable[[Commands, List[str]], None]]:
    """Decorator to set the primary name for a command method, for names that are invalid Python identifiers."""

    def decorator(
        func: Callable[[Commands, List[str]], None],
    ) -> Callable[[Commands, List[str]], None]:
        func._primary_alias = name  # type: ignore
        return func

    return decorator


def alias(
    *aliases: str,
) -> Callable[[Callable[[Commands, List[str]], None]], Callable[[Commands, List[str]], None]]:
    """Decorator to add aliases to command methods"""

    def decorator(
        func: Callable[[Commands, List[str]], None],
    ) -> Callable[[Commands, List[str]], None]:
        func._aliases = aliases  # type: ignore
        return func

    return decorator


class BaseCommands:
    """
    Base class for all command containers.
    """

    def __init__(self, code: Bytecode):
        self.code = code

    def _format_help(self, doc: str, cmd: str) -> Tuple[str, str]:
        """Formats the docstring for a command. Returns (usage, description)"""
        s = doc.strip().split("`")
        if len(s) == 1:
            return cmd, " ".join(s)
        return s[1], s[0]

    def _short_desc(self, desc: str) -> str:
        """Collapses a (possibly multi-line/multi-paragraph) description to a single summary line."""
        first_para = textwrap.dedent(desc).strip().split("\n\n")[0]
        return " ".join(first_para.split())

    def exit(self, args: List[str]) -> None:
        """Exit the program"""
        sys.exit()

    def help(self, args: List[str]) -> None:
        """Prints this help message, or details on a specific command. `help [command]`"""
        commands = self._get_commands()
        command_aliases = self._get_command_aliases()
        term_width = shutil.get_terminal_size(fallback=(100, 24)).columns

        if args:
            for command in args:
                if command not in commands:
                    print(f"Unknown command: {command}")
                    continue
                doc: str = commands[command].__doc__ or ""
                usage, desc = self._format_help(doc, command)
                primary = getattr(commands[command], "_primary_alias", None) or command
                aliases = command_aliases.get(primary, [])
                print(f"usage: {usage}")
                if aliases:
                    print(f"aliases: {', '.join(sorted(aliases))}")
                cleaned = textwrap.dedent(desc).strip()
                if "\n" in cleaned:
                    # Multi-line docstrings (e.g. with a worked-out "Usage:" block) are already
                    # hand-formatted, so print them as-is instead of re-wrapping.
                    print(cleaned)
                else:
                    for line in textwrap.wrap(cleaned, width=max(40, term_width - 2)) or [""]:
                        print(line)
                print()
            return

        print("Available commands:")
        print()

        # Group commands by their primary name (avoid showing aliases as separate entries)
        primary_commands = self._get_primary_commands()

        rows: List[Tuple[str, str]] = []
        for cmd, func in sorted(primary_commands.items()):
            usage, desc = self._format_help(func.__doc__ or "", cmd)
            aliases = command_aliases.get(cmd, [])
            label = usage if not aliases else f"{usage}  ({', '.join(sorted(aliases))})"
            rows.append((label, self._short_desc(desc)))

        label_width = min(max((len(label) for label, _ in rows), default=0) + 2, 36)
        desc_width = max(30, term_width - label_width - 4)
        for label, desc in rows:
            wrapped = textwrap.wrap(desc, width=desc_width) or [""]
            if len(label) >= label_width:
                print(f"  {label}")
                for cont in wrapped:
                    print(f"  {'':<{label_width}}{cont}")
            else:
                print(f"  {label:<{label_width}}{wrapped[0]}")
                for cont in wrapped[1:]:
                    print(f"  {'':<{label_width}}{cont}")

        print()
        print("Type 'help <command>' for details on a specific command.")
        print("Up/down arrows browse command history; 'history' lists it; 'clear' clears the screen.")

    def _get_commands(self) -> Dict[str, Callable[[List[str]], None]]:
        """Get all command methods using reflection, including primary aliases and other aliases."""
        commands: Dict[str, Callable[[List[str]], None]] = {}

        for name, func in inspect.getmembers(self, predicate=inspect.ismethod):
            primary_alias = getattr(func, "_primary_alias", None)

            # Determine the primary command name to register, if any
            primary_cmd_name = None
            if primary_alias:
                primary_cmd_name = primary_alias
            elif not name.startswith("_"):
                primary_cmd_name = name

            # If we identified a primary name, this is a command function.
            # Register its primary name and all of its aliases.
            if primary_cmd_name:
                commands[primary_cmd_name] = func
                if hasattr(func, "_aliases"):
                    for alias_name in func._aliases:  # pyright: ignore[reportAttributeAccessIssue]
                        commands[alias_name] = func

        return commands

    def _get_primary_commands(self) -> Dict[str, Callable[[List[str]], None]]:
        """Get only the primary command methods (no aliases), respecting primary aliases."""
        primary_commands: Dict[str, Callable[[List[str]], None]] = {}

        for name, func in inspect.getmembers(self, predicate=inspect.ismethod):
            primary_alias = getattr(func, "_primary_alias", None)

            if primary_alias:
                # Has @primary decorator, use that as the name
                primary_commands[primary_alias] = func
            elif not name.startswith("_"):
                # Regular public method
                primary_commands[name] = func
            # else: internal method without @primary, skip

        return primary_commands

    def _get_command_aliases(self) -> Dict[str, List[str]]:
        """Get a mapping of primary command names to their aliases, respecting primary aliases."""
        alias_map = {}

        for name, func in inspect.getmembers(self, predicate=inspect.ismethod):
            if hasattr(func, "_aliases"):
                primary_name = getattr(func, "_primary_alias", name)
                alias_map[primary_name] = list(func._aliases)  # pyright: ignore[reportAttributeAccessIssue]

        return alias_map


class Commands(BaseCommands):
    """Container class for all CLI commands"""

    def __init__(self, code: Bytecode):
        self.code = code

    def exit(self, args: List[str]) -> None:
        """Exit the program"""
        sys.exit()

    def clear(self, args: List[str]) -> None:
        """Clears the terminal screen."""
        os.system("cls" if platform.system() == "Windows" else "clear")

    @alias("hist")
    def history(self, args: List[str]) -> None:
        """Shows recently run REPL commands. `history [count]`"""
        try:
            import readline
        except ImportError:
            print("readline is not available on this platform, so no history is kept.")
            return
        try:
            count = int(args[0]) if args else 20
        except ValueError:
            print("Invalid count.")
            return
        length = readline.get_current_history_length()
        if length == 0:
            print("No history yet.")
            return
        start = max(1, length - count + 1)
        for i in range(start, length + 1):
            print(f"{i:>4}  {readline.get_history_item(i)}")

    def wiki(self, args: List[str]) -> None:
        """Open the ModDocCE wiki page on Hashlink bytecode in your default browser"""
        webbrowser.open("https://n3rdl0rd.github.io/ModDocCE/files/hlboot")

    def op(self, args: List[str]) -> None:
        """Prints the documentation for a given opcode. `op <opcode>`"""

        def _args(args: Dict[str, str]) -> str:
            return "Args -> " + ", ".join(f"{k}: {v}" for k, v in args.items())

        if len(args) == 0:
            print("Usage: op <opcode>")
            return

        query = args[0].lower()

        for opcode in opcode_docs:
            if opcode.lower() == query:
                print()
                print("--- " + opcode + " ---")
                print(_args(opcodes[opcode]))
                print("Desc -> " + opcode_docs[opcode])
                print()
                return

        matches = [opcode for opcode in opcode_docs if query in opcode.lower()]

        if not matches:
            print("Unknown opcode.")
            return

        if len(matches) == 1:
            print()
            print(f"--- {matches[0]} ---")
            print(_args(opcodes[matches[0]]))
            print(f"Desc -> {opcode_docs[matches[0]]}")
            print()
        else:
            print()
            print(f"Found {len(matches)} matching opcodes:")
            for match in matches:
                print(f"- {match}")
            print("\nUse 'op <exact_opcode>' to see documentation for a specific opcode.")
            print()

    @alias("fns")
    def funcs(self, args: List[str]) -> None:
        """List all functions in the bytecode - pass 'std' to not exclude stdlib `funcs [std]`"""
        std = args and args[0] == "std"
        for func in self.code.functions:
            if disasm.is_std(self.code, func) and not std:
                continue
            print(disasm.func_header(self.code, func))
        for native in self.code.natives:
            if disasm.is_std(self.code, native) and not std:
                continue
            print(disasm.native_header(self.code, native))

    def entry(self, args: List[str]) -> None:
        """Prints the entrypoint of the bytecode."""
        entry = self.code.entrypoint.resolve(self.code)
        if isinstance(entry, Native):
            print("Entrypoint: Native")
            print("    Name:", entry.name.resolve(self.code))
        else:
            print("    Entrypoint:", disasm.func_header(self.code, entry))

    @alias("f")
    def fn(self, args: List[str]) -> None:
        """Disassembles a function to pseudocode by findex. `fn <idx>`"""
        if len(args) == 0:
            print("Usage: fn <index>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        for func in self.code.functions:
            if func.findex.value == index:
                print(disasm.func(self.code, func))
                return
        for native in self.code.natives:
            if native.findex.value == index:
                print(disasm.native_header(self.code, native))
                return
        print("Function not found.")

    def cfg(self, args: List[str]) -> None:
        """Renders a control flow graph for a given findex and attempts to open it in the default image viewer. `cfg <idx>`"""
        if len(args) == 0:
            print("Usage: cfg <index>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        for func in self.code.functions:
            if func.findex.value == index:
                cfg = decomp.CFGraph(func)
                print("Building control flow graph...")
                cfg.build()
                print("DOT:")
                dot = cfg.graph(self.code)
                print(dot)
                print("Attempting to render graph...")
                with tempfile.NamedTemporaryFile(suffix=".dot", delete=False) as f:
                    f.write(dot.encode())
                    dot_file = f.name

                png_file = dot_file.replace(".dot", ".png")
                try:
                    subprocess.run(
                        ["dot", "-Tpng", dot_file, "-o", png_file, "-Gdpi=300"],
                        check=True,
                    )
                except FileNotFoundError:
                    print("Graphviz not found. Install Graphviz to generate PNGs.")
                    return

                try:
                    if platform.system() == "Windows":
                        subprocess.run(["start", png_file], shell=True)
                    elif platform.system() == "Darwin":
                        subprocess.run(["open", png_file])
                    else:
                        subprocess.run(["xdg-open", png_file])
                    os.unlink(dot_file)
                except:
                    print(f"Control flow graph saved to {png_file}. Use your favourite image viewer to open it.")
                return
        print("Function not found.")

    def ir(self, args: List[str]) -> None:
        """Prints the IR of a function in object-notation. `ir <idx>`"""
        if len(args) == 0:
            print("Usage: ir <index>")
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        for func in self.code.functions:
            if func.findex.value == index:
                ir = decomp.IRFunction(self.code, func)
                ir.print()
                return
        print("Function not found.")

    @alias("decompile", "dec", "pseudo", "d")
    def decomp(self, args: List[str]) -> None:
        """Prints the pseudocode decompilation of a function. `decomp <idx>`"""
        if len(args) == 0:
            print("Usage: decomp <index>")
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        for func in self.code.functions:
            if func.findex.value == index:
                ir = decomp.IRFunction(self.code, func)
                res = pseudo(ir)

                print("\n")

                try:
                    from pygments import highlight
                    from pygments.lexers import HaxeLexer
                    from pygments.formatters import Terminal256Formatter

                    lexer = HaxeLexer()
                    formatter = Terminal256Formatter(style="dracula")
                    highlighted_output = highlight(res, lexer, formatter)
                    print(highlighted_output)
                except ImportError:
                    print("[warning] pygments not found.")
                    print(res)
                return
        print("Function not found.")

    @alias("edit")
    def patch(self, args: List[str]) -> None:
        """Patches a function's raw opcodes. `patch <idx>`"""
        if len(args) == 0:
            print("Usage: patch <index>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        try:
            func = self.code.fn(index)
        except ValueError:
            print("Function not found.")
            return
        if isinstance(func, Native):
            print("Cannot patch native.")
            return
        content = f"""{disasm.func(self.code, func)}

###### Modify the opcodes below this line. Any edits above this line will be ignored, and removing this line will cause patching to fail. #####
{disasm.to_asm(func.ops)}"""
        with tempfile.NamedTemporaryFile(suffix=".hlasm", mode="w", encoding="utf-8", delete=False) as f:
            f.write(content)
            file = f.name
        try:
            import tkinter as tk
            from tkinter import scrolledtext

            def save_and_exit() -> None:
                with open(file, "w", encoding="utf-8") as f:
                    f.write(text.get("1.0", tk.END))
                root.destroy()

            root = tk.Tk()
            root.title(f"Editing function f@{index}")
            text = scrolledtext.ScrolledText(root, width=200, height=50)
            text.pack()
            text.insert("1.0", content)

            button = tk.Button(root, text="Save and Exit", command=save_and_exit)
            button.pack()

            root.mainloop()
        except ImportError:
            if os.name == "nt":
                os.system(f'notepad "{file}"')
            elif os.name == "posix":
                os.system(f'nano "{file}"')
            else:
                print("No suitable editor found")
                os.unlink(file)
                return
        try:
            with open(file, "r", encoding="utf-8") as f2:  # why mypy, why???
                modified = f2.read()

            lines = modified.split("\n")
            sep_idx = next(i for i, line in enumerate(lines) if "######" in line)
            new_asm = "\n".join(lines[sep_idx + 1 :])
            new_ops = disasm.from_asm(new_asm)

            func.ops = new_ops
            print(f"Function f@{index} updated successfully")

        except Exception as e:
            print(f"Failed to patch function: {e}")
        finally:
            os.unlink(file)

    def save(self, args: List[str]) -> None:
        """Saves the modified bytecode to a given path. `save <path>`"""
        if len(args) == 0:
            print("Usage: save <path>")
            return
        print("Serialising... (don't panic if it looks stuck!)")
        ser = self.code.serialise()
        print("Saving...")
        with open(args[0], "wb") as f:
            f.write(ser)
        print("Done!")

    @alias("libs")
    def nativelibs(self, args: List[str]) -> None:
        """Prints all unique native dynlibs used by the bytecode. `nativelibs`"""
        native_libs: Set[str] = set()
        for native in self.code.natives:
            if native.lib.value:
                native_libs.add(native.lib.resolve(self.code))
        if not native_libs:
            print("No native libraries found.")
            return
        print("Native libraries used by the bytecode:")
        for lib in sorted(native_libs):
            print(f"- {lib}")

    def hlc(self, args: List[str]) -> None:
        """Transpiles the loaded bytecode to crashlink cHL/C code. `hlc <output path>`"""
        if len(args) == 0:
            print("Usage: hlc <output path>")
            return
        output_path = args[0]
        print("Transpiling to cHL/C...")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(code_to_c(self.code, progress_cb=_make_progress_cb()))
        print(f"cHL/C code written to {output_path}")

    @alias("strs")
    def strings(self, args: List[str]) -> None:
        """List all strings in the bytecode."""
        for i, string in enumerate(self.code.strings.value):
            print(f"String {i}: {string}")

    def types(self, args: List[str]) -> None:
        """List all types in the bytecode."""
        for i, type in enumerate(self.code.types):
            print(f"Type t@{i}: ", end="")
            dfn = type.definition
            if isinstance(dfn, Obj):
                print(f"Obj {dfn.name.resolve(self.code)}")
            elif isinstance(dfn, Fun):
                print(f"Fun {dfn.str_resolve(self.code)}")
            else:
                print(type.kind)

    def objs(self, args: List[str]) -> None:
        """List all Objs in the bytecode. `objs`"""
        for i, type in enumerate(self.code.types):
            dfn = type.definition
            if isinstance(dfn, Obj):
                print(f"Type t@{i}: {dfn.name.resolve(self.code)}")

    @alias("tn")
    def typenamed(self, args: List[str]) -> None:
        """Finds the type named n. `tn <n>`"""
        if len(args) < 1:
            print("You need to pass a name!")
            return
        for i, type in enumerate(self.code.types):
            if not hasattr(type.definition, "name"):
                continue
            n = type.definition.name.resolve(self.code)  # type: ignore
            if n is None:
                continue
            if n == args[0]:  # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]
                print(f"Found it at t@{i}!")

    @alias("object")
    def obj(self, args: List[str]) -> None:
        """Prints a short overview of a class's fields, protos, and bindings. `obj <tIndex>`"""
        if len(args) == 0:
            print("Usage: obj <tIndex>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid tIndex.")
            return

        try:
            typ = self.code.types[index]
            if not isinstance(typ.definition, Obj):
                print(f"Type t@{index} is not a class (Obj).")
                return

            obj_def: Obj = typ.definition
            class_name = obj_def.name.resolve(self.code)

            print(f"--- Overview for class {class_name} (t@{index}) ---")

            if obj_def.super and obj_def.super.value is not None:
                try:
                    super_name = disasm.type_name(self.code, obj_def.super.resolve(self.code))
                    print(f"Inherits from: {super_name}")
                except Exception:
                    print(f"Inherits from: t@{obj_def.super.value} (Error resolving)")

            print("\nFields:")
            if obj_def.fields:
                for field in obj_def.fields:
                    field_name = field.name.resolve(self.code)
                    field_type_name = disasm.type_name(self.code, field.type.resolve(self.code))
                    print(f"  - {field_name}: {field_type_name}")
            else:
                print("  (No fields)")

            print("\nProtos (Instance Methods):")
            if obj_def.protos:
                for proto in obj_def.protos:
                    # func_header can sometimes include 'static' which is incorrect for protos, so we clean it
                    header = disasm.func_header(self.code, proto.findex.resolve(self.code))
                    print(f"  - {header.replace(' static ', ' ')}")
            else:
                print("  (No protos)")

            print("\nBindings (Static Methods):")
            if obj_def.bindings:
                for binding in obj_def.bindings:
                    header = disasm.func_header(self.code, binding.findex.resolve(self.code))
                    print(f"  - {header}")
            else:
                print("  (No bindings)")

        except IndexError:
            print(f"Type t@{index} not found.")
        except Exception as e:
            print(f"An error occurred: {e}")
            if "-t" in sys.argv or "--traceback" in sys.argv:
                traceback.print_exc()

    @primary("type")
    @alias("t")
    def type_command(self, args: List[str]) -> None:
        """Prints information about a type by tIndex. `type <tIndex>`"""
        if not args:
            print("Usage: type <tIndex>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid tIndex: must be an integer.")
            return

        try:
            resolved_type = self.code.types[index]
        except IndexError:
            print(f"Type t@{index} not found (index out of range).")
            return

        print(f"Type t@{index}:")
        kind_val = resolved_type.kind.value
        kind_name = "Unknown"
        try:
            kind_name = Type.Kind(kind_val).name
        except ValueError:
            # This can happen if kind_val is not a valid member of the Type.Kind enum
            pass

        print(f"  Kind: {kind_val} ({kind_name})")

        definition = resolved_type.definition
        print(f"  Definition Class: {definition.__class__.__name__}")

        # Specific details based on definition type
        if isinstance(definition, Fun):
            fun_def: Fun = definition
            arg_type_names = []
            for arg_tidx in fun_def.args:
                try:
                    arg_type_names.append(disasm.type_name(self.code, arg_tidx.resolve(self.code)))
                except Exception:
                    arg_type_names.append(f"t@{arg_tidx.value}(Error resolving)")

            ret_type_name = f"t@{fun_def.ret.value}(Error resolving)"
            try:
                ret_type_name = disasm.type_name(self.code, fun_def.ret.resolve(self.code))
            except Exception:
                pass

            print(f"  Function Signature: ({', '.join(arg_type_names)}) -> {ret_type_name}")
            print(f"    Argument Count: {fun_def.nargs.value}")

        elif isinstance(definition, Obj):
            obj_def: Obj = definition
            try:
                print(f"  Object Name: {obj_def.name.resolve(self.code)}")
            except Exception:
                print(f"  Object Name: s@{obj_def.name.value}(Error resolving string)")
            print(f"    Number of Fields: {obj_def.nfields.value}")
            print(f"    Number of Prototypes: {obj_def.nprotos.value}")
            if obj_def.super and obj_def.super.value is not None:
                try:
                    super_type_name = disasm.type_name(self.code, obj_def.super.resolve(self.code))
                    print(f"    Super Type: {super_type_name} (t@{obj_def.super.value})")
                except Exception:
                    print(f"    Super Type: t@{obj_def.super.value}(Error resolving)")

        elif isinstance(definition, Ref):
            ref_def: Ref = definition
            inner_type_name = f"t@{ref_def.type.value}(Error resolving)"
            try:
                inner_type_name = disasm.type_name(self.code, ref_def.type.resolve(self.code))
            except Exception:
                pass
            print(f"  References Type: {inner_type_name} (t@{ref_def.type.value})")

        elif isinstance(definition, Null):
            null_def: Null = definition
            inner_type_name = f"t@{null_def.type.value}(Error resolving)"
            try:
                inner_type_name = disasm.type_name(self.code, null_def.type.resolve(self.code))
            except Exception:
                pass
            print(f"  Null of Type: {inner_type_name} (t@{null_def.type.value})")

        elif isinstance(definition, Packed):
            packed_def: Packed = definition
            inner_type_name = f"t@{packed_def.inner.value}(Error resolving)"
            try:
                inner_type_name = disasm.type_name(self.code, packed_def.inner.resolve(self.code))
            except Exception:
                pass
            print(f"  Packed Inner Type: {inner_type_name} (t@{packed_def.inner.value})")

        elif isinstance(definition, GUID):
            print("  GUID Type (no data)")

        elif isinstance(definition, Abstract):
            abs_def: Abstract = definition
            try:
                print(f"  Abstract Name: {abs_def.name.resolve(self.code)}")
            except Exception:
                print(f"  Abstract Name: s@{abs_def.name.value}(Error resolving string)")

    @alias("search")
    def ss(self, args: List[str]) -> None:
        """
        Search for a string in the bytecode by substring. `ss <query>`
        """
        if len(args) == 0:
            print("Usage: ss <query>")
            return
        query = " ".join(args)
        for i, string in enumerate(self.code.strings.value):
            if query.lower() in string.lower():
                print(f"String {i}: {string}")

    @alias("s")
    def string(self, args: List[str]) -> None:
        """
        Print a string by index. `string <index>`
        """
        if len(args) == 0:
            print("Usage: string <index>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        try:
            print(self.code.strings.value[index])
        except IndexError:
            print("String not found.")

    @alias("i")
    def int(self, args: List[str]) -> None:
        """
        Print an int by index. `int <index>`
        """
        if len(args) == 0:
            print("Usage: int <index>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        try:
            print(self.code.ints[index].value)
        except IndexError:
            print("Int not found.")

    @primary("global")
    @alias("g")
    def global_command(self, args: List[str]) -> None:
        """Gets a specific global by its gIndex, then shows all its initialized values. `global <gIndex>`"""
        if not args:
            print("Usage: global <gIndex>")
            return

        try:
            gidx = int(args[0])
        except ValueError:
            print("Invalid gIndex: must be an integer.")
            return

        if not (0 <= gidx < len(self.code.global_types)):
            print(f"Global {gidx} not found (index out of range).")
            return

        # Attempt to get the type string for more context
        global_type_str = "Unknown Type"
        try:
            # self.code.global_types[gidx] is a tIndex
            # .resolve(self.code) gets the actual Type object
            global_type_obj = self.code.global_types[gidx].resolve(self.code)
            global_type_str = str(global_type_obj)
        except Exception as e:
            # This might happen if resolve fails or gidx is somehow problematic
            # or if str(global_type_obj) fails.
            if globals.DEBUG:  # Assuming 'globals' is the imported module
                print(f"Error resolving global type for gIndex {gidx}: {e}")
            # Keep "Unknown Type" or default if resolution fails

        initialized_global_data = self.code.initialized_globals.get(gidx)

        if initialized_global_data is not None:
            print(f"Global {gidx} (Type: {global_type_str}):")
            if isinstance(initialized_global_data, dict):
                if initialized_global_data:
                    for field_name, value in initialized_global_data.items():
                        print(f"  {field_name}: {value!r}")  # Use !r for better string representation
                else:
                    # This means it's an object but has no initialized fields, or it's an empty {}
                    print("  (Initialized as an empty object or has no constant-initialized fields)")
            else:
                # This case implies the global was initialized to a non-dict value.
                # Based on Bytecode.init_globals, this is unlikely for the objects it processes.
                print(f"  Initialized Value: {initialized_global_data!r}")
        else:
            # The global gIndex is valid, but it's not in initialized_globals
            print(f"Global {gidx} (Type: {global_type_str}) exists, but has no initialized constant values recorded.")

    def setstring(self, args: List[str]) -> None:
        """
        Set a string by index. `setstring <index> <string>`
        """
        if len(args) < 2:
            print("Usage: setstring <index> <string>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        try:
            self.code.strings.value[index] = " ".join(args[1:])
        except IndexError:
            print("String not found.")
        print("String set.")

    def xref(self, args: List[str]) -> None:
        """Cross-references for a function, type, field, global, or string. `xref <kind> <index> [aux]`

        Kinds:
          func <findex>               — all callers, closures, proto/binding decls
          type <tindex>               — allocations, casts, inheritors, field decls, signature uses
          field <tindex> <slot>       — all reads and writes to a specific field slot
          global <gindex>             — readers and writers
          string <string_idx>         — all functions using this string constant
          enum <tindex> <construct>   — all MakeEnum / EnumField refs to a construct
        """
        if len(args) < 2:
            print("Usage: xref <kind> <index> [aux]")
            print("  kinds: func, type, field, global, string, enum")
            return

        kind = args[0].lower()
        try:
            index = int(args[1])
            aux = int(args[2]) if len(args) > 2 else None
        except ValueError:
            print("Invalid index.")
            return

        xi = self.code.xref_index()
        code = self.code

        def _func_label(findex: int) -> str:
            try:
                f = code.get_findex_map()[findex]
                return disasm.func_header(code, f)
            except Exception:
                return f"f@{findex}"

        def _type_label(tindex: int) -> str:
            try:
                t = code.types[tindex]
                return f"t@{tindex} ({t.definition})"
            except Exception:
                return f"t@{tindex}"

        if kind == "func":
            func_map = code.get_findex_map()
            if index not in func_map:
                print(f"Function f@{index} not found.")
                return
            target = func_map[index]
            refs = xi.refs_to(TargetKind.FUNCTION, index)
            if not refs:
                print(f"No xrefs to f@{index} ({code.full_func_name(target)}).")
                return
            print(f"Xrefs to f@{index} ({code.full_func_name(target)}) [{len(refs)} total]:")
            by_kind: Dict[str, List[XRef]] = {}
            for r in refs:
                by_kind.setdefault(r.ref_kind.value, []).append(r)
            for rk, group in sorted(by_kind.items()):
                print(f"  [{rk}]")
                for r in group:
                    loc = f" op#{r.opcode_index}" if r.opcode_index is not None else ""
                    if r.source_kind == SourceKind.FUNCTION:
                        print(f"    {_func_label(r.source_index)}{loc}")
                    else:
                        print(f"    {r.source_kind.value}@{r.source_index}{loc}")

        elif kind == "type":
            refs = xi.refs_to(TargetKind.TYPE, index)
            if not refs:
                print(f"No xrefs to {_type_label(index)}.")
                return
            print(f"Xrefs to {_type_label(index)} [{len(refs)} total]:")
            by_kind = {}
            for r in refs:
                by_kind.setdefault(r.ref_kind.value, []).append(r)
            for rk, group in sorted(by_kind.items()):
                print(f"  [{rk}]")
                for r in group:
                    loc = f" op#{r.opcode_index}" if r.opcode_index is not None else ""
                    if r.source_kind == SourceKind.FUNCTION:
                        print(f"    {_func_label(r.source_index)}{loc}")
                    else:
                        print(f"    {r.source_kind.value}@{r.source_index}{loc}")

        elif kind == "field":
            if aux is None:
                print("Usage: xref field <tindex> <field_slot>")
                return
            from .core import Obj

            try:
                obj_def = code.types[index].definition
                field_name = obj_def.fields[aux].name.resolve(code) if isinstance(obj_def, Obj) else f"slot{aux}"
            except Exception:
                field_name = f"slot{aux}"
            refs = xi.all_field_accesses(index, aux)
            if not refs:
                print(f"No field accesses for t@{index}.{field_name}.")
                return
            reads = [r for r in refs if r.ref_kind == RefKind.FIELD_READ]
            writes = [r for r in refs if r.ref_kind == RefKind.FIELD_WRITE]
            print(f"Field t@{index}.{field_name}: {len(reads)} read(s), {len(writes)} write(s)")
            if reads:
                print("  [reads]")
                for r in reads:
                    print(f"    {_func_label(r.source_index)} op#{r.opcode_index}")
            if writes:
                print("  [writes]")
                for r in writes:
                    print(f"    {_func_label(r.source_index)} op#{r.opcode_index}")

        elif kind == "global":
            reads = xi.global_reads(index)
            writes = xi.global_writes(index)
            try:
                gt = code.global_types[index]
                glabel = f"g@{index} (t@{gt.value})"
            except Exception:
                glabel = f"g@{index}"
            if not reads and not writes:
                print(f"No xrefs to {glabel}.")
                return
            print(f"Xrefs to {glabel}: {len(reads)} read(s), {len(writes)} write(s)")
            if reads:
                print("  [reads]")
                for r in reads:
                    print(f"    {_func_label(r.source_index)} op#{r.opcode_index}")
            if writes:
                print("  [writes]")
                for r in writes:
                    print(f"    {_func_label(r.source_index)} op#{r.opcode_index}")

        elif kind == "string":
            try:
                s = code.strings.value[index]
                slabel = f"s@{index} ({s!r})"
            except Exception:
                slabel = f"s@{index}"
            refs = xi.string_uses(index)
            if not refs:
                print(f"No xrefs to {slabel}.")
                return
            print(f"Xrefs to {slabel} [{len(refs)} total]:")
            for r in refs:
                rk = (
                    "dyn_read"
                    if r.ref_kind == RefKind.DYN_FIELD_READ
                    else "dyn_write"
                    if r.ref_kind == RefKind.DYN_FIELD_WRITE
                    else "use"
                )
                print(f"  [{rk}] {_func_label(r.source_index)} op#{r.opcode_index}")

        elif kind == "enum":
            if aux is None:
                print("Usage: xref enum <tindex> <construct_idx>")
                return
            from .core import Enum as HLEnum

            try:
                edef = code.types[index].definition
                cname = edef.constructs[aux].name.resolve(code) if isinstance(edef, HLEnum) else f"construct{aux}"
                elabel = f"t@{index}.{cname}"
            except Exception:
                elabel = f"t@{index} construct#{aux}"
            refs = xi.construct_uses(index, aux)
            if not refs:
                print(f"No xrefs to {elabel}.")
                return
            print(f"Xrefs to {elabel} [{len(refs)} total]:")
            by_kind = {}
            for r in refs:
                by_kind.setdefault(r.ref_kind.value, []).append(r)
            for rk, group in sorted(by_kind.items()):
                print(f"  [{rk}]")
                for r in group:
                    print(f"    {_func_label(r.source_index)} op#{r.opcode_index}")

        else:
            print(f"Unknown xref kind: {kind!r}")
            print("  kinds: func, type, field, global, string, enum")

    @alias("ff")
    def findfunc(self, args: List[str]) -> None:
        """Search functions by name substring, or list functions in a source file.

        Usage:
          findfunc <query>            — substring match against qualified name
          findfunc file <filename>    — all functions from a source file
          findfunc files              — list all known source files
        """
        if not args:
            print("Usage: findfunc <query> | findfunc file <filename> | findfunc files")
            return

        si = self.code.search_index()

        if args[0] == "files":
            files = si.files()
            if not files:
                print("No debug file info available.")
                return
            for fname in sorted(files):
                print(fname)
            return

        if args[0] == "file":
            if len(args) < 2:
                print("Usage: search file <filename>")
                return
            file_funcs = si.in_file(args[1])
            if not file_funcs:
                print(f"No functions found in {args[1]!r}.")
                return
            print(f"{len(file_funcs)} function(s) in {args[1]!r}:")
            for func in file_funcs:
                print(f"  {disasm.func_header(self.code, func)}")
            return

        query = " ".join(args)
        results = si.search(query)
        if not results:
            print(f"No functions matching {query!r}.")
            return
        print(f"{len(results)} result(s) for {query!r}:")
        for hit in results:
            print(f"  {disasm.func_header(self.code, hit)}")

    def locals(self, args: List[str]) -> None:
        """List all IR locals for a function with their rename keys. `locals <findex>`"""
        if not args:
            print("Usage: locals <findex>")
            return
        try:
            findex = int(args[0])
        except ValueError:
            print("Invalid findex.")
            return
        func_map = self.code.get_findex_map()
        if findex not in func_map:
            print(f"f@{findex} not found.")
            return
        func = func_map[findex]
        from .decomp.function import IRFunction

        if not isinstance(func, Function):
            print("Natives have no locals.")
            return
        ir = IRFunction(self.code, func)
        print(f"Locals for f@{findex} ({self.code.full_func_name(func)}):")
        seen: Dict[int, object] = {}
        for local in ir.all_locals:
            if local.reg_idx is not None and local.reg_idx in seen:
                continue
            if local.reg_idx is not None:
                seen[local.reg_idx] = local
        for local in ir.all_locals:
            def_op = str(local.defining_op_idx) if local.defining_op_idx is not None else "_"
            renamed = self.code.annotations.get_rename(findex, local.reg_idx or 0, local.defining_op_idx)
            rename_str = f"  -> {renamed!r}" if renamed else ""
            print(f"  reg={local.reg_idx} def_op={def_op}  {local.name}: {local.get_type()}{rename_str}")

    def rename(self, args: List[str]) -> None:
        """Rename an IR local. `rename <findex> <reg_idx> <def_op|_> <new_name>`

        def_op is the opcode index that defines this local (see `locals <findex>`),
        or _ for the initial (pre-split) value of a register.
        """
        if len(args) < 4:
            print("Usage: rename <findex> <reg_idx> <def_op|_> <new_name>")
            return
        try:
            findex = int(args[0])
            reg_idx = int(args[1])
        except ValueError:
            print("Invalid findex or reg_idx.")
            return
        def_op_str = args[2]
        def_op: Optional[int] = None if def_op_str == "_" else int(def_op_str)
        new_name = args[3]
        self.code.annotations.rename(findex, reg_idx, def_op, new_name)
        print(f"Renamed reg{reg_idx} (def_op={def_op_str}) in f@{findex} -> {new_name!r}.")

    def unrename(self, args: List[str]) -> None:
        """Clear a local rename. `unrename <findex> <reg_idx> <def_op|_>`"""
        if len(args) < 3:
            print("Usage: unrename <findex> <reg_idx> <def_op|_>")
            return
        try:
            findex = int(args[0])
            reg_idx = int(args[1])
        except ValueError:
            print("Invalid findex or reg_idx.")
            return
        def_op: Optional[int] = None if args[2] == "_" else int(args[2])
        self.code.annotations.clear_rename(findex, reg_idx, def_op)
        print("Rename cleared.")

    def addcomment(self, args: List[str]) -> None:
        """Attach a comment to a statement by opcode index. `addcomment <findex> <op_idx> <text>`"""
        if len(args) < 3:
            print("Usage: addcomment <findex> <op_idx> <text>")
            return
        try:
            findex = int(args[0])
            op_idx = int(args[1])
        except ValueError:
            print("Invalid findex or op_idx.")
            return
        text = " ".join(args[2:])
        self.code.annotations.set_comment(findex, op_idx, text)
        print(f"Comment set on f@{findex} op#{op_idx}.")

    def rmcomment(self, args: List[str]) -> None:
        """Remove a comment from a statement. `rmcomment <findex> <op_idx>`"""
        if len(args) < 2:
            print("Usage: rmcomment <findex> <op_idx>")
            return
        try:
            findex = int(args[0])
            op_idx = int(args[1])
        except ValueError:
            print("Invalid findex or op_idx.")
            return
        self.code.annotations.clear_comment(findex, op_idx)
        print("Comment cleared.")

    def srcloc(self, args: List[str]) -> None:
        """Source location lookup.

        Usage:
          srcloc <findex> <op_idx>          — source location of a specific opcode
          srcloc line <filename> <line>     — functions/opcodes at a source line
          srcloc files                      — list all source files with debug info
        """
        if not args:
            print("Usage: srcloc <findex> <op> | srcloc line <file> <line> | srcloc files")
            return

        sm = self.code.source_map()

        if args[0] == "files":
            for f in sorted(sm.files()):
                print(f)
            return

        if args[0] == "line":
            if len(args) < 3:
                print("Usage: srcloc line <filename> <line>")
                return
            file_idx = sm.file_index(args[1])
            if file_idx is None:
                print(f"File {args[1]!r} not found in debug info.")
                return
            try:
                line = int(args[2])
            except ValueError:
                print("Invalid line number.")
                return
            hits = sm.ops_at(file_idx, line)
            if not hits:
                print(f"No opcodes at {args[1]}:{line}.")
                return
            seen_funcs: Dict[int, object] = {}
            print(f"{len(hits)} opcode(s) at {args[1]}:{line}:")
            for func, op_idx in hits:
                if func.findex.value not in seen_funcs:
                    seen_funcs[func.findex.value] = func
                    print(f"  {disasm.func_header(self.code, func)}")
                print(f"    op#{op_idx}  {func.ops[op_idx].op}")
            return

        try:
            findex = int(args[0])
            op_idx = int(args[1]) if len(args) > 1 else 0
        except ValueError:
            print("Invalid arguments.")
            return

        loc = sm.loc_str(findex, op_idx)
        if not loc:
            print(f"No debug info for f@{findex} op#{op_idx}.")
            return
        print(loc)

    @alias("pkl")
    def pickle(self, args: List[str]) -> None:
        """Pickle the bytecode to a given path. `pickle <path>`"""
        if len(args) == 0:
            print("Usage: pickle <path>")
            return
        try:
            import dill

            with open(args[0], "wb") as f:
                dill.dump(self.code, f)
            print("Bytecode pickled.")
        except ImportError:
            print("dill not found. Install dill to pickle bytecode, or install crashlink with the [extras] option.")

    def stub(self, args: List[str]) -> None:
        """Generate files in the same structure as the original Haxe source. Requires debuginfo. `stub <path>`"""
        if len(args) == 0:
            print("Usage: stub <path>")
            return
        if not self.code.has_debug_info:
            print("Debug info not found.")
            return
        path = args[0]
        if not os.path.exists(path):
            os.makedirs(path)
        if not self.code.debugfiles:
            print("No debug files found.")
            return
        for file in self.code.debugfiles.value:
            if (
                file == "std" or file == "?" or file.startswith("C:") or file.startswith("D:") or file.startswith("/")
            ):  # FIXME: lazy sanitization
                continue
            try:
                os.makedirs(os.path.join(path, os.path.dirname(file)), exist_ok=True)
                with open(os.path.join(path, file), "w") as f:
                    f.write("")
            except OSError:
                print(f"Failed to write to {os.path.join(path, file)}")
        print(f"Files generated in {os.path.abspath(path)}")

    @alias("run")
    def interp(self, args: List[str]) -> None:
        """Run the bytecode in crashlink's integrated interpreter."""
        if len(args) == 0:
            idx = self.code.entrypoint.value
        else:
            try:
                idx = int(args[0])
            except ValueError:
                print("Invalid index.")
                return

        vm = VM(self.code)
        vm.run(entry=idx)

    def repl(self, args: List[str]) -> None:
        """Drop into a Python REPL with direct access to the Bytecode object."""
        code = self.code

        banner = (
            "Interactive crashlink Python REPL\n"
            "Available globals:\n"
            "  - code: The Bytecode object\n"
            "  - disasm: The crashlink.disasm module\n"
            "  - decomp: The crashlink.decomp module\n"
        )

        local_vars = {
            "code": code,
            "disasm": disasm,
            "decomp": decomp,
        }

        try:
            import IPython

            IPython.embed(banner1=banner, user_ns=local_vars)  # type: ignore[no-untyped-call]
        except ImportError:
            import code as cd

            cd.interact(banner=banner, local=local_vars)

    def offset(self, args: List[str]) -> None:
        """Print the bytecode section at a given offset. `offset <offset in hex>`"""
        if len(args) == 0:
            print("Usage: offset <offset in hex>")
            return
        try:
            offset = int(args[0], 16)
        except ValueError:
            print("Invalid offset.")
            return
        print(self.code.section_at(offset))

    def floats(self, args: List[str]) -> None:
        """List all floats in the bytecode."""
        for i, float in enumerate(self.code.floats):
            print(f"Float {i}: {float.value}")

    def infile(self, args: List[str]) -> None:
        """Finds all functions from a given file in the bytecode. `infile <file>`"""
        if len(args) == 0:
            print("Usage: infile <file>")
            return
        file = args[0]
        if not self.code.has_debug_info:
            print("Debug info not found.")
            return
        for func in self.code.functions:
            if func.resolve_file(self.code) == file:
                print(disasm.func_header(self.code, func))

    def debugfiles(self, args: List[str]) -> None:
        """List all debug files in the bytecode."""
        if self.code.debugfiles and self.code.has_debug_info:
            for i, file in enumerate(self.code.debugfiles.value):
                print(f"{i}: {file}")
        else:
            print("No debug info in bytecode!")
            return

    def virt(self, args: List[str]) -> None:
        """Prints a virtual type by tIndex. `virt <index>`"""
        if len(args) == 0:
            print("Usage: virt <index>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        try:
            virt = tIndex(index).resolve(self.code)
        except IndexError:
            print("Type not found.")
            return
        if not isinstance(virt.definition, Virtual):
            print("Type is not a Virtual.")
            return
        print(f"Virtual t@{index}")
        print("Fields:")
        assert isinstance(virt.definition, Virtual), "Virtual type is not a Virtual."
        for field in virt.definition.fields:
            print(f"  {field.name.resolve(self.code)}: {disasm.type_name(self.code, field.type.resolve(self.code))}")

    def enum(self, args: List[str]) -> None:
        """Prints information about an enum by tIndex. `enum <index>`"""
        if len(args) == 0:
            print("Usage: enum <index>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return

        try:
            enum_type = self.code.types[index]
        except IndexError:
            print(f"Type t@{index} not found.")
            return

        if not isinstance(enum_type.definition, Enum):
            print(f"Type t@{index} is not an Enum.")
            return

        defn: Enum = enum_type.definition

        print(f"--- Enum: {defn.name.resolve(self.code)} (t@{index}) ---")
        print(f"Global index: g@{defn._global.value}")
        print(f"Constructs ({defn.nconstructs.value}):")

        if not defn.constructs:
            print("  (No constructs defined)")
        else:
            for i, construct in enumerate(defn.constructs):
                construct_name = construct.name.resolve(self.code)
                if construct.params:
                    # Resolve the type name for each parameter
                    param_types = [disasm.type_name(self.code, p.resolve(self.code)) for p in construct.params]
                    print(f"  {i}: {construct_name}({', '.join(param_types)})")
                else:
                    print(f"  {i}: {construct_name}")

    def fnn(self, args: List[str]) -> None:
        """Prints a function by name. `fnn <name>`"""
        if len(args) == 0:
            print("Usage: fnn <name>")
            return
        name = " ".join(args[0:])
        for func in self.code.functions:
            if self.code.full_func_name(func) == name:
                print(disasm.func_header(self.code, func))
                return
        print("Function not found.")

    def apidocs(self, args: List[str]) -> None:
        """Generate API documentation for all classes in the bytecode based on what can be inferred. Outputs to the given path. `apidocs <path>`"""
        if len(args) == 0:
            print("Usage: apidocs <path>")
            return
        path = args[0]
        if not os.path.exists(path):
            os.makedirs(path)
        if not self.code.debugfiles:
            print("No debug files found.")
            return
        docs: Dict[str, str] = disasm.gen_docs(self.code)
        for file, content in docs.items():
            try:
                os.makedirs(os.path.join(path, os.path.dirname(file)), exist_ok=True)
                with open(os.path.join(path, file), "w", encoding="utf-8") as f:
                    f.write(content)
            except OSError:
                print(f"Failed to write to {os.path.join(path, file)}")
        print(f"Files generated in {os.path.abspath(path)}")

    @alias("mkdoc")
    def mkdocs(self, args: List[str]) -> None:
        """Generate a MkDocs + Material site for the bytecode's API. `mkdocs <path> [site name]`"""
        if len(args) == 0:
            print("Usage: mkdocs <path> [site name]")
            return
        path = args[0]
        site_name = " ".join(args[1:]) if len(args) > 1 else "API Reference"
        if not os.path.exists(path):
            os.makedirs(path)
        pages = disasm.gen_mkdocs(self.code, site_name=site_name)
        for file, content in pages.items():
            full_path = os.path.join(path, file)
            try:
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, "w", encoding="utf-8") as f:
                    f.write(content)
            except OSError:
                print(f"Failed to write to {full_path}")
        print(f"MkDocs project generated in {os.path.abspath(path)}")
        print("To preview: pip install mkdocs-material && mkdocs serve")
        print("To build:   mkdocs build")
        print("(Run those commands from inside the output directory.)")

    def info(self, args: List[str]) -> None:
        """Prints information about the bytecode."""
        print(f"Bytecode version: {self.code.version}")
        print(f"Has debug info: {self.code.has_debug_info}")
        print(f"nints: {len(self.code.ints)}")
        print(f"nstrings: {len(self.code.strings.value)}")
        print(f"nfunctions: {len(self.code.functions)}")
        print(f"nnatives: {len(self.code.natives)}")
        print(f"nfloats: {len(self.code.floats)}")
        print(f"ntypes: {len(self.code.types)}")

    @alias("check")
    def verify(self, args: List[str]) -> None:
        """Runs a set of basic sanity checks to make sure the bytecode is correct-ish. `check`"""
        if not self.code.is_ok():
            print("Bytecode verification failed!")
            return
        print("Bytecode verification succeeded!")

    @alias("sref")
    def strref(self, args: List[str]) -> None:
        """
        Find cross-references to a string by index.
        Shows all opcodes that directly reference the string,
        and opcodes that reference global variables initialized with this string.
        `strref <index>`
        """
        if len(args) == 0:
            print("Usage: strref <index>")
            return
        try:
            string_idx_to_find = int(args[0])
        except ValueError:
            print("Invalid index.")
            return

        try:
            target_string = self.code.strings.value[string_idx_to_find]
        except IndexError:
            print(f"String at index {string_idx_to_find} not found in strings table.")
            return

        print(f'Finding references to string {string_idx_to_find}: "{target_string}"')
        print("-" * 30)

        direct_references_found = 0
        print("Direct string references:")
        for func in self.code.functions:
            if func.ops:
                for op_index, opcode in enumerate(func.ops):
                    for param_name, param_value in opcode.df.items():
                        if isinstance(param_value, strRef):
                            if param_value.value == string_idx_to_find:
                                direct_references_found += 1
                                func_name = self.code.full_func_name(func)
                                print(f"  Function {func.findex.value} ({func_name}):")
                                print(
                                    f"    Opcode {op_index}: {opcode.op} - parameter '{param_name}' references string {string_idx_to_find}"
                                )
                                print()

        if direct_references_found == 0:
            print("  No direct references found to this string.")
        print("-" * 30)

        global_refs_to_this_string_found = 0
        globals_containing_string_details = []

        for g_idx in range(len(self.code.global_types)):
            try:
                global_string_value = self.code.const_str(g_idx)
                if global_string_value == target_string:
                    globals_containing_string_details.append((g_idx, global_string_value))
            except (ValueError, TypeError):
                # Not a constant string global, or g_idx out of bounds / not initialized as const string.
                continue

        print("References via global variables:")
        if not globals_containing_string_details:
            print(f'  No global variables found initialized with the string "{target_string}".')
        else:
            for g_idx, global_str_val in globals_containing_string_details:
                printable_global_str_val = global_str_val.replace('"', '\\"')
                print(
                    f'  Global g@{g_idx} is initialized to "{printable_global_str_val}". Searching for references to g@{g_idx}:'
                )
                found_refs_for_this_global = 0
                for func in self.code.functions:
                    if func.ops:
                        for op_index, opcode in enumerate(func.ops):
                            for param_name, param_value in opcode.df.items():
                                if isinstance(param_value, gIndex):
                                    if param_value.value == g_idx:
                                        global_refs_to_this_string_found += 1
                                        found_refs_for_this_global += 1
                                        func_name = self.code.full_func_name(func)
                                        print(f"    Function {func.findex.value} ({func_name}):")
                                        print(
                                            f"      Opcode {op_index}: {opcode.op} - parameter '{param_name}' references global g@{g_idx}"
                                        )
                                        print()
                if found_refs_for_this_global == 0:
                    print(f"    No opcode references found for global g@{g_idx}.")
                print()

        print("-" * 30)
        total_references = direct_references_found + global_refs_to_this_string_found
        if total_references == 0:
            print(f'No references found for string "{target_string}" (index {string_idx_to_find}).')
        else:
            print(
                f"Total references found: {total_references} (Direct: {direct_references_found}, Via Globals: {global_refs_to_this_string_found})"
            )

    @primary("class")
    @alias("cls")
    @alias("c")
    def class_(self, args: List[str]) -> None:
        """Decompiles an entire class by its type index. `class <tIndex>`"""
        if len(args) == 0:
            print("Usage: class <tIndex>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid tIndex.")
            return

        try:
            typ = self.code.types[index]
            if not isinstance(typ.definition, Obj):
                print(f"Type t@{index} is not a class (Obj).")
                return

            ir_class = decomp.IRClass(self.code, typ.definition)
            res = ir_class.pseudo()

            print("\n")

            try:
                from pygments import highlight
                from pygments.lexers import HaxeLexer
                from pygments.formatters import Terminal256Formatter

                lexer = HaxeLexer()
                formatter = Terminal256Formatter(style="dracula")
                highlighted_output = highlight(res, lexer, formatter)
                print(highlighted_output)
            except ImportError:
                print("[warning] pygments not found.")
                print(res)
        except IndexError:
            print(f"Type t@{index} not found.")
        except Exception as e:
            print(f"An error occurred during class decompilation: {e}")
            # A simple way is to check the main args, but ideally it's passed during init.
            if "-t" in sys.argv or "--traceback" in sys.argv:
                traceback.print_exc()


def handle_cmd(code: Bytecode, cmd: str) -> None:
    """Handles a command."""
    cmd_list: List[str] = cmd.split(" ")
    if not cmd_list[0]:
        return

    commands = Commands(code)
    available_commands = commands._get_commands()

    if cmd_list[0] in available_commands:
        if len(cmd_list) > 1:
            available_commands[cmd_list[0]](cmd_list[1:])
        else:
            available_commands[cmd_list[0]]([])
    else:
        print("Unknown command.")


_HISTORY_FILE = Path.home() / ".crashlink_history"


def _setup_repl_readline(code: Bytecode) -> None:
    """Enables persistent history (up/down arrows) and tab-completion of command names for the REPL."""
    try:
        import readline
    except ImportError:
        # Not available on stock Windows Python; the REPL still works, just without history/completion.
        return

    try:
        readline.read_history_file(_HISTORY_FILE)
    except (FileNotFoundError, OSError):
        pass
    readline.set_history_length(1000)
    atexit.register(lambda: readline.write_history_file(_HISTORY_FILE))

    command_names = sorted(Commands(code)._get_commands().keys())

    def _completer(text: str, state: int) -> Optional[str]:
        matches = [c for c in command_names if c.startswith(text)]
        return matches[state] if state < len(matches) else None

    readline.set_completer(_completer)
    delims = readline.get_completer_delims().replace("-", "")
    readline.set_completer_delims(delims)
    readline.parse_and_bind("tab: complete")


def mcp_main(argv: List[str]) -> None:
    try:
        from .mcp import run_mcp_server
    except ImportError:
        print(
            "The 'mcp' package is required for 'crashlink mcp'. Install it with: pip install crashlink[extras]",
            file=sys.stderr,
        )
        sys.exit(1)
    preload = argv[0] if argv else None
    run_mcp_server(preload_path=preload)


def _print_help_all(
    parser: "argparse.ArgumentParser",
    subcommands: Dict[str, Callable[[List[str]], None]],
) -> None:
    """Print the top-level help, then each subcommand's own -h output."""
    print(parser.format_help())

    for name in _SUBCOMMAND_HELP:
        print(f"\n{'=' * 70}\ncrashlink {name}\n{'=' * 70}")
        if name == "gui":
            print("Launch the graphical bytecode inspector.\n\nusage: crashlink gui [file]")
            continue
        try:
            subcommands[name](["-h"])
        except SystemExit:
            pass


def main() -> None:
    """
    Main entrypoint.
    """
    if len(sys.argv) > 1 and sys.argv[1] == "gui":
        from .gui import main as gui_main

        sys.argv = [sys.argv[0]] + sys.argv[2:]
        gui_main()
        return

    _subcommands: Dict[str, Callable[[List[str]], None]] = {
        "hlc": hlc_main,
        "mcp": mcp_main,
        "info": info_main,
        "disasm": disasm_main,
        "search": search_main,
        "funcs": funcs_main,
        "decompile": decompile_main,
        "db": db_main,
    }
    if len(sys.argv) > 1 and sys.argv[1] in _subcommands:
        _subcommands[sys.argv[1]](sys.argv[2:])
        return

    epilog_lines = ["subcommands:"]
    epilog_lines += [f"  {name:<11}{desc}" for name, desc in _SUBCOMMAND_HELP.items()]
    epilog_lines += [
        "",
        "Run 'crashlink <subcommand> -h' for subcommand-specific help and examples,",
        "or 'crashlink --help-all' to print every subcommand's help at once.",
        "",
        "Without a subcommand, 'file' is opened directly for the options below",
        "(interactive REPL via -c, raw opcode patching via -p, assembly via -a).",
        "",
        "examples:",
        "  crashlink funcs game.hl",
        "      Quick look: list the functions in a bytecode file.",
        "",
        "  crashlink disasm game.hl 42",
        "      Disassemble function f@42.",
        "",
        "  crashlink decompile game.hl 42",
        "      Decompile function f@42 to pseudo-Haxe.",
        "",
        "  crashlink game.hl -c 'funcs'",
        "      Open game.hl and immediately run the interactive REPL command 'funcs'.",
        "",
        "  crashlink game.hl -c ''",
        "      Open game.hl and drop into the interactive REPL.",
        "",
        "  crashlink game.hl -p patch.txt -o patched.hl",
        "      Apply patch.txt to game.hl and write the result to patched.hl.",
        "",
        "  crashlink game.asm -a -o game.hl",
        "      Assemble a crashlink assembly file into bytecode.",
        "",
        "  crashlink hlc game.hl --build",
        "      Transpile to C and compile it against libhl (see 'crashlink hlc -h').",
    ]
    parser = argparse.ArgumentParser(
        description=f"crashlink CLI ({VERSION})",
        prog="crashlink",
        epilog="\n".join(epilog_lines),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "file",
        help="The file to operate on.",
    )
    parser.add_argument(
        "-a",
        "--assemble",
        help="Assemble the passed crashlink assembly file",
        action="store_true",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="The output filename for the assembled or patched bytecode.",
    )
    parser.add_argument("-c", "--command", help="The command to run on startup")
    parser.add_argument(
        "-p",
        "--patch",
        help="Patch the passed file with the following patch definition",
    )
    parser.add_argument(
        "-t",
        "--traceback",
        help="Print tracebacks for debugging when catching exceptions",
        action="store_true",
    )
    parser.add_argument(
        "-N",
        "--no-constants",
        help="Don't resolve constants during deserialisation - helpful for problematic or otherwise weird bytecode files",
        action="store_true",
    )
    parser.add_argument("-d", "--debug", help="Enable addtional debug output", action="store_true")
    parser.add_argument(
        "-D",
        "--no-debug",
        help="Disable debug output that may have been implicitly activted somewhere else",
        action="store_true",
    )
    parser.add_argument(
        "-C",
        "--dehlc",
        help="Extracts information about a compiled HL/C binary. Requires debug information (PDB for PE, DWARF for ELF)",
        action="store_true",
    )
    parser.add_argument(
        "--help-all",
        help="Print this help plus the -h output for every subcommand, then exit",
        action="store_true",
    )

    # --help-all needs handling before parse_args(): 'file' is otherwise required,
    # so 'crashlink --help-all' alone would fail argparse's own validation first.
    if "--help-all" in sys.argv:
        _print_help_all(parser, _subcommands)
        return

    args = parser.parse_args()

    if args.debug:
        globals.DEBUG = True

    if args.no_debug:
        globals.DEBUG = False

    if args.assemble:
        out = (
            args.output
            if args.output
            else os.path.join(
                os.path.dirname(args.file),
                ".".join(os.path.basename(args.file).split(".")[:-1]) + ".hl",
            )
        )
        with open(out, "wb") as f:
            f.write(AsmFile.from_path(args.file).assemble().serialise())
            print(f"{args.file} -> {'.'.join(os.path.basename(args.file).split('.')[:-1]) + '.hl'}")
            return

    if args.dehlc:
        try:
            from .dehlc import code_from_bin

            print(
                "crashlink De-HL/C is EXPERIMENTAL. Use at your own risk. Only x86 is well-supported, ARM is a work in progress."
            )
            print(
                "This will produce an in-memory bytecode image. If you want to work with any extracted information externally, use `save` to serialise it to the disk first."
            )
            print("Opening file...")
            with open(args.file, "rb") as f:
                print("Reading file...")
                code = code_from_bin(data=f.read())
        except ImportError:
            print(
                "You need to install crashlink with the [extras] group in order to use De-HL/C, since it requires `capstone` and `lief`. Sorry!"
            )
            return
    else:
        code = _load_code_from_cli_path(args.file, args.no_constants)

    if args.patch:
        print(f"Loading patch: {args.patch}")
        patch_dir = os.path.dirname(args.patch)
        patch_name = os.path.basename(args.patch)

        if patch_name.endswith(".py"):
            patch_name = patch_name[:-3]

        sys.path.insert(0, patch_dir)

        try:
            patch_module = importlib.import_module(patch_name)
            with open(args.patch, "r") as f:
                content = f.read()
            print(f"Successfully loaded patch module: {patch_module}")
            assert isinstance(patch_module.patch, Patch), "`patch` is not an instance of hlrun.patch.Patch!"
            patch_module.patch.apply(code)
            if not args.output:
                args.output = args.file + ".patch"
            with open(args.output, "wb") as f:
                f.write(code.serialise())
            with open(
                os.path.join(os.path.dirname(args.output), "crashlink_patch.py"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write(content)
        except ImportError as e:
            print(f"Failed to import patch module: {e}")
            if args.traceback:
                traceback.print_exc()
        except AttributeError:
            print("Could not find `patch`, did you define it?")
            if args.traceback:
                traceback.print_exc()
        finally:
            sys.path.pop(0)
        return

    if args.command:
        handle_cmd(code, args.command)
    else:
        _setup_repl_readline(code)
        while True:
            try:
                line = input("crashlink> ")
            except KeyboardInterrupt:
                print()
                continue
            except EOFError:
                print()
                break
            handle_cmd(code, line)


if __name__ == "__main__":
    main()

__all__: List[str] = []
