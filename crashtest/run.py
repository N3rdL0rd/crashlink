"""
Functions to run tests, collect results, and produce run reports.
"""

import datetime
import os
import re
import subprocess
import tempfile
import traceback
from difflib import SequenceMatcher
from typing import List, Optional, Tuple
from markupsafe import escape

from crashlink import Bytecode, decomp, globals
from crashlink.disasm import to_asm
from crashlink.pseudo import pseudo

from .models import SIMILARITY_THRESHOLD, GitInfo, MethodComparison, OpcodeComparison, Run, TestCase, TestContext, TestFile, save_run


def get_repo_info() -> GitInfo:
    """
    Get the git branch and commit hash, if available.
    """
    try:
        original_dir = os.getcwd()
        script_dir = os.path.dirname(os.path.abspath(__file__))
        os.chdir(script_dir)

        try:
            branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"]).strip().decode("utf-8")
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"]).strip().decode("utf-8")
            dirty = subprocess.check_output(["git", "status", "--porcelain"]).strip().decode("utf-8") != ""
            return GitInfo(
                is_release=False,
                branch=branch,
                commit=commit[:8],
                dirty=dirty,
                github=f"https://github.com/N3rdL0rd/crashlink/commit/{commit}",
            )
        finally:
            os.chdir(original_dir)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return GitInfo(is_release=True, dirty=False)


def file_to_name(file: str) -> str:
    return " ".join(
        re.sub(
            "([A-Z][a-z]+)",
            r" \1",
            re.sub("([A-Z]+)", r" \1", file.replace(".hx", "").replace("_", " ")),
        ).split()
    ).title()


def op_similarity(a: List[str], b: List[str]) -> float:
    """Sequence similarity of two opcode name lists, 0.0–1.0."""
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, a, b).ratio()


def compare_opcodes(original_code: Bytecode, recompiled_code: Bytecode, class_name: str) -> OpcodeComparison:
    """Compare per-method opcode sequences between original and recompiled bytecode."""
    try:
        original_code.get_test_obj(class_name)
    except ValueError:
        return OpcodeComparison(overall_similarity=-1.0, recompile_error=f"Class '{class_name}' not found in original")

    try:
        recompiled_code.get_test_obj(class_name)
    except ValueError:
        return OpcodeComparison(overall_similarity=-1.0, recompile_error=f"Class '{class_name}' not found in recompiled")

    def _belongs_to_class(name: str, cls: str) -> bool:
        return name.startswith(cls + ".") or name.startswith("$" + cls + ".")

    orig_funcs = {
        original_code.full_func_name(f): f
        for f in original_code.functions
        if _belongs_to_class(original_code.full_func_name(f), class_name)
    }
    recomp_funcs = {
        recompiled_code.full_func_name(f): f
        for f in recompiled_code.functions
        if _belongs_to_class(recompiled_code.full_func_name(f), class_name)
    }

    method_results: List[MethodComparison] = []
    for name, orig_func in orig_funcs.items():
        orig_ops = [op.op for op in orig_func.ops if op.op is not None]
        orig_asm = to_asm(orig_func.ops)
        if name in recomp_funcs:
            recomp_func = recomp_funcs[name]
            recomp_ops = [op.op for op in recomp_func.ops if op.op is not None]
            sim = op_similarity(orig_ops, recomp_ops)
            method_results.append(
                MethodComparison(
                    name=name,
                    similarity=sim,
                    original_count=len(orig_ops),
                    recompiled_count=len(recomp_ops),
                    orig_disasm=orig_asm,
                    recomp_disasm=to_asm(recomp_func.ops),
                )
            )
        else:
            method_results.append(
                MethodComparison(
                    name=name,
                    similarity=0.0,
                    original_count=len(orig_ops),
                    recompiled_count=0,
                    orig_disasm=orig_asm,
                    recomp_disasm="",
                    error="Method not found in recompiled bytecode",
                )
            )

    if method_results:
        overall = sum(m.similarity for m in method_results) / len(method_results)
    else:
        overall = -1.0

    return OpcodeComparison(overall_similarity=overall, methods=method_results)


def recompile_pseudo(pseudo_content: str, class_name: str) -> Tuple[Optional[Bytecode], Optional[str]]:
    """Write pseudocode to a temp file, compile with haxe, return loaded Bytecode or error string."""
    with tempfile.TemporaryDirectory() as tmpdir:
        hx_path = os.path.join(tmpdir, f"{class_name}.hx")
        hl_path = os.path.join(tmpdir, f"{class_name}.hl")
        with open(hx_path, "w", encoding="utf-8") as f:
            f.write(pseudo_content)
        try:
            result = subprocess.run(
                ["haxe", "-hl", hl_path, "-cp", tmpdir, "-main", class_name],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            return None, "Haxe compiler timed out"
        except FileNotFoundError:
            return None, "haxe compiler not found on PATH"
        if result.returncode != 0:
            stderr = result.stderr.strip()
            return None, f"Compilation failed:\n{stderr[:500]}"
        try:
            code = Bytecode.from_path(hl_path)
        except Exception as e:
            return None, f"Failed to load recompiled bytecode: {e}"
        return code, None


def run_case(case: str, id: int) -> TestCase:
    """
    Runs a single test case by decompiling the main class in the file.
    It generates both class-level pseudocode and a combined IR view of all methods,
    then recompiles the pseudocode and compares opcodes with the original.
    """
    try:
        original_content = open(
            os.path.join(os.path.dirname(__file__), "..", "tests", "haxe", case),
            "r",
        ).read()
    except Exception as e:
        tb_last = traceback.format_exc().splitlines()[-1]
        return TestCase(
            original=TestFile(name=case, content=escape("Failed to read original file.")),
            decompiled=TestFile(name=f"{case.replace('.hx', '')} (Decompiled)", content=escape("N/A")),
            ir=TestFile(name=f"{case.replace('.hx', '')} (IR)", content=escape("N/A")),
            failed=True,
            test_name=file_to_name(case),
            test_id=id,
            error=escape(f"Failed to read original file: {str(e)}\n{tb_last}"),
        )

    ir_content = "Failed to produce IR."
    pseudo_content = "Failed to produce pseudocode."
    raw_pseudo_content: Optional[str] = None
    error_message = None
    original_code: Optional[Bytecode] = None

    try:
        original_code = Bytecode.from_path(
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "tests",
                "haxe",
                case.replace(".hx", ".hl"),
            )
        )

        class_name = case.replace(".hx", "")
        test_obj = original_code.get_test_obj(class_name)

        ir_class = decomp.IRClass(original_code, test_obj)

        raw_pseudo_content = ir_class.pseudo()
        pseudo_content = raw_pseudo_content

        ir_parts = []
        if not ir_class.static_methods and not ir_class.methods:
            ir_parts.append("/* No methods found in class */")
        else:
            for static_method in ir_class.static_methods:
                func_name = original_code.full_func_name(static_method.func)
                ir_parts.append(f"// --- Static Method: {func_name} ---")
                ir_parts.append(str(static_method.block))

            for method in ir_class.methods:
                func_name = original_code.full_func_name(method.func)
                ir_parts.append(f"// --- Instance Method: {func_name} ---")
                ir_parts.append(str(method.block))

        ir_content = "\n\n".join(ir_parts)

    except Exception as e:
        tb_last = traceback.format_exc().splitlines()[-1]
        error_message = escape(f"An error occurred during decompilation: {str(e)}\n{tb_last}")

    opcode_comparison: Optional[OpcodeComparison] = None
    if raw_pseudo_content and original_code is not None:
        class_name = case.replace(".hx", "")
        recompiled, recompile_error = recompile_pseudo(raw_pseudo_content, class_name)
        if recompiled is not None:
            opcode_comparison = compare_opcodes(original_code, recompiled, class_name)
        else:
            opcode_comparison = OpcodeComparison(
                overall_similarity=-1.0,
                recompile_error=recompile_error,
            )

    similarity_failed = (
        opcode_comparison is not None
        and 0.0 <= opcode_comparison.overall_similarity < SIMILARITY_THRESHOLD
    )

    return TestCase(
        original=TestFile(
            name=case,
            content=escape(original_content),
        ),
        decompiled=TestFile(
            name=f"{case.replace('.hx', '')} (Decompiled)",
            content=escape(pseudo_content),
        ),
        ir=TestFile(name=f"{case.replace('.hx', '')} (IR)", content=escape(ir_content)),
        failed=bool(error_message) or similarity_failed,
        test_name=file_to_name(case),
        test_id=id,
        error=error_message,
        opcode_comparison=opcode_comparison,
    )


def gen_id() -> str:
    """
    Generate a unique ID for a test run.
    """
    return datetime.datetime.now().strftime("%Y%m%d%H%M%S")


def gen_status(results: List[TestCase]) -> Tuple[str, str]:
    """
    Generate a status message and color based on test results.
    Returns a tuple of (status_message, color_hex).

    Colors:
    - Green (#22C55E): All tests passed
    - Yellow (#EAB308): < 10% failures
    - Orange (#F97316): 10-20% failures
    - Red-Orange (#EF4444): 20-50% failures
    - Red (#DC2626): > 50% failures
    - Dark Red (#991B1B): All tests failed
    """
    if not results:
        return "No Tests Run", "#6B7280"

    total = len(results)
    failed = sum(1 for case in results if case.failed)
    failure_rate = (failed / total) * 100

    if failed == 0:
        return "All tests passed", "#22C55E"
    elif failed == total:
        return "All tests failed", "#991B1B"
    else:
        if failure_rate < 10:
            return f"Partial failure ({failure_rate:.1f}%)", "#EAB308"
        elif failure_rate < 20:
            return f"Partial failure ({failure_rate:.1f}%)", "#F97316"
        elif failure_rate < 50:
            return f"Major failures ({failure_rate:.1f}%)", "#EF4444"
        else:
            return f"Critical failures ({failure_rate:.1f}%)", "#DC2626"


def run() -> None:
    """
    Run all tests.
    """
    print("Getting repo info...")
    git = get_repo_info()
    if git.is_release:
        print(
            "Cannot run tests from a release build (eg. installed fro PyPI). Please clone the repo and run from there."
        )
        return  # TODO: add support for autodownloading and building test samples

    print("Finding test cases...")
    files = os.listdir(os.path.join(os.path.dirname(__file__), "..", "tests", "haxe"))
    cases = [f for f in files if f.endswith(".hx")]
    for case in cases:
        if case.replace(".hx", ".hl") not in files:
            print(f"Warning: no compiled bytecode found for {case}. Skipping.")
            cases.remove(case)

    print("Running tests...")
    results = []
    for i, case in enumerate(cases):
        print(f"Running {case}...")
        result = run_case(case, i)
        results.append(result)

    print("Generating run...")
    status, status_color = gen_status(results)
    r = Run(
        git=git,
        context=TestContext(version=globals.VERSION),
        cases=results,
        id=gen_id(),
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        status=status,
        status_color=status_color,
    )
    os.makedirs(os.path.join(os.path.dirname(__file__), "runs"), exist_ok=True)
    save_run(r, os.path.join(os.path.dirname(__file__), "runs", f"{gen_id()}.json"))
