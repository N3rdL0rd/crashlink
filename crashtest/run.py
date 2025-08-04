"""
Functions to run tests, collect results, and produce run reports.
"""

import datetime
import os
import re
import subprocess
import traceback
from typing import List, Tuple
from markupsafe import escape

from crashlink import Bytecode, decomp, globals
from crashlink.pseudo import pseudo

from .models import GitInfo, Run, TestCase, TestContext, TestFile, save_run


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


def run_case(case: str, id: int) -> TestCase:
    """
    Runs a single test case by decompiling the main class in the file.
    It generates both class-level pseudocode and a combined IR view of all methods.
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
    error_message = None

    try:
        code = Bytecode.from_path(
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "tests",
                "haxe",
                case.replace(".hx", ".hl"),
            )
        )

        class_name = case.replace(".hx", "")
        test_obj = code.get_test_obj(class_name)

        ir_class = decomp.IRClass(code, test_obj)

        pseudo_content = ir_class.pseudo()

        ir_parts = []
        if not ir_class.static_methods and not ir_class.methods:
             ir_parts.append("/* No methods found in class */")
        else:
            for static_method in ir_class.static_methods:
                func_name = code.full_func_name(static_method.func)
                ir_parts.append(f"// --- Static Method: {func_name} ---")
                ir_parts.append(str(static_method.block))
            
            for method in ir_class.methods:
                func_name = code.full_func_name(method.func)
                ir_parts.append(f"// --- Instance Method: {func_name} ---")
                ir_parts.append(str(method.block))

        ir_content = "\n\n".join(ir_parts)

    except Exception as e:
        tb_last = traceback.format_exc().splitlines()[-1]
        error_message = escape(f"An error occurred during decompilation: {str(e)}\n{tb_last}")

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
        failed=bool(error_message),
        test_name=file_to_name(case),
        test_id=id,
        error=error_message,
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
        return "No Tests Run", "#6B7280"  # Gray for no tests

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
