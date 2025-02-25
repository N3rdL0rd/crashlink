"""
Functions to run tests, collect results, and produce run reports.
"""

from .models import GitInfo, TestContext, TestCase, TestFile, Run, save_run
import os
import subprocess
import traceback
from crashlink import decomp, Bytecode, globals
import datetime

def get_repo_info() -> GitInfo:
    """
    Get the git branch and commit hash, if available.
    """
    try:
        original_dir = os.getcwd()
        script_dir = os.path.dirname(os.path.abspath(__file__))
        os.chdir(script_dir)

        try:
            branch = subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"]).strip().decode("utf-8")
            commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"]).strip().decode("utf-8")
            dirty = subprocess.check_output(
                ["git", "status", "--porcelain"]).strip().decode("utf-8") != ""
            return GitInfo(is_release=False, branch=branch, commit=commit[:8], dirty=dirty, github=f"https://github.com/N3rdL0rd/crashlink/commit/{commit}")
        finally:
            os.chdir(original_dir)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return GitInfo(is_release=True, dirty=False)

def run_case(case: str, id: int) -> TestCase:
    """
    Runs a single test case.
    """
    try:
        code = Bytecode.from_path(os.path.join(os.path.dirname(__file__), "..", "tests", "haxe", case.replace(".hx", ".hl")))
        irf = decomp.IRFunction(code, code.get_test_main())
        # TODO: pseudo output
        return TestCase(
            original=TestFile(name=case, content=open(os.path.join(os.path.dirname(__file__), "..", "tests", "haxe", case), "r").read()),
            decompiled=TestFile(name=f"{case.replace('.hx', '')} (Decompiled)", content="Failed to produce pseudocode."),
            ir=TestFile(name=f"{case.replace('.hx', '')} (IR)", content=str(irf.block)),
            failed=False,
            test_name=case.replace(".hx", "").replace("_", " ").title(),
            test_id=id,
        )
    except Exception as e:
        return TestCase(
            original=TestFile(name=case, content=open(os.path.join(os.path.dirname(__file__), "..", "tests", "haxe", case), "r").read()),
            decompiled=TestFile(name=f"{case.replace('.hx', '')} (Decompiled)", content="Failed to produce pseudocode."),
            ir=TestFile(name=f"{case.replace('.hx', '')} (IR)", content="Failed to produce IR."),
            failed=True,
            test_name=case.replace(".hx", "").replace("_", " ").title(),
            test_id=id,
            error=str(e)
        )


def gen_id() -> str:
    """
    Generate a unique ID for a test run.
    """
    return datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    
def run() -> None:
    """
    Run all tests.
    """
    print("Getting repo info...")
    git = get_repo_info()
    if git.is_release:
        print("Cannot run tests from a release build (eg. installed fro PyPI). Please clone the repo and run from there.")
        return # TODO: add support for autodownloading and building test samples
    
    print("Finding test cases...")
    files = os.listdir(os.path.join(os.path.dirname(__file__), "..", "tests", "haxe"))
    cases = [f for f in files if f.endswith(".hx")]
    for case in cases:
        if not case.replace(".hx", ".hl") in files:
            print(f"Warning: no compiled bytecode found for {case}. Skipping.")
            cases.remove(case)
    
    print("Running tests...")
    results = []
    for i, case in enumerate(cases):
        print(f"Running {case}...")
        result = run_case(case, i)
        results.append(result)
    
    print("Generating run...")
    r = Run(
        git=git,
        context=TestContext(version=globals.VERSION),
        cases=results,
        id=gen_id(),
        timestamp="TODO",
        status="TODO",
    )
    save_run(r, os.path.join(os.path.dirname(__file__), "runs", f"{gen_id()}.json"))