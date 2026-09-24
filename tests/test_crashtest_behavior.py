"""Behavioral verdicts must reject operand mutations, failures and nontermination."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from crashtest.behavior import (
    compare_programs,
    compile_haxe,
    execute,
    normalize_positions,
    resolve_hl_runtime,
)


@pytest.fixture
def toolchain():
    missing = [tool for tool in ("haxe",) if not shutil.which(tool)]
    runtime = resolve_hl_runtime()
    if not runtime or not Path(runtime).is_file():
        missing.append("HashLink (hl)")
    if missing:
        message = "Required behavioral toolchain missing: " + ", ".join(missing)
        if os.environ.get("CRASHLINK_REQUIRE_QUALITY") == "1":
            pytest.fail(message)
        pytest.skip(message)


def test_execution_deadline_and_exit_status(tmp_path):
    timeout = execute([sys.executable, "-c", "while True: pass"], str(tmp_path), timeout=0.1)
    assert timeout.error and "timed out" in timeout.error
    failure = execute([sys.executable, "-c", "raise SystemExit(7)"], str(tmp_path))
    assert failure.returncode == 7


def test_missing_runtime_cannot_pass(tmp_path, monkeypatch):
    monkeypatch.setenv("HL_RUNTIME", str(tmp_path / "missing-runtime"))
    artifact = tmp_path / "program.hl"
    artifact.write_bytes(b"not executed")
    result = compare_programs(artifact, artifact, "Probe")
    assert not result.passed
    assert result.original.error


def test_unknown_case_has_failure_exit_status():
    result = subprocess.run(
        [sys.executable, "-m", "crashtest", "run", "NoSuchQualityFixture"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1


@pytest.mark.parametrize("mutation", ["17", "18"])
def test_constant_mutation_controls_runner_verdict(toolchain, tmp_path, monkeypatch, mutation):
    from crashlink import decomp
    from crashtest.run import run_case

    source = Path("tests/quality/QualityConstants.hx").read_text()
    target, error = compile_haxe(source, "QualityConstants", tmp_path)
    assert error is None, error
    target.rename(tmp_path / "QualityConstants.hl")
    # Inject a candidate after real lifting: the oracle must not trust the
    # emitter simply because the opcode names are identical.
    monkeypatch.setattr(decomp.IRClass, "pseudo", lambda self: source.replace("17", mutation))
    result = run_case(str(tmp_path / "QualityConstants.hx"), 0)
    assert result.opcode_comparison is not None
    assert result.opcode_comparison.overall_similarity == 1.0
    assert result.behavioral_comparison is not None
    assert result.behavioral_comparison.passed is (mutation == "17")
    assert result.failed is (mutation != "17")


@pytest.mark.parametrize(
    "before,after",
    [
        ("Sys.println(17);", "Sys.println(18);"),
        ('Sys.stderr().writeString("left");', 'Sys.stderr().writeString("right");'),
        ("var a = [1]; a[0] = 2; Sys.println(a[0]);", "var a = [1]; a[0] = 3; Sys.println(a[0]);"),
        (
            'try { throw "left"; } catch (e:Dynamic) { Sys.println(e); }',
            'try { throw "right"; } catch (e:Dynamic) { Sys.println(e); }',
        ),
        ('Sys.println("done");', "while (true) {}"),
        ('Sys.println("done");', 'throw "uncaught";'),
    ],
)
def test_observable_mismatches_fail(toolchain, tmp_path, before, after):
    paths = []
    for index, body in enumerate((before, after)):
        path, error = compile_haxe(
            "class Probe { static function main() { " + body + " } }",
            "Probe",
            tmp_path / str(index),
        )
        assert error is None, error
        paths.append(path)
    result = compare_programs(paths[0], paths[1], "Probe", timeout=0.2)
    assert not result.passed
    assert result.error


@pytest.mark.parametrize("name", ["QualityConstants", "QualityEffects", "QualityLoopContinue"])
def test_shipped_corpus_roundtrip(toolchain, tmp_path, name):
    from crashtest.run import run_case

    source = (Path("tests/quality") / f"{name}.hx").read_text()
    path, error = compile_haxe(source, name, tmp_path)
    assert error is None, error
    path.rename(tmp_path / f"{name}.hl")
    result = run_case(str(tmp_path / f"{name}.hx"), 0)
    assert not result.failed, result.error or result.behavioral_comparison
    assert result.behavioral_comparison and result.behavioral_comparison.passed


def test_shipped_exemption_still_requires_recompilation(toolchain, monkeypatch):
    from crashlink import decomp
    from crashtest.run import run_case

    fixture = Path(__file__).parent / "haxe" / "Closure.hx"
    result = run_case(str(fixture), 0)
    assert not result.failed
    assert result.behavioral_comparison is not None
    assert result.behavioral_comparison.exemption_reason
    assert not result.behavioral_comparison.passed
    assert result.opcode_comparison is not None
    assert result.opcode_comparison.methods

    monkeypatch.setattr(decomp.IRClass, "pseudo", lambda self: "not valid Haxe")
    result = run_case(str(fixture), 0)
    assert result.failed
    assert result.opcode_comparison is not None
    assert result.opcode_comparison.recompile_error
    assert result.behavioral_comparison is not None
    assert result.behavioral_comparison.exemption_reason is None


def test_same_named_external_fixture_is_not_exempt(toolchain, tmp_path, monkeypatch):
    from crashlink import decomp
    from crashtest.run import run_case

    source = "class Random { static function main() { Sys.println(17); } }"
    path, error = compile_haxe(source, "Random", tmp_path)
    assert error is None, error
    path.rename(tmp_path / "Random.hl")
    monkeypatch.setattr(decomp.IRClass, "pseudo", lambda self: source.replace("17", "18"))
    result = run_case(str(tmp_path / "Random.hx"), 0)
    assert result.failed
    assert result.behavioral_comparison is not None
    assert not result.behavioral_comparison.passed
    assert result.behavioral_comparison.exemption_reason is None


def test_position_normalization_keeps_everything_but_layout():
    raw = (
        "tests/haxe/Probe.hx:12: value\n"
        "Uncaught exception: boom\n"
        "Called from $Probe.main(Probe.hx:6)\n"
        "Called from .init(?:1)\n"
    )
    assert normalize_positions(raw, "Probe") == (
        "value\nUncaught exception: boom\nCalled from $Probe.main(Probe.hx:?)\nCalled from .init(?:1)\n"
    )
    # A payload that merely looks like a position is data, not layout.
    assert normalize_positions("Other.hx:6: kept\n", "Probe") == "Other.hx:6: kept\n"


@pytest.mark.parametrize(
    "left,right,expected",
    [
        ('throw "x";', '\nthrow "x";', True),
        ('throw "x";', 'throw "y";', False),
        ('Sys.println("a"); throw "x";', 'Sys.println("b"); throw "x";', False),
    ],
)
def test_failing_programs_are_compared_not_skipped(toolchain, tmp_path, left, right, expected):
    # A fixture whose whole point is an uncaught exception still has to be
    # checked; the extra newline shifts line numbers so the verdict also
    # proves stack positions are normalized rather than compared.
    paths = []
    for index, body in enumerate((left, right)):
        path, error = compile_haxe(
            "class Probe { static function main() { " + body + " } }",
            "Probe",
            tmp_path / str(index),
        )
        assert error is None, error
        paths.append(path)
    result = compare_programs(paths[0], paths[1], "Probe", timeout=5.0)
    assert result.passed is expected
    assert result.original.returncode == 1
    assert result.recompiled.returncode == 1


def test_continue_chains_lift_without_duplication(toolchain, tmp_path):
    # `if (a && b) continue;` used to copy the rest of the loop body into both arms of the
    # chain's first test, doubling the output for every such statement (2^12 here).
    from crashlink.core import Bytecode
    from crashlink.decomp import IRFunction
    from crashlink.pseudo import pseudo

    source = (Path("tests/quality") / "QualityLoopContinue.hx").read_text()
    path, error = compile_haxe(source, "QualityLoopContinue", tmp_path)
    assert error is None, error
    code = Bytecode.from_path(str(path))
    chains = next(f for f in code.functions if code.full_func_name(f).endswith("QualityLoopContinue.chains"))
    out = pseudo(IRFunction(code, chains))
    assert out.count("sum += 12") == 1
    assert len(out.splitlines()) < 200
