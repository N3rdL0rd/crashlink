import os
import shutil
from dataclasses import replace
from typing import Any

import pytest

from crashtest.behavior import BehavioralComparison, Execution, resolve_hl_runtime
from crashtest.hxsmith import Observation, Quality, classify, generate, resolve
from crashtest.hxsmith.coverage import DEFAULT_HAXE, measure
from crashtest.hxsmith.pipeline import Result
from crashtest.hxsmith.quality import Verdict, error_kinds, normalize
from crashtest.hxsmith.runner import Report, lint


def _behavior(passed: bool, before: str = "1\n", after: str = "1\n") -> BehavioralComparison:
    return BehavioralComparison(
        passed, Execution(before, "", 0), Execution(after, "", 0), None if passed else "Behavior differs"
    )


def _observation(**overrides: Any) -> Observation:
    base = Observation(decompiled={"src/F.hx": "class F {}"}, behavior=_behavior(True), similarity=0.8)
    return replace(base, **overrides)


def test_ladder_orders_from_worst_to_best():
    assert list(Quality) == sorted(Quality)
    assert Quality.CRASH < Quality.UNLIFTED < Quality.NO_COMPILE < Quality.DIVERGES < Quality.BEHAVES
    assert Quality.BEHAVES < Quality.IDENTICAL


@pytest.mark.parametrize(
    "obs, expected",
    [
        (_observation(decompile_error="ValueError in lift: boom"), Quality.CRASH),
        (_observation(decompiled={"a.hx": "// decompilation failed: KeyError: 3"}), Quality.CRASH),
        (_observation(decompiled={"a.hx": "// UNLIFTED OPCODE: Switch 1 2"}), Quality.UNLIFTED),
        (
            _observation(compile_error="Haxe compilation failed:\nsrc/F.hx:3: Type not found"),
            Quality.NO_COMPILE,
        ),
        (_observation(behavior=_behavior(False, "1\n", "2\n")), Quality.DIVERGES),
        (_observation(behavior=None), Quality.DIVERGES),
        (_observation(), Quality.BEHAVES),
        (_observation(similarity=1.0), Quality.IDENTICAL),
        (_observation(similarity=1.0, differing=[("F.extra", 0.0)]), Quality.BEHAVES),
    ],
)
def test_classify_places_each_observation_on_its_rung(obs, expected):
    assert classify(obs).quality == expected


def test_a_lower_rung_wins_when_several_things_are_wrong():
    both = _observation(
        decompiled={"a.hx": "// UNLIFTED OPCODE: Switch"},
        compile_error="Haxe compilation failed:\nsrc/F.hx:3: oops",
        behavior=_behavior(False, "1", "2"),
    )
    assert classify(both).quality == Quality.UNLIFTED
    assert classify(_observation(decompile_error="boom", compile_error="x")).quality == Quality.CRASH


def test_divergence_reports_the_first_differing_output_line():
    verdict = classify(_observation(behavior=_behavior(False, "a\nb\nc\n", "a\nX\nc\n")))
    assert "line 2" in verdict.detail and "'b'" in verdict.detail and "'X'" in verdict.detail


def test_signature_groups_the_same_failure_across_programs():
    one = classify(
        _observation(
            compile_error="Haxe compilation failed:\nsrc/Fuzz12.hx:98: lines 98-176 : Cannot iterate backwards"
        )
    )
    two = classify(
        _observation(
            compile_error="Haxe compilation failed:\nsrc/Fuzz7.hx:4: lines 4-9 : Cannot iterate backwards"
        )
    )
    other = classify(
        _observation(compile_error="Haxe compilation failed:\nsrc/Fuzz7.hx:4: Type not found : Foo")
    )
    assert one.signature == two.signature != other.signature
    assert normalize("crash in f@1204: x") == normalize("crash in f@77: x")


def test_verdict_survives_json():
    verdict = classify(_observation(similarity=0.9, differing=[("F.main", 0.9)]))
    from crashtest.hxsmith import Verdict

    assert Verdict.from_json(verdict.to_json()) == verdict


def _result(seed, verdict=None, invalid=None, features=("literals",)):
    return Result(f"seed{seed}", f"Fuzz{seed}", features, verdict, invalid)


def test_report_buckets_failures_into_clusters_biggest_first():
    from crashtest.hxsmith import Verdict

    crash = lambda sig: Verdict(Quality.CRASH, "decompile", "", sig)  # noqa: E731
    report = Report(
        [
            _result(1, crash("crash: a")),
            _result(2, crash("crash: b")),
            _result(3, crash("crash: b")),
            _result(4, Verdict(Quality.BEHAVES, "compare", "", "behaves")),
            _result(5, invalid="generator: original does not compile"),
        ]
    )
    assert [(q, sig, seeds) for q, sig, seeds in report.clusters()] == [
        (Quality.CRASH, "crash: b", ["seed2", "seed3"]),
        (Quality.CRASH, "crash: a", ["seed1"]),
    ]
    assert report.histogram()[Quality.CRASH] == 3
    assert len(report.invalid) == 1 and len(report.valid) == 4


def test_generation_is_deterministic_per_seed():
    assert generate(3).source == generate(3).source
    assert generate(3).source != generate(4).source
    assert generate(3).class_name == "Fuzz3" and "class Fuzz3" in generate(3).source


def test_feature_selection_restricts_and_excludes():
    assert {f.name for f in resolve(["loops"])} >= {"loops", "literals"}
    assert "loops" not in {f.name for f in resolve(None, ["loops"])}
    assert "for (" not in generate(1, ["literals", "variables", "operators"]).source
    with pytest.raises(KeyError):
        resolve(["no_such_feature"])


def test_swarm_picks_a_seeded_feature_subset_and_keeps_output():
    subsets = {generate(seed, swarm=0.3).features for seed in range(12)}
    assert len(subsets) > 6, "each seed should enable a different subset"
    assert all("variables" in subset and "literals" in subset for subset in subsets)
    assert generate(5, swarm=0.3) == generate(5, swarm=0.3)
    assert len(generate(5, swarm=0.3).features) < len(resolve())


def test_features_claim_only_constructors_that_exist_in_the_haxe_ast():
    if not (DEFAULT_HAXE / "src" / "core" / "ast.ml").exists():
        pytest.skip("no Haxe checkout at ~/code/haxe")
    assert measure().unknown == {}


@pytest.mark.skipif(
    not shutil.which("haxe") or not resolve_hl_runtime(), reason="needs haxe and a HashLink runtime"
)
def test_generated_programs_are_valid_deterministic_tests():
    assert lint(range(24), jobs=os.cpu_count() or 1) == []


_REPORT = """Haxe compilation failed:
src/A.hx:3: characters 1-9 : Object requires field opt
src/A.hx:3: characters 1-9 : ... For function argument 'pos'
src/A.hx:9: lines 9-12 : Class<a.B1> has no field C
src/A.hx:9: characters 2-3 : Warning : (WUnusedPattern) This pattern is unused"""


def test_error_kinds_merge_instances_and_skip_context_and_warnings():
    assert error_kinds(_REPORT) == {"Object requires field opt", "Class<T> has no field <name>"}
    assert error_kinds("src/A.hx:1: Class<x.Y2> has no field Foo") == error_kinds(
        "src/B.hx:7: Class<z> has no field Bar"
    )


def test_fix_order_puts_the_fix_that_unblocks_most_programs_first():
    def broken(name, *errors):
        detail = "\n".join(f"src/F.hx:1: {e}" for e in errors)
        return _result(name, Verdict(Quality.NO_COMPILE, "compile", detail, "compile: x"))

    report = Report(
        [
            broken("a", "common", "rare"),
            broken("b", "common"),
            broken("c", "common"),
            broken("d", "other", "rare"),
            broken("e", "rare"),
        ]
    )
    order = report.fix_order()
    # "common" clears b and c immediately; "rare" then clears a (common+rare) and e.
    assert order[0] == ("common", 3, 2)
    assert order[1] == ("rare", 3, 2)
    assert [kind for kind, _, _ in order] == ["common", "rare", "other"] and order[2][2] == 1


def test_positions_of_the_compared_modules_are_normalised() -> None:
    from crashtest.behavior import normalize_positions

    text = "a.B.test(unit/issues/Issue1.hx:7)\nsrc/Other.hx:3: x\n"
    assert normalize_positions(text, "Harness", ("Issue1",)) == "a.B.test(Issue1.hx:?)\nsrc/Other.hx:3: x\n"
    # Without the module, a different line count in the decompiled source would show up as a difference.
    assert normalize_positions(text, "Harness") == text
