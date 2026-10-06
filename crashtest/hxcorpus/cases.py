"""Find the unit-test classes of a Haxe checkout and turn each into a `Job`."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ..hxsmith.job import Job

DEFAULT_HAXE = Path.home() / "code" / "haxe"
SHIM = Path(__file__).resolve().parent / "shim"

# Runner plumbing, not test classes.
_SKIP = {"Test", "TestMain", "TestMainNow", "TestHL", "TestJava", "TestLua", "TestIO", "TestHttps"}

_HARNESS = """class Harness {{
	static function main() {{
		var t = new {fqn}();
		var names = Type.getInstanceFields(Type.getClass(t));
		names.sort(Reflect.compare);
		for (name in names) {{
			if (name.indexOf("test") != 0)
				continue;
			Sys.println("== " + name);
			try {{
				Reflect.callMethod(t, Reflect.field(t, name), []);
			}} catch (e:Dynamic) {{
				Sys.println("exception: " + Std.string(e));
			}}
		}}
	}}
}}
"""


@dataclass(frozen=True)
class Case:
    name: str  # file stem, e.g. Issue10007
    fqn: str  # unit.issues.Issue10007
    path: Path
    root: Path  # the `src` folder it belongs to


def discover(haxe: Path = DEFAULT_HAXE, substring: Optional[str] = None) -> List[Case]:
    """Every test class of the checkout, issues last (there are over a thousand)."""
    src = haxe / "tests" / "unit" / "src"
    cases = [
        Case(p.stem, f"unit.{p.stem}", p, src)
        for p in sorted((src / "unit").glob("Test*.hx"))
        if p.stem not in _SKIP
    ]
    cases += [
        Case(p.stem, f"unit.issues.{p.stem}", p, src) for p in sorted((src / "unit" / "issues").glob("*.hx"))
    ]
    if substring:
        cases = [c for c in cases if substring in c.name]
    return cases


def job_for(case: Case) -> Job:
    return Job(
        name=case.name,
        class_name="Harness",
        sources={"Harness.hx": _HARNESS.format(fqn=case.fqn)},
        # The shim goes first so its `utest` shadows any installed library.
        classpaths=[str(SHIM), str(case.root)],
        modules=[case.name],
        origin=str(case.path),
    )
