"""
Export of a whole image as a Haxe project.

Every type the image declares outside the Haxe std is written to the module source would
have declared it in, under `src/`:

- A class, interface or enum named `pkg.Name` is the main type of `pkg/Name.hx`, unless
  debug info places its code in another file of the package, `pkg/Module.hx`: then it's
  declared there, and every reference to it goes through the module (`pkg.Module.Name`),
  since the bytecode names it `pkg.Name` either way. A top-level type in another module is
  imported for every module by `src/import.hx` instead.
- A private type is named `pkg._Module.Name`: it's declared `private` in `pkg/Module.hx`.
- An abstract is declared in the module its `_Impl_` class names.

Natives and std functions the code calls through externs are declared once, in
`Native.hx` and `StdFuncs.hx` at the root. `build.hxml` compiles the project to HashLink
with the image's `main`. Function bodies are decompiled, or stubbed (`stubs=True`): a
stubbed project has every type and signature of the image and compiles regardless of how
well bodies decompile.
"""

import collections
import os
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Tuple, Union

from . import abstracts, disasm, typeinit
from .core import Bytecode, Enum, Function, Obj, is_static_name
from .std_types import STD_TYPES

if TYPE_CHECKING:
    from . import pseudo

#: A type's own name, or a module's: what Haxe accepts as one.
_IDENTIFIER = re.compile(r"[A-Za-z_]\w*\Z")


@dataclass
class Declaration:
    """One type declared in a module."""

    kind: str  # "class", "interface", "enum" or "abstract"
    name: str
    private: bool
    #: The class (either half), interface (its static half), enum, or abstract (its
    #: `_Impl_` class) the declaration renders.
    definition: Union[Obj, Enum]
    #: First source line of the type's code, to keep the module's order; 0 when unknown.
    line: int = 0


@dataclass
class Module:
    package: str
    name: str
    declarations: List[Declaration] = field(default_factory=list)

    @property
    def path(self) -> str:
        """`pkg/Module.hx`, relative to the source root."""
        parts = self.package.split(".") if self.package else []
        return "/".join([*parts, f"{self.name}.hx"])

    @property
    def dotted(self) -> str:
        return f"{self.package}.{self.name}" if self.package else self.name


@dataclass
class Layout:
    """Where each type of an image is declared."""

    #: Modules by dotted path.
    modules: Dict[str, Module]
    #: Public types of a package declared in another type's module: bytecode name ->
    #: source path. References are rewritten to it.
    paths: Dict[str, str]
    #: Top-level public types declared in another type's module, as source paths: a bare
    #: name can't be rewritten safely, so `import.hx` imports them everywhere.
    imports: List[str]
    #: The class whose `main` the image starts with, as source names it.
    main: Optional[str]


def _bytecode_name(name: str) -> str:
    """A class's name without the static half's `$`."""
    path, _, last = name.rpartition(".")
    last = last.lstrip("$")
    return f"{path}.{last}" if path else last


def _split(name: str) -> Tuple[str, Optional[str], str]:
    """(package, module of a private type or None, type name) of a bytecode name."""
    parts = name.split(".")
    if len(parts) >= 2 and parts[-2].startswith("_"):
        return ".".join(parts[:-2]), parts[-2][1:], parts[-1]
    return ".".join(parts[:-1]), None, parts[-1]


def _halves(obj: Obj) -> List[Obj]:
    halves = [obj]
    for attr in ("static", "dynamic"):
        try:
            other = getattr(obj, attr)
        except (ValueError, AttributeError):
            continue
        if isinstance(other, Obj) and other is not obj:
            halves.append(other)
    return halves


def _functions(code: Bytecode, obj: Obj) -> List[Function]:
    found = []
    for half in _halves(obj):
        for member in list(half.protos) + list(half.bindings):
            try:
                func = member.findex.resolve(code)
            except Exception:
                continue
            if isinstance(func, Function):
                found.append(func)
    return found


def _function_file(code: Bytecode, func: Function) -> Optional[Tuple[str, int]]:
    """The file most of a function's code is on, and its first line there. Inlined code
    carries its own file, so the majority decides; line 0 is no position at all (the
    `throw null` an `abstract function` compiles to)."""
    if not func.has_debug or not func.debuginfo or not func.debuginfo.value:
        return None
    files = code.debugfiles.value if code.debugfiles is not None else []
    positioned = [ref for ref in func.debuginfo.value if ref.line > 0 and 0 <= ref.value < len(files)]
    if not positioned:
        return None
    fid = collections.Counter(ref.value for ref in positioned).most_common(1)[0][0]
    return str(files[fid]), min(ref.line for ref in positioned if ref.value == fid)


def _stem(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1].removesuffix(".hx")


def _source_file(code: Bytecode, functions: List[Function], name: str = "") -> Tuple[Optional[str], int]:
    """The file a type's functions are in, and the first line there: the file named after
    the type if any function is in it, else the one most are in. Macro-built members carry
    the macro's file, and can outnumber the type's own."""
    votes: collections.Counter = collections.Counter()
    first: Dict[str, int] = {}
    for func in functions:
        found = _function_file(code, func)
        if found is None:
            continue
        path, line = found
        votes[path] += 1
        first[path] = min(first.get(path, line), line)
    if not votes:
        return None, 0
    own = [path for path in votes if _stem(path) == name]
    path = max(own, key=votes.__getitem__) if own else votes.most_common(1)[0][0]
    return path, first[path]


def _is_std(code: Bytecode, name: str, functions: List[Function]) -> bool:
    if name in STD_TYPES:
        return True
    # A newer or patched std than the table's: its code is in a std directory.
    files = [found[0] for found in (_function_file(code, func) for func in functions) if found is not None]
    return bool(files) and all("/std/" in path.replace("\\", "/") for path in files)


def _main_class(code: Bytecode) -> Optional[str]:
    """Bytecode name of the class whose static `main` the entry point calls last."""
    try:
        entry = code.fn(code.entrypoint.value)
    except Exception:
        return None
    if not isinstance(entry, Function):
        return None
    main = None
    for op in entry.ops:
        if not str(op.op).startswith("Call") or "fun" not in op.df:
            continue
        callee = op.df["fun"].resolve(code)
        if isinstance(callee, Function) and code.partial_func_name(callee) == "main":
            owner = code.full_func_name(callee).rpartition(".")[0]
            if is_static_name(owner):
                main = _bytecode_name(owner)
    return main


def layout(code: Bytecode) -> Layout:
    """Place every non-std type of `code` in its module."""
    modules: Dict[str, Module] = {}
    paths: Dict[str, str] = {}
    imports: List[str] = []
    enum_names = set()
    for typ in code.types:
        if isinstance(typ.definition, Enum) and typ.definition.name.value:
            enum_names.add(typ.definition.name.resolve(code))

    def place(package: str, module: str, declaration: Declaration) -> None:
        dotted = f"{package}.{module}" if package else module
        modules.setdefault(dotted, Module(package, module)).declarations.append(declaration)

    seen_abstracts = set()
    for typ in code.types:
        definition = typ.definition
        if isinstance(definition, Enum):
            # Unnamed enums are closure capture contexts, declared by their class.
            if not definition.name.value:
                continue
            name = definition.name.resolve(code)
            if _is_std(code, name, []):
                continue
            package, private_module, short = _split(name)
            place(
                package,
                private_module or short,
                Declaration("enum", short, private_module is not None, definition),
            )
            continue
        if not isinstance(definition, Obj):
            continue
        raw = definition.name.resolve(code)
        abstract = abstracts.abstract_of(code, definition)
        if abstract is not None:
            if id(abstract) in seen_abstracts:
                continue
            seen_abstracts.add(id(abstract))
            package, _, module = abstract.module.rpartition(".")
            line = _source_file(code, _functions(code, abstract.obj), abstract.name)[1]
            place(package, module, Declaration("abstract", abstract.name, False, abstract.obj, line))
            continue
        if raw.endswith(abstracts.IMPL_SUFFIX):
            continue  # an std abstract, or one with no members left
        name = _bytecode_name(raw)
        interface = typeinit.interface_of(code, definition)
        if is_static_name(raw) and interface is None:
            continue  # the class's other half, or an enum's class object
        if not is_static_name(raw) and name in enum_names:
            continue
        functions = _functions(code, definition)
        if _is_std(code, name, functions):
            continue
        package, private_module, short = _split(name)
        kind = "interface" if interface is not None else "class"
        source, line = _source_file(code, functions, short)
        if private_module is not None:
            place(package, private_module, Declaration(kind, short, True, definition, line))
            continue
        module = short
        if source is not None:
            stem = _stem(source)
            if stem != short and _IDENTIFIER.match(stem):
                module = stem
                if package:
                    paths[name] = f"{package}.{stem}.{short}"
                else:
                    imports.append(f"{stem}.{short}")
        place(package, module, Declaration(kind, short, False, definition, line))

    for module in modules.values():
        # The module's main type first, the rest in source order.
        module.declarations.sort(key=lambda d: (d.name != module.name, d.line == 0, d.line))
    main = _main_class(code)
    if main is not None:
        main = paths.get(main, main)
        package, private_module, short = _split(main)
        if private_module is not None:
            main = f"{package}.{private_module}.{short}" if package else f"{private_module}.{short}"
        elif not package:
            main = next((path for path in imports if path.endswith(f".{short}")), main)
    return Layout(modules, paths, sorted(imports), main)


def _rewriter(paths: Dict[str, str]) -> Callable[[str], str]:
    """Rewrite references to types declared in another type's module: the image's own
    (`paths`), private ones and the std's (`disasm.source_paths`)."""
    if not paths:
        return disasm.source_paths
    pattern = re.compile(
        r"(?<![\w.])("
        + "|".join(re.escape(name) for name in sorted(paths, key=len, reverse=True))
        + r")(?!\w)"
    )
    return lambda text: disasm.source_paths(
        disasm.outside_literals(text, lambda chunk: pattern.sub(lambda m: paths[m.group(1)], chunk))
    )


def _render(code: Bytecode, declaration: Declaration, stubs: bool, externs: "pseudo.ProjectExterns") -> str:
    from . import pseudo
    from .decomp import IRClass

    definition = declaration.definition
    if isinstance(definition, Enum):
        text = pseudo._enum_pseudo(definition, code, name=declaration.name)
        return f"private {text}" if declaration.private else text
    target = pseudo.ModuleDeclaration(declaration.name, declaration.private, externs)
    if stubs:
        return pseudo._stub_class(code, definition, target)
    try:
        return pseudo._class_body(IRClass(code, definition), module=target)[0]
    except Exception as e:
        # Keep the project whole: the type with its signatures, and why it isn't decompiled.
        return f"// decompilation failed: {type(e).__name__}: {e}\n" + pseudo._stub_class(
            code, definition, target
        )


def build_file(layout_: Layout) -> str:
    """`build.hxml`: every module of `src`, compiled to HashLink. The image holds every type
    the build kept, so all are compiled (and typed), not only the ones `main` reaches."""
    lines = ["-cp src"]
    if layout_.main is not None:
        lines.append(f"-main {layout_.main}")
    lines.append('--macro include("", true, null, ["src"])')
    lines.append("-hl out.hl")
    return "\n".join(lines) + "\n"


def _qualify_shadowed_std(modules: List[Module], files: Dict[str, str]) -> None:
    """In a package declaring a type named like a top-level std one (`Array`), an
    unqualified name means the package's: write the std one `std.Array`. The renderer
    always qualifies a packaged type, so every bare occurrence there is the std's."""
    shadowing: Dict[str, set] = collections.defaultdict(set)
    for module in modules:
        if module.package:
            for declaration in module.declarations:
                if declaration.name in STD_TYPES:
                    shadowing[module.package].add(declaration.name)
    for module in modules:
        names = shadowing.get(module.package)
        if not names:
            continue
        pattern = re.compile(
            r"(?<![\w.])(?<!class )(?<!interface )(?<!enum )(?<!abstract )("
            + "|".join(re.escape(name) for name in sorted(names))
            + r")(?!\w)"
        )
        file = f"src/{module.path}"
        files[file] = disasm.outside_literals(files[file], lambda chunk: pattern.sub(r"std.\1", chunk))


def _publish_named_privates(modules: List[Module], files: Dict[str, str]) -> None:
    """Declare public a private type that another module's code names. Source only ever
    infers such a type there (an `inline` function returning it, unannotated), and
    rendered signatures and inlined code write it out, which Haxe rejects. Kept private
    when a public type of its package has the same name: both would be `pkg.Name`."""
    public_names = {
        f"{module.package}.{d.name}" if module.package else d.name
        for module in modules
        for d in module.declarations
        if not d.private
    }
    owners: Dict[str, Tuple[Module, Declaration]] = {}
    for module in modules:
        if not module.package:
            continue  # a top-level private type is named bare: no reliable reference to find
        for declaration in module.declarations:
            if declaration.private and f"{module.package}.{declaration.name}" not in public_names:
                owners[f"{module.dotted}.{declaration.name}"] = (module, declaration)
    if not owners:
        return
    pattern = re.compile(
        r"(?<![\w.])("
        + "|".join(re.escape(path) for path in sorted(owners, key=len, reverse=True))
        + r")(?!\w)"
    )
    named = set()
    for module in modules:

        def scan(chunk: str, module: Module = module) -> str:
            named.update(path for path in pattern.findall(chunk) if owners[path][0] is not module)
            return chunk

        disasm.outside_literals(files[f"src/{module.path}"], scan)
    for path in named:
        module, declaration = owners[path]
        declaration.private = False
        file = f"src/{module.path}"
        files[file] = re.sub(
            rf"^private ((?:class|interface|enum|abstract) {re.escape(declaration.name)}\b)",
            r"\1",
            files[file],
            count=1,
            flags=re.M,
        )


def export(
    code: Bytecode,
    stubs: bool = False,
    progress: Optional[Callable[[int, int], None]] = None,
) -> Dict[str, str]:
    """The project's files, by path relative to its root: `build.hxml` and `src/...`."""
    from . import pseudo

    plan = layout(code)
    rewrite = _rewriter(plan.paths)
    externs = pseudo.ProjectExterns()
    files: Dict[str, str] = {}
    modules = sorted(plan.modules.values(), key=lambda m: m.dotted)
    for done, module in enumerate(modules):
        chunks = [_render(code, declaration, stubs, externs) for declaration in module.declarations]
        header = f"package {module.package};\n\n" if module.package else ""
        files[f"src/{module.path}"] = rewrite(header + "\n\n".join(chunks) + "\n")
        if progress is not None:
            progress(done + 1, len(modules))
    _qualify_shadowed_std(modules, files)
    _publish_named_privates(modules, files)
    for name, text in externs.declarations(code).items():
        if f"src/{name}.hx" in files:
            raise ValueError(f"the image declares a type {name!r}, which the project's externs need")
        files[f"src/{name}.hx"] = rewrite(text + "\n")
    if plan.imports:
        files["src/import.hx"] = "".join(f"import {path};\n" for path in plan.imports)
    files["build.hxml"] = build_file(plan)
    return files


def write(folder: str, files: Dict[str, str]) -> None:
    """Write `files` (from `export`) under `folder`."""
    for rel, text in files.items():
        path = os.path.join(folder, rel)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
