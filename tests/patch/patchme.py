from hlrun import Args
from hlrun.core import HlPrim
from hlrun.core import Type as HlType
from hlrun.globals import is_runtime
from hlrun.patch import *
from hlrun.obj import HlString

# Don't touch this! Trying to import crashlink at runtime will not work.
if not is_runtime():
    from crashlink import *

patch = Patch(
    name="crashlink PatchMe test",
    author="N3rdL0rd",
    sha256="839d7847acdb59627f12b98a6a0ac51c1c03dfde9c49ae61277a97329ce584be",
)


# Intercepts are executed *at* runtime of the bytecode, so we don't have access to crashlink. Instead, we use hlrun's proxies to HL objects.
@patch.intercept("$PatchMe.thing")
def thing(args: Args) -> Args:
    args[0] = HlPrim(2.0, HlType.F64)
    s = args[2]
    assert isinstance(s, HlString), "This isn't a correctly typed proxy object!"
    s.bytes = "Successfully intercepted! Hello from Python!".encode("utf-16")
    # print(s.charAt(0).bytes)
    obj = args[3]
    obj.test = 99999999  # ty: ignore[unresolved-attribute]  # HlObj proxies HL fields dynamically at runtime
    return args


# Patches are executed before runtime, so we can use crashlink with a handle on the bytecode.
@patch.patch("$PatchMe.main")  # ty: ignore[invalid-argument-type]  -- Patch has two shapes gated on is_runtime(), see hlrun/patch.py's HACK comment
def main(code: "Bytecode", fn: "Function") -> None:
    fn.push_op(code, Opcode(op="Nop", df={}))
