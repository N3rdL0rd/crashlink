from hlrun import Args
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
    args[0] = 2.0
    s = args[2]
    assert isinstance(s, HlString), "This isn't a correctly typed proxy object!"
    s.bytes = "Successfully intercepted! Hello from Python!".encode("utf-16")
    #print(s.charAt(0).bytes)
    args[3].test = 99999999
    return args

# Patches are executed before runtime, so we can use crashlink with a handle on the bytecode.
@patch.patch("$PatchMe.main")
def main(code: "Bytecode", fn: "Function") -> None:
    fn.push_op(code, Opcode(op="Nop", df={}))
