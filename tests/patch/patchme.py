if "RUNTIME" not in globals():
    from crashlink import *
    from crashlink.patch import *
from hlrun import Args

patch = Patch(
    name="crashlink PatchMe test",
    author="N3rdL0rd",
    sha256="839d7847acdb59627f12b98a6a0ac51c1c03dfde9c49ae61277a97329ce584be",
)


def replace_val(inp: float) -> float:
    print(f"Replacing val {inp} with 2.0f")
    return 2.0


@patch.intercept("$PatchMe.thing")
def thing(args: Args) -> Args:
    args[0] = replace_val(args[0].obj)
    return args


@patch.patch("$PatchMe.main")
def main(code: Bytecode, fn: Function) -> None:
    fn.insert_op(code, 0, Opcode(op="Nop", df={}))
