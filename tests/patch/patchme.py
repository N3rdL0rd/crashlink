from crashlink.patch import *
from crashlink import *

patch = Patch(
    name="crashlink PatchMe test",
    author="N3rdL0rd",
    sha256="b2855efe184d9cdc3c79654a3ae456afd60c05d7ef50669256f31bb422cd0dd6",
)


@patch.intercept("$PatchMe.thing")
def thing(args: Args) -> Args:
    args[0] = 2.0
    return args

@patch.patch("$PatchMe.main")
def main(code: Bytecode, fn: Function) -> None:
    fn.insert_op(
        code,
        0,
        Opcode(
            op="Nop",
            definition={}
        )
    )