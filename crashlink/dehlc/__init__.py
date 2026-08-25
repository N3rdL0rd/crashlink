"""
De-HL/C: recovery of bytecode structure from HL/C-compiled binaries.

Sub-modules
-----------
binary         Image access, symbol views, call-target resolution (ELF/PE)
context        Shared reconstruction context
init_analysis  hl_init_types store/call analysis per architecture
types          Type-table reconstruction and typing
strings        String table and hash-name recovery
globals        Module global table recovery
functions      Function/native table reconstruction
pools          Constant-pool synthesis from immediates
lift           Machine-code -> lifted-operation framework (rule-based)
emit           Lifted operations -> real opcodes
reconstruct    Top-level pipeline (`code_from_bin`)
"""

from .binary import HLCBinary, disasm_function
from .context import DehlcContext
from .reconstruct import code_from_bin

__all__ = ["HLCBinary", "DehlcContext", "code_from_bin", "disasm_function"]
