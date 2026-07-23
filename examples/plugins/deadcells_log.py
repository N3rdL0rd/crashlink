"""
Example crashlink plugin optimizer for Dead Cells.

Dead Cells' logging macros (`tool.log.LogUtils.logInformation`, `logError`, …)
inline the call site's source position as a trailing anonymous object, e.g.:

    var pos = {};
    pos.fileName   = "src/Boot.hx";
    pos.lineNumber = 261;
    pos.className  = "Boot";
    pos.methodName = "initRes";
    tool.log.LogUtils.logInformation("initPak", pos);

The position object is compiler-injected `haxe.PosInfos` noise; the readable
source is just `LogUtils.logInformation("initPak")`. This optimizer drops that
trailing position argument from log calls.

To use it, drop this file in `~/.crashlink/plugins/` (or a dir on
`$CRASHLINK_PLUGINS`). It self-registers on import.

Two gating styles are shown:
  * `when=` — applies to *any* image that has a `logInformation`-style function
    (codebase-wide). This is what's active below.
  * `sha=`  — pin to one exact image; see the commented alternative at the bottom.
"""

from __future__ import annotations

from crashlink import disasm
from crashlink.decomp import IRCall, IRExpression, IRObjectLiteral, TraversingIROptimizer
from crashlink.plugins import optimizer

# The four fields Haxe's `haxe.PosInfos` injects.
_POS_FIELDS = {"fileName", "lineNumber", "className", "methodName"}
# Log function name fragments whose trailing PosInfos object is safe to drop.
_LOG_NAMES = ("logInformation", "logError", "logWarning", "logDebug", "logInfo")


def _has_log_util(code) -> bool:
    """True if the image defines a Dead-Cells-style log function."""
    for func in code.functions:
        name = disasm.full_func_name_str(code, func)
        if any(n in name for n in _LOG_NAMES):
            return True
    return False


def _is_pos_object(expr: IRExpression) -> bool:
    return (
        isinstance(expr, IRObjectLiteral)
        and _POS_FIELDS.issubset({field_name for field_name, _ in expr.fields})
    )


@optimizer(when=_has_log_util, name="StripLogPositions")
class StripLogPositions(TraversingIROptimizer):
    """Drops the trailing `haxe.PosInfos` object from Dead Cells log calls."""

    def _target_name(self, call: IRCall) -> str:
        target = call.target
        try:
            from crashlink.core import Function

            if target is not None and hasattr(target, "value") and isinstance(target.value, Function):
                return disasm.full_func_name_str(self.func.code, target.value)
        except Exception:
            pass
        return ""

    def _strip(self, call: IRCall) -> None:
        if len(call.args) >= 2 and _is_pos_object(call.args[-1]):
            if any(n in self._target_name(call) for n in _LOG_NAMES):
                call.args = call.args[:-1]

    def visit_expression(self, expr: IRExpression) -> None:
        if isinstance(expr, IRCall):
            self._strip(expr)

    def visit_assign(self, assign) -> None:  # calls nested in `x = log(...)`
        if isinstance(assign.expr, IRCall):
            self._strip(assign.expr)


# --- SHA-pinned alternative -------------------------------------------------
# To pin this to exactly one build instead of any log-having image, register with
# the image's SHA-256 (printed by `crashlink <file> sha`, or `code.sha256`):
#
#     from crashlink.plugins import register_optimizer
#     register_optimizer(StripLogPositions, sha="7d1f…the image's sha…")
