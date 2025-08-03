# Contributing to crashlink

First off, thank you for considering contributing to crashlink! We welcome any contribution, from fixing a typo in the documentation to implementing a new decompiler optimization pass. Every little bit helps.

This guide will help you get started. Please don't hesitate to ask for help if you get stuck!

## Getting Started

Before you begin, make sure you have the following prerequisites installed:

* Python 3.10+ (3.13+ is preferred)
* [just](https://just.systems/) (recommended, but not required)
* [uv](https://astral.sh/uv) (HIGHLY recommended for package management, but also not required)
* [Graphviz](https://graphviz.org/download/) (for generating CFG diagrams)

You can set up your development environment by following the instructions in the [Development section of the README](./README.md#development). TL;DR:

```bash
git clone https://github.com/N3rdL0rd/crashlink
cd crashlink
uv sync --extra dev
```

## How to Contribute

The general workflow for contributing is:

1. **Find an issue or feature** to work on. You can check the [open issues](https://github.com/N3rdL0rd/crashlink/issues) or the [Roadmap](../README.md#roadmap) in the README. If you have a new idea, please open an issue first to discuss it.
2. **Fork the repository** to your own GitHub account.
3. **Create a new branch** for your changes (e.g., `git checkout -b feature/new-optimizer`).
4. **Make your changes.** See the "Areas for Contribution" section below for guidance on specific parts of the codebase.
5. **Write tests** for your changes. We take testing semi-seriously, but sometimes testing decompiler stuff is hard and we get it.
6. **Format your code and ensure all checks pass** by running `just dev`. This will run formatting, tests, and build the documentation.
7. **Commit your changes** with a clear and descriptive message.
8. **Push your branch** to your fork and **open a Pull Request** against the main repository.

## Areas for Contribution

crashlink is divided into several modules. Here's each part and what it does.

### 1. The Command-Line Interface (`__main__.py`)

Adding a new command is straightforward.

**How to add a command:**

1. Open `crashlink/__main__.py`.
2. In the `Commands` class, add a new method for your command.
3. (Optional) Use the `@alias(...)` decorator to add shortcuts.
4. Write a clear docstring for the command. The first line is the description, and a ` `...` ` block specifies the usage string.

**Example: Adding a `stats` command**

```python
@alias("st")
def stats(self, args: List[str]) -> None:
    """Prints some basic statistics about the bytecode. `stats`"""
    print(f"Total Functions: {len(self.code.functions)}")
    print(f"Total Strings: {len(self.code.strings.value)}")
    print(f"Total Types: {len(self.code.types)}")
```

### 2. The Core Parser (`core.py`)

This is the heart of crashlink. Contributions here are for supporting new (or old) HashLink bytecode versions or fixing fundamental parsing errors.

* **When to modify:** When a new version of HashLink adds a new field to a structure (like `Function` or `Obj`), or changes how something is serialized, or when a core datatype is missing a good utility method that makes other code less verbose or difficult to work with.
* **What to do:**
    1. Modify the `deserialise` and `serialise` methods of the relevant class in `core.py`.
    2. Add a new Haxe source file to `tests/haxe/` that uses the new feature.
    3. Run `just build-tests`. This will compile your Haxe file to a `.hl` file that will be used in the automated tests.
    4. The existing test suite will automatically pick up the new `.hl` file and run a "round-trip" test (deserialize -> serialize -> compare).

### 3. The Disassembler (`disasm.py`)

This component is all about making the low-level bytecode human-readable. Contributions here often involve improving the text output.

* **How to contribute:**
  * **Improve Pseudocode:** Modify the `pseudo_from_op` function to provide a better one-line summary for an opcode.
  * **Improve Formatting:** Change the `fmt_op` or `func_header` functions to make the output clearer or more informative.
  * **Add New Helpers:** You could add new functions like `is_private` or `get_class_for_method` if you can find a reliable heuristic.

### 4. The Decompiler (`decomp.py`)

This is the most complex and exciting area to contribute to. The goal is to transform low-level opcodes into a high-level, structured Intermediate Representation (IR).

The pipeline is: **CFG -> IR Lifter -> IR Optimizers -> Final IR**

#### Lifting a New Opcode

When an opcode isn't yet understood by the decompiler, it's represented as an `IRUntranslatedOpcode`. The goal is to replace this with a more meaningful IR node.

**Example: Lifting the `Neg` opcode**

1. **Find the lifting logic:** Open `decomp.py` and go to the `_lift_block` method in the `IRFunction` class.
2. **Find the `else` block:** At the end of the `for op in enumerate(node.ops):` loop, find the final `else:` that handles untranslated opcodes.
3. **Add your logic:** Add an `elif op.op == "Neg":` block before the final `else`.
4. **Create the IR:** The `Neg` opcode is like `dst = -src`. This can be represented as `dst = 0 - src` using existing IR nodes.

```python
# In IRFunction._lift_block

# ... inside the loop ...
            elif op.op == "Mov":
                # ...
# Add your new block here
            elif op.op == "Neg":
                dst_local = self.locals[op.df["dst"].value]
                src_local = self.locals[op.df["src"].value]
                zero_const = IRConst(self.code, IRConst.ConstType.INT, value=0)
                
                # Create '0 - src' expression
                arith_expr = IRArithmetic(self.code, zero_const, src_local, IRArithmetic.ArithmeticType.SUB)
                
                # Create 'dst = (0 - src)' assignment
                assign_stmt = IRAssign(self.code, dst_local, arith_expr)
                block.statements.append(assign_stmt)

            elif op.op in ["NullCheck", #...
# ...
```

5. **Add a test:** Create a Python test in the `tests/` directory that decompiles a function using the `Neg` opcode and asserts that the resulting IR is correct.

#### Writing an IR Optimizer

Optimizers transform the IR to make it simpler and more readable. They are classes that inherit from `TraversingIROptimizer`.

**Example: A simple `if (true)` optimizer**

1. **Create a new class:** In `decomp.py`, create a new optimizer class.

```python
class IRIfTrueOptimizer(TraversingIROptimizer):
    """
    Simplifies `if (true) { ... } else { ... }` to just the true-block.
    """
    def visit_conditional(self, conditional: IRConditional) -> None:
        # Check if the condition is an IRConst boolean with value True
        if (
            isinstance(conditional.condition, IRConst) and
            conditional.condition.const_type == IRConst.ConstType.BOOL and
            conditional.condition.value is True
        ):
            # This is where you would implement the logic to replace
            # the IRConditional node with the statements from its true_block.
            # This is a complex operation that requires modifying the parent block.
            # For a real implementation, you would need a more robust way
            # to replace a node.
            dbg_print(f"IfTrueOptimizer: Found a foldable if-true at {conditional}")

```

2. **Add it to the pipeline:** In `IRFunction.__init__`, add your new optimizer to the `self.optimizers` list in the desired order.

### 5. The Pseudocode Generator (`pseudo.py`)

This is the final step, turning the optimized IR into Haxe code. Contributions here involve changing how an IR node is "pretty-printed".

* **How to contribute:**
  * To change how an Expression (like `IRArithmetic`, a subclass of `IRArithmetic`) is printed, modify `_expression_to_haxe`.
  * To change how a Statement (like `IRConditional`, a subclass of `IRStatement`) is printed, modify `_generate_statements`.

For example, to change `if (cond)` to `if cond` (without parentheses), you would find this line in `_generate_statements`:
`output_lines.append(f"{indent}if ({cond_str}) {{")`
and change it to:
`output_lines.append(f"{indent}if {cond_str} {{")`

---

Thank you again for your interest in making crashlink better! This project desperately needs new contributors, so please, pretty please, consider contributing.

💖 N3rdL0rd
