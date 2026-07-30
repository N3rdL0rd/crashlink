---
slug: /portability
title: Portability
---

# Portability

crashlink is written in pure typed Python with a minimum version of 3.10, required for the `|` operator and `match` statement. It should run on any modern platform, and has been tested heavily on Windows and Linux, and tested, but less heavily, on macOS.

It's also portable to a number of Python interpreters beyond CPython:

- CPython 3.10+ is the main target.
- PyPy also just works.
- IronPython and Jython are not supported, due to their earlier Python version targets.
- RustPython would work, but it doesn't support `match` statements.
- Pyodide works, and you can see a live demo [here](https://n3rdl0rd.github.io/crashlink/demo).
