# pyhl

pyhl is a wrapper for the Python C API for HashLink, designed for crashlink's patching framework.

## Why?

crashlink is Python through and through - embedding a second language internally just feels icky, and this feels much more elegant to end users.

## Building

Linux:

```bash
python install_python.py
make
```

Windows:

```bash
python intall_python.py
nmake /f Makefile.win
```

The resulting `pyhl.hdll` should be there in the same directory as the `Makefile`.