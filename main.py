"""
Entrypoint for bundling crashlink as a native executable (eg. with PyInstaller).
In any other reasonable case,this file should not be executed directly - instead install crashlink via pip and run it with `crashlink` in the shell of your choice.
"""

from crashlink.__main__ import main

if __name__ == "__main__":
    main()
