# This help list
default:
    @just --list

# Install locally with dev dependencies
install:
    uv pip install -e .[dev]

# Build crashlink
build:
    rm -rf build dist crashlink.egg-info
    uv build
    rm -rf build crashlink.egg-info

# Publish crashlink to PyPI
publish:
    uv publish -u "__token__" -p "$(cat PYPI_TOKEN.txt)"

# Build test samples
build-tests:
    cd tests/haxe && \
    for f in *.hx; do \
        haxe -hl "${f%.*}.hl" -main "$f"; \
    done

# Format the codebase
format:
    ruff format --line-length 120

# Run type checking
check:
    mypy --strict --check-untyped-defs crashlink

# Generate documentation
docs:
    python -m pdoc crashlink --html -o docs --force --template-dir docs/templates
    python -m pdoc crashtest --html -o docs --force --template-dir docs/templates
    python -m pdoc hlrun --html -o docs --force --template-dir docs/templates

# Host and open documentation locally
open-docs:
    python -m webbrowser -t "http://127.0.0.1:80"
    python -m http.server -b 127.0.0.1 80 -d docs

# Serve documentation locally
serve-docs:
    python -m http.server -b 127.0.0.1 80 -d docs

# Run tests
test:
    pytest -n 4 --ignore pyhl/

# Profile the codebase running tests
profile:
    python -m cProfile -o tests.prof -m pytest
    snakeviz tests.prof

# Download or build libpython for pyhl
pyhl-prepare:
    cd pyhl && python install_python.py

# Build the pyhl native hdll (Linux) - run pyhl-prepare first
pyhl:
    cd pyhl && make clean && make
    cp pyhl/pyhl.hdll pyhl/hashlink/build/bin/ || true
    cp -r pyhl/python/lib/python3.14/ pyhl/hashlink/build/bin/lib-py || true
    cp -r hlrun/ pyhl/hashlink/build/bin/lib-py/hlrun/ || true

# Build the pyhl native hdll (Windows) - run pyhl-prepare first
pyhl-win:
    cd pyhl && nmake /f Makefile.win
    mv pyhl/pyhl.dll pyhl/pyhl.hdll || true
    cp pyhl/pyhl.hdll pyhl/hashlink/build/bin/ || true
    cp -r pyhl/lib-py/ pyhl/hashlink/build/bin/lib-py || true
    cp -r hlrun/ pyhl/hashlink/build/bin/lib-py/hlrun/ || true
    cp pyhl/pyhl.hdll ../hashlink/pyhl.hdll || true
    rm -Rf ../hashlink/lib-py || true
    cp -r pyhl/lib-py/ ../hashlink/lib-py || true
    cp -r hlrun/ ../hashlink/lib-py/hlrun/ || true
    cp pyhl/python3.dll ../hashlink/python3.dll || true

# Updates the hashlink submodule in pyhl/
update-hl:
    rm -Rf pyhl/hashlink
    rm -f .gitmodules
    touch .gitmodules
    git submodule add --force https://github.com/HaxeFoundation/hashlink pyhl/hashlink

# Builds the hashlink submodule in pyhl/ to pyhl/hashlink/build/bin/
build-hl:
    cd pyhl/hashlink && mkdir -p build && cd build && cmake .. && make -j$(nproc)

# Runs the patchme test
patchme-test:
    @just pyhl
    crashlink tests/haxe/PatchMe.hl -tDp tests/patch/patchme.py
    ./hl tests/haxe/PatchMe.hl.patch

# Runs the patchme test (Windows)
patchme-test-win:
    @just pyhl-win
    crashlink tests/haxe/PatchMe.hl -tDp tests/patch/patchme.py
    cp tests/haxe/PatchMe.hl.patch ../hashlink/PatchMe.hl.patch || true
    cp tests/haxe/crashlink_patch.py ../hashlink/crashlink_patch.py || true
    pushd ../hashlink && PYTHONPATH=$(pwd)/lib-py ./hl.exe PatchMe.hl.patch && popd

# Clean the codebase
clean:
    rm -rf build dist crashlink.egg-info .mypy_cache .pytest_cache .coverage .coverage.* .tox .nox .hypothesis .pytest_cache tests.prof *_reser.dat
    rm -rf pyhl/include pyhl/libpython* pyhl/pyhl.hdll pyhl/hashlink/bin/pyhl.hdll pyhl/*.lib pyhl/*.dll pyhl/*.a pyhl/*.pdb pyhl/python
    rm -rf pyhl/hashlink-bin
    rm -rf pyhl/lib-py
    rm -rf pyhl/pyhl.obj*
    rm -rf pyhl/pyhl.exp
    @just update-hl

# Full development workflow: format, check, test and generate docs
dev: format check test docs