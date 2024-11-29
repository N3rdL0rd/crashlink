# This help list
default:
    @just --list

# Install locally with dev dependencies
install:
    pip install -e .[dev]

# Build crashlink
build:
    rm -rf build dist crashlink.egg-info
    python -m build
    rm -rf build crashlink.egg-info

# Build test samples
build-tests:
    cd tests/haxe && \
    for f in *.hx; do \
        haxe -hl "${f%.*}.hl" -main "$f"; \
    done

# Format the codebase
format:
    black --exclude env . --line-length 120
    isort . -s env
    no_implicit_optional crashlink

# Run type checking
check:
    mypy --strict --check-untyped-defs crashlink

# Generate documentation
docs:
    pdoc3 crashlink --html -o docs --force --template-dir docs/templates

# Host documentation locally
serve-docs:
    python -m http.server -b 127.0.0.1 80 -d docs/crashlink

# Run tests
test:
    pytest

# Profile the codebase running tests
profile:
    python -m cProfile -o tests.prof -m pytest
    snakeviz tests.prof

# Clean the codebase
clean:
    rm -rf build dist crashlink.egg-info .mypy_cache .pytest_cache .coverage .coverage.* .tox .nox .hypothesis .pytest_cache tests.prof *_reser.dat

# Full development workflow: format, check, test and generate docs
dev: format check test docs