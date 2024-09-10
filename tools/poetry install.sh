#!/bin/bash

if [ "$CI" ]; then
    export POETRY VIRTUALENVS OPTIONS NO PIP = true
    export POETRY VIRTUALENVS OPTIONS NO SETUPTOOLS = true
    poetry install --sync --no-cache
else
    # NOTE: Outside the CI we keep pip/setuptools because most IDE
    # (pycharm/vscode) didn't yet support virtualenv without them installed.
    poetry install --sync
fi
