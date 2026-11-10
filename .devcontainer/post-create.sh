#!/bin/sh
# Runs once in the container, after it is created (devcontainer.json, postCreateCommand). Writes the multi-root
# workspace (workspace.sh). When /workspaces/dsbench holds a dsbench checkout (DSBENCH_REPO_DIR in .devcontainer/.env),
# installs it editable with its dev tools into the checkout's own .venv, under its constraints.txt when it has one, and
# links the command as /usr/local/bin/dsbench. Never fails the container: without dsbench everything else works.
repo=/workspaces/dsbench
venv="$repo/.venv"

sh "$(dirname "$0")/workspace.sh" || echo "post-create: the workspace file could not be written"

if [ ! -f "$repo/pyproject.toml" ]; then
    echo "post-create: no dsbench checkout at $repo (set DSBENCH_REPO_DIR in .devcontainer/.env); skipped"
    exit 0
fi

constraints=
[ -f "$repo/constraints.txt" ] && constraints="--constraint $repo/constraints.txt"

if python -m venv "$venv" \
    && "$venv/bin/pip" install --quiet uv \
    && "$venv/bin/uv" pip install --quiet --python "$venv/bin/python" $constraints --editable "$repo[dev]" \
    && sudo ln -sf "$venv/bin/dsbench" /usr/local/bin/dsbench; then
    echo "post-create: dsbench installed from $repo"
else
    echo "post-create: dsbench could not be installed from $repo; the container works without it"
fi
exit 0
