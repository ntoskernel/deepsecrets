# AGENTS.md

Instructions for AI coding agents working on DeepSecrets, an offline secrets scanner.

**The maintainers' guide.** The full agent guide and its reference documents live in a private repository, cloned at
`docs/private/` (git-ignored here). If `docs/private/guide/AGENTS.md` exists, read it now and follow it: it is the
canonical guide and takes precedence over this file. If it does not exist, you are not expected to have it, and the
basics below are enough to work on the code.

Maintainers with access set it up once, from the repository root:

```bash
git clone git@github.com:ntoskernel/deepsecrets-agent-docs.git docs/private && sh docs/private/install.sh
```

## Basics

- Run everything as a module from the repository root: `python -m deepsecrets --target-dir <dir> --outfile <file>` and
  `python -m pytest -q`. `BASE_DIR` is the working directory captured at import, so the tests assume the root.
- Python 3.11 or later. CI runs the suite on 3.11 to 3.14 with the versions `poetry.lock` pins
  (`poetry install --no-root --with test,dev`).
- Format with `black --target-version py313 deepsecrets tests --exclude tests/fixtures` (line length 120, quotes kept).
  Do not reformat files you did not otherwise change.
- `tests/fixtures/` is test data that counts are pinned to: editing a fixture moves them, and `tests/fixtures/4.go` is
  byte-exact reference data.
- Tune detection in the rule files under `deepsecrets/rules/` before changing Python.
- Regexes use the third-party `regex` module (`import regex as re`).
- Some oddities are load-bearing: the misspelled `deepsecrets/core/model/rules/exlcuded_path.py` and the imports at the
  bottom of a few modules break the package if "fixed".
- Anything passed to or returned from worker processes must be picklable, and processes start only through
  `deepsecrets/core/utils/multiprocessing_setup.py`.
- Write scan reports outside the repository, and never commit one.
