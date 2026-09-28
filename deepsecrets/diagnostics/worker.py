"""Pool workers for `python -m deepsecrets.diagnostics`.

They live in an ordinary module because `spawn` children never re-import a package's `__main__.py`, so functions
defined there cannot be found by pool workers.
"""

import os
import traceback
from typing import Optional

RULESETS = None


def init(path_exclusions: bool = True, skip_bundles: bool = False, deep_max_size: Optional[int] = None):
    global RULESETS
    from deepsecrets.config import DEFAULT_DEEP_MAX_SIZE
    from deepsecrets.diagnostics.trace import Rulesets

    size = DEFAULT_DEEP_MAX_SIZE if deep_max_size is None else deep_max_size
    RULESETS = Rulesets.builtin(path_exclusions, skip_bundles, size)


def trace_job(job):
    (path, relative_path), cases, max_bytes = job
    from deepsecrets.diagnostics.trace import SCHEMA_VERSION, trace_file

    def failed(stage, detail):
        return [
            {
                'schema': SCHEMA_VERSION,
                'case_id': c['case_id'],
                'verdict': {'stage': stage, 'component': 'tracer', 'detail': detail},
            }
            for c in cases
        ]

    try:
        if max_bytes and os.path.getsize(path) > max_bytes:
            return failed('skipped_large', f'{os.path.getsize(path)} bytes')
        return trace_file(path, relative_path, cases, RULESETS)
    except Exception as e:  # one broken file must not lose the others
        return failed('trace_error', f'{type(e).__name__}: {e}\n{traceback.format_exc(limit=3)}')
