"""Pool workers for `python -m deepsecrets.diagnostics`.

They live in an ordinary module because `spawn` children never re-import a package's `__main__.py`, so functions
defined there cannot be found by pool workers.
"""

import os
import traceback

RULESETS = None


def init(path_exclusions: bool = True):
    global RULESETS
    from deepsecrets.diagnostics.trace import Rulesets

    RULESETS = Rulesets.builtin(path_exclusions)


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
