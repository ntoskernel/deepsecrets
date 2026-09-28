"""python -m deepsecrets.diagnostics trace --cases cases.jsonl --out traces.jsonl [--processes N] [--max-file-mb M]

Each input line: {"case_id", "path", "relative_path", "line", "end_line", "start_col", "end_col", "value"}.
Each output line is one trace (see trace.py). Files are traced once however many cases they hold.
"""

import argparse
import json
import sys
from collections import defaultdict
from multiprocessing import get_context

from deepsecrets.config import DEFAULT_DEEP_MAX_SIZE
from deepsecrets.diagnostics.worker import init, trace_job


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='python -m deepsecrets.diagnostics')
    sub = parser.add_subparsers(dest='command', required=True)
    t = sub.add_parser('trace', help='trace labelled spans through the scan pipeline')
    t.add_argument('--cases', required=True)
    t.add_argument('--out', required=True)
    t.add_argument('--processes', type=int, default=1)
    t.add_argument('--max-file-mb', type=float, default=20.0)
    t.add_argument(
        '--no-path-exclusions',
        action='store_true',
        help='replay files the built-in excluded_paths rules would skip, as `--excluded-paths disable` does',
    )
    t.add_argument(
        '--skip-bundles',
        action='store_true',
        help='stop minified files, source maps and bundles at selection, as a scan with `--skip-bundles` does',
    )
    t.add_argument(
        '--deep-max-size',
        type=int,
        default=DEFAULT_DEEP_MAX_SIZE,
        help='replay larger files without the lexer, as a scan with this `--deep-max-size` does (0: every file)',
    )
    args = parser.parse_args(argv)

    by_file = defaultdict(list)
    with open(args.cases, encoding='utf-8') as f:
        for line in f:
            if line.strip():
                case = json.loads(line)
                by_file[(case['path'], case['relative_path'])].append(case)
    max_bytes = int(args.max_file_mb * 1_000_000) if args.max_file_mb else 0
    jobs = [(key, cases, max_bytes) for key, cases in by_file.items()]

    written = 0
    with open(args.out, 'w', encoding='utf-8') as out:
        path_exclusions = not args.no_path_exclusions
        if args.processes > 1:
            with get_context('spawn').Pool(
                args.processes,
                initializer=init,
                initargs=(path_exclusions, args.skip_bundles, args.deep_max_size),
                maxtasksperchild=20,
            ) as pool:
                for traces in pool.imap_unordered(trace_job, jobs):
                    for trace in traces:
                        out.write(json.dumps(trace, default=str) + '\n')
                        written += 1
        else:
            init(path_exclusions, args.skip_bundles, args.deep_max_size)
            for job in jobs:
                for trace in trace_job(job):
                    out.write(json.dumps(trace, default=str) + '\n')
                    written += 1
    print(f'traced {written} cases in {len(jobs)} files', file=sys.stderr)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
