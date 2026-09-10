# Performance improvements (next release)

Scans are **3 to 5 times faster** end to end, and adding worker processes speeds them up again. Detection output is unchanged: on every corpus we compared, the SARIF report is identical to the previous release's, with the same findings, locations, snippets and fingerprints.

## What changed

- **Progress reporting no longer throttles the whole scan.** Workers reported progress to the parent process twice per token, through a single coordinator process that can handle only about 10,000 updates a second in total. On machines with many cores, workers spent most of their time waiting on it: raising `--process-count` beyond about 8 gave no speedup, and the default of one worker per CPU core was the slowest setting. Progress is now sent at most five times a second per file.
- **Faster tokenization for every file type.** Finding each token's position in the file compiled a new regular expression per token; it is now a plain substring search.
- **Faster rule matching.** Regex and variable-scoring rules now call their precompiled patterns directly instead of going through the module-level `regex` functions, which cost about five times as much per call on short tokens.
- **Shell scripts scale linearly.** The `curl -u` credential check re-scanned everything tokenized so far for every token, so time grew with the square of the script length.
- **Large JSON files scale linearly.** Each detected value was checked against every suppression region in the file; that lookup is now a binary search.
- **Files with many findings.** Every line-number lookup scanned all lines of the file. This made mapping findings, and building the SARIF report after the scan, quadratic on large files.
- **Less work per file.** The compiled rule set used to be serialised and sent to a worker along with every single file; it is now sent once per worker. This matters most for repositories with many small files.

## Measured

One 64-core container. Your absolute numbers will differ, but the ratios should hold.

| Scenario | Before | After |
| --- | ---: | ---: |
| 64 source files, 16 workers | 26.3 s | 5.7 s |
| same, default worker count (64) | 29.5 s | 6.7 s |
| 1,500 small files, 16 workers | 11.3 s | 3.4 s |
| 4,000-line shell script | 20.1 s | 1.0 s |
| 8,000-key flat JSON file | 5.3 s | 0.7 s |
| 40,000-line file with 4,000 findings: mapping + SARIF | 24.6 s | 0.2 s |

## Compatibility

- **No change to findings, confidence, rule ids, SARIF layout or fingerprints.** One case can still look like a difference: when a finding is matched by two rules of equal confidence, which rule is reported depends on Python's per-process string hashing. That was already true in earlier releases.
- **Per-file progress bars update at most five times a second.** Files that finish in under 0.2 s may never show a bar of their own. The overall bar is unaffected.
- **Only for code that embeds DeepSecrets and passes its own `pool_engine`:** the pool is now created with `initializer=` and `initargs=`, as `multiprocessing.Pool` and `multiprocessing.pool.ThreadPool` accept.
- **One dependency fewer.** `dotwiz` is no longer required, and neither is its compiled dependency `pyheck`. The data sent to workers is now a plain standard-library dataclass that carries only what workers use.
