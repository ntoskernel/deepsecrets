"""Imported last by the forkserver, after the scanner's modules: moves everything loaded so far out of the garbage
collector's reach, so a worker forked from the server does not write to those pages while collecting, and they stay
shared with the server instead of being copied into every worker."""

import gc

gc.freeze()
