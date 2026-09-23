"""Diagnostics: explain why a value was or was not reported, in terms of the scanner's own stages.

Nothing in the scanning path imports this package. `trace.trace_file` replays one file through the same components
a scan uses and records every decision, so it changes nothing about what a scan reports.
"""
