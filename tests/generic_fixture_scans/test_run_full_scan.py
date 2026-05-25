from typing import List

import pytest

from deepsecrets.cli import DeepSecretsCliTool


@pytest.fixture(scope='module')
def args():
    return [
        '',
        '--target-dir',
        '/app/tests/fixtures/',
        '--outfile',
        './fdsafad.json',
        '--outformat',
        'dojo-sarif',
        '--benchmarking-mode',
        '--process-count',
        '1',
    ]


def test_everything(args: List[str]) -> None:
    tool = DeepSecretsCliTool(args)
    tool.parse_arguments()
    findings, errors, timings, _ = tool.start()

    detections = [finding.detection for finding in findings]
    assert 'bAicxJVa5uVY7MjDlapthw' in detections
    assert 'nacc6opq' in detections
    assert 'xBfiGBARuoQ9HoLWtw1HwbrkPurCI8v7fO7RJDaZFp7gkBqWxRjQc9WemTVrwu1c' in detections
