import io

import pytest

from deepsecrets.core.utils.environment import is_ci_environment


class Terminal(io.StringIO):
    def isatty(self):
        return True


@pytest.mark.parametrize(
    'environ, expected',
    [
        ({}, False),
        ({'CI': 'true'}, True),
        ({'CI': '1'}, True),
        ({'CI': 'false'}, False),
        ({'CI': ''}, False),
        ({'GITHUB_ACTIONS': 'true'}, True),
        ({'TF_BUILD': 'True'}, True),
        ({'JENKINS_URL': 'https://ci.example/'}, True),
        ({'GITLAB_CI': 'false'}, False),
    ],
)
def test_ci_variables_on_a_terminal(environ, expected):
    assert is_ci_environment(environ, Terminal()) is expected


def test_output_that_is_not_a_terminal_counts_as_ci():
    assert is_ci_environment({}, io.StringIO()) is True


def test_a_stream_without_isatty_counts_as_ci():
    assert is_ci_environment({}, object()) is True
