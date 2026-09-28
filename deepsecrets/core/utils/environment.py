import os
import sys
from typing import Mapping, Optional, TextIO

# Set by the CI services that do not also set CI=true.
CI_VARIABLES = (
    'GITHUB_ACTIONS',
    'GITLAB_CI',
    'CIRCLECI',
    'TRAVIS',
    'BUILDKITE',
    'TF_BUILD',  # Azure Pipelines
    'JENKINS_URL',
    'TEAMCITY_VERSION',
    'BITBUCKET_BUILD_NUMBER',
    'CODEBUILD_BUILD_ID',  # AWS CodeBuild
    'DRONE',
    'APPVEYOR',
)
FALSE_VALUES = ('', '0', 'false', 'no', 'off')


def is_ci_environment(environ: Optional[Mapping[str, str]] = None, stream: Optional[TextIO] = None) -> bool:
    """Whether to run without the live terminal UI: inside a CI service, or when the output is not a terminal
    (piped, redirected, or captured by a build log), where live progress bars only add redraw work and noise."""
    environ = os.environ if environ is None else environ
    stream = sys.stdout if stream is None else stream

    if environ.get('CI', '').strip().lower() not in FALSE_VALUES:
        return True
    if any(environ.get(name, '').strip().lower() not in FALSE_VALUES for name in CI_VARIABLES):
        return True

    try:
        return not stream.isatty()
    except (AttributeError, ValueError):  # a replaced or closed stream
        return True
