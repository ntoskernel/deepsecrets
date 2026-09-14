import pytest

from deepsecrets import BASE_DIR
from deepsecrets.core.utils.fs import get_abspath, get_relative_path


@pytest.mark.parametrize(
    "path, expected",
    [
        ('/repo/', '/repo'),
        ('/repo//sub/', '/repo/sub'),
        ('/repo', '/repo'),
        ('/', '/'),
        ('tests/fixtures/', f'{BASE_DIR}/tests/fixtures'),
    ],
)
def test_get_abspath_normalizes(path, expected):
    assert get_abspath(path) == expected


@pytest.mark.parametrize(
    "path, base, expected",
    [
        ('/repo/a/b.py', '/repo', 'a/b.py'),
        # base with a trailing slash used to leave the path absolute
        ('/repo/a/b.py', '/repo/', 'a/b.py'),
        # a later occurrence of the base must survive (used to become 'packages/uiindex.js')
        ('/src/packages/ui/src/index.js', '/src', 'packages/ui/src/index.js'),
        ('/w/pkg/w/app.py', '/w', 'pkg/w/app.py'),
        ('/etc/passwd', '/', 'etc/passwd'),
        # oneshot mode has no workdir (used to strip every slash)
        ('/a/b/c.py', '', 'c.py'),
    ],
)
def test_get_relative_path(path, base, expected):
    assert get_relative_path(path, base) == expected
