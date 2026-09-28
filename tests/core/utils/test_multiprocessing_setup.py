import os
import subprocess
import sys
from pathlib import Path

from deepsecrets.core.utils.multiprocessing_setup import SOCKET_BELOW_TEMP_DIR, SOCKET_PATH_MAX, default_start_method

# a fresh interpreter: multiprocessing picks its private directory once per process
SCRIPT = '''
from multiprocessing import connection, util
from deepsecrets.core.utils.multiprocessing_setup import pool_context, start_manager
ctx = pool_context('forkserver', [])
manager = start_manager(ctx)
shared = manager.dict({'a': 1})
with ctx.Pool(2) as pool:
    squares = pool.map(abs, [-1, -2, -3])
print(len(util.get_temp_dir()), shared['a'], squares)
manager.shutdown()
'''


def test_default_start_method_is_forkserver_where_available():
    assert default_start_method() == ('forkserver' if sys.platform != 'win32' else 'spawn')


def test_a_long_tmpdir_no_longer_breaks_the_manager_or_the_forkserver(tmp_path: Path):
    # KI-CLI-40: <TMPDIR>/pymp-XXXXXXXX/listener-XXXXXXXX must stay under the socket path limit
    long_dir = tmp_path / ('d' * 60) / ('e' * 60)
    long_dir.mkdir(parents=True)
    assert len(str(long_dir)) + SOCKET_BELOW_TEMP_DIR > SOCKET_PATH_MAX
    env = dict(os.environ, TMPDIR=str(long_dir), PYTHONPATH=os.getcwd())

    broken = subprocess.run(
        [sys.executable, '-c', 'from multiprocessing import Manager; Manager()'],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if sys.version_info < (3, 14):  # 3.14 picks a short directory itself (multiprocessing.util._get_base_temp_dir)
        assert broken.returncode != 0 and 'EOFError' in broken.stderr  # what used to happen to every scan

    fixed = subprocess.run([sys.executable, '-c', SCRIPT], env=env, capture_output=True, text=True, timeout=120)
    assert fixed.returncode == 0, fixed.stderr
    tempdir_length, value, squares = fixed.stdout.split(' ', 2)
    assert int(tempdir_length) + len('/listener-XXXXXXXX') <= SOCKET_PATH_MAX
    assert value == '1' and squares.strip() == '[1, 2, 3]'
