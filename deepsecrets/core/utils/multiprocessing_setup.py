"""How the scan starts its processes: the start method, where multiprocessing puts its sockets, and the manager.

multiprocessing creates Unix sockets for the progress manager and for the forkserver at
`<temp dir>/pymp-XXXXXXXX/listener-XXXXXXXX`, 32 characters below the temporary directory. A socket path is at most
107 bytes on Linux and 103 on macOS, so a long `TMPDIR` made every scan die with a bare `EOFError` (KI-CLI-40). The
functions here put multiprocessing's private directory somewhere short instead, before any socket is created.
"""

import contextlib
import os
import sys
import tempfile
import time
from multiprocessing import connection, forkserver, get_all_start_methods, get_context, process, util
from multiprocessing.context import BaseContext
from multiprocessing.managers import SyncManager
from typing import List, Optional

SOCKET_PATH_MAX = 103  # macOS: 104 bytes with the terminating NUL; Linux allows 108
SOCKET_BELOW_TEMP_DIR = len('/pymp-XXXXXXXX/listener-XXXXXXXX')
SOCKET_BELOW_MP_DIR = len('/listener-XXXXXXXX')
SHORT_TEMP_DIRS = ('/tmp', '/var/tmp', '/dev/shm')

# imported by the forkserver before it forks any worker, so every worker shares them instead of importing them again
FREEZE_MODULE = 'deepsecrets.core.utils.gc_freeze'
# how long stop_forkserver waits for the server to exit
FORKSERVER_STOP_SECONDS = 10.0


class TempDirTooLongError(RuntimeError):
    """No directory was found where multiprocessing's socket paths fit."""


def default_start_method() -> str:
    """`forkserver` where the platform has it (Linux, macOS): workers are forked from a server that has already
    imported the scanner, so they share its memory and start faster. `spawn` elsewhere (Windows)."""
    return 'forkserver' if 'forkserver' in get_all_start_methods() else 'spawn'


def ensure_socket_friendly_tempdir() -> Optional[str]:
    """Create multiprocessing's private directory where a socket path inside it fits, and return it.

    Uses `TMPDIR` when it is short enough, else the first of `SHORT_TEMP_DIRS` that is writable. Must run before
    multiprocessing creates its directory, that is before the first manager or forkserver starts. `None` on Windows,
    where multiprocessing uses named pipes."""
    if sys.platform == 'win32':
        return None

    existing = process.current_process()._config.get('tempdir')
    if existing:
        if len(existing) + SOCKET_BELOW_MP_DIR > SOCKET_PATH_MAX:
            raise TempDirTooLongError(_too_long_message(existing))
        return existing

    base = tempfile.gettempdir()
    if len(base) + SOCKET_BELOW_TEMP_DIR <= SOCKET_PATH_MAX:
        return util.get_temp_dir()

    for candidate in SHORT_TEMP_DIRS:
        if len(candidate) + SOCKET_BELOW_TEMP_DIR > SOCKET_PATH_MAX:
            continue
        if not os.path.isdir(candidate) or not os.access(candidate, os.W_OK | os.X_OK):
            continue
        saved = tempfile.tempdir
        tempfile.tempdir = candidate
        try:
            # created once per process and removed at exit by multiprocessing itself
            return util.get_temp_dir()
        finally:
            tempfile.tempdir = saved

    raise TempDirTooLongError(_too_long_message(base))


def _too_long_message(directory: str) -> str:
    limit = SOCKET_PATH_MAX - SOCKET_BELOW_TEMP_DIR
    return (
        f'the temporary directory {directory} is {len(directory)} characters long, and no shorter one is writable; '
        f'multiprocessing needs one of at most {limit} characters for its sockets. Set TMPDIR to a shorter directory'
    )


def pool_context(start_method: str, preload: List[str]) -> BaseContext:
    """The multiprocessing context for the worker pool. For `forkserver`, the server imports `preload` and then
    freezes the garbage collector, so the workers forked from it share those modules' memory."""
    ctx = get_context(start_method)
    if start_method == 'forkserver':
        ensure_socket_friendly_tempdir()
        # takes effect when the server starts, at the first manager or pool of the process
        ctx.set_forkserver_preload(list(preload) + [FREEZE_MODULE])
    return ctx


def stop_forkserver(timeout: float = FORKSERVER_STOP_SECONDS) -> bool:
    """Stop this process's forkserver, if one runs, and wait for it; True when it has exited (or none ran).

    The server reaps the workers it forked, so their CPU time reaches this process only through this wait. Without it
    the server outlives the scan as an orphan, and `time`, or a benchmark harness that waits for the scanner, sees the
    main process alone (KI-CLI-42). Call it when the pool and the manager are gone: every process the server started
    holds the server's alive pipe, so it exits only after the last of them. The wait is bounded for that reason; on
    timeout the server exits later, with its last child. The next pool starts a new server.

    CPython's `ForkServer._stop` would wait without a bound, so this does the same steps with one."""
    server = getattr(forkserver, '_forkserver', None)
    if server is None:
        return True
    if not all(hasattr(server, a) for a in ('_lock', '_forkserver_pid', '_forkserver_alive_fd', '_forkserver_address')):
        return False  # a CPython whose forkserver is built differently: leave it to exit on its own
    with server._lock:
        pid = server._forkserver_pid
        if pid is None:
            return True
        # closing our end of the alive pipe asks the server to exit once no child holds it either
        os.close(server._forkserver_alive_fd)
        server._forkserver_alive_fd = None
        server._forkserver_pid = None
        address, server._forkserver_address = server._forkserver_address, None
        if address and not util.is_abstract_socket_namespace(address):
            with contextlib.suppress(OSError):
                os.unlink(address)
    deadline = time.monotonic() + timeout
    while True:
        try:
            if os.waitpid(pid, os.WNOHANG)[0]:
                return True
        except ChildProcessError:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


def start_manager(ctx: BaseContext) -> SyncManager:
    """What `ctx.Manager()` does, with the socket address chosen here: a spawned or forkserver-started manager
    would otherwise pick its own, under the original `TMPDIR`."""
    address = None
    if sys.platform != 'win32':
        ensure_socket_friendly_tempdir()
        address = connection.arbitrary_address('AF_UNIX')
    manager = SyncManager(address=address, ctx=ctx)
    manager.start()
    return manager
