import multiprocessing
import signal


def handle_sigint(signum, frame):
    raise KeyboardInterrupt()


def setup_interrupts():
    signal.signal(signal.SIGINT, handle_sigint)


def setup_interrupts_for_subprocess():
    if multiprocessing.current_process().name == 'MainProcess':
        return

    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except ValueError:
        pass
