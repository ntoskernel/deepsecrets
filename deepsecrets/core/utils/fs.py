import os
import sys

from deepsecrets import BASE_DIR, MODULE_NAME


def get_abspath(filepath: str) -> str:
    if filepath.startswith('/'):
        return os.path.normpath(filepath)
    else:
        return os.path.normpath(os.path.join(BASE_DIR, filepath))


def get_relative_path(path: str, base: str) -> str:
    # os.path.relpath strips the base as a prefix only; str.replace would also
    # remove any later occurrence of it (/src/a/src/b.py -> ab.py)
    if not base:
        # oneshot mode runs without a workdir
        return os.path.basename(path)
    return os.path.relpath(path, base)


def path_exists(filepath: str) -> bool:
    abs_path = get_abspath(filepath)
    return os.path.exists(abs_path)


def get_path_inside_package(filepath: str) -> str:
    pkg_root = sys.modules[MODULE_NAME].__path__[0]
    return os.path.join(pkg_root, filepath)
