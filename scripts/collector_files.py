"""Host file access across the disposable collector bind-mount boundary."""
import json
import os
import re
import stat


def component(name):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name):
        raise ValueError("expected a single bounded filename component")
    return name


def directory_fd(path):
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)


def write(root, name, content, private=False):
    """Create once; never follow, truncate or chmod an existing path."""
    component(name)
    data = content if isinstance(content, str) else json.dumps(content, indent=2) + "\n"
    parent = directory_fd(root)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(data)
            stream.flush()
            # Public fixture configs must be readable by image-specific UIDs.
            os.fchmod(stream.fileno(), 0o600 if private else 0o644)
    finally:
        os.close(parent)
    return root / name


def open_runtime_file(path, mode="rb"):
    """Pin an existing regular log; the mount's parent is host-only.

    Guests can replace a leaf inside their mount, but cannot replace its parent
    entry or any ancestor. NOFOLLOW and handle-based operations avoid following
    a guest-created link even if the leaf changes immediately after opening.
    """
    component(path.name)
    flags = {"rb": os.O_RDONLY, "a": os.O_WRONLY | os.O_APPEND}[mode]
    parent = directory_fd(path.parent)
    try:
        fd = os.open(path.name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("runtime evidence must be a single-link regular file")
        return os.fdopen(fd, mode)
    except BaseException:
        os.close(fd)
        raise


def assert_current_runtime_file(path, stream):
    """Reject stale-descriptor evidence without following the current leaf."""
    component(path.name)
    try:
        parent = directory_fd(path.parent)
        try:
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        finally:
            os.close(parent)
    except OSError as error:
        raise AssertionError("runtime log pathname cannot be verified") from error
    pinned = os.fstat(stream.fileno())
    if any(not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 for info in (current, pinned)):
        raise AssertionError("runtime log was replaced by an unsafe object")
    if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
        raise AssertionError("runtime log pathname was replaced")
