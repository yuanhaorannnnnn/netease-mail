"""Local runtime management; never reads mailbox credentials or contacts a mailbox."""
from __future__ import annotations
import fcntl
import json
import os
from pathlib import Path
import shutil
import shlex
import stat
import subprocess
import sys
import tempfile
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent


class RuntimeFailure(Exception):
    pass


def data_root():
    path = Path(os.environ.get('XDG_DATA_HOME') or Path.home() / '.local/share')
    if not path.is_absolute(): raise RuntimeFailure('XDG_DATA_HOME must be an absolute path.')
    return path / 'netease-mail'


def runtime_python(base):
    current = base / 'current'
    if current.is_symlink():
        try: runtime = current.resolve(strict=True)
        except OSError: raise RuntimeFailure('Active runtime pointer is invalid; rerun scripts/install-runtime.sh.') from None
    elif current.exists():
        raise RuntimeFailure('Active runtime pointer is not a symlink; installation was not changed.')
    else:
        runtime = (base / 'venv').resolve()
    python = runtime / 'bin/python'
    if not python.is_file() or not os.access(python, os.X_OK):
        raise RuntimeFailure('NetEase Mail runtime missing. Run sh scripts/install-runtime.sh.')
    return python


def check_runtime(python):
    required = dict(line.strip().split('==') for line in (ROOT / 'requirements.txt').read_text().splitlines() if line.strip() and not line.startswith('#'))
    code = ('import importlib.metadata,json,sys; import keyring; from mcp.server.fastmcp import FastMCP; '
            'print(json.dumps({name:importlib.metadata.version(name) for name in json.loads(sys.argv[1])}))')
    try:
        checked = subprocess.run([str(python), '-c', code, json.dumps(required)], capture_output=True, text=True, timeout=30)
        if checked.returncode or json.loads(checked.stdout) != required: raise ValueError()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise RuntimeFailure('Runtime dependencies are missing, incompatible, or failed to import. Run sh scripts/install-runtime.sh; no mailbox connection was attempted.') from None
    return required


def session_environment(environ, platform=sys.platform, uid=None):
    env = dict(environ)
    if env.get('DBUS_SESSION_BUS_ADDRESS'):
        return env, 'explicit_address_preserved'
    if platform != 'linux': return env, 'not_applicable'
    uid = os.getuid() if uid is None else uid
    candidates = []
    if env.get('XDG_RUNTIME_DIR'):
        directory = Path(env['XDG_RUNTIME_DIR'])
        if directory.is_absolute(): candidates.append(directory / 'bus')
    candidates.append(Path('/run/user') / str(uid) / 'bus')
    for path in candidates:
        try:
            parent, endpoint = path.parent.lstat(), path.lstat()
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != uid or parent.st_mode & 0o022 or
                    not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != uid):
                continue
        except OSError:
            continue
        env['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=' + quote(str(path), safe='/')
        return env, 'verified_user_socket_discovered'
    env.pop('DBUS_SESSION_BUS_ADDRESS', None)
    return env, 'user_session_socket_unavailable'


def install():
    base = data_root(); base.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = base.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeFailure('Runtime directory must be a real directory owned by this user; nothing was changed.')
    with (base / 'install.lock').open('a') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeFailure('Another runtime installation is in progress; nothing was changed.') from None
        try:
            check_runtime(runtime_python(base))
        except RuntimeFailure:
            pass
        else:
            print('Existing runtime verified; no dependency installation or restart was needed.')
            return
        if info.st_mode & 0o022:
            raise RuntimeFailure('Runtime directory is group/other-writable. After checking its ACLs, run:\n  chmod 700 -- ' + shlex.quote(str(base)) + '\nExisting runtime was retained; no permissions were changed.')
        versions = base / 'versions'
        try: versions.mkdir(mode=0o700)
        except FileExistsError: pass
        version_info = versions.lstat()
        if not stat.S_ISDIR(version_info.st_mode) or version_info.st_uid != os.getuid() or version_info.st_mode & 0o022:
            raise RuntimeFailure('Runtime versions must be a real, user-owned directory not writable by group/others; symlinks are refused. Existing runtime was retained.')
        candidate = Path(tempfile.mkdtemp(prefix='runtime-', dir=versions.resolve(strict=True))).resolve(strict=True)
        try:
            for command in ([sys.executable, '-m', 'venv', str(candidate)],
                            [str(candidate / 'bin/python'), '-m', 'pip', 'install', '-r', str(ROOT / 'requirements.txt')]):
                completed = subprocess.run(command, capture_output=True, text=True)
                if completed.returncode:
                    raise RuntimeFailure('Runtime candidate installation failed (exit ' + str(completed.returncode) + '); existing runtime was retained. Check Python venv support and dependency/network availability, then rerun installation.')
            check_runtime(candidate / 'bin/python')
            with tempfile.TemporaryDirectory(prefix='.publish-', dir=base) as temporary:
                pointer = Path(temporary) / 'current'; pointer.symlink_to(candidate)
                os.replace(pointer, base / 'current')
            print('Runtime candidate verified and activated. Existing runtime directories and running sessions were not removed or restarted.')
        finally:
            # An interruption after pointer replacement must not remove the newly active runtime.
            try:
                active = (base / 'current').resolve()
                physical_candidate = candidate.resolve(strict=True)
            except (OSError, RuntimeError):
                pass  # Uncertain path identity: retain the candidate rather than risk deleting active code.
            else:
                if active != physical_candidate:
                    shutil.rmtree(physical_candidate)


def run(arguments):
    if not arguments: raise RuntimeFailure('Supply a Python script or arguments to scripts/run-python.sh.')
    python = runtime_python(data_root()); check_runtime(python)
    env, bus = session_environment(os.environ)
    if bus == 'user_session_socket_unavailable':
        print('NetEase Mail: no verified user session D-Bus socket. SecretService may be unavailable; use the same unlocked desktop session or provide a valid explicit DBUS_SESSION_BUS_ADDRESS. No credential was read by the launcher.', file=sys.stderr)
    os.execve(str(python), [str(python), *arguments], env)


def doctor():
    python = runtime_python(data_root()); versions = check_runtime(python)
    env, bus = session_environment(os.environ)
    code = ('import json,sys; sys.path.insert(0,sys.argv[1]); import configure; '
            'backend=configure.secure_backend(); '
            'print(json.dumps({"backend_type":type(backend).__module__+"."+type(backend).__name__,"supported":True}))')
    checked = subprocess.run([str(python), '-c', code, str(ROOT / 'skills/netease-mail/scripts')], env=env, capture_output=True, text=True, timeout=15)
    try: backend = json.loads(checked.stdout) if checked.returncode == 0 else {'supported': False}
    except ValueError: backend = {'supported': False}
    print(json.dumps({'runtime': 'ready', 'dependencies': versions, 'session_bus': bus, 'keyring': backend,
                      'credential_access': 'not_checked', 'credentials_read': False, 'mailbox_access': False}))
    return 0 if backend.get('supported') else 1


def main():
    try:
        if len(sys.argv) < 2: raise RuntimeFailure('Choose install, run, or doctor.')
        if sys.argv[1] == 'install': install()
        elif sys.argv[1] == 'run': run(sys.argv[2:])
        elif sys.argv[1] == 'doctor': return doctor()
        else: raise RuntimeFailure('Unknown runtime command.')
    except (RuntimeFailure, OSError, subprocess.TimeoutExpired):
        error = sys.exc_info()[1]
        print(str(error) if isinstance(error, RuntimeFailure) else 'Runtime operation failed; no success was recorded. Inspect the installation and rerun diagnostics.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
