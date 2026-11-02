"""Runtime-only regression tests; no HOME/CODEX_HOME overrides or credentials."""
from contextlib import ExitStack, redirect_stdout
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('runtime_support', SCRIPTS / 'runtime_support.py')
runtime = importlib.util.module_from_spec(spec); spec.loader.exec_module(runtime)


class TestRuntime(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='.runtime-test-', dir=SCRIPTS)))
        self.stack.enter_context(patch.dict(os.environ, {'XDG_DATA_HOME': str(self.root / 'data')}))
        self.base = runtime.data_root()
        self.stdout = self.stack.enter_context(redirect_stdout(io.StringIO()))

    def old_runtime(self):
        self.base.mkdir(mode=0o700, parents=True, exist_ok=True)
        old = self.base / 'venv'; (old / 'bin').mkdir(parents=True)
        python = old / 'bin/python'; python.write_text('old runtime unchanged'); python.chmod(0o700)
        return python

    def candidate_commands(self, fail=''):
        def execute(command, **kwargs):
            if command[1:3] == ['-m', 'venv']:
                python = Path(command[3]) / 'bin/python'; python.parent.mkdir(); python.write_text('candidate'); python.chmod(0o700)
                return subprocess.CompletedProcess(command, int(fail == 'venv'), '', '')
            if command[1:3] == ['-m', 'pip']:
                return subprocess.CompletedProcess(command, int(fail == 'pip'), '', '')
            raise AssertionError(command)
        return execute

    def test_failed_venv_or_pip_installation_preserves_existing_runtime_and_pointer(self):
        old = self.old_runtime(); self.base.joinpath('current').symlink_to(old.parent.parent)
        for failure in ('venv', 'pip'):
            with self.subTest(failure=failure), patch.object(runtime, 'check_runtime', side_effect=runtime.RuntimeFailure('outdated')), patch.object(runtime.subprocess, 'run', side_effect=self.candidate_commands(failure)):
                with self.assertRaisesRegex(runtime.RuntimeFailure, 'existing runtime was retained'): runtime.install()
            self.assertEqual(old.read_text(), 'old runtime unchanged')
            self.assertEqual(runtime.runtime_python(self.base), old)
            self.assertEqual(list((self.base / 'versions').iterdir()), [])

    def test_candidate_is_published_only_after_validation_and_legacy_is_retained(self):
        old = self.old_runtime()
        with patch.object(runtime, 'check_runtime', side_effect=[runtime.RuntimeFailure('outdated'), {}]), patch.object(runtime.subprocess, 'run', side_effect=self.candidate_commands()) as commands:
            runtime.install()
        active = runtime.runtime_python(self.base)
        self.assertNotEqual(active, old); self.assertEqual(active.read_text(), 'candidate')
        self.assertEqual(old.read_text(), 'old runtime unchanged')
        self.assertEqual(commands.call_args_list[0].args[0][3], str(active.parent.parent))

    def test_pointer_switch_failure_preserves_old_runtime_and_cleans_only_candidate(self):
        old = self.old_runtime()
        with patch.object(runtime, 'check_runtime', side_effect=[runtime.RuntimeFailure('outdated'), {}]), patch.object(runtime.subprocess, 'run', side_effect=self.candidate_commands()), patch.object(runtime.os, 'replace', side_effect=OSError('simulated')):
            with self.assertRaises(OSError): runtime.install()
        self.assertEqual(runtime.runtime_python(self.base), old)
        self.assertEqual(list((self.base / 'versions').iterdir()), [])

    def test_interruption_after_publication_does_not_delete_active_candidate(self):
        old = self.old_runtime(); replace = os.replace
        def interrupt_after_replace(source, target): replace(source, target); raise KeyboardInterrupt()
        with patch.object(runtime, 'check_runtime', side_effect=[runtime.RuntimeFailure('outdated'), {}]), patch.object(runtime.subprocess, 'run', side_effect=self.candidate_commands()), patch.object(runtime.os, 'replace', side_effect=interrupt_after_replace):
            with self.assertRaises(KeyboardInterrupt): runtime.install()
        self.assertTrue(runtime.runtime_python(self.base).is_file()); self.assertEqual(old.read_text(), 'old runtime unchanged')

    def test_concurrent_install_is_rejected_and_healthy_runtime_needs_no_network(self):
        old = self.old_runtime()
        with (self.base / 'install.lock').open('a') as lock, patch.object(runtime.subprocess, 'run') as commands:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(runtime.RuntimeFailure, 'in progress'): runtime.install()
            commands.assert_not_called()
        with patch.object(runtime, 'check_runtime', return_value={}), patch.object(runtime.subprocess, 'run') as commands:
            runtime.install(); commands.assert_not_called()
        self.assertEqual(runtime.runtime_python(self.base), old)

    def test_healthy_775_runtime_is_reused_and_rebuild_requires_explicit_permission_fix(self):
        old = self.old_runtime(); self.base.chmod(0o775)
        with patch.object(runtime, 'check_runtime', return_value={}), patch.object(runtime.subprocess, 'run') as commands:
            runtime.install(); commands.assert_not_called()
        self.assertEqual(self.base.stat().st_mode & 0o777, 0o775)
        with patch.object(runtime, 'check_runtime', side_effect=runtime.RuntimeFailure('outdated')), patch.object(runtime.subprocess, 'run') as commands:
            with self.assertRaisesRegex(runtime.RuntimeFailure, 'chmod 700 --') as caught: runtime.install()
            self.assertIn(shlex.quote(str(self.base)), str(caught.exception)); commands.assert_not_called()
        self.assertEqual(self.base.stat().st_mode & 0o777, 0o775)
        self.assertEqual(old.read_text(), 'old runtime unchanged')

    def test_versions_symlink_or_shared_permissions_are_rejected_without_install_or_cleanup(self):
        old = self.old_runtime(); versions = self.base / 'versions'
        outside = self.root / 'private-versions'; outside.mkdir(mode=0o700); marker = outside / 'keep'; marker.write_text('untouched')
        versions.symlink_to(outside)
        with patch.object(runtime, 'check_runtime', side_effect=runtime.RuntimeFailure('outdated')), patch.object(runtime.subprocess, 'run') as commands:
            with self.assertRaisesRegex(runtime.RuntimeFailure, 'symlinks are refused'): runtime.install()
            commands.assert_not_called()
        self.assertEqual(marker.read_text(), 'untouched'); self.assertEqual(old.read_text(), 'old runtime unchanged')
        versions.unlink(); versions.mkdir(mode=0o700); versions.chmod(0o775)
        with patch.object(runtime, 'check_runtime', side_effect=runtime.RuntimeFailure('outdated')), patch.object(runtime.subprocess, 'run') as commands:
            with self.assertRaisesRegex(runtime.RuntimeFailure, 'versions must be'): runtime.install()
            commands.assert_not_called()
        versions.chmod(0o700); lstat = Path.lstat
        def foreign_owner(path):
            if path == versions: return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=os.getuid() + 1)
            return lstat(path)
        with patch.object(runtime, 'check_runtime', side_effect=runtime.RuntimeFailure('outdated')), patch.object(runtime.subprocess, 'run') as commands, patch.object(Path, 'lstat', foreign_owner):
            with self.assertRaisesRegex(runtime.RuntimeFailure, 'versions must be'): runtime.install()
            commands.assert_not_called()

    def test_symlinked_data_home_ancestor_cannot_cause_active_candidate_cleanup(self):
        old = self.old_runtime(); alias = self.root / 'data-alias'; alias.symlink_to(self.root / 'data')
        with patch.dict(os.environ, {'XDG_DATA_HOME': str(alias)}), patch.object(runtime, 'check_runtime', side_effect=[runtime.RuntimeFailure('outdated'), {}]), patch.object(runtime.subprocess, 'run', side_effect=self.candidate_commands()):
            runtime.install()
            active = runtime.runtime_python(runtime.data_root())
            self.assertTrue(active.is_file()); self.assertEqual(active.read_text(), 'candidate')
            self.assertEqual(active, (self.base / 'current').resolve(strict=True) / 'bin/python')
        self.assertEqual(old.read_text(), 'old runtime unchanged')

    def test_empty_bus_address_discovers_only_private_current_uid_owned_real_socket(self):
        directory = self.root / 'session,private'; directory.mkdir(mode=0o700)
        with socket.socket(socket.AF_UNIX) as endpoint:
            endpoint.bind(str(directory / 'bus'))
            original_lstat = Path.lstat
            def isolated_stat(path):
                if path.is_relative_to(self.root): return original_lstat(path)
                raise FileNotFoundError()
            env = {'DBUS_SESSION_BUS_ADDRESS': '', 'XDG_RUNTIME_DIR': str(directory), 'HOME': 'unchanged', 'CODEX_HOME': 'unchanged'}
            with patch.object(Path, 'lstat', isolated_stat):
                prepared, status = runtime.session_environment(env, platform='linux')
                self.assertEqual(status, 'verified_user_socket_discovered'); self.assertIn('%2C', prepared['DBUS_SESSION_BUS_ADDRESS'])
                self.assertEqual((prepared['HOME'], prepared['CODEX_HOME']), ('unchanged', 'unchanged'))
                directory.chmod(0o777)
                self.assertEqual(runtime.session_environment(env, platform='linux')[1], 'user_session_socket_unavailable')
                directory.chmod(0o700)
                self.assertEqual(runtime.session_environment(env, platform='linux', uid=os.getuid() + 1)[1], 'user_session_socket_unavailable')

    def test_explicit_bus_address_is_preserved_and_symlink_or_regular_file_is_rejected(self):
        explicit = {'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/explicit/not-probed'}
        with patch.object(Path, 'lstat', side_effect=AssertionError('Explicit addresses are not replaced')):
            self.assertEqual(runtime.session_environment(explicit, platform='linux'), (explicit, 'explicit_address_preserved'))
        directory = self.root / 'session'; directory.mkdir(mode=0o700); (directory / 'bus').write_text('not a socket')
        original_lstat = Path.lstat
        def isolated_stat(path):
            if path.is_relative_to(self.root): return original_lstat(path)
            raise FileNotFoundError()
        env = {'DBUS_SESSION_BUS_ADDRESS': '', 'XDG_RUNTIME_DIR': str(directory)}
        with patch.object(Path, 'lstat', isolated_stat):
            self.assertEqual(runtime.session_environment(env, platform='linux')[1], 'user_session_socket_unavailable')
            (directory / 'bus').unlink(); (directory / 'bus').symlink_to('other')
            prepared, status = runtime.session_environment(env, platform='linux')
            self.assertEqual(status, 'user_session_socket_unavailable'); self.assertNotIn('DBUS_SESSION_BUS_ADDRESS', prepared)

    def test_real_offline_install_failure_leaves_no_launchable_partial_environment(self):
        env = dict(os.environ, PIP_NO_INDEX='1', PIP_FIND_LINKS=str(self.root / 'empty-wheels'), PIP_CONFIG_FILE=os.devnull,
                   PIP_DISABLE_PIP_VERSION_CHECK='1', PIP_CACHE_DIR=str(self.root / 'cache'), PYTHONPATH='')
        (self.root / 'empty-wheels').mkdir()
        installed = subprocess.run(['sh', str(SCRIPTS / 'install-runtime.sh')], env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(installed.returncode, 0); self.assertIn('candidate installation failed', installed.stderr)
        self.assertFalse((self.base / 'current').exists()); self.assertEqual(list((self.base / 'versions').iterdir()), [])
        started = subprocess.run(['sh', str(SCRIPTS / 'run-server.sh')], env=env, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(started.returncode, 0); self.assertIn('runtime missing', started.stderr)
        self.assertNotIn('Traceback', started.stderr); self.assertEqual(started.stdout, '')

    def test_doctor_never_calls_password_or_mailbox_apis_and_marks_access_unchecked(self):
        self.old_runtime()
        with patch.object(runtime, 'check_runtime', return_value={'mcp': '1.26.0', 'keyring': '25.7.0'}), patch.object(runtime, 'session_environment', return_value=(dict(os.environ), 'explicit_address_preserved')), patch.object(runtime.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{"supported":true,"backend_type":"simulated"}', '')) as probe:
            self.assertEqual(runtime.doctor(), 0)
        self.assertNotIn('get_password', probe.call_args.args[0][2]); self.assertNotIn('set_password', probe.call_args.args[0][2])
        output = json.loads(self.stdout.getvalue()); self.assertEqual(output['credential_access'], 'not_checked')
        self.assertFalse(output['credentials_read']); self.assertFalse(output['mailbox_access'])

    def test_startup_preflight_failure_never_executes_server(self):
        self.old_runtime()
        with patch.object(runtime, 'check_runtime', side_effect=runtime.RuntimeFailure('Runtime dependencies are missing')), patch.object(runtime.os, 'execve') as execute:
            with self.assertRaisesRegex(runtime.RuntimeFailure, 'dependencies are missing'):
                runtime.run(['not-executed-server.py'])
        execute.assert_not_called()

    def test_relocated_cache_launches_current_runtime_without_changing_home_or_explicit_bus(self):
        package = self.root / 'relocated plugin cache'; (package / 'scripts').mkdir(parents=True)
        for name in ('runtime_support.py', 'run-python.sh', 'run-server.sh'):
            shutil.copy2(SCRIPTS / name, package / 'scripts' / name)
        (package / 'requirements.txt').write_text('mcp==1.26.0\nkeyring==25.7.0\n')
        payload = package / 'skills/netease-mail/scripts/server.py'; payload.parent.mkdir(parents=True)
        payload.write_text('import json,os\nprint(json.dumps({"fixture_server":True,"home_unchanged":os.environ.get("HOME", "<unset>")==os.environ["TEST_EXPECTED_HOME"],"codex_home_unchanged":os.environ.get("CODEX_HOME", "<unset>")==os.environ["TEST_EXPECTED_CODEX_HOME"],"bus_preserved":os.environ["DBUS_SESSION_BUS_ADDRESS"]=="unix:path=/explicit/not-probed"}))\n')
        active = self.base / 'versions/fixture'; (active / 'bin').mkdir(parents=True)
        python = active / 'bin/python'
        python.write_text('#!/bin/sh\nif [ "$1" = "-c" ]; then\n  printf \'%s\\n\' \'{"mcp":"1.26.0","keyring":"25.7.0"}\'\nelse\n  exec ' + shlex.quote(sys.executable) + ' "$@"\nfi\n')
        python.chmod(0o700); (self.base / 'current').symlink_to(active)
        env = dict(os.environ, DBUS_SESSION_BUS_ADDRESS='unix:path=/explicit/not-probed', TEST_EXPECTED_HOME=os.environ.get('HOME', '<unset>'), TEST_EXPECTED_CODEX_HOME=os.environ.get('CODEX_HOME', '<unset>'))
        launched = subprocess.run(['sh', str(package / 'scripts/run-server.sh')], env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(launched.returncode, 0, launched.stderr)
        self.assertEqual(json.loads(launched.stdout), {'fixture_server': True, 'home_unchanged': True, 'codex_home_unchanged': True, 'bus_preserved': True})


if __name__ == '__main__': unittest.main()
