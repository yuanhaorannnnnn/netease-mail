"""Offline setup tests: all keyring access is replaced before main() runs."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import configure

ADDRESS = 'offline-config-test@163.com'
CODE = 'synthetic-client-code-never-a-real-credential'


class MemoryBackend:
    def __init__(self, existing=None, fault=''):
        self.value = existing; self.fault = fault; self.reads = 0; self.writes = 0
    def get_password(self, service, address):
        assert (service, address) == (configure.SERVICE, ADDRESS)
        self.reads += 1
        if self.fault == 'read_error' or (self.fault == 'readback_error' and self.reads > 1):
            raise RuntimeError(CODE)
        return self.value
    def set_password(self, service, address, value):
        assert (service, address) == (configure.SERVICE, ADDRESS)
        self.writes += 1
        if self.fault == 'write_error': raise RuntimeError(CODE)
        if self.fault == 'noop': return
        self.value = 'different-synthetic-value' if self.fault == 'mismatch' else value


SecureBackend = type('Keyring', (MemoryBackend,), {'__module__': 'keyring.backends.SecretService'})


class TestConfigure(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.home = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.config = self.home / '.config/netease-mail/account.json'
        self.stdout = io.StringIO(); self.stderr = io.StringIO()
        self.stack.enter_context(redirect_stdout(self.stdout)); self.stack.enter_context(redirect_stderr(self.stderr))
        self.stack.enter_context(patch.object(configure.Path, 'home', return_value=self.home))
        self.tty = self.stack.enter_context(patch.object(configure.sys.stdin, 'isatty', return_value=True))
        self.input = self.stack.enter_context(patch('builtins.input', return_value=ADDRESS))
        self.password = self.stack.enter_context(patch.object(configure.getpass, 'getpass', return_value=CODE))
        self.select = self.stack.enter_context(patch.object(configure.keyring, 'get_keyring'))
        self.import_module = self.stack.enter_context(patch.object(configure.importlib, 'import_module', return_value=SimpleNamespace(Keyring=SecureBackend)))
        # A global backend switch must not reroute a checked native backend's operations.
        self.stack.enter_context(patch.object(configure.keyring, 'set_password', side_effect=AssertionError('Do not use global dispatcher')))
        self.stack.enter_context(patch.object(configure.keyring, 'get_password', side_effect=AssertionError('Do not use global dispatcher')))

    def seed_account_config(self):
        self.config.parent.mkdir(parents=True)
        self.old_config = b'{"email":"previous-offline-account@163.com"}'
        self.config.write_bytes(self.old_config)

    def assert_failure_is_private(self, expected):
        with self.assertRaisesRegex(SystemExit, expected) as caught:
            configure.main()
        rendered = ''.join(traceback.format_exception(caught.exception)) + self.stdout.getvalue() + self.stderr.getvalue()
        self.assertNotIn(CODE, rendered)
        self.assertNotIn('Account saved.', rendered)
        self.assertEqual(self.config.read_bytes(), self.old_config)

    def test_null_fail_plaintext_unknown_and_chained_backends_are_rejected_before_credentials(self):
        self.seed_account_config()
        for module, name in [('keyring.backends.null', 'Keyring'), ('keyring.backends.fail', 'Keyring'),
                             ('keyrings.alt.file', 'PlaintextKeyring'), ('keyring.backends.chainer', 'ChainerBackend'),
                             ('unreviewed.backend', 'Keyring')]:
            with self.subTest(module=module):
                backend = type(name, (MemoryBackend,), {'__module__': module})()
                self.select.return_value = backend
                self.assert_failure_is_private('supported built-in system keyring')
                self.assertEqual((backend.reads, backend.writes), (0, 0))
        self.input.assert_not_called(); self.password.assert_not_called(); self.import_module.assert_not_called()

    def test_backend_cannot_impersonate_a_native_class_by_name(self):
        self.seed_account_config(); backend = SecureBackend(); self.select.return_value = backend
        self.import_module.return_value = SimpleNamespace(Keyring=object)
        self.assert_failure_is_private('supported built-in system keyring')
        self.assertEqual((backend.reads, backend.writes), (0, 0)); self.password.assert_not_called()

    def test_null_backend_never_creates_an_account_config(self):
        self.select.return_value = type('Keyring', (MemoryBackend,), {'__module__': 'keyring.backends.null'})()
        with self.assertRaisesRegex(SystemExit, 'supported built-in system keyring'):
            configure.main()
        self.assertFalse(self.config.exists()); self.password.assert_not_called()

    def test_backend_selection_exception_does_not_leak_or_touch_config(self):
        self.seed_account_config(); self.select.side_effect = RuntimeError(CODE)
        self.assert_failure_is_private('supported built-in system keyring'); self.password.assert_not_called()

    def test_safe_simulated_secretservice_is_read_back_before_atomic_account_save(self):
        backend = SecureBackend(); self.select.return_value = backend
        configure.main()
        self.assertEqual((backend.reads, backend.writes), (2, 1))
        self.assertEqual(json.loads(self.config.read_text()), {'email': ADDRESS})
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assertIn('Authorization code verified', self.stdout.getvalue())
        self.assertNotIn(CODE, self.stdout.getvalue() + self.stderr.getvalue() + self.config.read_text())

    def test_fake_success_readback_mismatch_and_backend_errors_never_publish_config(self):
        self.seed_account_config()
        for fault in ('noop', 'mismatch', 'read_error', 'write_error', 'readback_error'):
            with self.subTest(fault=fault):
                self.select.return_value = SecureBackend(fault=fault)
                self.assert_failure_is_private('account config was not changed')

    def test_existing_different_credential_is_never_overwritten(self):
        self.seed_account_config(); backend = SecureBackend(existing='previous-synthetic-credential'); self.select.return_value = backend
        self.assert_failure_is_private('different credential already exists')
        self.assertEqual(backend.value, 'previous-synthetic-credential'); self.assertEqual(backend.writes, 0)

    def test_existing_matching_credential_is_reused_without_writing_keyring(self):
        backend = SecureBackend(existing=CODE); self.select.return_value = backend
        configure.main()
        self.assertEqual((backend.reads, backend.writes), (2, 0))
        self.assertEqual(json.loads(self.config.read_text()), {'email': ADDRESS})

    def test_atomic_config_replace_failure_preserves_previous_config_and_hides_error(self):
        self.seed_account_config(); self.select.return_value = SecureBackend()
        with patch.object(configure.os, 'replace', side_effect=OSError(CODE)):
            self.assert_failure_is_private('account config could not be updated')
        self.assertEqual(list(self.config.parent.glob('.account-*')), [])

    def test_noninteractive_and_invalid_input_do_not_touch_keyring_storage(self):
        self.tty.return_value = False
        with self.assertRaisesRegex(SystemExit, 'interactively'): configure.main()
        self.select.assert_not_called()
        self.tty.return_value = True; backend = SecureBackend(); self.select.return_value = backend
        self.input.return_value = 'not-an-address'
        with self.assertRaisesRegex(SystemExit, 'Only 163.com'): configure.main()
        self.input.return_value = ADDRESS; self.password.return_value = ''
        with self.assertRaisesRegex(SystemExit, 'No authorization code'): configure.main()
        self.assertEqual((backend.reads, backend.writes), (0, 0)); self.assertFalse(self.config.exists())


if __name__ == '__main__':
    unittest.main()
