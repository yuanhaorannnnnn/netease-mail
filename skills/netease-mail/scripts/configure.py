#!/usr/bin/env python3
"""Interactive local-only account setup. Run in a private host terminal."""
import getpass
import hmac
import importlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import keyring

SERVICE = 'codex-netease-mail'
SYSTEM_BACKENDS = {
    ('keyring.backends.SecretService', 'Keyring'),
    ('keyring.backends.libsecret', 'Keyring'),
    ('keyring.backends.kwallet', 'DBusKeyring'),
    ('keyring.backends.kwallet', 'DBusKeyringKWallet4'),
    ('keyring.backends.macOS', 'Keyring'),
    ('keyring.backends.Windows', 'WinVaultKeyring'),
}


def secure_backend():
    try:
        backend = keyring.get_keyring()
        kind = type(backend)
        identity = (kind.__module__, kind.__name__)
        if identity not in SYSTEM_BACKENDS or getattr(importlib.import_module(identity[0]), identity[1]) is not kind:
            raise ValueError('Unsupported backend')
    except Exception:
        raise SystemExit('Select a supported built-in system keyring (SecretService/libsecret, KWallet, macOS Keychain, or Windows Credential Locker). Null, fallback chains and third-party backends are refused; nothing was saved.') from None
    return backend


def main():
    if not sys.stdin.isatty():
        raise SystemExit('Run interactively in a private local terminal; never pipe or provide credentials through an agent.')
    backend = secure_backend()
    address = input('NetEase email address: ').strip()
    if not re.fullmatch(r'[^\s@<>]+@(163\.com|126\.com|yeah\.net)', address, re.I):
        raise SystemExit('Only 163.com, 126.com and yeah.net personal addresses are supported.')
    secret = getpass.getpass('NetEase client authorization code (not your account password): ')
    if not secret: raise SystemExit('No authorization code entered; nothing saved.')
    stored = None
    try:
        existing = backend.get_password(SERVICE, address)
        if existing is not None:
            if not isinstance(existing, str) or not hmac.compare_digest(existing.encode('utf-8'), secret.encode('utf-8')):
                raise SystemExit('A different credential already exists; nothing was overwritten or saved to account config. Update it deliberately in the system keyring before rerunning setup.')
        else:
            backend.set_password(SERVICE, address, secret)
        stored = backend.get_password(SERVICE, address)
        if not isinstance(stored, str) or not hmac.compare_digest(stored.encode('utf-8'), secret.encode('utf-8')):
            raise SystemExit('System keyring did not confirm the credential write; account config was not changed. Inspect the keyring before retrying.')
    except Exception:
        raise SystemExit('System keyring read or write failed; account config was not changed. Inspect the keyring before retrying.') from None
    finally:
        secret = stored = existing = None
    directory = Path.home() / '.config/netease-mail'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.account-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump({'email': address}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, directory / 'account.json')
    except OSError:
        raise SystemExit('Credential was verified, but account config could not be updated; no success was recorded.') from None
    finally:
        try:
            if os.path.exists(tmp): os.unlink(tmp)
        except OSError:
            pass
    print('Account saved. Authorization code verified in system keyring. Connection is not yet verified.')

if __name__ == '__main__': main()
