"""In-memory cloud credentials. No keychain fallback or caller-side AWS dependency."""
import json
import os
from pathlib import Path
import selectors
import subprocess
import time

LIMIT = 65536
TIMEOUT = 45
REASONS = frozenset(('missing', 'denied', 'identity-expired', 'unavailable',
    'client-unavailable', 'field-unavailable', 'invalid-reference', 'invalid-value',
    'invalid-field', 'unencrypted-parameter', 'value-too-large'))

class CredentialError(RuntimeError):
    pass


def _binary():
    for path in (Path.home() / '.local/bin/zeug-key', Path('/usr/local/bin/zeug-key')):
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    raise CredentialError('client-unavailable')


def resolve(reference, *, env=None, field=None, required=True):
    """Resolve reference, preferring a nonempty explicitly named environment variable.

    required=False returns None only for a missing or denied cloud record.
    All failures contain only a fixed reason, never child diagnostics or values.
    """
    if (not isinstance(reference, str) or not reference or '\0' in reference
            or (env is not None and (not isinstance(env, str) or not env or '\0' in env or '=' in env))
            or (field is not None and (not isinstance(field, str) or not field or '\0' in field))
            or not isinstance(required, bool)):
        raise CredentialError('invalid-arguments')
    if env is not None and os.environ.get(env):
        return os.environ[env]
    read, write = os.pipe()
    process = None
    chunks = {'value': bytearray(), 'error': bytearray()}
    try:
        command = [_binary(), 'read-fd', reference, '--fd', str(write)]
        if field is not None:
            command.extend(['--field', field])
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, pass_fds=(write,))
        os.close(write)
        write = None
        deadline = time.monotonic() + TIMEOUT
        with selectors.DefaultSelector() as selector:
            selector.register(read, selectors.EVENT_READ, 'value')
            selector.register(process.stderr, selectors.EVENT_READ, 'error')
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CredentialError('client-timeout')
                for key, _ in selector.select(remaining):
                    data = os.read(key.fd, 8192)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    chunks[key.data].extend(data)
                    if len(chunks[key.data]) > LIMIT:
                        raise CredentialError('client-output-too-large')
            process.wait(timeout=max(0.001, deadline-time.monotonic()))
        if process.returncode:
            try:
                reason = json.loads(chunks['error'])['reason']
                if reason not in REASONS:
                    reason = 'client-failed'
            except (ValueError, KeyError, TypeError):
                reason = 'client-failed'
            if not required and reason in ('missing', 'denied'):
                return None
            raise CredentialError(reason)
        try:
            value = json.loads(chunks['value'])['value']
        except (ValueError, KeyError, TypeError):
            raise CredentialError('invalid-client-response') from None
        if not isinstance(value, str) or not value or '\0' in value:
            raise CredentialError('invalid-client-response')
        return value
    except subprocess.TimeoutExpired:
        raise CredentialError('client-timeout') from None
    except OSError:
        raise CredentialError('client-unavailable') from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stderr.close()
        os.close(read)
        if write is not None:
            os.close(write)
