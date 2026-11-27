"""Supervised managed enrollment/session/heartbeat path; no remote commands."""
import copy
import hashlib
import http.client
import logging
import random
import time
import json
import os
import signal
import ssl
import threading
import urllib.error
import urllib.request
from zog.host_identify import signatures
from zog.host_install.state_contract import StateError, canonical, require
from .daemon import NoRedirect
from .managed import ManagedState
from .managed_transport import Runtime
from .supervisor import Client
from .retry import RetryableTransport, classify


def digest(value): return hashlib.sha256(canonical(value)).hexdigest()


class HTTPS:
    """Bounded TLS-verified requests, fixed caller-selected registry, no redirects."""
    def post(self, url, payload, key, subject, ca):
        require(url.startswith('https://'), 'managed-origin', 'HTTPS required')
        context = ssl.create_default_context(cadata=ca.decode('ascii') if ca is not None else None)
        prepared = signatures.sign(url, canonical(payload), key, subject)
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context), urllib.request.ProxyHandler({}))
        request = urllib.request.Request(prepared.url, data=prepared.body, headers=dict(prepared.headers), method='POST')
        try:
            with opener.open(request, timeout=10) as response:
                require(response.status in (200, 202), 'managed-http-status', 'Unexpected status')
                raw = response.read(65537)
                require(len(raw) <= 65536, 'managed-response-size', 'Oversize response')
                result = json.loads(raw)
                require(type(result) is dict, 'managed-response', 'Object required')
                return result
        except StateError:
            raise
        except ValueError as exc:
            raise StateError('managed-response-invalid', 'Invalid response or redirect') from exc
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            classify(exc)


class Beacon(Runtime):
    """Production entry point. Fixture Runtime remains separate and disabled."""
    def __init__(self, state):
        super().__init__(state)
        self.supervisor = Client(state.context)
        self.preparing = False
        self.initial = None

    def unused_state(self):
        # This profile owns trust/bindings inside its validated journal. Never
        # ignore newer or foreign component state in the reserved directories.
        from zog.host_install.state_inspect import metadata
        home=os.open('host-discover',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.state.context.fd)
        try:
            metadata(home,970,970,0o700)
            for name in ('trust','registries','health'):
                fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=home)
                try:
                    metadata(fd,970,970,0o700)
                    require(os.fstat(fd).st_dev==os.fstat(self.state.context.fd).st_dev and not os.listdir(fd), 'managed-component-state', 'Reserved state requires an explicit migration')
                finally:os.close(fd)
        finally:os.close(home)

    def allow_initial_expected_uuid(self):
        return False

    def open(self, prepare=False):
        require(not prepare, 'managed-prepare-disabled', 'Preparation requires protected supervisor authorization')
        try:
            b = self.state.context.bundle['bootstrap']
            require(len(b['registries']) == 1 and b['registries'][0]['role'] == 'control' and b['registries'][0]['registry_id'] == b['control_authority']['registry_id'], 'managed-profile', 'Initial beacon profile requires exactly one control registry')
            self.initial = self.supervisor.begin()
            self.unused_state()
            self.state._protected_uuid_pending = (self.initial['journal_sha256'] is not None
                                                   or self.allow_initial_expected_uuid())
            self.preparing = self.initial['journal_sha256'] is None
            # The root ledger authorizes the first empty control journal exactly
            # once. Missing or changed state after that is never initialized.
            super().open(self.preparing)
            self.preparing = False
            require(self.initial['binding'] == {k:self.saved[k] for k in ('installation_id','state_volume_id','fingerprint')}, 'supervisor-binding', 'Wrong identity')
            self.supervisor.check(digest(self.saved))
            return self
        except Exception as exc: self.fail(exc)

    def verify_expected_uuid(self):
        expected = self.bootstrap['initialization']['expected_host_uuid']
        if expected is not None:
            row = self.saved['registries'].get(self.bootstrap['control_authority']['registry_id'])
            require(row is not None and row['host_id'] == expected, 'registry-binding-conflict', 'Protected journal does not bind expected UUID')

    def guard(self):
        super().guard()
        self.unused_state()
        if self.saved is not None:
            require(self.journal.read() == self.saved, 'managed-journal-changed', 'Persisted journal changed during run')
            if self.preparing and self.supervisor.digest is None:
                self.supervisor.commit(digest(self.saved))
            self.supervisor.check(digest(self.saved))
            self.verify_expected_uuid()

    def commit(self, value):
        try:
            self.guard()
            self.journal.write(value)
            # Interruption on either side requires explicit root retry; a
            # checkpoint mismatch is never silently adopted or overwritten.
            self.supervisor.commit(digest(value))
            self.saved = copy.deepcopy(value)
            self.guard()
        except Exception as exc: self.fail(exc)

    def fail(self, error):
        self.key = None; self.sessions.clear(); self.state._key = None
        try: self.supervisor.fault()
        except Exception: pass  # An already durable active run still blocks restart.
        self.state.fail(getattr(error, 'code', 'managed-state-fault'))

    def transport_failure(self, error):
        # An outage is not a durable fault. Local health must still pass after
        # the failed request, before retaining this supervised run for retry.
        try: self.guard()
        except Exception as exc: self.fail(exc)
        self.sessions.clear()
        raise error

    def tick(self, transport=None, report=None):
        return super().tick(transport or HTTPS(), report)

    def inspect_command(self, *args, **kwargs):
        raise StateError('managed-control-disabled', 'Beacon profile cannot execute commands')

    def finish(self):
        self.guard(); self.supervisor.finish(); self.close()


class ApprovedBeacon(Beacon):
    """Explicit supervised HTTPS for an independently approved existing Host."""
    def open(self, prepare=False):
        from . import approved_binding
        try:
            self.expected = approved_binding.load(self.state.context.bundle['bootstrap'])
        except Exception as exc:
            self.state.fail(getattr(exc, 'code', 'station-binding-unavailable'))
        return super().open(prepare)

    def allow_initial_expected_uuid(self):
        # The root-installed expectation was checked against bootstrap before begin.
        return True

    def initial_journal(self, binding):
        require(binding['fingerprint'] == self.expected['fingerprint'],
                'station-binding-conflict', 'Retained identity differs from approved Host')
        value = super().initial_journal(binding)
        reg = self.bootstrap['registries'][0]
        value['registries'][reg['registry_id']] = dict(
            origin=reg['origin'], role='control', host_id=self.expected['host_id'],
            public_key=None, previous=None, pending=None)
        return value

    def guard(self):
        from . import approved_binding
        self.state.check()
        require(approved_binding.load(self.state.context.bundle['bootstrap']) == self.expected,
                'station-binding-changed', 'Independent station expectation changed')
        require(self.observation['receipt']['fingerprint'] == self.expected['fingerprint'],
                'station-binding-conflict', 'Consumed identity differs from approved Host')
        if self.saved is not None:
            require(not self.saved['replay'], 'station-binding-conflict',
                    'Command history is outside the approved beacon profile')
            row = self.saved['registries'].get(self.expected['registry_id'])
            require(row is not None and len(self.saved['registries']) == 1
                    and row['host_id'] == self.expected['host_id'],
                    'station-binding-conflict', 'Existing journal lacks the approved Host binding')
            if row['public_key'] is not None:
                self.validate_station_key(self.bootstrap['registries'][0],
                                          signatures.public_key(row['public_key']))
        super().guard()

    def fail(self, error):
        self.verified_binding = None
        return super().fail(error)

    def transport_failure(self, error):
        self.verified_binding = None
        return super().transport_failure(error)

    def validate_station_key(self, reg, key):
        require(reg['registry_id'] == self.expected['registry_id']
                and signatures.fingerprint(key) == self.expected['station_key_id'],
                'station-signer-conflict', 'Session signer differs from independent expectation')

    def registry(self, transport, reg, report):
        self.guard()
        require(self.saved['registries'][reg['registry_id']]['host_id'] == self.expected['host_id'],
                'station-binding-conflict', 'Approved Host binding required')
        result = super().registry(transport, reg, report)
        self.guard()
        session = self.sessions[reg['registry_id']]
        self.verified_binding = {name:session[name] for name in (
            'sub', 'fingerprint', 'installation_id', 'state_volume_id',
            'registry_id', 'boot_id', 'epoch', 'checkpoint', 'exp')}
        self.verified_binding['host_id'] = self.verified_binding.pop('sub')
        self.verified_binding['authority_id'] = self.expected['authority_id']
        self.verified_binding['station_key_id'] = self.expected['station_key_id']
        # No session token, private key, or credential material in diagnostics.
        return result

    def certificate_assignment(self, *args, **kwargs):
        # This profile proves managed admission only. Certificate assignment
        # trust installation and protected credential delivery are separate gates.
        return {'status':'not-requested'}


def wait_checked(runtime, stop, seconds, clock=time.monotonic):
    deadline = clock() + seconds
    while not stop.is_set():
        try: runtime.guard()
        except Exception as exc: runtime.fail(exc)
        remaining = deadline - clock()
        if remaining <= 0: return
        stop.wait(min(5, remaining))


def loop(runtime, stop, once=False):
    failures = 0
    while not stop.is_set():
        try:
            runtime.tick()
            failures = 0
        except RetryableTransport:
            failures += 1
            logging.warning('Managed beacon connectivity unavailable; retaining request for retry')
            if once: return 'retry-pending'
            delay = min(60, 2 ** min(failures, 6)) * random.uniform(0.8, 1.0)
            wait_checked(runtime, stop, delay)
            continue
        if once: break
        wait_checked(runtime, stop, 60)
    return 'managed-beacon-stopped'


def run(once=False, approved=False):
    stop = threading.Event()
    for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, lambda *_:stop.set())
    try:
        with ManagedState() as state:
            runtime = (ApprovedBeacon if approved else Beacon)(state)
            try:
                runtime.open()
                status = loop(runtime, stop, once)
                binding = getattr(runtime, 'verified_binding', None) if approved and once and status == 'managed-beacon-stopped' else None
                runtime.finish()
            finally: runtime.close()
        result = {'status':status, 'remote_control_enabled':False}
        if binding is not None:
            result['verified_binding'] = binding
        return result
    except (StateError, OSError, ValueError) as exc:
        return {'status':'blocked', 'code':getattr(exc,'code','managed-state-fault'), 'remote_control_enabled':False}
