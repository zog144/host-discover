"""Root-owned durable beacon-run supervision. No key access or controller dispatch."""
import argparse
import copy
import fcntl
import hashlib
import json
import os
import secrets
import socket
import stat
import uuid
from contextlib import contextmanager
from zog.host_install import state_admission as wire
from zog.host_install.state_contract import CONFIG, StateError, canonical, decode, fields, header, require, sha
from zog.host_install.state_inspect import inspect_live, metadata, directory, read_at
from zog.host_install.state_io import ensure_directory, publish, raw, lock as state_lock

NAME = 'host-discover-supervisor'
SOCKET = '/run/host-discover-supervisor/beacon.sock'

AUTHORITY_NAME = 'host-discover-certificate-authority'
AUTHORITY_FILE = 'authority.json'
AUTHORITY_PIN_FILE = 'certificate-assignment-authority.json'
AUTHORITY_PIN_KIND = 'zog-certificate-assignment-authority-pin'
AUTHORITY_SCHEMA = 'zog-host-discover-certificate-authority-observation-v1'
_AUTHORITY_MAX_OPERATIONS = 128


def identifier(value):
    require(type(value) is str and str(uuid.UUID(value)) == value, 'supervisor-id', 'Canonical UUID required')
    return value


def fixed(context, observation):
    b = context.bundle['bootstrap']
    return dict(installation_id=b['installation_id'], state_volume_id=b['state']['state_volume_id'],
                fingerprint=observation['receipt']['fingerprint'])


def _authority_pin():
    """Read the separately installed root-owned command-center assignment key."""
    from zog.host_identify import signatures
    fd = directory(CONFIG)
    try:
        info = os.fstat(fd)
        require(
            info.st_uid == 0 and info.st_gid == 0 and not info.st_mode & 0o022,
            'certificate-authority-pin-owner',
            'Host-install configuration ancestry must remain root-owned',
        )
        value = decode(read_at(fd, AUTHORITY_PIN_FILE, 0, 0, 0o444))
    finally:
        os.close(fd)
    fields(value, 'schema kind registry_id authority_public_key authority_key_id')
    require(
        value['schema'] == 1 and type(value['schema']) is int
        and value['kind'] == AUTHORITY_PIN_KIND
        and type(value['registry_id']) is str
        and 1 <= len(value['registry_id']) <= 64,
        'certificate-authority-pin',
        'Invalid assignment authority pin',
    )
    try:
        key = signatures.public_key(value['authority_public_key'])
    except (TypeError, ValueError) as exc:
        raise StateError(
            'certificate-authority-pin',
            'Invalid assignment authority public key',
        ) from exc
    require(
        signatures.fingerprint(key) == value['authority_key_id'],
        'certificate-authority-pin',
        'Assignment authority key fingerprint mismatch',
    )
    return value, key


def authority_validate(value):
    """Validate the self-contained root-owned managed authority observation."""
    from zog.host_identify import signatures
    from .certificate_assignment import assignment_digest, validate_envelope

    fields(
        value,
        'schema origin verified_by host_id installation_id state_volume_id '
        'registry_id authority_public_key authority_key_id revision operation_id '
        'assignment_sha256 operations envelope',
    )
    require(
        value['schema'] == AUTHORITY_SCHEMA
        and value['origin'] == 'managed'
        and value['verified_by'] == 'signed-host-discover',
        'certificate-authority-record',
        'Unsupported authority observation',
    )
    identifier(value['host_id'])
    identifier(value['installation_id'])
    identifier(value['state_volume_id'])
    identifier(value['operation_id'])
    sha(value['authority_key_id'])
    sha(value['assignment_sha256'])
    require(
        type(value['registry_id']) is str and 1 <= len(value['registry_id']) <= 64
        and type(value['revision']) is int and 1 <= value['revision'] < 2**53,
        'certificate-authority-record',
        'Invalid authority identity or revision',
    )
    try:
        key = signatures.public_key(value['authority_public_key'])
    except (TypeError, ValueError) as exc:
        raise StateError(
            'certificate-authority-record',
            'Invalid retained authority key',
        ) from exc
    require(
        signatures.fingerprint(key) == value['authority_key_id'],
        'certificate-authority-record',
        'Retained authority key fingerprint mismatch',
    )
    try:
        assignment = validate_envelope(
            value['envelope'],
            key,
            expected_host=value['host_id'],
            expected_installation=value['installation_id'],
        )
    except ValueError as exc:
        raise StateError(
            'certificate-authority-record',
            'Retained assignment signature is invalid',
        ) from exc
    require(
        assignment['revision'] == value['revision']
        and assignment['operation_id'] == value['operation_id']
        and assignment_digest(assignment) == value['assignment_sha256'],
        'certificate-authority-record',
        'Retained assignment binding mismatch',
    )
    operations = value['operations']
    require(
        type(operations) is list and 1 <= len(operations) <= _AUTHORITY_MAX_OPERATIONS,
        'certificate-authority-record',
        'Invalid root operation history',
    )
    seen = set()
    current = None
    for row in operations:
        fields(row, 'operation_id assignment_sha256')
        identifier(row['operation_id'])
        sha(row['assignment_sha256'])
        require(
            row['operation_id'] not in seen,
            'certificate-authority-record',
            'Duplicate root operation binding',
        )
        seen.add(row['operation_id'])
        if row['operation_id'] == value['operation_id']:
            current = row
    require(
        current is not None
        and current['assignment_sha256'] == value['assignment_sha256'],
        'certificate-authority-record',
        'Current operation is not root-checkpointed',
    )
    return value


def _authority_read(fd):
    names = set(os.listdir(fd))
    require(
        names <= {'lock', AUTHORITY_FILE},
        'certificate-authority-incomplete',
        'Interrupted or unknown authority publication requires reconciliation',
    )
    data = raw(fd, AUTHORITY_FILE, 0, 0, 0o600)
    if data is None:
        return None
    return authority_validate(decode(data))


def _authority_replace(fd, value):
    """Durable replacement; an interrupted marker blocks automatic adoption."""
    data = canonical(value)
    require(
        len(data) <= 65536,
        'certificate-authority-capacity',
        'Authority observation exceeds capacity',
    )
    require(
        set(os.listdir(fd)) <= {'lock', AUTHORITY_FILE},
        'certificate-authority-incomplete',
        'Authority publication already incomplete',
    )
    pending = 'authority.pending'
    next_name = 'authority.next'
    out = os.open(
        pending,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=fd,
    )
    try:
        os.fchmod(out, 0o600)
        view = memoryview(data)
        while view:
            count = os.write(out, view)
            require(
                count > 0,
                'state-io-failure',
                'Short authority observation write',
            )
            view = view[count:]
        os.fsync(out)
    finally:
        os.close(out)
    os.fsync(fd)
    os.link(
        pending,
        next_name,
        src_dir_fd=fd,
        dst_dir_fd=fd,
        follow_symlinks=False,
    )
    os.replace(next_name, AUTHORITY_FILE, src_dir_fd=fd, dst_dir_fd=fd)
    os.fsync(fd)
    os.unlink(pending, dir_fd=fd)
    os.fsync(fd)


def _authority_next(previous, state, pin):
    from .certificate_assignment import assignment_digest

    assignment = state['envelope']['assignment']
    digest = assignment_digest(assignment)
    operation = assignment['operation_id']
    revision = assignment['revision']
    if previous is not None:
        authority_validate(previous)
        for key, wanted in (
            ('host_id', assignment['host_id']),
            ('installation_id', assignment['installation_id']),
            ('state_volume_id', state['installation_state_volume_id']),
            ('registry_id', pin['registry_id']),
            ('authority_key_id', pin['authority_key_id']),
        ):
            require(
                previous[key] == wanted,
                'certificate-authority-conflict',
                'Authority identity changed',
            )
        if revision < previous['revision']:
            raise StateError(
                'certificate-authority-stale',
                'Signed assignment rolled back below root checkpoint',
            )
        if revision == previous['revision']:
            require(
                operation == previous['operation_id']
                and digest == previous['assignment_sha256'],
                'certificate-authority-conflict',
                'Same authority revision changed contents',
            )
            return previous, False
        history = {
            row['operation_id']: row['assignment_sha256']
            for row in previous['operations']
        }
        require(
            operation not in history,
            'certificate-authority-operation-replayed',
            'Authority operation ID was already root-checkpointed',
        )
        require(
            len(previous['operations']) < _AUTHORITY_MAX_OPERATIONS,
            'certificate-authority-history-full',
            'Root authority operation history is full',
        )
        operations = list(previous['operations'])
    else:
        operations = []
    operations.append({
        'operation_id': operation,
        'assignment_sha256': digest,
    })
    result = {
        'schema': AUTHORITY_SCHEMA,
        'origin': 'managed',
        'verified_by': 'signed-host-discover',
        'host_id': assignment['host_id'],
        'installation_id': assignment['installation_id'],
        'state_volume_id': state['installation_state_volume_id'],
        'registry_id': pin['registry_id'],
        'authority_public_key': pin['authority_public_key'],
        'authority_key_id': pin['authority_key_id'],
        'revision': revision,
        'operation_id': operation,
        'assignment_sha256': digest,
        'operations': operations,
        'envelope': state['envelope'],
    }
    authority_validate(result)
    return result, True


def checkpoint_authority(context, supervisor_value):
    """Root independently verifies and checkpoints the service-owned assignment."""
    from zog.host_identify import signatures
    from . import admission
    from .certificate_assignment import managed_read_state

    require(
        os.geteuid() == 0,
        'root-required',
        'Certificate authority checkpoint is root-owned',
    )
    require(
        supervisor_value['journal_sha256'] is not None,
        'certificate-authority-journal',
        'Managed journal has not been root-checkpointed',
    )
    b = context.bundle['bootstrap']
    pin, authority_key = _authority_pin()
    registry_id = b['control_authority']['registry_id']
    require(
        pin['registry_id'] == registry_id,
        'certificate-authority-pin',
        'Authority pin belongs to a different control registry',
    )
    configured = next(
        (row for row in b['registries'] if row['registry_id'] == registry_id),
        None,
    )
    require(
        configured is not None and configured['role'] == 'control',
        'certificate-authority-registry',
        'Pinned registry is not the control registry',
    )

    journal = admission.Journal(context)
    authority_fd = None
    try:
        saved = journal.read()
        require(
            hashlib.sha256(canonical(saved)).hexdigest()
            == supervisor_value['journal_sha256'],
            'certificate-authority-journal',
            'Managed journal differs from root checkpoint',
        )
        require(
            all(
                saved[key] == supervisor_value['binding'][key]
                for key in ('installation_id', 'state_volume_id', 'fingerprint')
            ),
            'certificate-authority-binding',
            'Managed journal identity differs from root supervisor binding',
        )
        row = saved['registries'].get(registry_id)
        require(
            row is not None
            and row['origin'] == configured['origin']
            and row['role'] == 'control'
            and row['host_id'] is not None
            and row['public_key'] is not None
            and row['pending'] is None,
            'certificate-authority-registry',
            'Control registry trust is incomplete or changed',
        )
        expected = b['initialization']['expected_host_uuid']
        require(
            expected is None or row['host_id'] == expected,
            'certificate-authority-binding',
            'Control registry host binding differs from installer identity',
        )
        require(
            row['public_key'] == pin['authority_public_key']
            and signatures.fingerprint(authority_key) != saved['fingerprint'],
            'certificate-authority-pin',
            'Managed registry signing key differs from root-owned authority pin',
        )
        state = managed_read_state(
            journal.fd,
            authority_key,
            expected_host=row['host_id'],
            expected_installation=saved['installation_id'],
            expected_uid=970,
        )
        require(
            state is not None,
            'certificate-authority-unavailable',
            'No signed managed certificate assignment is retained',
        )
        # The extra value is internal only; it is never persisted as part of
        # the service-owned state and binds the root record to this STATE volume.
        state = dict(state)
        state['installation_state_volume_id'] = saved['state_volume_id']

        authority_fd = ensure_directory(
            context.fd,
            AUTHORITY_NAME,
            0,
            0,
            0o700,
        )
        with state_lock(authority_fd, 'lock'):
            previous = _authority_read(authority_fd)
            result, changed = _authority_next(previous, state, pin)
            if changed:
                _authority_replace(authority_fd, result)
        context.recheck()
        return result
    finally:
        if authority_fd is not None:
            os.close(authority_fd)
        journal.close()


def inspect_authority(context):
    """Return the protected root observation; never synthesize missing authority."""
    require(os.geteuid() == 0, 'root-required', 'Root authority inspection only')
    fd = os.open(
        AUTHORITY_NAME,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=context.fd,
    )
    try:
        metadata(fd, 0, 0, 0o700)
        require(
            os.fstat(fd).st_dev == os.fstat(context.fd).st_dev,
            'nested-mount',
            AUTHORITY_NAME,
        )
        with state_lock(fd, 'lock'):
            value = _authority_read(fd)
            require(
                value is not None,
                'certificate-authority-unavailable',
                'No root-owned authority observation is installed',
            )
            context.recheck()
            return value
    finally:
        os.close(fd)


@contextmanager
def ledger(context, recovery=False):
    context.recheck()
    fd = os.open(NAME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=context.fd)
    handle = None
    try:
        metadata(fd, 0, 0, 0o700)
        require(os.fstat(fd).st_dev == os.fstat(context.fd).st_dev, 'nested-mount', NAME)
        handle = os.open('lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        metadata(handle, 0, 0, 0o600, False)
        try: fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise StateError('supervisor-busy', 'Another supervisor transaction is active') from None
        require({'lock','ledger.json'} <= set(os.listdir(fd)) and set(os.listdir(fd)) <= ({'lock','ledger.json','last-recovery.json','recovery.json','recovery.stage','ledger.recovery'} if recovery else {'lock','ledger.json','last-recovery.json'}), 'supervisor-incomplete', 'Interrupted or unknown publication requires offline reconciliation')
        value = decode(read_at(fd, 'ledger.json', 0, 0, 0o600))
        header(value, 'zog-beacon-supervisor', 'binding revision run fault journal_sha256 reset')
        require(type(value['revision']) is int and value['revision'] >= 0, 'supervisor-schema', 'revision')
        if value['journal_sha256'] is not None: sha(value['journal_sha256'])
        if value['run'] is not None:
            fields(value['run'], 'id bindings'); identifier(value['run']['id'])
        if value['fault'] is not None:
            fields(value['fault'], 'id code'); identifier(value['fault']['id'])
        yield fd, value
        context.recheck()
    finally:
        if handle is not None: os.close(handle)
        os.close(fd)


def replace(fd, value):
    """Pending survives every uncertain write; no daemon repairs it."""
    data = canonical(value)
    require(len(data) <= 65536, 'supervisor-size', 'ledger too large')
    f = os.open('pending.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        view = memoryview(data)
        while view:
            count = os.write(f, view)
            require(count > 0, 'state-io-failure', 'Short write')
            view = view[count:]
        os.fsync(f)
    finally: os.close(f)
    os.fsync(fd)
    os.link('pending.json', 'next.json', src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
    os.replace('next.json', 'ledger.json', src_dir_fd=fd, dst_dir_fd=fd)
    os.fsync(fd)
    os.unlink('pending.json', dir_fd=fd); os.fsync(fd)


def prepare(context, volume):
    require(os.geteuid() == 0, 'root-required', 'Root provisioning only')
    observation = wire.observe(context)
    require(not observation['recovery_hold'], 'recovery-required', 'Installer hold')
    require(volume == context.bundle['bootstrap']['state']['state_volume_id'], 'volume-confirmation', 'Explicit STATE ID required')
    fd = ensure_directory(context.fd, NAME, 0, 0, 0o700)
    try:
        # Existing initialized state is never reset by repeating preparation.
        with __import__('zog.host_install.state_io', fromlist=['lock']).lock(fd, 'lock'):
            require(set(os.listdir(fd)) <= {'lock', 'ledger.json', '.pending.ledger.json'}, 'supervisor-conflict', 'Unexpected files')
            value = dict(schema=1, kind='zog-beacon-supervisor', binding=fixed(context, observation),
                         revision=0, run=None, fault=None, journal_sha256=None, reset=None)
            publish(fd, 'ledger.json', canonical(value))
    finally: os.close(fd)
    context.recheck()
    return {'status': 'supervisor-prepared', 'transport_enabled': False}


@contextmanager
def stopped_consumer(context):
    home = os.open('host-discover', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=context.fd)
    control = handle = None
    try:
        metadata(home, 970, 970, 0o700)
        control = os.open('control', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home)
        metadata(control, 970, 970, 0o700)
        require(os.fstat(control).st_dev == os.fstat(context.fd).st_dev, 'nested-mount', 'control')
        try: handle = os.open('managed.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=control)
        except FileNotFoundError:
            require(not os.listdir(control), 'managed-state-incomplete', 'Missing lock in nonempty journal')
        if handle is not None:
            metadata(handle, 970, 970, 0o600, False)
            try: fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise StateError('managed-busy', 'Stop consumer before reset') from None
        yield
    finally:
        for fd in (handle, control, home):
            if fd is not None: os.close(fd)


def reset(context, revision, run_id, reason):
    """Root-only compare-and-set retry authorization, never trust/journal repair."""
    require(os.geteuid() == 0, 'root-required', 'Root reset only')
    require(type(reason) is str and 1 <= len(reason) <= 256 and all(ord(c) >= 32 for c in reason), 'reset-reason', 'Bounded reason required')
    observation = wire.observe(context)
    require(not observation['recovery_hold'], 'recovery-required', 'Installer hold must be reconciled separately')
    with stopped_consumer(context), ledger(context) as (fd, value):
        require(value['binding'] == fixed(context, observation), 'supervisor-binding', 'Identity binding changed')
        require(value['revision'] == revision and value['run'] is not None and value['run']['id'] == run_id,
                'reset-conflict', 'Inspect exact revision and run before authorizing retry')
        value['reset'] = dict(id=str(uuid.uuid4()), run_id=run_id, reason=reason)
        value['run'] = None; value['fault'] = None; value['revision'] += 1
        replace(fd, value)
    return {'status': 'retry-authorized', 'revision': value['revision'], 'transport_enabled': False}


def action(context, request):
    fields(request, 'schema kind nonce action run_id bindings journal_sha256 code')
    require(request['schema'] == 1 and type(request['schema']) is int and request['kind'] == 'zog-beacon-supervisor-request', 'supervisor-request', 'Unsupported protocol')
    sha(request['nonce']); identifier(request['run_id'])
    require(request['action'] in ('begin', 'check', 'commit', 'certificate-authority', 'finish', 'fault'), 'supervisor-action', 'Unsupported action')
    require(request['code'] in (None, 'managed-state-fault', 'managed-transport-fault'), 'supervisor-code', 'No free-form error text')
    require((request['action'] == 'fault') == (request['code'] is not None), 'supervisor-code', 'Fault code only on fault')
    if request['journal_sha256'] is not None: sha(request['journal_sha256'])
    # Fault recording does not require a healthy installer ledger. The actual
    # STATE mount and run/configuration binding still must be verified.
    require(request['bindings'] == wire.bindings(context), 'supervisor-binding', 'Wrong boot/configuration/volume')
    observation = None if request['action'] == 'fault' else wire.observe(context)
    if observation is not None: require(not observation['recovery_hold'], 'recovery-required', 'Installer hold')
    with ledger(context) as (fd, original):
        value = copy.deepcopy(original)
        if observation is not None:
            require(value['binding'] == fixed(context, observation), 'supervisor-binding', 'Identity binding changed')
        run = dict(id=request['run_id'], bindings=request['bindings'])
        if request['action'] == 'begin':
            require(value['run'] is None and value['fault'] is None, 'supervisor-recovery-required', 'Previous run did not finish cleanly')
            value['run'] = run
        else:
            require(value['run'] == run, 'supervisor-run', 'Different run or boot/configuration')
            if request['action'] == 'fault':
                value['fault'] = value['fault'] or dict(id=str(uuid.uuid4()), code=request['code'])
            else:
                require(value['fault'] is None, 'supervisor-recovery-required', 'Fault is latched')
                if request['action'] in ('check', 'certificate-authority', 'finish'):
                    require(request['journal_sha256'] == value['journal_sha256'], 'supervisor-journal-conflict', 'Journal differs from protected checkpoint')
                if request['action'] == 'commit':
                    require(request['journal_sha256'] is not None, 'supervisor-journal-conflict', 'Cannot clear journal checkpoint')
                    value['journal_sha256'] = request['journal_sha256']
                if request['action'] == 'certificate-authority':
                    checkpoint_authority(context, value)
                if request['action'] == 'finish': value['run'] = None
        if request['action'] not in ('check', 'certificate-authority'):
            value['revision'] += 1; replace(fd, value)
        return dict(binding=value['binding'], revision=value['revision'], journal_sha256=value['journal_sha256'],
                    run_id=request['run_id'], transport_enabled=False, control_authorized=False)


def serve_connection(connection):
    require(os.geteuid() == 0, 'root-required', 'Root service only')
    require(connection.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == socket.AF_UNIX, 'supervisor-socket', 'Local socket required')
    connection.settimeout(wire.TIMEOUT)
    require(wire.peer_uid(connection) == 970, 'supervisor-peer', 'UID970 required')
    request = wire.receive(connection, 8192)
    nonce = request.get('nonce') if type(request) is dict else None
    sha(nonce)
    response = dict(schema=1, kind='zog-beacon-supervisor-response', nonce=nonce)
    try:
        with inspect_live() as context: result = action(context, request)
        response.update(ok=True, result=result)
    except (StateError, OSError, ValueError, KeyError, TypeError) as exc:
        response.update(ok=False, code=getattr(exc, 'code', 'supervisor-unavailable'))
    connection.sendall(canonical(response))


def serve():
    with socket.fromfd(0, socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        serve_connection(connection)


def validate_response(response, nonce, run_id):
    require(type(response) is dict and type(response.get('ok')) is bool, 'supervisor-response', 'Invalid response')
    header(response, 'zog-beacon-supervisor-response', 'nonce ok ' + ('result' if response['ok'] else 'code'))
    require(response['nonce'] == nonce, 'supervisor-nonce', 'Wrong request')
    require(response['ok'], 'supervisor-refused', 'Protected supervisor refused operation')
    result = response['result']
    fields(result, 'binding revision journal_sha256 run_id transport_enabled control_authorized')
    fields(result['binding'], 'installation_id state_volume_id fingerprint')
    identifier(result['binding']['installation_id']); identifier(result['binding']['state_volume_id']); sha(result['binding']['fingerprint'])
    require(type(result['revision']) is int and result['revision'] >= 0, 'supervisor-response', 'Invalid revision')
    if result['journal_sha256'] is not None: sha(result['journal_sha256'])
    require(result['run_id'] == run_id and result['transport_enabled'] is False and result['control_authorized'] is False, 'supervisor-response', 'Invalid capabilities/run')
    return result


class Client:
    def __init__(self, context):
        self.context = context; self.run_id = str(uuid.uuid4()); self.digest = None; self.started = False

    def call(self, action_name, digest=None, code=None):
        require(os.geteuid() == 970 and os.getegid() == 970, 'supervisor-account', 'UID/GID970 required')
        self.context.recheck()
        nonce = secrets.token_hex(32)
        request = dict(schema=1, kind='zog-beacon-supervisor-request', nonce=nonce, action=action_name,
                       run_id=self.run_id, bindings=wire.bindings(self.context), journal_sha256=digest, code=code)
        parent = directory('/run/host-discover-supervisor')
        try:
            metadata(parent, 0, 0, 0o755)
            s = os.stat('beacon.sock', dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISSOCK(s.st_mode) and (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (0, 970, 0o660), 'supervisor-socket', 'Wrong socket permissions')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
                c.settimeout(wire.TIMEOUT); c.connect(f'/proc/self/fd/{parent}/beacon.sock')
                require(wire.peer_uid(c) == 0, 'supervisor-peer', 'Root server required')
                c.sendall(canonical(request)); c.shutdown(socket.SHUT_WR)
                response = wire.receive(c, 8192)
        finally: os.close(parent)
        result = validate_response(response, nonce, self.run_id)
        self.context.recheck()
        return result

    def begin(self):
        # Set before sending: a lost reply must leave the durable run blocked.
        self.started = True
        result = self.call('begin'); self.digest = result['journal_sha256']; return result

    def check(self, digest): return self.call('check', digest)
    def commit(self, digest):
        result = self.call('commit', digest)
        require(result['journal_sha256'] == digest, 'supervisor-response', 'Checkpoint mismatch')
        self.digest = digest
    def certificate_authority(self, digest):
        result = self.call('certificate-authority', digest)
        require(result['journal_sha256'] == digest, 'supervisor-response', 'Authority checkpoint used a different journal')
        return result
    def finish(self): self.call('finish', self.digest); self.started = False
    def fault(self):
        if self.started: self.call('fault', self.digest, 'managed-state-fault')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('serve')
    sub.add_parser('serve-listen')
    p = sub.add_parser('prepare'); p.add_argument('--state-volume-id', required=True)
    sub.add_parser('inspect')
    sub.add_parser('authority-inspect')
    p = sub.add_parser('reset'); p.add_argument('--revision', type=int, required=True); p.add_argument('--run-id', required=True); p.add_argument('--reason', required=True)
    a = parser.parse_args()
    try:
        require(os.geteuid() == 0, 'root-required', 'Root administrator/service required')
        if a.command == 'serve': serve(); return
        if a.command == 'serve-listen': wire.serve_listener(serve_connection); return
        with inspect_live() as context:
            if a.command == 'prepare': result = prepare(context, a.state_volume_id)
            elif a.command == 'reset': result = reset(context, a.revision, a.run_id, a.reason)
            elif a.command == 'authority-inspect': result = inspect_authority(context)
            else:
                with ledger(context) as (_, value): result = value
        print(json.dumps(result, sort_keys=True))
    except (StateError, OSError, ValueError) as exc:
        print(json.dumps({'status': 'blocked', 'code': getattr(exc, 'code', 'supervisor-unavailable')}))
        raise SystemExit(2) from None

if __name__ == '__main__': main()
