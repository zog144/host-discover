"""Persistent role intent. Only a locally configured adapter can execute it."""
import fcntl
import json
import os
import time
import uuid
from pathlib import Path
from zog.host_identify import storage
from zog.host_identify.signatures import origin
from .box_bridge import BridgeError

# Only these administrator-provisioned, narrowly scoped host-export trees may
# become a box-control host-capability source. Not the credential/identity tree.
_LIVE_EXPORT_ROOTS = ("/run/zog-host-export/", "/var/lib/zog-host-export/")
_TERMINAL_REQUEST = {'cancelled', 'failed', 'abandoned'}
_ACCEPTED_REQUEST = {'accepted', 'satisfied'}
_UNRESOLVED_CANCEL = {'pending', 'uncertain', 'unknown'}
_BROKER_REASON = {
    'application-unavailable': 'application-missing',
    'preparation-not-ready': 'operation-pending',
    'controller-busy': 'operation-pending',
    'definition-mismatch': 'configuration-invalid',
    'scope-rejected': 'configuration-invalid',
    'image-selection-invalid': 'configuration-invalid',
}


def _published_broker_reason(code):
    """Map bounded broker detail onto station-access's existing wire contract."""
    return _BROKER_REASON.get(code, 'state-unavailable')


def validate(value, now=None):
    now = time.time() if now is None else now
    if not isinstance(value, dict) or set(value) != {'desired', 'candidates'}:
        raise ValueError('Invalid roles')
    desired = value['desired']
    if (not isinstance(desired, dict)
            or set(desired) != {
                'version', 'revision', 'selected', 'endpoint',
                'retain_archives', 'lease_expires_at',
            }):
        raise ValueError('Invalid intent')
    if (desired['version'] != 1
            or type(desired['revision']) is not int
            or not 0 <= desired['revision'] <= 2**53 - 1
            or type(desired['selected']) is not bool
            or desired['retain_archives'] is not True):
        raise ValueError('Invalid intent')
    if (type(desired['lease_expires_at']) is not int
            or not now < desired['lease_expires_at'] <= now + 905):
        raise ValueError('Invalid lease')
    if desired['selected']:
        origin(desired['endpoint'])
    elif desired['endpoint'] != '':
        raise ValueError('Invalid inactive endpoint')

    candidates = value['candidates']
    if not isinstance(candidates, list) or len(candidates) > 32:
        raise ValueError('Invalid candidates')
    seen = set()
    addresses = set()
    for candidate in candidates:
        if (not isinstance(candidate, dict)
                or set(candidate) != {
                    'host_id', 'endpoint', 'revision', 'ready', 'state'
                }):
            raise ValueError('Invalid candidate')
        if (str(uuid.UUID(candidate['host_id'])) != candidate['host_id']
                or candidate['host_id'] in seen
                or candidate['endpoint'] in addresses):
            raise ValueError('Duplicate candidate')
        origin(candidate['endpoint'])
        if (type(candidate['ready']) is not bool
                or type(candidate['revision']) is not int
                or candidate['revision'] < 1
                or candidate['state'] not in {
                    'assigned', 'received', 'blocked', 'starting', 'running',
                    'ready', 'stopping', 'stopped', 'failed',
                }):
            raise ValueError('Invalid candidate status')
        if candidate['ready'] and candidate['state'] != 'ready':
            raise ValueError('Invalid readiness')
        seen.add(candidate['host_id'])
        addresses.add(candidate['endpoint'])
    return value


class Controller:
    def __init__(self, configuration, adapter=None):
        self.configuration = configuration
        self.root = storage.directory(configuration['identity_directory'])
        self.path = self.root / 'mirror-role.json'
        self.adapter = adapter

    def save(self, state):
        storage.atomic(self.path, json.dumps(state).encode())

    def load(self):
        return (
            json.loads(storage.read_owned(self.path, 0o600))
            if self.path.exists() else {}
        )

    def status(self):
        state = self.load()
        return state.get(
            'status',
            {'revision': 0, 'state': 'stopped', 'reason': '', 'runtime_id': ''},
        )

    def _clear_lifecycle(self, state):
        for name in (
                'request_id', 'runtime_id', 'launch_revision',
                'launch_attempted', 'termination_request_id'):
            state.pop(name, None)
        self.save(state)

    def _runtime_state(self, adapter, runtime_id):
        method = getattr(adapter, 'runtime_state', None)
        if callable(method):
            return method(runtime_id)
        running = adapter.running(runtime_id)
        if running is True:
            return 'running'
        if running is False:
            return 'failed'
        return None

    def _stop_owned(self, adapter, state):
        """Cancel launch, then terminate only the exact persisted runtime."""
        request_id = state.get('request_id')
        if not request_id:
            self._clear_lifecycle(state)
            return True, ''

        cancel = getattr(adapter, 'cancel', None)
        terminate = getattr(adapter, 'terminate', None)
        if not callable(cancel) or not callable(terminate):
            # Compatibility for injected legacy test adapters only. Production
            # BoxBridge always uses explicit cancellation and termination IDs.
            adapter.stop(request_id, state.get('runtime_id', ''))
            self._clear_lifecycle(state)
            return True, ''

        result = cancel(request_id)
        if not isinstance(result, dict):
            raise BridgeError('controller-blocked')
        cancel_state = result.get('status')
        resolved = result.get('runtime_id')
        runtime_id = state.get('runtime_id') or ''
        if runtime_id and resolved and runtime_id != resolved:
            raise BridgeError('scope-rejected')
        target = runtime_id or resolved or ''

        if cancel_state in _UNRESOLVED_CANCEL:
            return False, 'operation-pending'
        if cancel_state == 'accepted' and not target:
            raise BridgeError('controller-blocked')
        if cancel_state == 'cancelled' and target:
            raise BridgeError('scope-rejected')
        if cancel_state not in _TERMINAL_REQUEST | {'accepted'}:
            return False, 'operation-pending'

        if not target:
            self._clear_lifecycle(state)
            return True, ''

        if state.get('runtime_id') != target:
            state['runtime_id'] = target
            self.save(state)
        if not state.get('termination_request_id'):
            # Durability barrier: persist the independent termination identity
            # before invoking the mutating termination RPC.
            state['termination_request_id'] = adapter.issue()
            self.save(state)

        adapter.terminate(target, state['termination_request_id'])
        observed = self._runtime_state(adapter, target)
        if observed is None:
            return False, 'runtime-unavailable'
        if observed == 'running':
            return False, 'operation-pending'
        if observed not in {'stopped', 'failed', 'stale'}:
            return False, 'runtime-unavailable'
        self._clear_lifecycle(state)
        return True, ''

    def _reconcile_launch(self, adapter, state):
        """Resolve a retained launch identity without inventing another one."""
        result = adapter.result(state['request_id'])
        if not isinstance(result, dict):
            raise BridgeError('controller-blocked')
        request_state = result.get('status')
        runtime_id = result.get('runtime_id')

        if request_state == 'satisfied':
            if not runtime_id:
                raise BridgeError('controller-blocked')
            state['runtime_id'] = runtime_id
            self.save(state)
            return 'resolved'

        if request_state == 'pending':
            return 'pending'

        if request_state in _TERMINAL_REQUEST:
            if runtime_id:
                state['runtime_id'] = runtime_id
                self.save(state)
                return 'terminal-runtime'
            self._clear_lifecycle(state)
            return 'terminal'

        if request_state != 'unknown':
            raise BridgeError('controller-blocked')

        # A missing result after an attempted launch is ambiguous. Cancellation
        # is the supported reconciliation primitive and preserves the same
        # original launch identity.
        cancel = adapter.cancel(state['request_id'])
        if not isinstance(cancel, dict):
            raise BridgeError('controller-blocked')
        cancel_state = cancel.get('status')
        runtime_id = cancel.get('runtime_id')
        if cancel_state == 'accepted':
            if not runtime_id:
                raise BridgeError('controller-blocked')
            state['runtime_id'] = runtime_id
            self.save(state)
            return 'resolved'
        if cancel_state in _TERMINAL_REQUEST:
            if runtime_id:
                state['runtime_id'] = runtime_id
                self.save(state)
                return 'terminal-runtime'
            self._clear_lifecycle(state)
            return 'terminal'
        if cancel_state in _UNRESOLVED_CANCEL:
            return 'unknown'
        raise BridgeError('controller-blocked')

    def tick(self, host_id=None, incoming=None, withdraw=False):
        # Independent invocations serialize intent changes, launches, and
        # durable request IDs.
        lock = self.root / 'mirror-role.lock'
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            storage.read_owned(lock, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            state = self.load()
            if incoming is not None:
                validate(incoming)
                desired = incoming['desired']
                old = state.get('desired')
                if state.get('host_id') not in (None, host_id):
                    raise ValueError('Role belongs to another identity')
                if old and (
                        desired['revision'] < old['revision']
                        or (desired['revision'] == old['revision']
                            and any(
                                desired[key] != old[key]
                                for key in ('selected', 'endpoint')
                            ))):
                    raise ValueError('Role revision rollback')
                state.update(
                    host_id=host_id,
                    desired=desired,
                    candidates=incoming['candidates'],
                )
                self.save(state)
            if not state:
                return self.status()

            desired = state['desired']
            selected = (
                desired['selected']
                and desired['lease_expires_at'] > time.time()
                and not withdraw
            )
            if withdraw:
                desired['lease_expires_at'] = 0
                self.save(state)

            def status(value, reason=''):
                state['status'] = {
                    'revision': desired['revision'],
                    'state': value,
                    'reason': reason,
                    'runtime_id': state.get('runtime_id', ''),
                }
                self.save(state)
                return state['status']

            # Publish only accepted monotonic intent while holding the same role
            # lock. The optional dedicated read-only consumer export is
            # producer-updated on each renewal and withdrawal. Never expose the
            # enrollment identity/credential directory to station-access.
            export_failed = False
            try:
                from zog.host_identify.mirror_access import save_candidates
                values = {
                    'desired': desired,
                    'candidates': state.get('candidates', []),
                }
                save_candidates(
                    self.configuration['credential_directory'],
                    state['host_id'],
                    values,
                )
                export = self.configuration.get('mirror_live_export_directory')
                if export:
                    directory = Path(export)
                    if (not directory.is_absolute()
                            or str(directory) != export
                            or '..' in directory.parts
                            or not any(
                                export.startswith(prefix)
                                for prefix in _LIVE_EXPORT_ROOTS
                            )):
                        raise ValueError('Unapproved mirror export directory')
                    save_candidates(export, state['host_id'], values)
            except Exception:
                export_failed = True
                if selected:
                    return status('blocked', 'state-unavailable')
                # Still stop the owned runtime, but never acknowledge a safe
                # withdrawal if consumers may retain an unrefreshed export.

            adapter = self.adapter
            if adapter is None:
                bridge = self.configuration.get('mirror_box_control')
                if not bridge:
                    active = selected or state.get('request_id')
                    return status(
                        'blocked' if active else 'stopped',
                        'bridge-unconfigured' if active else '',
                    )
                try:
                    from .box_bridge import BoxBridge
                    adapter = BoxBridge(bridge)
                except Exception:
                    return status('blocked', 'configuration-invalid')

            try:
                if not selected:
                    if state.get('request_id'):
                        done, reason = self._stop_owned(adapter, state)
                        if not done:
                            return status('stopping', reason)
                    if export_failed:
                        return status('blocked', 'state-unavailable')
                    return status(
                        'stopped',
                        'lease-withdrawn' if withdraw
                        else 'lease-expired' if desired['selected']
                        else '',
                    )

                if state.get('retry_after', 0) > time.time():
                    return status('failed', 'runtime-failed')

                # A changed role revision never reuses a runtime from the prior
                # binding. Reconcile/terminate it first, then launch on a later
                # tick with a fresh durable launch identity.
                if (state.get('request_id')
                        and state.get('launch_revision') != desired['revision']):
                    done, reason = self._stop_owned(adapter, state)
                    if not done:
                        return status('stopping', reason)
                    return status('stopped', 'operation-pending')

                if not state.get('request_id'):
                    if not adapter.available():
                        return status('blocked', 'application-missing')
                    preparation = getattr(adapter, 'preparation', None)
                    if callable(preparation):
                        evidence = preparation()
                        if evidence.get('state') != 'ready':
                            return status('blocked', 'operation-pending')
                    preflight = getattr(adapter, 'preflight', None)
                    if callable(preflight):
                        assessment = preflight()
                        if assessment.get('status') == 'blocked':
                            return status('blocked', 'configuration-invalid')
                        if assessment.get('status') != 'ready-to-attempt':
                            return status('blocked', 'state-unavailable')
                    state['request_id'] = adapter.issue()
                    state['launch_revision'] = desired['revision']
                    state['launch_attempted'] = False
                    self.save(state)

                if not state.get('runtime_id'):
                    if state.get('launch_attempted'):
                        reconciliation = self._reconcile_launch(adapter, state)
                        if reconciliation == 'pending':
                            return status('starting', 'operation-pending')
                        if reconciliation == 'unknown':
                            return status('starting', 'start-uncertain')
                        if reconciliation == 'terminal':
                            return status('failed', 'runtime-failed')
                        if reconciliation == 'terminal-runtime':
                            done, reason = self._stop_owned(adapter, state)
                            if not done:
                                return status('stopping', reason)
                            state['failures'] = min(
                                state.get('failures', 0) + 1, 5
                            )
                            state['retry_after'] = (
                                time.time()
                                + min(60 * 2**(state['failures'] - 1), 900)
                            )
                            self.save(state)
                            return status('failed', 'runtime-failed')
                        if not state.get('request_id'):
                            return status('failed', 'runtime-failed')

                    if not state.get('runtime_id'):
                        status('starting')
                        # Durability barrier: a lost reply cannot authorize a
                        # different request identity on the next heartbeat.
                        state['launch_attempted'] = True
                        self.save(state)
                        try:
                            state['runtime_id'] = adapter.start(
                                state['request_id']
                            )
                            self.save(state)
                        except BridgeError as error:
                            return status(
                                'starting' if error.uncertain else 'blocked',
                                'start-uncertain'
                                if error.uncertain
                                else _published_broker_reason(error.code),
                            )
                        except Exception:
                            return status(
                                'starting', 'start-uncertain'
                            )

                runtime_id = state['runtime_id']
                runtime_state = self._runtime_state(adapter, runtime_id)
                if runtime_state is None:
                    return status('blocked', 'runtime-unavailable')

                if runtime_state == 'stale':
                    done, reason = self._stop_owned(adapter, state)
                    if not done:
                        return status('stopping', reason)
                    return status('blocked', 'runtime-unavailable')

                if runtime_state in {'stopped', 'failed'}:
                    done, reason = self._stop_owned(adapter, state)
                    if not done:
                        return status('stopping', reason)
                    state['failures'] = min(state.get('failures', 0) + 1, 5)
                    state['retry_after'] = (
                        time.time()
                        + min(60 * 2**(state['failures'] - 1), 900)
                    )
                    self.save(state)
                    return status('failed', 'runtime-failed')

                if runtime_state != 'running':
                    return status('blocked', 'runtime-unavailable')

                if not adapter.ready(
                        desired['endpoint'],
                        state['host_id'],
                        desired['revision']):
                    return status('running', 'probe-failed')

                state['failures'] = 0
                state.pop('retry_after', None)
                self.save(state)
                return status('ready')

            except BridgeError as error:
                # Structured broker failures are stable/nonsecret blocked
                # reasons; never surface controller exception text.
                return status(
                    'blocked' if selected else 'stopping',
                    _published_broker_reason(error.code),
                )
            except Exception:
                # Never surface application output, private configuration, or
                # arbitrary exception text.
                return status(
                    'failed' if selected else 'stopping',
                    'runtime-failed' if selected else 'runtime-unavailable',
                )
        finally:
            os.close(fd)
