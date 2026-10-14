"""Optional box-control adapter. No shell, downloaded commands, or host-root fallback."""
import json
import re
import ssl
import urllib.request
from pathlib import Path

REQUIRED_METHODS = (
    'issue_application_request_id', 'launch_application', 'cancel_application_launch',
    'terminate_application_runtime', 'observe_application_runtime',
    'application_request_result',
)
_SAFE_CODE = re.compile(r'[a-z0-9][a-z0-9-]{0,47}')


class BridgeError(RuntimeError):
    """Sanitized local-controller failure suitable for role status reporting."""

    def __init__(self, code='controller-blocked', *, uncertain=False):
        if not isinstance(code, str) or not _SAFE_CODE.fullmatch(code):
            code = 'controller-blocked'
        super().__init__(code)
        self.code = code
        self.uncertain = bool(uncertain)


def check_control(control):
    missing = [name for name in REQUIRED_METHODS if not callable(getattr(control, name, None))]
    if missing:
        raise ValueError('Unsupported box-control API: ' + ', '.join(missing))


class BoxBridge:
    """One archive application lifecycle, either local-direct or brokered."""

    def __init__(self, configuration):
        if not isinstance(configuration, dict):
            raise ValueError('Invalid bridge configuration')
        allowed = {
            'project', 'broker_socket', 'application', 'required_programs',
            'ca_file', 'timeout_seconds',
        }
        if set(configuration) - allowed:
            raise ValueError('Invalid bridge configuration')
        self.application = configuration.get('application', 'archive-mirror')
        if self.application != 'archive-mirror':
            raise ValueError('Archive role application must be archive-mirror')
        self.required = configuration.get(
            'required_programs', ['server', 'refresh-scheduler']
        )
        if (not self.required
                or not all(isinstance(item, str) and item for item in self.required)
                or len(set(self.required)) != len(self.required)):
            raise ValueError('Required programs missing')
        self.ca = configuration.get('ca_file')
        if self.ca is not None:
            ca_path = Path(self.ca)
            if not isinstance(self.ca, str) or not ca_path.is_absolute():
                raise ValueError('ca_file must be an absolute path')

        project = configuration.get('project')
        broker_socket = configuration.get('broker_socket')
        if bool(project) == bool(broker_socket):
            raise ValueError('Configure exactly one box-control project or broker socket')

        self._broker = False
        self._broker_error = ()
        if broker_socket:
            if set(self.required) != {'server', 'refresh-scheduler'}:
                raise ValueError('Broker mode requires both archive programs')
            from zog.box_control.role_broker import RoleBrokerError
            from zog.box_control.role_broker_client import RoleBrokerClient
            timeout = configuration.get('timeout_seconds', 10)
            self.control = RoleBrokerClient(
                broker_socket,
                application='archive-mirror',
                timeout_seconds=timeout,
            )
            self._broker = True
            self._broker_error = (RoleBrokerError,)
        else:
            if 'timeout_seconds' in configuration:
                raise ValueError('timeout_seconds requires broker_socket')
            from zog.box_control.api import BoxControl
            from zog.box_control.project import Project
            path = Path(project)
            if not path.is_absolute() or path == Path('/'):
                raise ValueError('Explicit project required')
            self.control = BoxControl(Project(path))
        check_control(self.control)

    def _invoke(self, method, *args, uncertain=False, **kwargs):
        try:
            return method(*args, **kwargs)
        except self._broker_error as error:
            raise BridgeError(
                getattr(error, 'code', 'controller-blocked')
            ) from None
        except (OSError, TimeoutError):
            if self._broker:
                raise BridgeError(
                    'controller-unavailable', uncertain=uncertain
                ) from None
            raise

    def available(self):
        if self._broker:
            return bool(self._invoke(self.control.application_available))
        from zog.box_control.specification import discover_applications
        return self.application in discover_applications(
            self.control.project.application_dir
        )

    def preparation(self):
        if self._broker:
            value = self._invoke(self.control.application_preparation_status)
        else:
            method = getattr(self.control, 'application_preparation', None)
            if not callable(method):
                raise BridgeError('controller-blocked')
            value = method(self.application)
        if value is None:
            return {'state': 'unavailable'}
        if not isinstance(value, dict) or not isinstance(value.get('state'), str):
            raise BridgeError('controller-blocked')
        return value

    def preflight(self):
        if self._broker:
            value = self._invoke(self.control.application_launch_preflight)
        else:
            method = getattr(self.control, 'preflight_application_launch', None)
            if not callable(method):
                raise BridgeError('controller-blocked')
            value = method(self.application)
        if (not isinstance(value, dict)
                or value.get('status') not in {
                    'ready-to-attempt', 'blocked', 'unable-to-verify'
                }):
            raise BridgeError('controller-blocked')
        return value

    def issue(self):
        value = self._invoke(self.control.issue_application_request_id)
        if not isinstance(value, str) or not value:
            raise BridgeError('controller-blocked')
        return value

    def start(self, request_id):
        reference = self._invoke(
            self.control.launch_application,
            self.application,
            request_id=request_id,
            uncertain=True,
        )
        runtime = getattr(reference, 'runtime_id', None)
        if not isinstance(runtime, str) or not runtime:
            raise BridgeError('controller-blocked')
        return runtime

    def result(self, request_id):
        value = self._invoke(self.control.application_request_result, request_id)
        if value is None:
            return {
                'status': 'unknown',
                'request_id': request_id,
                'runtime_id': None,
            }
        if isinstance(value, dict):
            result = dict(value)
        else:
            operation = getattr(value, 'operation', None)
            operation = getattr(operation, 'value', operation)
            application = getattr(value, 'application', None)
            if operation not in (None, 'launch') or application not in (
                    None, self.application):
                raise BridgeError('scope-rejected')
            state = getattr(value, 'status', None)
            result = {
                'status': getattr(state, 'value', state),
                'request_id': request_id,
                'runtime_id': getattr(value, 'runtime_id', None),
            }
        if result.get('request_id', request_id) != request_id:
            raise BridgeError('scope-rejected')
        status = result.get('status')
        runtime = result.get('runtime_id')
        if not isinstance(status, str) or len(status) > 32:
            raise BridgeError('controller-blocked')
        if runtime is not None and (not isinstance(runtime, str) or not runtime):
            raise BridgeError('controller-blocked')
        return {
            'status': status,
            'request_id': request_id,
            'runtime_id': runtime,
        }

    def cancel(self, request_id):
        value = self._invoke(
            self.control.cancel_application_launch,
            self.application,
            request_id=request_id,
            uncertain=True,
        )
        if isinstance(value, dict):
            if (value.get('request_id') != request_id
                    or value.get('application') != self.application):
                raise BridgeError('scope-rejected')
            status = value.get('status')
            runtime = value.get('runtime_id')
        else:
            runtime = getattr(value, 'runtime_id', None)
            status = 'accepted' if runtime else 'cancelled'
        if not isinstance(status, str) or len(status) > 32:
            raise BridgeError('controller-blocked')
        if runtime is not None and (not isinstance(runtime, str) or not runtime):
            raise BridgeError('controller-blocked')
        return {
            'status': status,
            'request_id': request_id,
            'runtime_id': runtime,
        }

    def terminate(self, runtime_id, request_id):
        reference = self._invoke(
            self.control.terminate_application_runtime,
            runtime_id,
            request_id=request_id,
            uncertain=True,
        )
        resolved = (
            reference.get('runtime_id')
            if isinstance(reference, dict)
            else getattr(reference, 'runtime_id', runtime_id)
        )
        if resolved != runtime_id:
            raise BridgeError('scope-rejected')
        return runtime_id

    def runtime_state(self, runtime_id):
        result = self._invoke(
            self.control.observe_application_runtime, runtime_id
        )
        if not isinstance(result, dict):
            return None
        if result.get('status') == 'previous-boot':
            return 'stale'
        if result.get('status') != 'observed':
            return None
        programs = result.get('programs')
        if not isinstance(programs, list):
            return None
        members = {
            item.get('program'): item
            for item in programs
            if isinstance(item, dict)
        }
        if (len(members) != len(programs)
                or any(name not in members for name in self.required)):
            return None

        states = []
        for name in self.required:
            member = members[name]
            member_status = member.get('status')
            if member_status == 'previous-boot':
                states.append('stale')
            elif member_status == 'absent':
                states.append('stopped')
            elif member_status == 'observed':
                observation = member.get('observation')
                if not isinstance(observation, dict):
                    return None
                recorded = member.get('recorded_invocation_id')
                current = observation.get('invocation_id')
                if (recorded and current and recorded != current):
                    states.append('stale')
                    continue
                active = observation.get('active_state')
                if active == 'active':
                    states.append('running')
                elif active == 'inactive':
                    states.append('stopped')
                elif active == 'failed':
                    states.append('failed')
                else:
                    return None
            else:
                return None

        if 'stale' in states:
            return 'stale'
        if all(state == 'running' for state in states):
            return 'running'
        if 'failed' in states:
            return 'failed'
        if all(state == 'stopped' for state in states):
            return 'stopped'
        return 'failed'

    def running(self, runtime_id):
        state = self.runtime_state(runtime_id)
        if state == 'running':
            return True
        if state in {'stopped', 'failed', 'stale'}:
            return False
        return None

    def ready(self, endpoint, host_id, revision):
        from .daemon import NoRedirect
        from zog.host_identify.signatures import origin
        opener = urllib.request.build_opener(
            NoRedirect(),
            urllib.request.HTTPSHandler(
                context=ssl.create_default_context(cafile=self.ca)
            ),
        )
        with opener.open(
                origin(endpoint) + '/.well-known/zog/archive-mirror/ready',
                timeout=5) as response:
            raw = response.read(4097)
            if response.status != 200 or len(raw) > 4096:
                return False
            value = json.loads(raw)
        return value == {
            'version': 1,
            'host_id': host_id,
            'role_revision': revision,
            'serving': True,
            'scheduler_running': True,
        }
