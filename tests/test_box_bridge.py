import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock
import pytest
from zog.host_discover.box_bridge import (
    BoxBridge, BridgeError, REQUIRED_METHODS, check_control,
)


def bridge(programs, status='observed'):
    result = object.__new__(BoxBridge)
    result.required = ['server', 'refresh-scheduler']
    result.application = 'archive-mirror'
    result.control = Mock()
    result._broker = False
    result._broker_error = ()
    result.control.observe_application_runtime.return_value = {
        'status': status, 'programs': programs,
    }
    result.control.cancel_application_launch.return_value = {
        'request_id': 'request-1',
        'application': 'archive-mirror',
        'status': 'accepted',
        'runtime_id': 'runtime-1',
    }
    result.control.terminate_application_runtime.return_value = (
        SimpleNamespace(runtime_id='runtime-1')
    )
    result.control.application_request_result.return_value = SimpleNamespace(
        operation='launch',
        application='archive-mirror',
        status=SimpleNamespace(value='satisfied'),
        runtime_id='runtime-1',
    )
    return result


def member(name, status='observed', active='active'):
    return {
        'program': name,
        'status': status,
        'observation': (
            {'active_state': active} if status == 'observed' else None
        ),
    }


def test_capability_gate_rejects_missing_request_result_before_lifecycle():
    calls = []
    control = SimpleNamespace(**{
        name: (lambda: calls.append('called'))
        for name in REQUIRED_METHODS
        if name != 'application_request_result'
    })
    with pytest.raises(ValueError, match='application_request_result'):
        check_control(control)
    assert calls == []
    control.application_request_result = lambda _request_id: None
    check_control(control)


@pytest.mark.parametrize(
    'status,active',
    [
        ('unavailable', 'active'),
        ('identity-unavailable', 'active'),
        ('integrity-fault', 'active'),
        ('observed', 'activating'),
        ('observed', 'deactivating'),
    ],
)
def test_uncertainty_remains_unknown(status, active):
    value = bridge([
        member('server'),
        member('refresh-scheduler', status, active),
    ])
    assert value.runtime_state('runtime-1') is None
    assert value.running('runtime-1') is None


def test_missing_and_duplicate_members_are_unknown():
    for programs in (
        [member('server')],
        [member('server'), member('server'), member('refresh-scheduler')],
    ):
        value = bridge(programs)
        assert value.runtime_state('runtime-1') is None


@pytest.mark.parametrize(
    'status,active,expected',
    [
        ('observed', 'inactive', 'stopped'),
        ('observed', 'failed', 'failed'),
        ('absent', 'active', 'stopped'),
        ('previous-boot', 'active', 'stale'),
    ],
)
def test_runtime_observation_distinguishes_stopped_failed_and_stale(
        status, active, expected):
    value = bridge([
        member(name, status, active)
        for name in ['server', 'refresh-scheduler']
    ])
    assert value.runtime_state('runtime-1') == expected
    assert value.running('runtime-1') is False


def test_recorded_prior_invocation_cannot_count_as_current_runtime():
    value = bridge([
        member('server'),
        member('refresh-scheduler'),
    ])
    for item in value.control.observe_application_runtime.return_value['programs']:
        item['recorded_invocation_id'] = 'old-' + item['program']
        item['observation']['invocation_id'] = 'current-' + item['program']
    assert value.runtime_state('runtime-1') == 'stale'
    assert value.running('runtime-1') is False


def test_cancel_and_terminate_keep_distinct_request_identities():
    value = bridge([
        member(name, active='inactive')
        for name in ['server', 'refresh-scheduler']
    ])
    cancellation = value.cancel('request-1')
    assert cancellation == {
        'status': 'accepted',
        'request_id': 'request-1',
        'runtime_id': 'runtime-1',
    }
    value.terminate('runtime-1', 'termination-1')
    value.control.terminate_application_runtime.assert_called_once_with(
        'runtime-1', request_id='termination-1'
    )


@pytest.mark.parametrize('status', ['pending', 'uncertain', 'unknown'])
def test_structured_unresolved_cancellation_is_preserved(status):
    value = bridge([])
    value.control.cancel_application_launch.return_value = {
        'request_id': 'request-1',
        'application': 'archive-mirror',
        'status': status,
        'runtime_id': None,
    }
    assert value.cancel('request-1')['status'] == status
    value.control.terminate_application_runtime.assert_not_called()


def test_result_reconciles_satisfied_launch_without_new_launch():
    value = bridge([])
    result = value.result('request-1')
    assert result == {
        'status': 'satisfied',
        'request_id': 'request-1',
        'runtime_id': 'runtime-1',
    }
    value.control.launch_application.assert_not_called()


def test_result_none_is_unknown_not_success():
    value = bridge([])
    value.control.application_request_result.return_value = None
    assert value.result('request-1') == {
        'status': 'unknown',
        'request_id': 'request-1',
        'runtime_id': None,
    }


def test_broker_configuration_uses_fixed_archive_scope(monkeypatch):
    package = ModuleType('zog.box_control')
    package.__path__ = []
    broker = ModuleType('zog.box_control.role_broker')
    client_module = ModuleType('zog.box_control.role_broker_client')

    class RoleBrokerError(ValueError):
        def __init__(self, message='blocked', *, code='blocked'):
            super().__init__(message)
            self.code = code

    class Client:
        instances = []
        def __init__(self, socket_path, *, application, timeout_seconds):
            self.socket_path = socket_path
            self.application = application
            self.timeout_seconds = timeout_seconds
            self.instances.append(self)
        def application_available(self): return True
        def application_preparation_status(self): return {'state': 'ready'}
        def application_launch_preflight(self):
            return {'status': 'ready-to-attempt', 'advisory': True, 'checks': []}
        def issue_application_request_id(self): return 'request-1'
        def launch_application(self, application, *, request_id):
            return SimpleNamespace(
                application=application, runtime_id='runtime-1'
            )
        def cancel_application_launch(self, application, *, request_id):
            return {
                'application': application, 'request_id': request_id,
                'status': 'accepted', 'runtime_id': 'runtime-1',
            }
        def terminate_application_runtime(self, runtime_id, *, request_id):
            return {'runtime_id': runtime_id, 'request_id': request_id}
        def observe_application_runtime(self, runtime_id):
            return {
                'runtime_id': runtime_id, 'status': 'observed',
                'programs': [
                    member('server'),
                    member('refresh-scheduler'),
                ],
            }
        def application_request_result(self, request_id):
            return {
                'status': 'satisfied', 'request_id': request_id,
                'runtime_id': 'runtime-1',
            }

    broker.RoleBrokerError = RoleBrokerError
    client_module.RoleBrokerClient = Client
    monkeypatch.setitem(sys.modules, 'zog.box_control', package)
    monkeypatch.setitem(sys.modules, 'zog.box_control.role_broker', broker)
    monkeypatch.setitem(
        sys.modules, 'zog.box_control.role_broker_client', client_module
    )

    value = BoxBridge({
        'broker_socket': '/run/zog/archive-role.sock',
        'application': 'archive-mirror',
        'required_programs': ['server', 'refresh-scheduler'],
        'timeout_seconds': 7,
    })
    assert value.available() is True
    assert value.preparation()['state'] == 'ready'
    assert value.preflight()['status'] == 'ready-to-attempt'
    assert Client.instances[0].application == 'archive-mirror'
    assert Client.instances[0].socket_path == '/run/zog/archive-role.sock'
    assert Client.instances[0].timeout_seconds == 7


def test_broker_transport_failure_is_sanitized(monkeypatch):
    package = ModuleType('zog.box_control')
    package.__path__ = []
    broker = ModuleType('zog.box_control.role_broker')
    client_module = ModuleType('zog.box_control.role_broker_client')

    class RoleBrokerError(ValueError):
        code = 'controller-blocked'

    class Client:
        def __init__(self, *_args, **_kwargs): pass
        def application_available(self): raise OSError('private socket detail')
        def application_preparation_status(self): return {'state': 'ready'}
        def application_launch_preflight(self):
            return {'status': 'ready-to-attempt'}
        def issue_application_request_id(self): return 'request-1'
        def launch_application(self, application, *, request_id): pass
        def cancel_application_launch(self, application, *, request_id): pass
        def terminate_application_runtime(self, runtime_id, *, request_id): pass
        def observe_application_runtime(self, runtime_id): pass
        def application_request_result(self, request_id): pass

    broker.RoleBrokerError = RoleBrokerError
    client_module.RoleBrokerClient = Client
    monkeypatch.setitem(sys.modules, 'zog.box_control', package)
    monkeypatch.setitem(sys.modules, 'zog.box_control.role_broker', broker)
    monkeypatch.setitem(
        sys.modules, 'zog.box_control.role_broker_client', client_module
    )
    value = BoxBridge({'broker_socket': '/run/zog/archive-role.sock'})
    with pytest.raises(BridgeError) as error:
        value.available()
    assert error.value.code == 'controller-unavailable'
    assert 'private socket detail' not in str(error.value)


@pytest.mark.parametrize(
    'configuration',
    [
        {},
        {'project': '/tmp/project', 'broker_socket': '/run/zog/archive-role.sock'},
        {'broker_socket': '/run/zog/archive-role.sock',
         'application': 'station-access'},
        {'broker_socket': '/run/zog/archive-role.sock',
         'required_programs': ['server']},
        {'broker_socket': '/run/zog/archive-role.sock',
         'ca_file': 'relative-ca.pem'},
        {'project': '/tmp/project', 'timeout_seconds': 2},
    ],
)
def test_invalid_or_ambiguous_bridge_configuration_is_rejected(
        configuration, monkeypatch):
    if configuration.get('project') and not configuration.get('broker_socket'):
        package = ModuleType('zog.box_control')
        package.__path__ = []
        api = ModuleType('zog.box_control.api')
        project = ModuleType('zog.box_control.project')
        api.BoxControl = lambda _project: object()
        project.Project = lambda path: path
        monkeypatch.setitem(sys.modules, 'zog.box_control', package)
        monkeypatch.setitem(sys.modules, 'zog.box_control.api', api)
        monkeypatch.setitem(sys.modules, 'zog.box_control.project', project)
    with pytest.raises(ValueError):
        BoxBridge(configuration)
