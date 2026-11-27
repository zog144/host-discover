"""Approved-host production HTTPS; synthetic station and disposable STATE only."""
import copy
import datetime
import json
import ssl
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.x509.oid import NameOID
from zog.host_discover import approved_binding, beacon, managed_transport
from zog.host_discover.retry import RetryableTransport
from zog.host_identify import signatures
from zog.host_install.state_contract import StateError
from test_supervised_beacon import environment, current
from test_managed_admission import Station


def expectation(state, station):
    b = state.bundle['bootstrap']
    reg = b['registries'][0]
    return dict(schema=1, kind='zog-managed-station-binding',
                host_id=station.host, fingerprint=signatures.fingerprint(state.key.public_key()),
                installation_id=b['installation_id'], state_volume_id=b['state']['state_volume_id'],
                authority_id=b['control_authority']['authority_id'], registry_id=reg['registry_id'],
                origin=reg['origin'], station_key_id=signatures.fingerprint(station.key.public_key()))


def select(monkeypatch, state, station):
    value = expectation(state, station)
    monkeypatch.setattr(approved_binding, 'load', lambda b: approved_binding.validate(copy.deepcopy(value), b))
    return value


def test_approved_binding_rejects_foreign_installation_origin_and_signer(environment, monkeypatch):
    state, _, _ = environment
    station = Station()
    value = expectation(state, station)
    for field, replacement in [('installation_id', str(uuid.uuid4())),
                               ('state_volume_id', str(uuid.uuid4())),
                               ('authority_id', str(uuid.uuid4())),
                               ('origin', 'https://another.example.invalid'),
                               ('registry_id', 'foreign'),
                               ('station_key_id', value['fingerprint'])]:
        bad = dict(value, **{field: replacement})
        with pytest.raises(StateError):
            approved_binding.validate(bad, state.bundle['bootstrap'])
    assert approved_binding.validate(value, state.bundle['bootstrap']) == value


def test_unknown_signer_denied_on_first_session_before_heartbeat(environment, monkeypatch):
    state, _, _ = environment
    station = Station()
    station.approved = True
    select(monkeypatch, state, station)
    station.key = ed25519.Ed25519PrivateKey.generate()
    runtime = beacon.ApprovedBeacon(state).open()
    try:
        with pytest.raises(StateError, match='station-signer-conflict'):
            runtime.tick(station, {'version':1})
        assert len(station.calls) == 1 and station.calls[0].endswith('/managed-session/')
        assert runtime.saved['registries']['primary']['previous'] is None
        assert runtime.saved['registries']['primary']['pending'] is not None
        assert not runtime.sessions
        assert runtime.verified_binding is None
    finally:
        runtime.close()


def test_changed_binding_blocks_before_network(environment, monkeypatch):
    state, _, _ = environment
    station = Station()
    value = select(monkeypatch, state, station)
    runtime = beacon.ApprovedBeacon(state).open()
    value['host_id'] = str(uuid.uuid4())
    try:
        with pytest.raises(StateError, match='station-binding-changed'):
            runtime.tick(station, {'version':1})
        assert not station.calls
    finally:
        runtime.close()


def test_missing_expectation_does_not_acquire_supervisor(environment, monkeypatch):
    state, _, _ = environment
    def absent(_): raise FileNotFoundError()
    monkeypatch.setattr(approved_binding, 'load', absent)
    with pytest.raises(StateError, match='station-binding-unavailable'):
        beacon.ApprovedBeacon(state).open()
    assert current(state)['run'] is None


def test_existing_empty_journal_is_not_silently_rebound(environment, monkeypatch):
    state, _, _ = environment
    runtime = beacon.Beacon(state).open()
    runtime.finish()
    station = Station()
    select(monkeypatch, state, station)
    with pytest.raises(StateError, match='station-binding-conflict'):
        beacon.ApprovedBeacon(state).open()
    assert not station.calls


def test_experimental_runtime_remains_disabled():
    with pytest.raises(StateError, match='managed-transport-disabled'):
        managed_transport.Transport().post()


def test_real_https_approved_session_heartbeat_expiry_and_reconnect(environment, monkeypatch, tmp_path):
    state, _, _ = environment
    station = Station()
    station.approved = True
    tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-datetime.timedelta(minutes=1))
            .not_valid_after(now+datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(tls_key, hashes.SHA256()))
    ca = cert.public_bytes(serialization.Encoding.PEM)
    cp = tmp_path/'server-cert.pem'; cp.write_bytes(ca)
    kp = tmp_path/'server-key.pem'; kp.write_bytes(tls_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    calls=[]; nonces=[]; errors=[]; lose=[False]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            try:
                raw=self.rfile.read(int(self.headers['Content-Length']))
                nonce,_=signatures.verify(origin+self.path, 'POST', self.headers, raw,
                                         state.key.public_key(), station.host)
                nonces.append(nonce); calls.append(self.path)
                assert self.path in (f'/api/hosts/{station.host}/managed-session/',
                                     f'/api/hosts/{station.host}/heartbeat/')
                if lose[0]:
                    lose[0]=False
                    self.send_response(503);self.end_headers();return
                result=station.post(origin+self.path, json.loads(raw), state.key, station.host, ca)
                self.send_response(200);self.end_headers()
                self.wfile.write(json.dumps(result).encode())
            except Exception as exc: errors.append(exc)
    server=HTTPServer(('127.0.0.1',0),Handler)
    origin=f'https://localhost:{server.server_port}'
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cp,kp)
    server.socket=context.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever);thread.start()
    state.bundle['bootstrap']['registries'][0]['origin']=origin
    value=select(monkeypatch,state,station)
    monkeypatch.setattr(beacon.ApprovedBeacon,'ca',lambda self,reg:ca)
    runtime=None
    try:
        runtime=beacon.ApprovedBeacon(state).open()
        runtime.tick(report={'version':1})
        assert runtime.verified_binding['host_id']==station.host
        assert runtime.verified_binding['fingerprint']==value['fingerprint']
        assert runtime.verified_binding['installation_id']==value['installation_id']
        assert runtime.verified_binding['station_key_id']==value['station_key_id']
        assert runtime.verified_binding['epoch']==1
        runtime.sessions['primary']['exp']=int(time.time())-1
        runtime.tick(report={'version':1})
        assert runtime.verified_binding['epoch']==2
        lose[0]=True
        with pytest.raises(RetryableTransport):
            runtime.tick(report={'version':1})
        assert not runtime.sessions and runtime.verified_binding is None
        runtime.tick(report={'version':1})
        assert runtime.verified_binding['epoch']==3
        runtime.finish()
        runtime=beacon.ApprovedBeacon(state).open()
        runtime.tick(report={'version':1})
        assert runtime.verified_binding['epoch']==4
        runtime.finish()
        assert not errors and len(set(nonces))==len(nonces)
        assert all('/enrollment/' not in path for path in calls)
    finally:
        if runtime is not None:runtime.close()
        server.shutdown();server.server_close();thread.join(5)


def test_real_root_owned_pin_rejects_unsafe_path_and_file(environment, monkeypatch):
    import os
    import tempfile
    from pathlib import Path
    from zog.host_install.state_contract import canonical
    if os.geteuid() != 0:
        pytest.skip('root-owned synthetic pin fixture')
    state, _, _ = environment
    station = Station()
    value = expectation(state, station)
    with tempfile.TemporaryDirectory(prefix='zog-approved-pin-', dir='/root') as tmp:
        root = Path(tmp)
        path = root/'binding.json'
        path.write_bytes(canonical(value)); path.chmod(0o444)
        monkeypatch.setattr(approved_binding,'PATH',str(path))
        assert approved_binding.load(state.bundle['bootstrap']) == value
        path.chmod(0o644)
        with pytest.raises(StateError):
            approved_binding.load(state.bundle['bootstrap'])
        path.chmod(0o444)
        (root/'alias').hardlink_to(path)
        with pytest.raises(StateError):
            approved_binding.load(state.bundle['bootstrap'])
        (root/'alias').unlink()
        root.chmod(0o777)
        with pytest.raises(StateError):
            approved_binding.load(state.bundle['bootstrap'])
        root.chmod(0o700)
        path.rename(root/'retained.json')
        path.symlink_to(root/'retained.json')
        with pytest.raises(OSError):
            approved_binding.load(state.bundle['bootstrap'])
