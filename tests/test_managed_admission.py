import copy
import json
import os
import time
import uuid
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from zog.host_install import state_inspect
from zog.host_install.state_contract import StateError
from zog.host_identify import signatures,managed as protocol
from zog.host_discover import admission,managed_transport,certificate_assignment

B=json.loads((Path(__file__).parent/'fixtures/host-install/bundle.json').read_text())


class State:
    def __init__(self,root,key):
        self.context=self;self.fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);self.bundle=copy.deepcopy(B)
        self.key=key;self.fault=None
    def recheck(self):
        if self.fault:raise StateError(self.fault,'test')
    check=recheck
    def fail(self,code):self.fault=self.fault or code;raise StateError(self.fault,'test')
    def _identity(self,receipt):
        assert receipt['fingerprint']==signatures.fingerprint(self.key.public_key());self._key=self.key


@pytest.fixture
def local(tmp_path,monkeypatch):
    (tmp_path/'host-discover').mkdir(mode=0o700)
    (tmp_path/'host-discover/control').mkdir(mode=0o700)
    key=Ed25519PrivateKey.generate();state=State(tmp_path,key)
    projection=dict(bindings={'boot_id':str(uuid.uuid4())},receipt=dict(fingerprint=signatures.fingerprint(key.public_key())))
    monkeypatch.setattr(admission,'observe',lambda _:copy.deepcopy(projection))
    original=state_inspect.metadata
    monkeypatch.setattr(admission,'metadata',lambda fd,u,g,m,*a:original(fd,os.geteuid(),os.getegid(),m,*a))
    read=admission.read_at
    monkeypatch.setattr(admission,'read_at',lambda fd,n,*a:read(fd,n,os.geteuid(),os.getegid(),0o600))
    yield state,projection
    os.close(state.fd)


class Station:
    def __init__(self):
        self.key=Ed25519PrivateKey.generate();self.host=str(uuid.uuid4());self.approved=False
        self.previous=None;self.calls=[];self.last=None
    def post(self,url,payload,key,subject,ca):
        self.calls.append(url)
        if url.endswith('/enrollment/'):
            return dict(status='approved' if self.approved else 'pending',fingerprint=signatures.fingerprint(key.public_key()),host_id=self.host)
        if url.endswith('/managed-session/'):
            assert payload['previous']==self.previous
            now=int(time.time())
            claims=dict(iss=url.split('/api/')[0],aud=payload['authority_id'],sub=self.host,iat=now,exp=now+300,jti=str(uuid.uuid4()),
                epoch=(self.previous['epoch']+1 if self.previous else 1),checkpoint=str(uuid.uuid4()),operations=['inspect'],
                fingerprint=signatures.fingerprint(key.public_key()),**{k:payload[k] for k in ('installation_id','state_volume_id','registry_id','challenge','previous','boot_id')})
            self.last=claims;self.previous={k:claims[k] for k in ('epoch','checkpoint')}
            return dict(version=1,public_key=signatures.public_text(self.key.public_key()),session=protocol.sign(claims,self.key,protocol.SESSION_TYPE))
        assert payload['managed_session']==self.last['jti']
        return dict(version=2,host_id=self.host,managed_session=self.last['jti'],archive=None)


def prepared(state):
    runtime=managed_transport.Runtime(state).open(True);runtime.close()
    return managed_transport.Runtime(state).open()


def test_pending_approval_session_heartbeat_and_restart(local):
    state,_=local;runtime=prepared(state);station=Station()
    try:
        runtime.tick(station,{'version':1,'hostname':'host'})
        assert len(station.calls)==1 and not runtime.sessions
        station.approved=True;runtime.tick(station,{'version':1,'hostname':'host'})
        first=runtime.sessions['primary']['jti']
        assert runtime.saved['registries']['primary']['previous']['epoch']==1
        runtime.close();runtime=managed_transport.Runtime(state).open()
        assert not runtime.sessions
        runtime.tick(station,{'version':1,'hostname':'host'})
        assert runtime.sessions['primary']['jti']!=first
        assert runtime.saved['registries']['primary']['previous']['epoch']==2
    finally:runtime.close()


def test_missing_journal_is_not_initialized(local):
    state,_=local
    with pytest.raises(StateError):managed_transport.Runtime(state).open()
    assert os.listdir('/proc/self/fd/'+str(state.fd)+'/host-discover/control')==[]


def test_projection_withdrawal_stops_before_signing(local,monkeypatch):
    state,_=local;runtime=prepared(state)
    def missing(_):raise FileNotFoundError()
    monkeypatch.setattr(admission,'observe',missing)
    class NoNetwork:
        def post(*a):pytest.fail('must not sign/send')
    try:
        with pytest.raises(StateError):runtime.tick(NoNetwork(),{'version':1})
        assert runtime.key is None and not runtime.sessions
    finally:runtime.close()


def test_storage_failure_leaves_blocking_marker(local,monkeypatch):
    state,_=local;runtime=prepared(state)
    original=os.fsync
    def fail(fd):raise OSError('disk failure')
    monkeypatch.setattr(os,'fsync',fail)
    with pytest.raises(StateError):runtime.commit(copy.deepcopy(runtime.saved))
    monkeypatch.setattr(os,'fsync',original)
    assert 'managed.pending' in os.listdir(runtime.journal.fd)
    runtime.close()


def test_control_replay_persisted_before_gateway(local):
    state,_=local;runtime=prepared(state);station=Station();station.approved=True
    runtime.tick(station,{'version':1})
    session=runtime.sessions['primary'];now=int(time.time());request=str(uuid.uuid4())
    claims=dict(iss=session['iss'],aud=session['aud'],sub=session['sub'],iat=now,exp=now+60,jti=request,
        session_id=session['jti'],operation='inspect',runtime_id=str(uuid.uuid4()))
    token=protocol.sign(claims,station.key,protocol.COMMAND_TYPE)
    class Gateway:
        def inspect(self,rid,target):
            assert runtime.journal.read()['replay'][0]['id']==rid
            return {'state':'running'}
    try:
        result=runtime.inspect_command('primary',token,Gateway())
        value=protocol.verify(result,state.key.public_key(),protocol.RESULT_TYPE,runtime.saved['fingerprint'],session['iss'])
        assert value['jti']==request and value['session_id']==session['jti']
        with pytest.raises(StateError,match='command-replay'):runtime.inspect_command('primary',token,Gateway())
    finally:runtime.close()


def test_exclusive_process_lock(local):
    state,_=local;runtime=prepared(state)
    try:
        with pytest.raises(StateError,match='managed-busy'):managed_transport.Runtime(state).open()
    finally:runtime.close()


def test_trust_key_substitution_refused(local):
    state,_=local;runtime=prepared(state);station=Station();station.approved=True
    runtime.tick(station,{'version':1});runtime.close()
    runtime=managed_transport.Runtime(state).open();station.key=Ed25519PrivateKey.generate()
    try:
        with pytest.raises(StateError,match='station-key-conflict'):runtime.tick(station,{'version':1})
        assert runtime.key is None
    finally:runtime.close()


def test_observer_cannot_control(local):
    state,_=local;runtime=prepared(state);station=Station();station.approved=True
    runtime.tick(station,{'version':1})
    runtime.bootstrap['registries'][0]['role']='observation'
    try:
        with pytest.raises(StateError,match='observer-control-denied'):runtime.inspect_command('primary','unused',None)
    finally:runtime.close()


def test_expired_session_cannot_dispatch(local):
    state,_=local;runtime=prepared(state);station=Station();station.approved=True
    runtime.tick(station,{'version':1});session=runtime.sessions['primary'];session['exp']=int(time.time())-1
    claims=dict(iss=session['iss'],aud=session['aud'],sub=session['sub'],iat=int(time.time())-30,exp=int(time.time())+30,jti=str(uuid.uuid4()),session_id=session['jti'],operation='inspect',runtime_id=str(uuid.uuid4()))
    try:
        with pytest.raises(StateError):runtime.inspect_command('primary',protocol.sign(claims,station.key,protocol.COMMAND_TYPE),None)
    finally:runtime.close()


def test_replayed_command_after_process_restart_denied(local):
    state,_=local;runtime=prepared(state);station=Station();station.approved=True
    runtime.tick(station,{'version':1});session=runtime.sessions['primary'];now=int(time.time())
    request=str(uuid.uuid4())
    command=dict(iss=session['iss'],aud=session['aud'],sub=session['sub'],iat=now,exp=now+60,jti=request,session_id=session['jti'],operation='inspect',runtime_id=str(uuid.uuid4()))
    token=protocol.sign(command,station.key,protocol.COMMAND_TYPE)
    class Gateway:
        def inspect(self,*a):return {'state':'running'}
    runtime.inspect_command('primary',token,Gateway());runtime.close()
    runtime=managed_transport.Runtime(state).open();runtime.tick(station,{'version':1})
    try:
        assert runtime.journal.read()['replay'][0]['id']==request
        with pytest.raises(StateError):runtime.inspect_command('primary',token,Gateway())
    finally:runtime.close()


def test_lost_session_response_is_reconciled_then_replaced(local):
    state,_=local;runtime=prepared(state);station=Station();station.approved=True
    original=station.post;saved={}
    def lost(url,payload,key,subject,ca):
        result=original(url,payload,key,subject,ca)
        if url.endswith('/managed-session/'):
            saved.update(payload=copy.deepcopy(payload),result=result)
            raise ConnectionError('lost response')
        return result
    station.post=lost
    with pytest.raises(StateError):runtime.tick(station,{'version':1})
    runtime.close();state.fault=None  # new synthetic process repeats admission
    def retry(url,payload,key,subject,ca):
        if url.endswith('/managed-session/') and payload==saved['payload']:return saved['result']
        return original(url,payload,key,subject,ca)
    station.post=retry
    runtime=managed_transport.Runtime(state).open()
    try:
        runtime.tick(station,{'version':1})
        assert runtime.sessions['primary']['epoch']==2
        assert runtime.saved['registries']['primary']['pending'] is None
    finally:runtime.close()



def test_control_registry_opt_in_retrieves_signed_certificate_assignment(local):
    state,_=local

    class AssignmentStation(Station):
        def post(self,url,payload,key,subject,ca):
            if url.endswith('/certificate-assignment/'):
                self.calls.append(url)
                assert payload['schema']==certificate_assignment.REQUEST_SCHEMA
                assert payload['host_id']==self.host
                assert payload['installation_id']==B['bootstrap']['installation_id']
                assert payload['known_revision']==0
                assert payload['known_operation_id'] is None
                assert payload['managed_session']==self.last['jti']
                now=int(time.time())
                value={
                    'schema':certificate_assignment.ASSIGNMENT_SCHEMA,
                    'authority_origin':'command-center',
                    'host_id':self.host,
                    'installation_id':B['bootstrap']['installation_id'],
                    'operation_id':str(uuid.uuid4()),
                    'revision':1,
                    'status':'approved',
                    'approved_at':now-1,
                    'revoked_at':None,
                    'expires_at':now+3600,
                    'certificate_id':'station-https',
                    'hostnames':['station.hosts.example.test'],
                    'contact_email':'acme@example.test',
                    'acme_directory':'https://acme.example.test/directory',
                    'challenge':'dns-01',
                    'dns_mode':'local-cloudflare',
                    'dns_zone':'hosts.example.test',
                    'credential_id':'cloudflare-station',
                    'credential_revision':1,
                    'consumer':'station-access',
                }
                signature=self.key.sign(
                    certificate_assignment._assignment_bytes(value)
                )
                import base64
                envelope={
                    'schema':certificate_assignment.ENVELOPE_SCHEMA,
                    'key_id':signatures.fingerprint(self.key.public_key()),
                    'assignment':value,
                    'signature':base64.b64encode(signature).decode(),
                }
                return {
                    'schema':certificate_assignment.RESPONSE_SCHEMA,
                    'host_id':self.host,
                    'state':'receipt',
                    'revision':1,
                    'envelope':envelope,
                }
            result=super().post(url,payload,key,subject,ca)
            if url.endswith('/heartbeat/') and self.approved:
                result['certificate_assignment']={'version':1}
            return result

    station=AssignmentStation();station.approved=True
    runtime=prepared(state)
    try:
        runtime.tick(station,{'version':1,'hostname':'host'})
        assert station.calls[-2].endswith('/heartbeat/')
        assert station.calls[-1].endswith('/certificate-assignment/')
        authority=signatures.public_key(
            runtime.saved['registries']['primary']['public_key']
        )
        saved=certificate_assignment.managed_read_state(
            runtime.journal.fd,
            authority,
            expected_host=station.host,
            expected_installation=B['bootstrap']['installation_id'],
        )
        assert saved['revision']==1
        assert saved['envelope']['assignment']['hostnames']==[
            'station.hosts.example.test'
        ]
    finally:
        runtime.close()



def test_managed_heartbeat_cannot_enable_credential_delivery(local):
    state,_=local

    class CredentialStation(Station):
        def post(self,url,payload,key,subject,ca):
            result=super().post(url,payload,key,subject,ca)
            if url.endswith('/heartbeat/') and self.approved:
                result['credential_delivery']={
                    'version':1,
                    'purpose':'administrator-bootstrap',
                }
            return result

    station=CredentialStation();station.approved=True
    runtime=prepared(state)
    try:
        with pytest.raises(StateError,match='credential-delivery-channel-denied'):
            runtime.tick(station,{'version':1,'hostname':'host'})
        assert state.fault=='credential-delivery-channel-denied'
        assert runtime.key is None
    finally:
        runtime.close()
