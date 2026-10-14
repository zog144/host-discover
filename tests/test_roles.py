import json
import time
import uuid
from pathlib import Path
from unittest.mock import patch
import pytest
from zog.host_discover.roles import Controller, validate
from zog.host_discover.daemon import announce
from zog.host_identify import storage,signatures
from test_signed_daemon import configuration,Response


def intent(selected=True,revision=1):
    return {'desired':{'version':1,'revision':revision,'selected':selected,'endpoint':'https://mirror.example.test' if selected else '',
        'retain_archives':True,'lease_expires_at':int(time.time())+900},'candidates':[]}

class Adapter:
    def __init__(self):
        self.starts=[]
        self.cancels=[]
        self.terminations=[]
        self.present=True
        self.prepared=True
        self.preflight_status='ready-to-attempt'
        self.runtime='running'
        self.serving=True
        self.failure=False
        self.termination_failure=False
        self.issued=0
        self.results={}

    def available(self):return self.present
    def preparation(self):return {'state':'ready' if self.prepared else 'pending'}
    def preflight(self):return {'status':self.preflight_status,'advisory':True,'checks':[]}
    def issue(self):
        self.issued+=1
        return 'request-'+str(self.issued)
    def start(self,request):
        self.starts.append(request)
        self.results[request]={'status':'satisfied','request_id':request,'runtime_id':'runtime-1'}
        self.runtime='running'
        if self.failure:raise RuntimeError('DO-NOT-LOG')
        return 'runtime-1'
    def result(self,request):
        return self.results.get(request,{'status':'unknown','request_id':request,'runtime_id':None})
    def cancel(self,request):
        self.cancels.append(request)
        result=self.results.get(request)
        if result and result.get('runtime_id'):
            return {'status':'accepted','request_id':request,'runtime_id':result['runtime_id']}
        return {'status':'cancelled','request_id':request,'runtime_id':None}
    def terminate(self,runtime,request):
        self.terminations.append((runtime,request))
        if self.termination_failure:raise RuntimeError('fixture termination unavailable')
        self.runtime='stopped'
    def runtime_state(self,runtime):return self.runtime
    def running(self,runtime):
        if self.runtime=='running':return True
        if self.runtime in {'stopped','failed','stale'}:return False
        return None
    def ready(self,*args):return self.serving


def test_restart_idempotence_lease_expiry_and_retained_archives(configuration,tmp_path):
    adapter=Adapter();host=str(uuid.uuid4());c=Controller(configuration,adapter)
    archive=tmp_path/'retained-archive.tar';archive.write_text('retained')
    assert c.tick(host,intent())['state']=='ready'
    assert len(adapter.starts)==1
    assert Controller(configuration,adapter).tick()['state']=='ready'
    assert len(adapter.starts)==1
    with patch('zog.host_discover.roles.time.time',return_value=time.time()+901):assert c.tick()['state']=='stopped'
    assert len(adapter.terminations)==1;assert archive.read_text()=='retained'
    assert adapter.terminations[0][1]=='request-2'
    assert c.path.stat().st_mode&0o777==0o600


def test_assignment_removal_restart_and_rollback(configuration):
    a=Adapter();c=Controller(configuration,a);host=str(uuid.uuid4())
    c.tick(host,intent());assert c.tick(host,intent(False,2))['state']=='stopped'
    assert len(a.terminations)==1
    with pytest.raises(ValueError):c.tick(host,intent(True,1))
    assert c.tick(host,intent(True,3))['state']=='ready';assert a.issued==3
    value=intent(True,3);value['desired']['endpoint']='https://different.example.test'
    with pytest.raises(ValueError):c.tick(host,value)


def test_uncertain_start_reuses_identity_and_withdraw_cancels(configuration):
    a=Adapter();a.failure=True;c=Controller(configuration,a);host=str(uuid.uuid4())
    first=c.tick(host,intent())
    assert first['state']=='starting' and first['reason']=='start-uncertain'
    retained=c.load()['request_id']
    a.failure=False
    assert Controller(configuration,a).tick()['state']=='ready'
    assert a.starts==[retained]
    assert c.tick(withdraw=True)['state']=='stopped'
    assert a.cancels[-1]==retained
    assert a.terminations[-1][0]=='runtime-1'
    assert c.tick()['state']=='stopped'


def test_blocked_missing_bridge_application_and_failed_probe(configuration):
    host=str(uuid.uuid4());c=Controller(configuration)
    assert c.tick(host,intent())['reason']=='bridge-unconfigured'
    a=Adapter();a.present=False;c=Controller(configuration,a)
    assert c.tick()['reason']=='application-missing';assert not a.starts
    a.present=True;a.serving=False;assert c.tick()['state']=='running'
    a.runtime='failed';assert c.tick()['state']=='failed'


def test_malformed_roles_cannot_start(configuration):
    a=Adapter();c=Controller(configuration,a);d=intent();d['desired']['retain_archives']=False
    with pytest.raises(ValueError):c.tick(str(uuid.uuid4()),d)
    assert not a.starts
    d=intent();d['desired']['endpoint']='http://evil.example'
    with pytest.raises(ValueError):validate(d)


def test_station_login_sent_only_after_binding_and_protected_file(configuration):
    root=Path(configuration['identity_directory']);source=root/'station-login.json'
    storage.atomic(source,json.dumps({'username':'station-admin','password':'SYNTHETIC-TEST-SECRET'}).encode())
    configuration['station_login_file']=str(source)
    key=storage.load_key(root);fp=signatures.fingerprint(key.public_key());host=str(uuid.uuid4())
    with patch('urllib.request.OpenerDirector.open',return_value=Response({'status':'pending'},202)) as open:
        announce(configuration,{'version':1});assert b'SYNTHETIC' not in open.call_args.args[0].data
    storage.atomic(root/'binding.json',json.dumps({'host_id':host,'fingerprint':fp}).encode())
    with patch('urllib.request.OpenerDirector.open',return_value=Response({'version':2,'host_id':host,'archive':None,'mirror_roles':intent(False,0)})) as open:
        announce(configuration,{'version':1});request=open.call_args.args[0]
        assert json.loads(request.data)['station_login']['password']=='SYNTHETIC-TEST-SECRET'
        signatures.verify(request.full_url,'POST',dict(request.header_items()),request.data,key.public_key(),host)
        source.chmod(0o644);announce(configuration,{'version':1});assert 'station_login' not in json.loads(open.call_args.args[0].data)
        configuration['station_login_withdraw']=True;announce(configuration,{'version':1});assert json.loads(open.call_args.args[0].data)['station_login'] is None


def test_box_bridge_required_members_and_probe():
    from zog.host_discover.box_bridge import BoxBridge
    from unittest.mock import Mock
    bridge=object.__new__(BoxBridge);bridge.control=Mock();bridge.required=['server','refresh-scheduler']
    p=lambda name,state:{'program':name,'status':'observed','observation':{'active_state':state}}
    bridge.control.observe_application_runtime.return_value={'status':'observed','programs':[p('server','active')]}
    assert bridge.running('r') is None
    bridge.control.observe_application_runtime.return_value['programs'].append(p('refresh-scheduler','active'))
    assert bridge.running('r')
    bridge.control.observe_application_runtime.return_value['status']='partial';assert bridge.running('r') is None


def test_confirmed_failure_restarts_after_backoff_but_unknown_observation_does_not(configuration):
    a=Adapter();c=Controller(configuration,a);host=str(uuid.uuid4());c.tick(host,intent())
    a.runtime=None;assert c.tick()['reason']=='runtime-unavailable';assert not a.terminations
    a.runtime='failed';assert c.tick()['state']=='failed';assert len(a.terminations)==1
    a.runtime='running';assert c.tick()['state']=='failed';assert len(a.starts)==1
    with patch('zog.host_discover.roles.time.time',return_value=time.time()+61):
        assert c.tick()['state']=='ready'
    assert len(a.starts)==2;assert a.starts[0]!=a.starts[1]


def test_failed_stop_retries_same_owned_runtime_and_termination_identity(configuration):
    a=Adapter();c=Controller(configuration,a);host=str(uuid.uuid4());c.tick(host,intent())
    a.termination_failure=True
    result=c.tick(host,intent(False,2))
    assert result['state']=='stopping'
    retained=c.load()
    assert retained['runtime_id']=='runtime-1'
    termination_id=retained['termination_request_id']
    assert a.terminations[-1]==('runtime-1',termination_id)
    a.termination_failure=False
    assert Controller(configuration,a).tick()['state']=='stopped'
    assert a.terminations[-1]==('runtime-1',termination_id)


def test_old_response_cannot_overwrite_shared_intent(configuration):
    a=Adapter();c=Controller(configuration,a);host=str(uuid.uuid4());c.tick(host,intent(True,2))
    target=Path(configuration['credential_directory'])/'mirror-intent.json';original=target.read_bytes()
    with pytest.raises(ValueError):Controller(configuration,a).tick(host,intent(False,1))
    assert target.read_bytes()==original
    assert target.stat().st_mode&0o777==0o640


def test_narrow_live_export_tracks_replacement_and_revocation(configuration, tmp_path, monkeypatch):
    from zog.host_discover import roles
    export = tmp_path / 'host-exports' / 'mirror-live'
    export.mkdir(parents=True, mode=0o750)
    export.chmod(0o750)
    monkeypatch.setattr(roles, '_LIVE_EXPORT_ROOTS', (str(tmp_path / 'host-exports') + '/',))
    configuration['mirror_live_export_directory'] = str(export)
    adapter = Adapter(); controller = Controller(configuration, adapter)
    host = str(uuid.uuid4())
    controller.tick(host, intent(True, 1))
    published = export / 'mirror-intent.json'
    assert published.exists()
    first = json.loads(published.read_text())
    assert first['host_id'] == host and first['desired']['selected'] is True
    assert published.stat().st_mode & 0o777 == 0o640
    assert not (export / 'identity.pem').exists()
    assert not (export / 'archive.json').exists()
    first_inode = published.stat().st_ino
    controller.tick(host, intent(True, 2))
    second = json.loads(published.read_text())
    assert second['desired']['revision'] == 2
    assert published.stat().st_ino != first_inode
    assert controller.tick(withdraw=True)['state'] == 'stopped'
    withdrawn = json.loads(published.read_text())
    assert withdrawn['desired']['lease_expires_at'] == 0


def test_live_export_missing_or_unsafe_blocks_without_exposing_private_state(configuration, tmp_path, monkeypatch):
    from zog.host_discover import roles
    export = tmp_path / 'host-exports' / 'mirror-live'
    export.mkdir(parents=True, mode=0o750)
    export.chmod(0o750)
    monkeypatch.setattr(roles, '_LIVE_EXPORT_ROOTS', (str(tmp_path / 'host-exports') + '/',))
    configuration['mirror_live_export_directory'] = str(export)
    a = Adapter(); host = str(uuid.uuid4()); controller = Controller(configuration, a)
    export.chmod(0o777)
    denied = controller.tick(host, intent())
    assert denied['state'] == 'blocked'
    assert denied['reason'] == 'state-unavailable'
    assert not a.starts
    export.chmod(0o750)
    assert controller.tick()['state'] == 'ready'
    assert len(a.starts) == 1
    export.rename(tmp_path / 'moved')
    assert controller.tick(withdraw=True)['state'] == 'blocked'
    assert a.terminations and a.terminations[0][0] == 'runtime-1'
    assert not (tmp_path / 'moved' / 'archive.json').exists()


def test_mirror_live_export_denies_relative_and_parent_escape(configuration, tmp_path, monkeypatch):
    from zog.host_discover import roles
    base = tmp_path / 'host-exports'
    base.mkdir()
    export = base / 'mirror-live'
    export.mkdir(mode=0o750); export.chmod(0o750)
    monkeypatch.setattr(roles, '_LIVE_EXPORT_ROOTS', (str(base) + '/',))
    configuration['mirror_live_export_directory'] = str(base / '..' / 'unapproved')
    a = Adapter()
    status = Controller(configuration, a).tick(str(uuid.uuid4()), intent())
    assert status['state'] == 'blocked'
    assert status['reason'] == 'state-unavailable'
    assert not a.starts


def test_preparation_and_preflight_block_before_issuing_request(configuration):
    a=Adapter();c=Controller(configuration,a);host=str(uuid.uuid4())
    a.prepared=False
    value=c.tick(host,intent())
    assert value=={'revision':1,'state':'blocked','reason':'operation-pending','runtime_id':''}
    assert a.issued==0 and not a.starts
    a.prepared=True;a.preflight_status='blocked'
    value=c.tick()
    assert value['state']=='blocked' and value['reason']=='configuration-invalid'
    assert a.issued==0 and not a.starts


def test_unknown_lost_launch_is_cancelled_before_a_new_identity(configuration):
    class Lost(Adapter):
        def start(self,request):
            self.starts.append(request)
            raise RuntimeError('lost reply')
    a=Lost();c=Controller(configuration,a);host=str(uuid.uuid4())
    first=c.tick(host,intent())
    assert first['state']=='starting' and first['reason']=='start-uncertain'
    original=c.load()['request_id']
    second=Controller(configuration,a).tick()
    assert second['state']=='failed' and second['reason']=='runtime-failed'
    assert a.cancels==[original]
    assert 'request_id' not in c.load()
    a.start=Adapter.start.__get__(a,Adapter)
    assert c.tick()['state']=='ready'
    assert c.load()['request_id']!=original


def test_prior_boot_runtime_is_stale_not_serving_then_reselected(configuration):
    a=Adapter();c=Controller(configuration,a);host=str(uuid.uuid4())
    assert c.tick(host,intent())['state']=='ready'
    first_request=c.load()['request_id']
    a.runtime='stale'
    value=c.tick()
    assert value['state']=='blocked' and value['reason']=='runtime-unavailable'
    assert a.terminations and a.terminations[-1][0]=='runtime-1'
    assert 'request_id' not in c.load()
    assert c.tick()['state']=='ready'
    assert c.load()['request_id']!=first_request


def test_unavailable_broker_is_blocked_without_new_request(configuration):
    from zog.host_discover.box_bridge import BridgeError
    class Offline(Adapter):
        def available(self):raise BridgeError('controller-unavailable')
    a=Offline();c=Controller(configuration,a);host=str(uuid.uuid4())
    value=c.tick(host,intent())
    assert value['state']=='blocked'
    assert value['reason']=='state-unavailable'
    assert a.issued==0 and not a.starts


def test_withdrawal_racing_unaccepted_launch_cancels_without_termination(configuration):
    class Pending(Adapter):
        def start(self,request):
            self.starts.append(request)
            raise RuntimeError('lost before acceptance evidence')
    a=Pending();c=Controller(configuration,a);host=str(uuid.uuid4())
    assert c.tick(host,intent())['reason']=='start-uncertain'
    request_id=c.load()['request_id']
    assert c.tick(withdraw=True)['state']=='stopped'
    assert a.cancels==[request_id]
    assert not a.terminations


def test_selected_scheduler_failure_is_failure_but_withdrawal_is_expected_stop(configuration):
    a=Adapter();c=Controller(configuration,a);host=str(uuid.uuid4())
    assert c.tick(host,intent())['state']=='ready'
    a.runtime='failed'
    failed=c.tick()
    assert failed['state']=='failed' and failed['reason']=='runtime-failed'
    # A new selection can recover after the bounded backoff.
    a.runtime='running'
    with patch('zog.host_discover.roles.time.time',return_value=time.time()+61):
        assert c.tick()['state']=='ready'
    withdrawn=c.tick(withdraw=True)
    assert withdrawn['state']=='stopped'
    assert withdrawn['reason']=='lease-withdrawn'


def test_new_lifecycle_reasons_stay_within_station_access_wire_vocabulary(configuration):
    allowed={
        '', 'application-missing', 'runtime-unavailable',
        'bridge-unconfigured', 'lease-expired', 'probe-failed',
        'runtime-failed', 'identity-unapproved', 'configuration-invalid',
        'operation-pending', 'lease-withdrawn', 'state-unavailable',
        'start-uncertain',
    }
    a=Adapter();c=Controller(configuration,a);host=str(uuid.uuid4())
    a.prepared=False
    assert c.tick(host,intent())['reason'] in allowed
    a.prepared=True;a.preflight_status='blocked'
    assert c.tick()['reason'] in allowed
