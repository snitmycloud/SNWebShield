"""Local execution: policy fencing, pure analysis, real HTTP fixture and Python IPC."""
import json
import socket
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4
import pytest
from sqlalchemy import select
from app.core.config import settings
from app.db.session import SessionLocal
from app.models.jobs import Job
from app.models.assessment import AssessmentReport
from app.services import assessments as service
from app.services import local_assessment_runtime as runtime
from app.services import assessment_broker as broker
from app.services.header_analyzer import analyze, ALLOWED
from test_authorization_correctness import api, NOW
from test_assessments import assessed

HEADERS={"content-security-policy":"default-src 'self'; frame-ancestors 'none'; script-src 'nonce-PRIVATE'",
    "strict-transport-security":"max-age=31536000", "x-frame-options":"DENY",
    "x-content-type-options":"nosniff", "referrer-policy":"strict-origin-when-cross-origin",
    "permissions-policy":"camera=()", "server":"PRIVATE-version"}
OBS={"status":200,"tls_verified":True,"connected_ip":"8.8.8.8","dns_addresses":["8.8.8.8"],
    "response_ms":1.2,"header_bytes":500,"certificate_not_after":None,"redirect_followed":False,
    "selected_headers":HEADERS.copy(),"facts":{}}

@pytest.fixture
def network(assessed,monkeypatch):
    monkeypatch.setattr(settings,'assessment_local_http_enabled',True)
    api,auth,site,key,body=assessed
    body={**body,'profile_id':service.HTTP_PROFILE_ID,'network_permission_confirmed':True}
    return api,auth,body

def create(network):
    api,_,body=network
    r=api.post('/api/v1/assessments',json=body)
    assert r.status_code==201,r.text
    return r.json()

def fake_broker(monkeypatch):
    original=runtime.invoke
    def invoke(script,payload,permitted,seconds):
        assert permitted()
        if script=='assessment_broker.py':return {'result':{**OBS,'selected_headers':HEADERS.copy()}}
        return original(script,payload,permitted,seconds)
    monkeypatch.setattr(runtime,'invoke',invoke)


def test_local_worker_uses_real_analyzer_and_private_report(network,monkeypatch):
    fake_broker(monkeypatch);row=create(network);service.worker_tick()
    api,auth,body=network
    detail=api.get(f"/api/v1/assessments/{row['id']}").json()
    assert detail['job']['status']=='completed',detail
    assert detail['result']['payload']['findings_created']==0
    download=api.get(f"/api/v1/assessments/{row['id']}/report/download")
    assert download.status_code==200,download.text
    assert 'PRIVATE' not in download.text
    assert download.json()['evidence']
    assert download.json()['analysis']['confirmed_findings']==0
    assert download.headers['cache-control']=='no-store, private'
    with SessionLocal() as db:
        report=db.scalar(select(AssessmentReport));report.sha256='0'*64;db.commit()
    assert api.get(f"/api/v1/assessments/{row['id']}/report/download").status_code==409
    api.headers.pop('Authorization')
    assert api.get(f"/api/v1/assessments/{row['id']}/report/download").status_code==401


@pytest.mark.parametrize('change,expected', [('disabled','local_http_disabled'),('consent','explicit_network_permission_required'),('method','profile_methods_not_authorized')])
def test_request_policy(network,monkeypatch,change,expected):
    api,auth,body=network
    if change=='disabled':monkeypatch.setattr(settings,'assessment_local_http_enabled',False)
    elif change=='consent':body={**body,'network_permission_confirmed':False}
    else:
        from app.models.authorization import WebsiteAuthorization
        with SessionLocal() as db:db.get(WebsiteAuthorization,auth).permitted_methods=['passive_reconnaissance'];db.commit()
    response=api.post('/api/v1/assessments',json=body)
    assert response.status_code==409;assert expected in response.text


def test_revoked_before_or_during_execution_never_records_report(network,monkeypatch):
    row=create(network);api,auth,_=network
    def execute(url,permitted):
        assert api.post(f'/api/v1/authorizations/{auth}/revoke',json={'reason':'Withdraw synthetic local permission during execution.'}).status_code==200
        assert not permitted()
        raise RuntimeError('cancelled')
    monkeypatch.setattr(runtime.ADAPTERS['local-python-v1'],'execute',execute)
    service.worker_tick()
    with SessionLocal() as db:
        assert db.get(Job,row['job_id']).status=='cancelled'
        assert db.scalar(select(AssessmentReport)) is None


def test_runtime_failure_is_failed_not_completed(network,monkeypatch):
    row=create(network)
    def fail(*args):raise OSError('synthetic')
    monkeypatch.setattr(runtime.ADAPTERS['local-python-v1'],'execute',fail)
    service.worker_tick()
    with SessionLocal() as db:
        assert db.get(Job,row['job_id']).status=='failed'
        assert db.scalar(select(AssessmentReport)) is None


def test_http_request_cooldown_and_replay(network):
    api,auth,body=network;row=create(network)
    assert api.post('/api/v1/assessments',json=body).json()['id']==row['id']
    assert api.post(f"/api/v1/assessments/{row['id']}/cancel",json={'reason':'Cancel synthetic test before network.'}).status_code==200
    r=api.post('/api/v1/assessments',json={**body,'idempotency_key':str(uuid4())})
    assert r.status_code==429


@pytest.mark.parametrize('https', [True,False])
def test_pure_analyzer_never_uses_network(monkeypatch,https):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a:pytest.fail('Unexpected DNS'))
    result=analyze({'status':200,'https':https,'headers':HEADERS})
    assert len(result['observations'])==8
    assert all(o['confirmed_vulnerability'] is False for o in result['observations'])
    assert 'PRIVATE' not in json.dumps(result)


@pytest.mark.parametrize('headers',[{'cookie':'secret'}, {'server':'x'*2049}, {'server':'bad\nheader'}, {'server':4},[]])
def test_analyzer_rejects_unselected_or_unbounded_data(headers):
    with pytest.raises(ValueError):analyze({'status':200,'https':True,'headers':headers})


def test_real_python_analysis_process_and_deadline():
    data={'status':200,'https':True,'headers':HEADERS}
    assert runtime.invoke('header_analyzer.py',data,lambda:True,5)==analyze(data)
    channel=runtime.Channel([__import__('sys').executable,'-I','-S','-c','import time;time.sleep(30)'])
    try:
        with pytest.raises(runtime.RuntimeFailure):channel.receive(.1,lambda:True)
    finally:channel.close()
    assert channel.process.poll() is not None


def test_real_broker_child_blocks_loopback():
    result=runtime.invoke('assessment_broker.py',{'url':'http://127.0.0.1/'},lambda:True,5)
    assert result=={'error':'prohibited_destination'}


@pytest.mark.parametrize('path,status',[('/',200),('/redirect',302),('/down',503)])
def test_real_head_never_follows_redirect_or_saves_headers(monkeypatch,path,status):
    hits=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*a):pass
        def do_HEAD(self):
            hits.append((self.command,self.path,self.headers['Host']))
            self.send_response(status);self.send_header('Location','http://127.0.0.1/private')
            self.send_header('Permissions-Policy','camera=()');self.send_header('Set-Cookie','PRIVATE')
            self.end_headers()
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    monkeypatch.setattr(broker.policy,'resolve',lambda host,port:[(socket.AF_INET,('127.0.0.1',server.server_port))])
    try:result=broker.collect('http://synthetic.example'+path,lambda:True)
    finally:server.shutdown();server.server_close();thread.join()
    assert hits==[('HEAD',path,'synthetic.example')]
    assert result['status']==status and result['redirect_followed'] is False
    assert 'set-cookie' not in result['selected_headers']
    assert result['selected_headers']['permissions-policy']=='camera=()'


@pytest.mark.parametrize('address',['127.0.0.1','10.0.0.1','169.254.169.254','::1','::ffff:8.8.8.8','2002:0808:0808::'])
def test_public_destination_policy(address,monkeypatch):
    monkeypatch.setattr(broker.policy.socket,'getaddrinfo',lambda *a,**k:[(socket.AF_INET,socket.SOCK_STREAM,6,'',(address,80))])
    with pytest.raises(broker.policy.Blocked):broker.policy.resolve('synthetic.example',80)


def test_mixed_public_private_dns_rejected(monkeypatch):
    monkeypatch.setattr(broker.policy.socket,'getaddrinfo',lambda *a,**k:[
        (socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',80)),
        (socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',80))])
    with pytest.raises(broker.policy.Blocked):broker.policy.resolve('synthetic.example',80)


def test_network_attestation_and_profile_bound_to_live_permission(network,monkeypatch):
    row=create(network)
    from app.models.assessment import AssessmentRequest
    with SessionLocal() as db:
        intent=db.get(AssessmentRequest,row['id'])
        intent.execution_snapshot={**intent.execution_snapshot,'confirmed_by':99999};db.commit()
    monkeypatch.setattr(runtime.ADAPTERS['local-python-v1'],'execute',lambda *a:pytest.fail('Must not execute'))
    service.worker_tick()
    with SessionLocal() as db:assert db.get(Job,row['job_id']).status=='cancelled'
