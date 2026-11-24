"""Assessment control plane; synthetic permissions, no tools or target traffic."""
from datetime import timedelta
from uuid import uuid4
import pytest
from sqlalchemy import select, func, event
from app.db.session import SessionLocal
from app.models import Admin, Website, WebsiteAuthorization, AuthorizationAuditEvent
from app.models.assessment import AssessmentRequest
from app.models.evidence import AuthorizationEvidence, EvidenceReview
from app.models.jobs import Job, JobResult, ExecutionEvent
from app.services import assessments as service, job_engine as engine, evidence
from test_authorization_correctness import api, seed_record, NOW, APPROVAL
from evidence_helpers import attach_review

@pytest.fixture
def assessed(api, monkeypatch):
    monkeypatch.setattr(service, 'utc_now', lambda: NOW)
    monkeypatch.setattr(engine, 'utc_now', lambda: NOW)
    auth,site=seed_record()
    with SessionLocal() as db:
        db.get(WebsiteAuthorization,auth).permitted_methods=['automated_non_intrusive_scanning'];db.commit()
    key=attach_review(api,auth)
    assert api.post(f'/api/v1/authorizations/{auth}/approve',json=APPROVAL).status_code==200
    body=dict(website_id=site,authorization_id=auth,profile_id=service.PROFILE_ID,
        explicitly_requested=True,note='Request synthetic network-free permission preflight.',idempotency_key=str(uuid4()))
    return api,auth,site,key,body


def create(data):
    api,_,_,_,body=data
    r=api.post('/api/v1/assessments',json=body)
    assert r.status_code==201,r.text
    return r.json()


def test_explicit_and_network_free(assessed,monkeypatch):
    import socket,subprocess
    api,auth,site,key,body=assessed
    with SessionLocal() as db:
        engine.scheduler_tick(db)
        assert not list(db.scalars(select(Job).where(Job.job_type=='assessment')))
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:pytest.fail('Unexpected DNS'))
    monkeypatch.setattr(subprocess,'Popen',lambda *a,**k:pytest.fail('Unexpected subprocess'))
    row=create(assessed);assert row['job']['status']=='queued';assert row['job']['max_attempts']==1
    service.worker_tick()
    final=api.get(f"/api/v1/assessments/{row['id']}").json()
    assert final['job']['status']=='completed'
    assert final['result']['payload']['network_execution'] is False
    assert final['result']['payload']['outcome']=='permission_preflight_passed'
    assert final['result']['payload']['findings_created']==0
    assert 'claim_token' not in final['job']
    assert len(api.get(f"/api/v1/assessments/{row['id']}/attempts").json())==1


@pytest.mark.parametrize('field,value,reason',[
    ('status','pending','not_currently_approved'),('status','revoked','not_currently_approved'),
    ('status','rejected','not_currently_approved'),('timestamps_verified',False,'not_currently_approved'),
    ('valid_until',NOW,'outside_validity_window'),('valid_from',NOW+timedelta(seconds=1),'outside_validity_window'),
    ('authorized_domains',['other.example.com'],'exact_domain_not_authorized'),
    ('authorized_domains',['*.example.com'],'exact_domain_not_authorized'),
    ('permitted_methods',['passive_reconnaissance'],'methods_not_authorized')])
def test_denied_permission(assessed,field,value,reason):
    api,auth,site,key,body=assessed
    with SessionLocal() as db:setattr(db.get(WebsiteAuthorization,auth),field,value);db.commit()
    r=api.post('/api/v1/assessments',json=body)
    assert r.status_code==409;assert reason in r.text
    with SessionLocal() as db:
        assert not list(db.scalars(select(AssessmentRequest)))
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action=='assessment_request_denied'))


@pytest.mark.parametrize('mutation',['approval','no_review_id','review','revision','withdrawn','missing','tampered','client'])
def test_evidence_gate(assessed,mutation):
    api,auth,site,key,body=assessed
    with SessionLocal() as db:
        approval=db.scalar(select(AuthorizationAuditEvent));doc=db.get(AuthorizationEvidence,key)
        if mutation=='approval':db.delete(approval)
        elif mutation=='no_review_id':approval.evidence_review_id=None
        elif mutation=='review':db.delete(db.get(EvidenceReview,approval.evidence_review_id))
        elif mutation=='revision':db.get(WebsiteAuthorization,auth).evidence_revision+=1
        elif mutation=='withdrawn':doc.state='withdrawn'
        elif mutation=='missing':evidence.stored_path(key).unlink()
        elif mutation=='tampered':evidence.stored_path(key).write_bytes(b'tampered')
        elif mutation=='client':doc.client_id+=999
        db.commit()
    assert api.post('/api/v1/assessments',json=body).status_code==409


@pytest.mark.parametrize('change',[dict(explicitly_requested=False),dict(note='short'),dict(command='nmap'),dict(target_url='https://other.example')])
def test_request_schema(assessed,change):
    api,_,_,_,body=assessed
    assert api.post('/api/v1/assessments',json={**body,**change}).status_code==422


def test_unknown_profile_and_wrong_website(assessed):
    api,auth,site,key,body=assessed
    assert api.post('/api/v1/assessments',json={**body,'profile_id':'arbitrary-tool'}).status_code==409
    _,other=seed_record()
    assert api.post('/api/v1/assessments',json={**body,'website_id':other}).status_code==409
    profiles=api.get('/api/v1/assessments/profiles').json()
    assert len(profiles)==4;assert profiles[0]['network_execution'] is False


def test_idempotency_and_active_limit(assessed):
    api,_,_,_,body=assessed;row=create(assessed)
    assert create(assessed)['id']==row['id']
    assert api.post('/api/v1/assessments',json={**body,'note':'Different valid request description.'}).status_code==409
    assert api.post('/api/v1/assessments',json={**body,'idempotency_key':str(uuid4())}).status_code==409
    service.worker_tick()
    assert create(assessed)['id']==row['id']
    assert api.post('/api/v1/assessments',json={**body,'idempotency_key':str(uuid4())}).status_code==201


@pytest.mark.parametrize('mutation',['expiry','scope','method','url','revision','profile','requester','snapshot'])
def test_recheck_at_execution(assessed,monkeypatch,mutation):
    api,auth,site,key,body=assessed;row=create(assessed)
    with SessionLocal() as db:
        record=db.get(WebsiteAuthorization,auth)
        if mutation=='expiry':monkeypatch.setattr(service,'utc_now',lambda:NOW+timedelta(hours=2))
        elif mutation=='scope':record.authorized_domains=['different.example.com']
        elif mutation=='method':record.permitted_methods=['passive_reconnaissance']
        elif mutation=='url':db.get(Website,site).url='https://other.example.com'
        elif mutation=='revision':record.evidence_revision+=1
        elif mutation=='profile':monkeypatch.setitem(service.PROFILES[service.PROFILE_ID],'version',2)
        elif mutation=='requester':db.get(Admin,api.admin_id).is_active=False
        elif mutation=='snapshot':db.get(AssessmentRequest,row['id']).target_url='https://changed.example.com'
        db.commit()
    service.worker_tick()
    with SessionLocal() as db:
        assert db.get(Job,row['job_id']).status=='cancelled'
        assert db.get(JobResult,row['job_id']).payload['state']=='cancelled'
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.job_id==row['job_id'],ExecutionEvent.action=='assessment_permission_denied'))


@pytest.mark.parametrize('action',['cancel','revoke'])
def test_cancel_late_result(assessed,action):
    api,auth,site,key,body=assessed;row=create(assessed)
    with SessionLocal() as db:claimed=engine.claim(db,'assessment')
    if action=='revoke':r=api.post(f'/api/v1/authorizations/{auth}/revoke',json={'reason':'Withdraw synthetic assessment permission.'})
    else:r=api.post(f"/api/v1/assessments/{row['id']}/cancel",json={'reason':'Cancel synthetic assessment request.'})
    assert r.status_code==200
    with SessionLocal() as db:
        assert db.get(Job,row['job_id']).status=='cancelled'
        assert not engine.finish(db,*claimed,{'state':'up','mode':'policy_only','network_execution':False})
        assert db.get(JobResult,row['job_id']) is None


def test_expired_lease_no_retry(assessed):
    row=create(assessed)
    with SessionLocal() as db:
        old=engine.claim(db,'assessment',NOW);assert old
        assert engine.claim(db,'assessment',NOW) is None
        lease=engine.lease_seconds('assessment')
        assert engine.claim(db,'assessment',NOW+timedelta(seconds=lease-1)) is None
        assert db.get(Job,row['job_id']).status=='running'
        assert engine.claim(db,'assessment',NOW+timedelta(seconds=lease+1)) is None
        assert db.get(Job,row['job_id']).status=='failed'
        assert not engine.finish(db,*old,{'state':'up','mode':'policy_only','network_execution':False},NOW+timedelta(seconds=lease+2))


def test_audit_failure_rolls_back_request_and_result(assessed):
    from app.api.routes.assessments import CreateRequest
    api,auth,site,key,body=assessed
    def reject(session,context,instances):
        if any(isinstance(x,ExecutionEvent) for x in session.new):raise RuntimeError('Synthetic audit failure')
    with SessionLocal() as db:
        event.listen(db,'before_flush',reject)
        with pytest.raises(RuntimeError):service.create_request(db,api.admin_id,CreateRequest(**body))
        event.remove(db,'before_flush',reject)
    with SessionLocal() as db:assert db.scalar(select(func.count()).select_from(AssessmentRequest))==0
    row=create(assessed)
    with SessionLocal() as db:
        claimed=engine.claim(db,'assessment');event.listen(db,'before_flush',reject)
        with pytest.raises(RuntimeError):engine.finish(db,*claimed,{'state':'up','mode':'policy_only','network_execution':False})
        db.rollback();event.remove(db,'before_flush',reject)
        assert db.get(Job,row['job_id']).status=='running';assert db.get(JobResult,row['job_id']) is None


def test_authentication_and_pagination(assessed):
    api,auth,site,key,body=assessed;row=create(assessed)
    assert len(api.get(f'/api/v1/assessments?website_id={site}&limit=1').json())==1
    assert api.get('/api/v1/assessments?offset=1').json()==[]
    assert api.get('/api/v1/assessments?limit=101').status_code==422
    api.headers.pop('Authorization')
    for path in ['', '/profiles', '/worker-status', f"/{row['id']}", f"/{row['id']}/events"]:
        assert api.get('/api/v1/assessments'+path).status_code==401
    assert api.post('/api/v1/assessments',json=body).status_code==401


@pytest.mark.parametrize('url',['http://127.0.0.1','https://[::1]','https://metadata.internal','http://public.example:8080','http://user:pass@public.example'])
def test_static_destination_policy(assessed,url):
    api,auth,site,key,body=assessed
    with SessionLocal() as db:
        db.get(Website,site).url=url;db.commit()
    r=api.post('/api/v1/assessments',json=body)
    assert r.status_code==409;assert 'unsupported_assessment_destination' in r.text


def test_competing_requests_have_one_winner(assessed):
    from concurrent.futures import ThreadPoolExecutor
    from fastapi import HTTPException
    from app.api.routes.assessments import CreateRequest
    api,auth,site,key,body=assessed
    def submit(i):
        with SessionLocal() as db:
            try:
                service.create_request(db,api.admin_id,CreateRequest(**{**body,'idempotency_key':str(uuid4())}))
                return 201
            except HTTPException as exc:return exc.status_code
    with ThreadPoolExecutor(max_workers=2) as workers:results=list(workers.map(submit,range(2)))
    assert sorted(results)==[201,409]
    with SessionLocal() as db:assert db.scalar(select(func.count()).select_from(AssessmentRequest))==1


def test_separate_pool_and_concurrent_claims(assessed):
    from concurrent.futures import ThreadPoolExecutor
    api,auth,site,key,body=assessed;row=create(assessed)
    with SessionLocal() as db:
        engine.enqueue(db,'monitoring',site,1,'synthetic-other-pool',NOW);db.commit()
        monitor=engine.claim(db,'monitoring',NOW);assert monitor
    def claim(_):
        with SessionLocal() as db:return engine.claim(db,'assessment',NOW)
    with ThreadPoolExecutor(max_workers=2) as workers:claims=list(workers.map(claim,range(2)))
    assert sum(x is not None for x in claims)==1


def test_revocation_audit_failure_preserves_job(assessed):
    from app.services.authorizations import decide_authorization
    api,auth,site,key,body=assessed;row=create(assessed)
    def reject(session,context,instances):
        if any(isinstance(x,AuthorizationAuditEvent) for x in session.new):raise RuntimeError('Synthetic revoke audit failure')
    with SessionLocal() as db:
        event.listen(db,'before_flush',reject)
        with pytest.raises(RuntimeError):decide_authorization(db,auth,api.admin_id,'revoked','Withdraw synthetic permission.',now=NOW)
        event.remove(db,'before_flush',reject)
    with SessionLocal() as db:
        assert db.get(WebsiteAuthorization,auth).status=='approved'
        assert db.get(Job,row['job_id']).status=='queued'
        assert not db.scalar(select(ExecutionEvent).where(ExecutionEvent.job_id==row['job_id'],ExecutionEvent.action=='assessment_cancelled'))


def test_valid_from_inclusive_and_missing_client_denied(assessed):
    api,auth,site,key,body=assessed
    with SessionLocal() as db:
        db.get(WebsiteAuthorization,auth).valid_from=NOW;db.commit()
    row=create(assessed)
    assert api.post(f"/api/v1/assessments/{row['id']}/cancel",json={'reason':'Cancel boundary test preflight.'}).status_code==200
    with SessionLocal() as db:
        db.get(Website,site).client_id=999999;db.commit()
    assert api.post('/api/v1/assessments',json={**body,'idempotency_key':str(uuid4())}).status_code==409


def test_concurrent_idempotent_replay(assessed):
    from concurrent.futures import ThreadPoolExecutor
    from app.api.routes.assessments import CreateRequest
    api,auth,site,key,body=assessed
    def submit(_):
        with SessionLocal() as db:return service.create_request(db,api.admin_id,CreateRequest(**body)).id
    with ThreadPoolExecutor(max_workers=2) as workers:ids=list(workers.map(submit,range(2)))
    assert ids[0]==ids[1]


def test_database_enforces_one_active_assessment(assessed):
    from sqlalchemy.exc import IntegrityError
    api,auth,site,key,body=assessed;create(assessed)
    with SessionLocal() as db:
        with pytest.raises(IntegrityError):engine.enqueue(db,'assessment',site,1,'different-explicit-key',NOW)
        db.rollback()


def test_independent_cli_worker_reads_durable_intent(assessed):
    from datetime import datetime, UTC
    from pathlib import Path
    import subprocess, sys
    api,auth,site,key,body=assessed
    actual=datetime.now(UTC)
    with SessionLocal() as db:
        record=db.get(WebsiteAuthorization,auth)
        record.valid_from=min(NOW,actual)-timedelta(days=1)
        record.valid_until=max(NOW,actual)+timedelta(days=1)
        db.commit()
    row=create(assessed)
    result=subprocess.run([sys.executable,'-m','app.cli.operations','assessment-worker','--once'],
        cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stderr
    with SessionLocal() as db:
        assert db.get(Job,row['job_id']).status=='completed'
        assert db.get(JobResult,row['job_id']).payload['network_execution'] is False
