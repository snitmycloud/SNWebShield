"""Monitoring policy and durable engine tests; never contact external targets."""
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
import pytest
from sqlalchemy import select, func, event
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.models.jobs import Job, JobResult, JobAttempt, ExecutionEvent, ExecutionSlot
from app.models.monitoring import MonitoringConfig, MonitoringConsent, MonitoringIncident, NotificationDelivery
from app.models.evidence import AuthorizationEvidence
from app.services import monitoring as service, job_engine as engine
from app.cli import operations
from test_authorization_correctness import api, seed_record
from evidence_helpers import attach_review


def setup_site(api, **changes):
    authorization_id, website_id = seed_record()
    evidence_id = attach_review(api, authorization_id)
    payload = dict(evidence_id=evidence_id, consent_reference="SYNTHETIC-MONITOR-PERMISSION",
                   monitoring_permission_reviewed=True, expires_at=(utc_now()+timedelta(days=7)).isoformat(),
                   interval_seconds=60, failure_threshold=1)
    payload.update(changes)
    response = api.post(f"/api/v1/websites/{website_id}/monitoring/configure", json=payload)
    assert response.status_code == 200, response.text
    return website_id, evidence_id


def enable(api, key):
    response = api.post(f"/api/v1/websites/{key}/monitoring/enable")
    assert response.status_code == 200, response.text


def schedule(key, now):
    with SessionLocal() as db:
        config = db.get(MonitoringConfig, key)
        job = service.enqueue_due(db, config, now=now)
        assert job
        job_id = job.id
        db.commit()
        return job_id


def complete(state, now):
    with SessionLocal() as db:
        claimed = engine.claim(db, "monitoring", now)
        assert claimed
        assert engine.finish(db, *claimed, {"state":state,"response_ms":12,"http_status":200 if state=="up" else 503}, now)
        return claimed


def test_explicit_enable_and_admin_access(api):
    key, _ = setup_site(api)
    with SessionLocal() as db:
        service.scheduler_tick(db)
        assert not list(db.scalars(select(Job)))
    assert api.get("/api/v1/monitoring/overview").json()["websites"][0]["state"] == "disabled"
    enable(api,key)
    with SessionLocal() as db:
        service.scheduler_tick(db); service.scheduler_tick(db)
        assert db.scalar(select(func.count()).select_from(Job)) == 1
    assert api.post(f"/api/v1/websites/{key}/monitoring/check-now").status_code == 429
    api.headers.pop("Authorization")
    for path in ["/monitoring/overview", f"/websites/{key}/monitoring", f"/websites/{key}/monitoring/results"]:
        assert api.get("/api/v1"+path).status_code == 401
    assert api.post("/api/v1/monitoring/stop").status_code == 401


@pytest.mark.parametrize("changes", [dict(monitoring_permission_reviewed=False), dict(timeout_seconds=21),
    dict(interval_seconds=1), dict(expires_at="2099-01-01T00:00:00"),dict(expires_at="2020-01-01T00:00:00Z")])
def test_invalid_configuration(api, changes):
    authorization_id, key = seed_record(); evidence = attach_review(api,authorization_id)
    payload=dict(evidence_id=evidence,consent_reference="Synthetic permission",monitoring_permission_reviewed=True,
        expires_at=(utc_now()+timedelta(days=1)).isoformat()); payload.update(changes)
    assert api.post(f"/api/v1/websites/{key}/monitoring/configure",json=payload).status_code==422


def test_wrong_website_and_unreviewed_document(api):
    key,evidence=setup_site(api); _,other=seed_record()
    payload=dict(evidence_id=evidence,consent_reference="Synthetic permission",monitoring_permission_reviewed=True,
        expires_at=(utc_now()+timedelta(days=1)).isoformat())
    assert api.post(f"/api/v1/websites/{other}/monitoring/configure",json=payload).status_code==422
    with SessionLocal() as db:
        from app.models.evidence import EvidenceReview
        for row in db.scalars(select(EvidenceReview)): db.delete(row)
        db.commit()
    assert api.post(f"/api/v1/websites/{key}/monitoring/configure",json=payload).status_code==409


def test_retry_incident_recovery_and_idempotent_result(api,monkeypatch):
    key,_=setup_site(api);enable(api,key); now=utc_now(); job_id=schedule(key,now)
    first=complete("down",now)
    with SessionLocal() as db:
        assert db.get(Job,job_id).status=="queued"
        assert db.get(JobResult,job_id) is None
        assert engine.claim(db,"monitoring",now+timedelta(seconds=4)) is None
    final=complete("down",now+timedelta(seconds=6))
    with SessionLocal() as db:
        assert not engine.finish(db,*final,{"state":"up"},now+timedelta(seconds=7))
        assert db.scalar(select(func.count()).select_from(MonitoringIncident))==1
        assert db.scalar(select(func.count()).select_from(NotificationDelivery))==1
        assert db.get(Job,job_id).attempts==2
        assert len(list(db.scalars(select(JobAttempt))))==2
    schedule(key,now+timedelta(seconds=61));complete("up",now+timedelta(seconds=62))
    with SessionLocal() as db:
        assert db.scalar(select(MonitoringIncident)).closed_at is not None
        assert db.scalar(select(func.count()).select_from(NotificationDelivery))==2
    monkeypatch.setattr(operations,"utc_now",lambda:now+timedelta(seconds=70))
    operations.notification_tick();operations.notification_tick()
    rows=api.get(f"/api/v1/websites/{key}/monitoring/notifications").json()
    assert {r["status"] for r in rows}=={"delivered"}


@pytest.mark.parametrize("action",["disable","revoke-consent","stop"])
def test_cancellation_fences_late_worker(api,action):
    key,_=setup_site(api);enable(api,key);now=utc_now();job_id=schedule(key,now)
    with SessionLocal() as db: claimed=engine.claim(db,"monitoring",now)
    path="/api/v1/monitoring/stop" if action=="stop" else f"/api/v1/websites/{key}/monitoring/{action}"
    assert api.post(path).status_code==200
    assert not operations.permitted(*claimed)
    with SessionLocal() as db:
        assert not engine.finish(db,*claimed,{"state":"down"},now+timedelta(seconds=1))
        assert db.get(Job,job_id).status=="cancelled"
        assert not list(db.scalars(select(MonitoringIncident)))
        assert not list(db.scalars(select(JobResult)))
    if action=="revoke-consent":
        assert api.post(f"/api/v1/websites/{key}/monitoring/enable").status_code==409


def test_expiry_and_withdrawal_block_execution(api):
    key,evidence=setup_site(api);enable(api,key);now=utc_now();schedule(key,now)
    with SessionLocal() as db:
        claimed=engine.claim(db,"monitoring",now)
        db.get(AuthorizationEvidence,evidence).state="withdrawn";db.commit()
    assert not operations.permitted(*claimed)
    with SessionLocal() as db:
        assert engine.finish(db,*claimed,{"state":"up"},now)
        assert db.get(JobResult,claimed[0]).payload["state"]=="cancelled"
        config=db.get(MonitoringConfig,key)
        db.get(MonitoringConsent,config.consent_id).expires_at=now-timedelta(seconds=1);db.commit()
        service.scheduler_tick(db,now+timedelta(seconds=61))
        db.refresh(config);assert not config.enabled


def test_pool_concurrency_and_lease_failure_not_downtime(api):
    first,_=setup_site(api);second,_=setup_site(api)
    enable(api,first);enable(api,second);now=utc_now();schedule(first,now);schedule(second,now)
    def claim():
        with SessionLocal() as db:return engine.claim(db,"monitoring",now)
    with ThreadPoolExecutor(max_workers=2) as workers:claims=list(workers.map(lambda _:claim(),range(2)))
    assert sum(x is not None for x in claims)==1
    old=next(x for x in claims if x)
    with SessionLocal() as db:
        new=engine.claim(db,"monitoring",now+timedelta(seconds=61));assert new
        assert db.get(Job,old[0]).status=="failed"
        assert not engine.finish(db,*old,{"state":"down"},now+timedelta(seconds=62))
        assert not list(db.scalars(select(MonitoringIncident)))
        assert engine.finish(db,*new,{"state":"unknown","error":"probe_process_failed"},now+timedelta(seconds=62))
        assert not list(db.scalars(select(MonitoringIncident)))
    with pytest.raises(ValueError):
        with SessionLocal() as db:engine.claim(db,"scanner")


def test_result_audit_failure_rolls_back_everything(api):
    key,_=setup_site(api);enable(api,key);now=utc_now();schedule(key,now)
    with SessionLocal() as db:
        claimed=engine.claim(db,"monitoring",now)
        def fail(session,context,instances):
            if any(isinstance(x,ExecutionEvent) for x in session.new): raise RuntimeError("Synthetic audit failure")
        event.listen(db,"before_flush",fail)
        with pytest.raises(RuntimeError):engine.finish(db,*claimed,{"state":"up"},now)
        db.rollback();event.remove(db,"before_flush",fail)
        assert db.get(Job,claimed[0]).status=="running"
        assert db.get(JobResult,claimed[0]) is None
        assert db.get(MonitoringConfig,key).successes==0


def test_smtp_failure_retries_and_dead_letters(api,monkeypatch):
    key,_=setup_site(api);now=utc_now()
    with SessionLocal() as db:service.notify(db,key,"incident_opened","synthetic",now);db.commit()
    monkeypatch.setattr(operations.settings,"notification_channel","smtp")
    monkeypatch.setattr(operations.settings,"smtp_host","")
    for i in range(3):
        operations.notification_tick()
        with SessionLocal() as db:
            row=db.scalar(select(NotificationDelivery));row.next_due=now-timedelta(seconds=1);db.commit()
    with SessionLocal() as db:
        row=db.scalar(select(NotificationDelivery));assert row.status=="failed";assert row.attempts==3
        assert row.last_error=="notification_delivery_failed"


def test_real_worker_subprocess_blocks_loopback_without_http(api):
    """Exercise spawn, bidirectional permission checks and result processing."""
    from app.models.website import Website
    key,_=setup_site(api)
    with SessionLocal() as db:
        config=db.get(MonitoringConfig,key)
        # Test database only: a consented loopback URL still MUST be blocked.
        db.get(Website,key).url='http://127.0.0.1/'
        db.get(MonitoringConsent,config.consent_id).url='http://127.0.0.1/'
        db.commit()
    enable(api,key)
    with SessionLocal() as db:service.scheduler_tick(db)
    operations.worker_tick()
    rows=api.get(f'/api/v1/websites/{key}/monitoring/results').json()
    assert len(rows)==1;assert rows[0]['payload']['state']=='blocked'
    assert rows[0]['payload']['error']=='prohibited_destination'
    assert api.get('/api/v1/monitoring/overview').json()['websites'][0]['state']=='blocked'
    with SessionLocal() as db:
        assert not db.get(MonitoringConfig,key).enabled
        assert not list(db.scalars(select(MonitoringIncident)))


def test_smtp_success_uses_tls_and_stable_reference(api,monkeypatch):
    key,_=setup_site(api);now=utc_now();sent=[]
    with SessionLocal() as db:service.notify(db,key,'recovered','fixture-incident',now);db.commit()
    monkeypatch.setattr(operations.settings,'notification_channel','smtp')
    monkeypatch.setattr(operations.settings,'smtp_host','smtp.synthetic.example')
    monkeypatch.setattr(operations.settings,'smtp_sender','sender@example.com')
    monkeypatch.setattr(operations.settings,'notification_recipient','operator@example.com')
    class SMTP:
        def __init__(self,host,port,timeout,context):assert host=='smtp.synthetic.example';assert timeout==10;assert context.check_hostname
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def send_message(self,message):sent.append(message)
    monkeypatch.setattr(operations.smtplib,'SMTP_SSL',SMTP)
    operations.notification_tick();operations.notification_tick()
    assert len(sent)==1;assert sent[0]['To']=='operator@example.com'
    assert 'snwebshield.local' in sent[0]['Message-ID']


def test_due_enqueue_competition_has_one_job(api):
    key,_=setup_site(api);enable(api,key);now=utc_now()
    def tick(_):
        with SessionLocal() as db:service.scheduler_tick(db,now)
    with ThreadPoolExecutor(max_workers=2) as workers:list(workers.map(tick,range(2)))
    with SessionLocal() as db:assert db.scalar(select(func.count()).select_from(Job))==1


def hanging_fixture_child(pipe,url,timeout):
    """Test-only blocked transport, deliberately without a child watchdog."""
    import time
    time.sleep(30)


def test_worker_hard_deadline_terminates_hung_child(api,monkeypatch):
    import time
    key,_=setup_site(api,timeout_seconds=2);enable(api,key)
    schedule(key,utc_now())
    monkeypatch.setattr(operations,'probe_child',hanging_fixture_child)
    start=time.monotonic();operations.worker_tick()
    assert time.monotonic()-start < 12
    with SessionLocal() as db:
        job=db.scalar(select(Job));assert job.status=='queued';assert job.attempts==1
        assert db.scalar(select(JobAttempt)).outcome=='retry_scheduled'


def test_expired_notification_lease_is_bounded(api):
    key,_=setup_site(api);now=utc_now()
    with SessionLocal() as db:
        service.notify(db,key,'recovered','crashed-delivery',now);db.commit()
        row=db.scalar(select(NotificationDelivery));row.status='sending';row.attempts=3
        row.claim_token='old-claim';row.lease_until=now-timedelta(seconds=1);db.commit()
    operations.notification_tick()
    with SessionLocal() as db:
        row=db.scalar(select(NotificationDelivery));assert row.status=='failed';assert row.attempts==3


def test_attempt_history_omits_execution_tokens(api):
    key,_=setup_site(api);enable(api,key);now=utc_now();schedule(key,now);complete('up',now)
    attempts=api.get(f'/api/v1/websites/{key}/monitoring/attempts').json()
    jobs=api.get(f'/api/v1/websites/{key}/monitoring/jobs').json()
    assert len(attempts)==len(jobs)==1
    assert 'claim_token' not in attempts[0];assert 'claim_token' not in jobs[0]
