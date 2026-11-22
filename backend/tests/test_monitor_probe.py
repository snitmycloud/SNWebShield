"""Real policy with controlled DNS, sockets and HTTP headers; no live traffic."""
import socket
import ssl
import pytest
from app.services import monitor_probe as probe


def dns(ip):
    return [(socket.AF_INET6 if ':' in ip else socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443))]


@pytest.mark.parametrize('ip',['127.0.0.1','10.0.0.1','169.254.169.254','192.168.1.1','100.64.0.1','0.0.0.0',
    '192.0.0.8','192.88.99.1','fec0::1','3fff::1','5f00::1','224.0.0.1','::1','::','fc00::1','fe80::1','::ffff:8.8.8.8','64:ff9b::a00:1','2002:0808:0808::1'])
def test_prohibited_addresses(monkeypatch,ip):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:dns(ip))
    with pytest.raises(probe.Blocked):probe.resolve('synthetic.example',443)


def test_mixed_dns_answers_rejected(monkeypatch):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:dns('8.8.8.8')+dns('127.0.0.1'))
    with pytest.raises(probe.Blocked):probe.resolve('synthetic.example',443)


@pytest.mark.parametrize('url',['file:///etc/passwd','ftp://example.com','http://user:pass@example.com',
    'http://example.com:8080','https://example.com:80','http://[fe80::1%25eth0]','http://example.com/\rsecret'])
def test_invalid_target(url):
    with pytest.raises(probe.Blocked):probe.target(url)


class FakeSocket:
    def __init__(self,*args):self.address=None
    def settimeout(self,n):assert 0<n<=20
    def connect(self,address):self.address=address
    def getpeername(self):return self.address
    def close(self):pass
    def getpeercert(self):return {'notAfter':'Dec 31 23:59:59 2030 GMT'}


def transport(monkeypatch,status=200,location=None,tls_error=False):
    connections=[];requests=[];sni=[];resolutions=[]
    def resolve(*a,**k):resolutions.append(a);return dns('8.8.8.8')
    monkeypatch.setattr(socket,'getaddrinfo',resolve)
    def sock(*args):s=FakeSocket();connections.append(s);return s
    monkeypatch.setattr(socket,'socket',sock)
    class Context:
        def wrap_socket(self,sock,server_hostname):
            sni.append(server_hostname)
            if tls_error:raise ssl.SSLCertVerificationError()
            return sock
    monkeypatch.setattr(ssl,'create_default_context',lambda:Context())
    class Response:
        def __init__(self):self.status=status
        def getheader(self,name):return location
    class Connection:
        def __init__(self,host,port,timeout):self.host=host
        def request(self,method,path,headers):requests.append((method,path,self.host,headers))
        def getresponse(self):return Response()
        def close(self):pass
    monkeypatch.setattr(probe.http.client,'HTTPConnection',Connection)
    return connections,requests,sni,resolutions


@pytest.mark.parametrize('status,expected',[(200,'up'),(404,'degraded'),(503,'down')])
def test_headers_only_and_pinned_address_host_sni(monkeypatch,status,expected):
    con,requests,sni,dns_calls=transport(monkeypatch,status=status)
    result=probe.probe('https://synthetic.example/health?ready=1',5)
    assert result['state']==expected;assert result['http_status']==status
    assert result['dns_ok'];assert result['tls_valid'];assert result['certificate_expires_at']
    assert result['response_ms']>=0
    assert con[0].address==('8.8.8.8',443)
    assert requests[0][:3]==('GET','/health?ready=1','synthetic.example')
    assert sni==['synthetic.example'];assert len(dns_calls)==1


@pytest.mark.parametrize('location',['http://synthetic.example/next','https://127.0.0.1/x','https://other.example/x'])
def test_redirect_changes_cannot_reach_second_origin(monkeypatch,location):
    con,requests,sni,dns_calls=transport(monkeypatch,302,location)
    result=probe.probe('https://synthetic.example/',5)
    assert result['state']=='blocked'
    assert len(con)==1;assert len(dns_calls)==1


def test_same_origin_redirect_revalidates_dns(monkeypatch):
    con,requests,*_=transport(monkeypatch,302,'/next')
    calls=iter([dns('8.8.8.8'),dns('127.0.0.1')])
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:next(calls))
    assert probe.probe('https://synthetic.example/',5)['state']=='blocked'
    assert len(con)==1


def test_redirect_limit(monkeypatch):
    con,*_=transport(monkeypatch,302,'/loop')
    assert probe.probe('https://synthetic.example/',5)['error']=='redirect_limit_or_missing_location'
    assert len(con)==4


def test_tls_validation_failure(monkeypatch):
    transport(monkeypatch,tls_error=True)
    result=probe.probe('https://synthetic.example/',5)
    assert result['tls_valid'] is False;assert result['state']=='down'


def test_dns_failure_timeout_and_revocation(monkeypatch):
    def broken(*a,**k):raise socket.gaierror()
    monkeypatch.setattr(socket,'getaddrinfo',broken)
    assert probe.probe('https://synthetic.example/',5)['error']=='dns_resolution_failed'
    transport(monkeypatch)
    assert probe.probe('https://synthetic.example/',0)['error']=='deadline_exceeded'
    assert probe.probe('https://synthetic.example/',5,permitted=lambda:False)['state']=='cancelled'


def test_revocation_after_dns_prevents_connection(monkeypatch):
    con,*_=transport(monkeypatch);decisions=iter([True,True,False])
    assert probe.probe('https://synthetic.example/',5,permitted=lambda:next(decisions))['state']=='cancelled'
    assert con==[]


def test_near_expiry_is_degraded(monkeypatch):
    from datetime import datetime,UTC,timedelta
    transport(monkeypatch)
    monkeypatch.setattr(FakeSocket,'getpeercert',lambda self:{'notAfter':(datetime.now(UTC)+timedelta(days=10)).strftime('%b %d %H:%M:%S %Y GMT')})
    assert probe.probe('https://synthetic.example/',5)['state']=='degraded'


@pytest.mark.parametrize('ip',['8.8.8.8','2001:4860:4860::8888'])
def test_ordinary_public_dns_answers_are_accepted(monkeypatch,ip):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:dns(ip))
    assert probe.resolve('synthetic.example',443)[0][1][0]==ip
