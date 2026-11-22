"""Exercise the real HTTP parser against an isolated local fixture.

Only this test replaces DNS policy to reach loopback. Production has no such
setting; separate tests prove loopback is rejected by the real resolver.
"""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
from threading import Thread
import time
import pytest
from app.services import monitor_probe as monitor


@contextmanager
def server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/slow': time.sleep(.15)
            self.send_response(503 if self.path == '/down' else 404 if self.path == '/missing' else 302 if self.path == '/redirect' else 200)
            if self.path == '/redirect':self.send_header('Location','/health')
            self.end_headers()
        def log_message(self,*a):pass
    http=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=Thread(target=http.serve_forever,daemon=True);thread.start()
    try:yield http.server_address[1]
    finally:http.shutdown();http.server_close();thread.join(timeout=2)


@pytest.mark.parametrize('path,state,status',[('/health','up',200),('/down','down',503),('/missing','degraded',404),('/redirect','up',200)])
def test_real_http_response_and_redirect(monkeypatch,path,state,status):
    with server() as port:
        monkeypatch.setattr(monitor,'resolve',lambda host,p:[(socket.AF_INET,('127.0.0.1',port))])
        result=monitor.probe('http://synthetic.example'+path,2)
        assert result['state']==state;assert result['http_status']==status
        assert result['response_ms'] >= 0
        assert result['tls_valid'] is None
        assert result['redirects']==int(path=='/redirect')


def test_real_http_response_deadline(monkeypatch):
    with server() as port:
        monkeypatch.setattr(monitor,'resolve',lambda host,p:[(socket.AF_INET,('127.0.0.1',port))])
        result=monitor.probe('http://synthetic.example/slow',.05)
        assert result['state']=='down';assert result['error']=='deadline_exceeded'
