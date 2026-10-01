#!/usr/bin/env python3
"""本地转发代理：Chrome 不带认证连本地，本地向上游代理做认证 CONNECT。
解决 Chrome --proxy-server 不支持 user:pass@ 的问题。"""
import socket, threading, base64, os, sys
from urllib.parse import urlparse

UPSTREAM = os.environ.get("UPSTREAM_PROXY", "")
u = urlparse(UPSTREAM)
UP_HOST, UP_PORT = u.hostname, u.port
AUTH = base64.b64encode(f"{u.username}:{u.password}".encode()).decode()
LISTEN_PORT = int(os.environ.get("LOCAL_PROXY_PORT", "18888"))

def handle(client):
    try:
        # 读 CONNECT 请求
        req = b""
        while b"\r\n\r\n" not in req:
            chunk = client.recv(4096)
            if not chunk: return
            req += chunk
        lines = req.decode("iso-8859-1").split("\r\n")
        target = lines[0].split()[1]  # host:port
        # 向上游做认证 CONNECT（不带 User-Agent，走干净出口）
        up = socket.create_connection((UP_HOST, UP_PORT), timeout=15)
        up.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {AUTH}\r\n\r\n".encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            resp += up.recv(4096)
        if b"200" not in resp.split(b"\r\n")[0]:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        # 双向转发
        def pipe(a, b):
            try:
                while True:
                    d = a.recv(65536)
                    if not d: break
                    b.sendall(d)
            except: pass
            try: a.close()
            except: pass
            try: b.shutdown(socket.SHUT_WR)
            except: pass
        t = threading.Thread(target=pipe, args=(client, up), daemon=True)
        t.start()
        pipe(up, client)
    except Exception:
        try: client.close()
        except: pass

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", LISTEN_PORT))
srv.listen(100)
print(f"forward proxy on 127.0.0.1:{LISTEN_PORT} -> {UP_HOST}:{UP_PORT}", flush=True)
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
